// Package server provides the HTTP server for Straylight-AI.
package server

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/straylight-ai/straylight/internal/audit"
	"github.com/straylight-ai/straylight/internal/cloud"
	"github.com/straylight-ai/straylight/internal/database"
	"github.com/straylight-ai/straylight/internal/egress"
	"github.com/straylight-ai/straylight/internal/mcpauth"
	"github.com/straylight-ai/straylight/internal/mcphttp"
	"github.com/straylight-ai/straylight/internal/oauth"
	"github.com/straylight-ai/straylight/internal/oidc"
	"github.com/straylight-ai/straylight/internal/services"
)

// MCPRouteHandler is an http.Handler that handles both
// GET /api/v1/mcp/tool-list and POST /api/v1/mcp/tool-call.
// Implemented by *mcp.Handler; use nil to return 501 Not Implemented.
type MCPRouteHandler interface {
	HandleToolList(w http.ResponseWriter, r *http.Request)
	HandleToolCall(w http.ResponseWriter, r *http.Request)
}

const (
	shutdownTimeout = 10 * time.Second
	readTimeout     = 30 * time.Second
	writeTimeout    = 30 * time.Second
	idleTimeout     = 120 * time.Second
)

// Config holds the parameters needed to create a Server.
type Config struct {
	ListenAddress string
	Version       string

	// VaultStatus is an optional function that returns the current OpenBao vault
	// status as one of "unsealed", "sealed", or "unavailable". When nil, the
	// health endpoint reports "unavailable" for the openbao field.
	VaultStatus func() string

	// Registry is the service registry used by the service management endpoints.
	// When nil, service endpoints return 501 Not Implemented.
	Registry *services.Registry

	// OAuthHandler handles the OAuth authorization code flow endpoints.
	// When nil, OAuth endpoints return 501 Not Implemented.
	OAuthHandler *oauth.Handler

	// MCPHandler handles the MCP tool forwarding endpoints (WP-1.4).
	// When nil, MCP endpoints return 501 Not Implemented.
	MCPHandler MCPRouteHandler

	// ActivityLog tracks tool call activity for the stats endpoint.
	// When nil, a new empty log is created automatically.
	ActivityLog *ActivityLog

	// AuditLogger is the audit event logger used by the audit API endpoints.
	// When nil, audit endpoints return 501 Not Implemented.
	AuditLogger *audit.Logger

	// DBManager is the database credential manager for database service management.
	// When nil, database endpoints return 501 Not Implemented.
	DBManager *database.Manager

	// OIDCDiscovery is the OIDC discovery document served at
	// /.well-known/openid-configuration and the public JWKS at
	// /.well-known/jwks.json. These endpoints are unauthenticated by design.
	// When nil, the well-known endpoints return 404.
	OIDCDiscovery *oidc.Discovery

	// CloudManager is the keyless cloud credential manager (ADR-012 Phase 2).
	// When non-nil, it is available to route handlers that generate cloud
	// credentials for services opting in to the keyless path. When nil, the
	// cloud credential generation path is not available.
	CloudManager *cloud.Manager

	// EgressGuard is the SSRF guard used by the import endpoint when fetching a
	// remote OpenAPI spec. When nil, the default egress.New() guard is used.
	EgressGuard egress.Guard

	// Templates is the merged (built-ins + community) service template catalog
	// served by the /api/v1/templates endpoint and template lookup. When nil,
	// handlers fall back to services.ServiceTemplates. Prefer setting this via
	// LoadCommunityTemplates + MergeTemplates at startup.
	Templates []services.ServiceTemplate

	// ---------------------------------------------------------------------------
	// Remote MCP (ADR-015, Wave 3). All nil/zero = remote mode OFF.
	// The existing stdio path and /api/v1/mcp/* are UNCHANGED when unset.
	// ---------------------------------------------------------------------------

	// RemoteListenAddress is the listen address for the opt-in remote MCP listener
	// (e.g. "127.0.0.1:9471"). Empty string = remote mode OFF. Default is loopback;
	// never auto-binds 0.0.0.0 (ADR-015 §A.4).
	RemoteListenAddress string

	// MCPResourceServer holds the OAuth 2.1 RS configuration for the remote MCP
	// endpoint. When non-nil, validates inbound bearer tokens from the user's IdP.
	// MUST be non-nil when RemoteListenAddress is set.
	MCPResourceServer *mcpauth.ValidatorConfig

	// MCPAllowedOrigins is the exact-match Origin allowlist for the remote listener.
	// "*" is never permitted. Empty = no cross-origin (loopback clients only).
	MCPAllowedOrigins []string

	// MCPAuthorizationServer is the external IdP URL advertised in the PRM
	// authorization_servers field. Must NOT be Straylight's own issuer (ADR-015).
	MCPAuthorizationServer string

	// MCPRemoteRateLimit holds optional tighter rate-limit options for the remote
	// listener (separate from the dashboard/internal surface).
	MCPRemoteRateLimit Options
}

// Options holds optional tuning parameters for the server's security middleware.
// Zero values select the sensible defaults defined in middleware.go.
type Options struct {
	// RateLimit sets requests per second for the rate limiter.
	// Default: 100 req/s.
	RateLimit int
	// Burst sets the token-bucket burst size.
	// Default: 200.
	Burst int
}

// Server is the Straylight-AI HTTP server. It implements http.Handler so it
// can be used directly with httptest.NewRecorder in tests.
type Server struct {
	cfg     Config
	opts    Options
	mux     *http.ServeMux
	handler http.Handler // mux wrapped with security middleware
	logger  *slog.Logger
	stopCh  chan struct{}
}

// New constructs a Server with all routes registered and default middleware options.
func New(cfg Config) *Server {
	return NewWithOptions(cfg, Options{})
}

// NewWithOptions constructs a Server with all routes registered and custom
// middleware options. Use this in tests to set a tight rate limit.
func NewWithOptions(cfg Config, opts Options) *Server {
	if cfg.ActivityLog == nil {
		cfg.ActivityLog = NewActivityLog()
	}
	s := &Server{
		cfg:    cfg,
		opts:   opts,
		mux:    http.NewServeMux(),
		logger: slog.New(slog.NewJSONHandler(os.Stdout, nil)),
		stopCh: make(chan struct{}),
	}
	registerRoutes(s)
	// Build the full middleware chain once:
	// RequestLogging -> SecurityHeaders -> CORS -> RateLimit -> MaxBodySize -> mux
	s.handler = RequestLogging(s.logger, applyMiddlewareChain(s.mux, opts))
	return s
}

// ServeHTTP implements http.Handler, allowing the server to be used in tests.
// Requests pass through the security middleware chain before reaching the mux.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.handler.ServeHTTP(w, r)
}

// ListenAddress returns the configured listen address.
func (s *Server) ListenAddress() string {
	return s.cfg.ListenAddress
}

// Stop signals the server to shut down gracefully. The provided context controls
// the timeout for in-flight requests to complete.
func (s *Server) Stop(ctx context.Context) error {
	select {
	case <-s.stopCh:
		// Already stopped.
	default:
		close(s.stopCh)
	}
	return nil
}

// Run starts the HTTP server and blocks until SIGTERM, SIGINT, or Stop() is called,
// then performs a graceful shutdown.
func (s *Server) Run() error {
	httpServer := &http.Server{
		Addr:         s.cfg.ListenAddress,
		Handler:      s.handler,
		ReadTimeout:  readTimeout,
		WriteTimeout: writeTimeout,
		IdleTimeout:  idleTimeout,
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(quit)

	errCh := make(chan error, 1)
	go func() {
		s.logger.Info("straylight server starting",
			"address", s.cfg.ListenAddress,
			"version", s.cfg.Version,
		)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
		close(errCh)
	}()

	// Start the opt-in remote MCP listener when configured (ADR-015).
	// When RemoteListenAddress is empty, this is a no-op — existing behavior
	// is byte-for-byte unchanged.
	var remoteServer *http.Server
	if s.cfg.RemoteListenAddress != "" && s.cfg.MCPResourceServer != nil {
		rs, err := s.buildRemoteServer()
		if err != nil {
			s.logger.Error("remote MCP listener: failed to build", "error", err)
		} else {
			remoteServer = rs
			go func() {
				s.logger.Info("remote MCP listener starting",
					"address", s.cfg.RemoteListenAddress,
				)
				if err := remoteServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
					s.logger.Error("remote MCP listener error", "error", err)
				}
			}()
		}
	}

	select {
	case err := <-errCh:
		return err
	case sig := <-quit:
		s.logger.Info("shutdown signal received", "signal", sig)
	case <-s.stopCh:
		s.logger.Info("programmatic stop requested")
	}

	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	s.logger.Info("shutting down gracefully", "timeout", shutdownTimeout)
	if err := httpServer.Shutdown(ctx); err != nil {
		return err
	}
	if remoteServer != nil {
		if err := remoteServer.Shutdown(ctx); err != nil {
			s.logger.Error("remote MCP shutdown error", "error", err)
		}
	}

	s.logger.Info("server stopped")
	return nil
}

// buildRemoteServer constructs the opt-in remote MCP HTTP server (ADR-015).
// Returns an error if configuration is invalid. Only called when
// RemoteListenAddress and MCPResourceServer are both set.
func (s *Server) buildRemoteServer() (*http.Server, error) {
	// Clone the resource-server config and inject the runtime issuer URL so
	// New() can enforce role-disjointness against the actual issuer (not just
	// the legacy sentinel "https://straylight.internal").
	rsCfg := *s.cfg.MCPResourceServer
	if rsCfg.OwnIssuerURL == "" && s.cfg.OIDCDiscovery != nil {
		rsCfg.OwnIssuerURL = s.cfg.OIDCDiscovery.IssuerURL
	}

	// Wire the egress SSRF guard into the JWKS provider so JWKS fetches to
	// private/link-local addresses are blocked (finding 3, ADR-014).
	if rsCfg.JWKSProvider == nil && s.cfg.EgressGuard != nil {
		rsCfg.JWKSProvider = mcpauth.NewSSRFGatedJWKSProvider(
			NewEgressSSRFGuard(s.cfg.EgressGuard), nil)
	}

	// Build the TokenValidator from the MCPResourceServer config.
	validator, err := mcpauth.New(rsCfg)
	if err != nil {
		return nil, fmt.Errorf("remote MCP: token validator: %w", err)
	}

	handlerCfg := mcphttp.Config{
		ResourceURI:         s.cfg.MCPResourceServer.Resource,
		AuthorizationServer: s.cfg.MCPAuthorizationServer,
		AllowedOrigins:      s.cfg.MCPAllowedOrigins,
		Validator:           validator,
	}

	// The remote adapter uses the MCPHandler if it also implements ToolDispatcher.
	// In production wiring, pass a *mcp.Handler that implements both interfaces.
	// When nil or the cast fails, tools/call returns "not configured"; the remote
	// endpoint still serves initialize/tools/list (no tool logic is duplicated).
	var dispatcher mcphttp.ToolDispatcher
	if s.cfg.MCPHandler != nil {
		if td, ok := s.cfg.MCPHandler.(mcphttp.ToolDispatcher); ok {
			dispatcher = td
		}
	}

	mcpHandler, err := mcphttp.NewHandler(handlerCfg, dispatcher)
	if err != nil {
		return nil, fmt.Errorf("remote MCP: handler: %w", err)
	}

	// Remote chain: RequestLogging -> SecurityHeaders -> OriginValidate ->
	//   RateLimiter -> MaxBodySize -> mcpHandler.
	// OriginValidate runs BEFORE the rate limiter so DNS-rebinding probes do
	// not consume rate-limit budget. The PRM endpoint is exempt (public per RFC 9728).
	// This is SEPARATE from applyMiddlewareChain (which uses CORS, not Origin-reject).
	prmPath := "/.well-known/oauth-protected-resource"
	remoteChain := RequestLogging(s.logger,
		SecurityHeaders(
			OriginValidate(s.cfg.MCPAllowedOrigins, prmPath)(
				RateLimiter(
					rateOrDefault(s.cfg.MCPRemoteRateLimit.RateLimit, 20),
					rateOrDefault(s.cfg.MCPRemoteRateLimit.Burst, 40),
				)(
					MaxBodySize(defaultMaxBodyBytes)(mcpHandler),
				),
			),
		),
	)

	return &http.Server{
		Addr:         s.cfg.RemoteListenAddress,
		Handler:      remoteChain,
		ReadTimeout:  readTimeout,
		WriteTimeout: writeTimeout,
		IdleTimeout:  idleTimeout,
	}, nil
}

// mcpHandlerDispatcher is intentionally omitted: the MCPRouteHandler interface
// is for the internal /api/v1/mcp/* REST API. The remote MCP (mcphttp) dispatcher
// interface uses mcp.ToolCallRequest + *mcpauth.Identity, which requires a
// concrete *mcp.Handler with all deps. In production, pass a *mcp.Handler via
// serve() wiring. In Phase 1, when MCPHandler is set, it is cast to a concrete
// dispatcher if it implements mcphttp.ToolDispatcher.
//
// We leave the dispatcher nil when the cast isn't available: the remote endpoint
// still serves initialize/tools/list; tools/call returns a "not configured" error.

// rateOrDefault returns val if positive, otherwise returns def.
func rateOrDefault(val, def int) int {
	if val > 0 {
		return val
	}
	return def
}
