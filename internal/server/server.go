// Package server provides the HTTP server for Straylight-AI.
package server

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/straylight-ai/straylight/internal/oauth"
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

	s.logger.Info("server stopped")
	return nil
}
