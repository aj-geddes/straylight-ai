// Package mcphttp implements the Streamable HTTP MCP transport for the remote
// MCP endpoint (ADR-015 Part A). It is a protocol adapter + auth gate over the
// existing mcp.dispatchToolCall core — it adds no tool logic of its own.
//
// Security model:
//   - Origin validation REJECTS (403) before auth — anti-DNS-rebinding.
//   - RS token validation (mcpauth) returns 401 + WWW-Authenticate on failure.
//   - The inbound token NEVER reaches the downstream request path (no-passthrough).
//   - Validated Identity is passed to the ToolDispatcher for audit attribution.
//   - PRM endpoint is public (no auth) per RFC 9728.
package mcphttp

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/straylight-ai/straylight/internal/mcp"
	"github.com/straylight-ai/straylight/internal/mcpauth"
)

// supportedProtocolVersion is the stable MCP protocol version this server
// implements (ADR-015 §A.2; pin the stable 2025-06-18 profile).
const supportedProtocolVersion = "2025-06-18"

// sessionIDBytes is the number of cryptographically random bytes for session IDs.
// 16 bytes = 128 bits of entropy per ADR-015 §A.3.
const sessionIDBytes = 16

// sessionTTL is the idle TTL after which sessions are expired.
const sessionTTL = 24 * time.Hour

// maxSessions is the hard cap on concurrent session count.
// Exceeded cap at initialize returns HTTP 503 (finding 7, ADR-015 §A.3).
const maxSessions = 10000

// prmCacheControl is the Cache-Control for the PRM document, matching the
// oidcCacheControl pattern from routes_oidc.go.
const prmCacheControl = "public, max-age=3600, stale-while-revalidate=300"

// ToolDispatcher is the consumer-declared interface for dispatching MCP tool
// calls. The canonical implementation wraps mcp.dispatchToolCall. Identity is
// the validated user — used for audit attribution; the raw token is never passed.
type ToolDispatcher interface {
	Dispatch(ctx context.Context, req mcp.ToolCallRequest, identity *mcpauth.Identity) mcp.ToolCallResult
}

// Config holds the configuration for the remote MCP handler.
type Config struct {
	// ResourceURI is the canonical resource URI advertised in the PRM and
	// expected as the token audience. Must match the aud claim validators accept.
	ResourceURI string

	// AuthorizationServer is the external IdP URL advertised in the PRM's
	// authorization_servers field. Must NOT be Straylight's own issuer (ADR-015).
	AuthorizationServer string

	// AllowedOrigins is the exact-match allowlist for the Origin header.
	// "*" is never permitted. An empty list means no cross-origin is allowed.
	AllowedOrigins []string

	// Validator validates inbound bearer tokens and returns an Identity.
	Validator mcpauth.TokenValidator

	// ScopesSupported is an optional advisory list of scopes for the PRM.
	ScopesSupported []string
}

// Validate checks Config invariants. Returns an error if any constraint fails.
func (c *Config) Validate() error {
	if c.ResourceURI == "" {
		return fmt.Errorf("mcphttp: ResourceURI must not be empty")
	}
	if c.Validator == nil {
		return fmt.Errorf("mcphttp: Validator must not be nil")
	}
	for _, o := range c.AllowedOrigins {
		if o == "*" {
			return fmt.Errorf("mcphttp: wildcard '*' is not permitted in AllowedOrigins (ADR-015 §A.4)")
		}
	}
	return nil
}

// sessionState holds the per-session protocol state.
type sessionState struct {
	negotiatedVersion string
	identity          *mcpauth.Identity
	lastSeen          time.Time
}

// Handler is the HTTP handler for the remote MCP endpoint.
// It implements http.Handler and routes:
//
//	POST /.well-known/oauth-protected-resource  (public, no auth)
//	POST /mcp                                    (Origin → auth → dispatch)
//	GET  /mcp                                    (405 in Phase 1)
//	DELETE /mcp                                  (session termination)
type Handler struct {
	cfg          Config
	dispatcher   ToolDispatcher
	originSet    map[string]bool
	sessions     sync.Map      // sessionID -> *sessionState
	sessionCount int64         // atomic; tracks live session count for cap enforcement
	stopCh       chan struct{} // closed by Close() to stop the background reaper
}

// NewHandler constructs a Handler, validating cfg. dispatcher may be nil (tools/call
// will return an error result in that case); pass a real dispatcher in production.
func NewHandler(cfg Config, dispatcher ToolDispatcher) (*Handler, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	originSet := make(map[string]bool, len(cfg.AllowedOrigins))
	for _, o := range cfg.AllowedOrigins {
		originSet[o] = true
	}
	h := &Handler{
		cfg:        cfg,
		dispatcher: dispatcher,
		originSet:  originSet,
		stopCh:     make(chan struct{}),
	}
	go h.startReaper(context.Background())
	return h, nil
}

// Close stops the background session reaper goroutine. Call this when the
// Handler is no longer needed (e.g. on server shutdown).
func (h *Handler) Close() {
	select {
	case <-h.stopCh:
		// already closed
	default:
		close(h.stopCh)
	}
}

// startReaper runs a background goroutine that sweeps and expires idle sessions.
// It deletes sessions whose lastSeen is older than sessionTTL and decrements
// the session count, capping unbounded growth (finding 7, ADR-015 §A.3).
func (h *Handler) startReaper(ctx context.Context) {
	ticker := time.NewTicker(sessionTTL / 2)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-h.stopCh:
			return
		case <-ticker.C:
			now := time.Now()
			h.sessions.Range(func(key, value interface{}) bool {
				sess := value.(*sessionState)
				if now.After(sess.lastSeen.Add(sessionTTL)) {
					h.sessions.Delete(key)
					atomic.AddInt64(&h.sessionCount, -1)
				}
				return true
			})
		}
	}
}

// ServeHTTP implements http.Handler. It routes requests:
//   - GET /.well-known/oauth-protected-resource → handlePRM (public)
//   - POST /mcp → handleMCP (Origin + auth gate)
//   - DELETE /mcp → handleDeleteSession
//   - anything else → 404
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/.well-known/oauth-protected-resource":
		h.handlePRM(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/mcp":
		h.handleMCP(w, r)
	case r.Method == http.MethodDelete && r.URL.Path == "/mcp":
		h.handleDeleteSession(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/mcp":
		// Phase 1: no server-initiated messages.
		w.Header().Set("Allow", "POST, DELETE")
		writeJSONError(w, http.StatusMethodNotAllowed, -32000, "GET /mcp not supported in Phase 1")
	default:
		http.NotFound(w, r)
	}
}

// handlePRM serves GET /.well-known/oauth-protected-resource (RFC 9728).
// This endpoint is PUBLIC — no Origin check, no auth. Clients use it for
// the WWW-Authenticate discovery bootstrap.
func (h *Handler) handlePRM(w http.ResponseWriter, r *http.Request) {
	prm := map[string]interface{}{
		"resource":                 h.cfg.ResourceURI,
		"authorization_servers":    h.buildAuthorizationServers(),
		"bearer_methods_supported": []string{"header"},
	}
	if len(h.cfg.ScopesSupported) > 0 {
		prm["scopes_supported"] = h.cfg.ScopesSupported
	}
	w.Header().Set("Cache-Control", prmCacheControl)
	writeJSON(w, http.StatusOK, prm)
}

// buildAuthorizationServers returns the list of trusted AS URLs for the PRM.
// In Phase 1, this is the configured AuthorizationServer (the user's IdP).
func (h *Handler) buildAuthorizationServers() []string {
	if h.cfg.AuthorizationServer != "" {
		return []string{h.cfg.AuthorizationServer}
	}
	return []string{}
}

// handleMCP processes POST /mcp. Order:
//  1. Origin validation → 403 on fail (before auth).
//  2. Session lookup (if MCP-Session-Id header present) → 404 on unknown session.
//  3. RS token validation → 401 + WWW-Authenticate on fail.
//  4. Parse JSON-RPC body.
//  5. Route by method.
func (h *Handler) handleMCP(w http.ResponseWriter, r *http.Request) {
	// Step 1: Origin validation — reject before auth (anti-DNS-rebinding).
	origin := r.Header.Get("Origin")
	if !h.isAllowedOrigin(origin) {
		writeJSONError(w, http.StatusForbidden, -32003, "Origin not allowed")
		return
	}

	// Step 2: Session lookup — if a session ID is provided and is unknown, 404.
	incomingSessionID := r.Header.Get("MCP-Session-Id")
	var sess *sessionState
	if incomingSessionID != "" {
		v, ok := h.sessions.Load(incomingSessionID)
		if !ok {
			writeJSONError(w, http.StatusNotFound, -32001, "unknown or expired MCP-Session-Id")
			return
		}
		sess = v.(*sessionState)
		// Protocol version must match the negotiated version.
		reqVersion := r.Header.Get("MCP-Protocol-Version")
		if reqVersion != "" && reqVersion != sess.negotiatedVersion {
			writeJSONError(w, http.StatusBadRequest, -32002,
				fmt.Sprintf("MCP-Protocol-Version mismatch: session uses %q, request sent %q",
					sess.negotiatedVersion, reqVersion))
			return
		}
		sess.lastSeen = time.Now()
	}

	// Step 3: RS token validation.
	identity, err := h.validateBearer(r)
	if err != nil {
		prmURI := h.cfg.ResourceURI + "/.well-known/oauth-protected-resource"
		ve, ok := err.(*mcpauth.ValidationError)
		if !ok {
			ve = &mcpauth.ValidationError{
				Code:        "invalid_token",
				Message:     err.Error(),
				ResourceURI: h.cfg.ResourceURI,
			}
		}
		w.Header().Set("WWW-Authenticate", ve.WWWAuthenticateHeader(prmURI))
		writeJSONError(w, http.StatusUnauthorized, -32000, ve.Message)
		return
	}
	_ = identity // used below in dispatch

	// Step 4: Parse JSON-RPC body.
	var rpcReq jsonRPCRequest
	if err := json.NewDecoder(r.Body).Decode(&rpcReq); err != nil {
		writeJSONError(w, http.StatusBadRequest, -32700, "parse error: "+err.Error())
		return
	}

	// Step 5: Route by JSON-RPC method.
	switch rpcReq.Method {
	case "initialize":
		h.handleInitialize(w, r, rpcReq, identity)
	case "tools/list":
		h.handleToolsList(w, rpcReq)
	case "tools/call":
		h.handleToolsCall(w, r, rpcReq, identity)
	case "ping":
		writeJSON(w, http.StatusOK, jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      rpcReq.ID,
			Result:  map[string]interface{}{},
		})
	default:
		writeJSONError(w, http.StatusOK, -32601, "method not found: "+rpcReq.Method)
	}
}

// handleInitialize processes the MCP initialize method (ADR-015 §A.2/A.3).
// It negotiates the protocol version, assigns a session ID, and returns
// server capabilities.
func (h *Handler) handleInitialize(w http.ResponseWriter, r *http.Request, req jsonRPCRequest, identity *mcpauth.Identity) {
	// Parse client's requested protocol version from params.
	clientVersion := ""
	if req.Params != nil {
		var params map[string]interface{}
		if data, err := json.Marshal(req.Params); err == nil {
			if err2 := json.Unmarshal(data, &params); err2 == nil {
				if v, ok := params["protocolVersion"].(string); ok {
					clientVersion = v
				}
			}
		}
	}
	// Also accept from MCP-Protocol-Version header.
	if hv := r.Header.Get("MCP-Protocol-Version"); hv != "" {
		clientVersion = hv
	}

	// Negotiate: use the client's version if it's the one we support,
	// otherwise fall back to our supported version.
	negotiated := supportedProtocolVersion
	if clientVersion == supportedProtocolVersion {
		negotiated = clientVersion
	}

	// Enforce hard session cap before allocating a new session (finding 7).
	if atomic.LoadInt64(&h.sessionCount) >= maxSessions {
		writeJSONError(w, http.StatusServiceUnavailable, -32000, "too many concurrent sessions")
		return
	}

	// Generate session ID.
	sessionID := generateSessionID()
	h.sessions.Store(sessionID, &sessionState{
		negotiatedVersion: negotiated,
		identity:          identity,
		lastSeen:          time.Now(),
	})
	atomic.AddInt64(&h.sessionCount, 1)

	w.Header().Set("MCP-Session-Id", sessionID)
	writeJSON(w, http.StatusOK, jsonRPCResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result: map[string]interface{}{
			"protocolVersion": negotiated,
			"capabilities": map[string]interface{}{
				"tools": map[string]interface{}{"listChanged": false},
			},
			"serverInfo": map[string]interface{}{
				"name":    "straylight",
				"version": "1.0.0",
			},
		},
	})
}

// handleToolsList returns the tool definitions from mcp.toolDefinitions.
// Uses the same definitions the internal API serves (reuse, no duplication).
func (h *Handler) handleToolsList(w http.ResponseWriter, req jsonRPCRequest) {
	// Access the package-level toolDefinitions via the exported list function
	// to avoid coupling to the internal variable directly.
	tools := mcp.ToolDefinitionList()
	writeJSON(w, http.StatusOK, jsonRPCResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result: map[string]interface{}{
			"tools": tools,
		},
	})
}

// handleToolsCall routes a tools/call request into the ToolDispatcher.
// The validated Identity is passed for audit attribution; the raw token is
// not present (no-passthrough by construction).
func (h *Handler) handleToolsCall(w http.ResponseWriter, r *http.Request, req jsonRPCRequest, identity *mcpauth.Identity) {
	if h.dispatcher == nil {
		writeJSONError(w, http.StatusOK, -32000, "tool dispatcher not configured")
		return
	}

	// Parse tools/call params: { name, arguments }.
	var params struct {
		Name      string                 `json:"name"`
		Arguments map[string]interface{} `json:"arguments"`
	}
	if req.Params != nil {
		data, _ := json.Marshal(req.Params)
		_ = json.Unmarshal(data, &params)
	}

	toolReq := mcp.ToolCallRequest{
		Tool:      params.Name,
		Arguments: params.Arguments,
	}

	result := h.dispatcher.Dispatch(r.Context(), toolReq, identity)

	writeJSON(w, http.StatusOK, jsonRPCResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result:  result,
	})
}

// handleDeleteSession handles DELETE /mcp to terminate a session.
// Origin validation runs first — consistent with handleMCP — to prevent
// DNS-rebinding attacks even on the session-termination path.
func (h *Handler) handleDeleteSession(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	if !h.isAllowedOrigin(origin) {
		writeJSONError(w, http.StatusForbidden, -32003, "Origin not allowed")
		return
	}
	sessionID := r.Header.Get("MCP-Session-Id")
	if sessionID == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if _, existed := h.sessions.LoadAndDelete(sessionID); existed {
		atomic.AddInt64(&h.sessionCount, -1)
	}
	w.WriteHeader(http.StatusNoContent)
}

// validateBearer extracts and validates the Bearer token from the Authorization header.
func (h *Handler) validateBearer(r *http.Request) (*mcpauth.Identity, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return nil, &mcpauth.ValidationError{
			Code:        "invalid_token",
			Message:     "missing Authorization header",
			ResourceURI: h.cfg.ResourceURI,
		}
	}
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return nil, &mcpauth.ValidationError{
			Code:        "invalid_token",
			Message:     "Authorization header must use Bearer scheme",
			ResourceURI: h.cfg.ResourceURI,
		}
	}
	rawToken := strings.TrimPrefix(authHeader, "Bearer ")
	return h.cfg.Validator.Validate(r.Context(), rawToken)
}

// isAllowedOrigin reports whether origin is in the configured allowlist.
// An empty Origin is rejected. No wildcard is ever permitted.
func (h *Handler) isAllowedOrigin(origin string) bool {
	if origin == "" {
		return false
	}
	return h.originSet[origin]
}

// generateSessionID returns a cryptographically random session ID string.
func generateSessionID() string {
	b := make([]byte, sessionIDBytes)
	if _, err := rand.Read(b); err != nil {
		// Extremely rare; use timestamp fallback.
		return fmt.Sprintf("sess-%d", time.Now().UnixNano())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// ---------------------------------------------------------------------------
// JSON-RPC helpers
// ---------------------------------------------------------------------------

type jsonRPCRequest struct {
	JSONRPC string      `json:"jsonrpc"`
	Method  string      `json:"method"`
	ID      interface{} `json:"id"`
	Params  interface{} `json:"params,omitempty"`
}

type jsonRPCResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      interface{} `json:"id"`
	Result  interface{} `json:"result,omitempty"`
	Error   interface{} `json:"error,omitempty"`
}

type jsonRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeJSONError(w http.ResponseWriter, httpStatus, rpcCode int, msg string) {
	writeJSON(w, httpStatus, map[string]interface{}{
		"jsonrpc": "2.0",
		"error": jsonRPCError{
			Code:    rpcCode,
			Message: msg,
		},
	})
}
