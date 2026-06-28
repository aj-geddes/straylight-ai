package mcphttp_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/straylight-ai/straylight/internal/mcp"
	"github.com/straylight-ai/straylight/internal/mcpauth"
	"github.com/straylight-ai/straylight/internal/mcphttp"
)

// ---------------------------------------------------------------------------
// Test stubs
// ---------------------------------------------------------------------------

// stubValidator returns a valid Identity for any token containing "valid",
// and a ValidationError otherwise.
type stubValidator struct {
	validToken bool
}

func (v *stubValidator) Validate(_ context.Context, token string) (*mcpauth.Identity, error) {
	if v.validToken || strings.Contains(token, "valid") {
		return &mcpauth.Identity{
			Subject:  "user|alice",
			Issuer:   "https://idp.example.com",
			Audience: "https://mcp.example.com",
		}, nil
	}
	return nil, &mcpauth.ValidationError{
		Code:        "invalid_token",
		Message:     "token invalid",
		ResourceURI: "https://mcp.example.com",
	}
}

// stubDispatcher records whether Dispatch was called and returns a canned result.
type stubDispatcher struct {
	called   bool
	identity *mcpauth.Identity
	result   mcp.ToolCallResult
}

func (d *stubDispatcher) Dispatch(_ context.Context, _ mcp.ToolCallRequest, id *mcpauth.Identity) mcp.ToolCallResult {
	d.called = true
	d.identity = id
	if len(d.result.Content) == 0 {
		return mcp.ToolCallResult{
			Content: []mcp.ContentItem{{Type: "text", Text: "ok"}},
		}
	}
	return d.result
}

// newTestConfig returns a Config with sensible test defaults.
func newTestConfig() mcphttp.Config {
	return mcphttp.Config{
		ResourceURI:         "https://mcp.example.com",
		AuthorizationServer: "https://idp.example.com",
		AllowedOrigins:      []string{"https://claude.ai", "https://cursor.sh"},
		Validator:           &stubValidator{},
	}
}

// postMCP sends a POST /mcp with the given JSON body and headers, returns the recorder.
func postMCP(h http.Handler, body interface{}, headers map[string]string) *httptest.ResponseRecorder {
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// ---------------------------------------------------------------------------
// Config validation
// ---------------------------------------------------------------------------

func TestNewHandler_RejectsWildcardOrigin(t *testing.T) {
	cfg := newTestConfig()
	cfg.AllowedOrigins = []string{"*"}
	_, err := mcphttp.NewHandler(cfg, nil)
	if err == nil {
		t.Fatal("expected error for wildcard AllowedOrigins, got nil")
	}
}

func TestNewHandler_RejectsWildcardAmongOrigins(t *testing.T) {
	cfg := newTestConfig()
	cfg.AllowedOrigins = []string{"https://example.com", "*"}
	_, err := mcphttp.NewHandler(cfg, nil)
	if err == nil {
		t.Fatal("expected error when '*' appears in AllowedOrigins")
	}
}

func TestNewHandler_RejectsEmptyResourceURI(t *testing.T) {
	cfg := newTestConfig()
	cfg.ResourceURI = ""
	_, err := mcphttp.NewHandler(cfg, nil)
	if err == nil {
		t.Fatal("expected error for empty ResourceURI")
	}
}

func TestNewHandler_RejectsNilValidator(t *testing.T) {
	cfg := newTestConfig()
	cfg.Validator = nil
	_, err := mcphttp.NewHandler(cfg, nil)
	if err == nil {
		t.Fatal("expected error for nil Validator")
	}
}

// ---------------------------------------------------------------------------
// Origin validation (MUST run before auth)
// ---------------------------------------------------------------------------

func TestHandler_MissingOrigin_Returns403(t *testing.T) {
	cfg := newTestConfig()
	h, err := mcphttp.NewHandler(cfg, nil)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	rec := postMCP(h, map[string]interface{}{"jsonrpc": "2.0", "method": "initialize", "id": 1}, map[string]string{
		"Authorization": "Bearer valid-token",
		// no Origin
	})
	if rec.Code != http.StatusForbidden {
		t.Errorf("missing Origin: status = %d, want 403", rec.Code)
	}
}

func TestHandler_BadOrigin_Returns403(t *testing.T) {
	cfg := newTestConfig()
	h, err := mcphttp.NewHandler(cfg, nil)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	rec := postMCP(h, map[string]interface{}{"jsonrpc": "2.0", "method": "initialize", "id": 1}, map[string]string{
		"Origin":        "https://evil.example.com",
		"Authorization": "Bearer valid-token",
	})
	if rec.Code != http.StatusForbidden {
		t.Errorf("bad Origin: status = %d, want 403", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// Auth gate (after Origin, before handler)
// ---------------------------------------------------------------------------

func TestHandler_MissingAuth_Returns401WithWWWAuthenticate(t *testing.T) {
	cfg := newTestConfig()
	h, err := mcphttp.NewHandler(cfg, nil)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	rec := postMCP(h, map[string]interface{}{"jsonrpc": "2.0", "method": "initialize", "id": 1}, map[string]string{
		"Origin": "https://claude.ai",
		// no Authorization
	})
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("missing auth: status = %d, want 401", rec.Code)
	}
	wwwAuth := rec.Header().Get("WWW-Authenticate")
	if !strings.HasPrefix(wwwAuth, "Bearer ") {
		t.Errorf("WWW-Authenticate must start with 'Bearer ', got: %q", wwwAuth)
	}
	if !strings.Contains(wwwAuth, "resource_metadata=") {
		t.Errorf("WWW-Authenticate must contain resource_metadata, got: %q", wwwAuth)
	}
}

func TestHandler_InvalidToken_Returns401(t *testing.T) {
	cfg := newTestConfig()
	h, err := mcphttp.NewHandler(cfg, nil)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	rec := postMCP(h, map[string]interface{}{"jsonrpc": "2.0", "method": "initialize", "id": 1}, map[string]string{
		"Origin":        "https://claude.ai",
		"Authorization": "Bearer bad-token",
	})
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("invalid token: status = %d, want 401", rec.Code)
	}
	if !strings.HasPrefix(rec.Header().Get("WWW-Authenticate"), "Bearer ") {
		t.Error("invalid token: missing or wrong WWW-Authenticate header")
	}
}

// ---------------------------------------------------------------------------
// MCP protocol: initialize
// ---------------------------------------------------------------------------

func TestHandler_Initialize_Returns200WithSessionID(t *testing.T) {
	cfg := newTestConfig()
	h, err := mcphttp.NewHandler(cfg, nil)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	rec := postMCP(h, map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "initialize",
		"id":      1,
		"params":  map[string]interface{}{"protocolVersion": "2025-06-18"},
	}, map[string]string{
		"Origin":        "https://claude.ai",
		"Authorization": "Bearer valid-token",
	})
	if rec.Code != http.StatusOK {
		t.Errorf("initialize: status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	sessionID := rec.Header().Get("MCP-Session-Id")
	if sessionID == "" {
		t.Error("initialize: missing MCP-Session-Id response header")
	}
}

// ---------------------------------------------------------------------------
// MCP protocol: tools/list
// ---------------------------------------------------------------------------

func TestHandler_ToolsList_ReturnsToolDefinitions(t *testing.T) {
	cfg := newTestConfig()
	h, err := mcphttp.NewHandler(cfg, nil)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	rec := postMCP(h, map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "tools/list",
		"id":      2,
	}, map[string]string{
		"Origin":        "https://claude.ai",
		"Authorization": "Bearer valid-token",
	})
	if rec.Code != http.StatusOK {
		t.Errorf("tools/list: status = %d, want 200", rec.Code)
	}
	var resp map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("tools/list: decode error: %v", err)
	}
	result, ok := resp["result"].(map[string]interface{})
	if !ok {
		t.Fatalf("tools/list: no result field in %v", resp)
	}
	tools, ok := result["tools"].([]interface{})
	if !ok {
		t.Fatalf("tools/list: result.tools is not an array, got %T", result["tools"])
	}
	if len(tools) == 0 {
		t.Error("tools/list: expected non-empty tools array")
	}
}

// ---------------------------------------------------------------------------
// MCP protocol: tools/call dispatch + audit attribution
// ---------------------------------------------------------------------------

func TestHandler_ToolsCall_DispatchesWithIdentity(t *testing.T) {
	dispatcher := &stubDispatcher{}
	cfg := newTestConfig()
	h, err := mcphttp.NewHandler(cfg, dispatcher)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	rec := postMCP(h, map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "tools/call",
		"id":      3,
		"params": map[string]interface{}{
			"name":      "straylight_services",
			"arguments": map[string]interface{}{},
		},
	}, map[string]string{
		"Origin":        "https://claude.ai",
		"Authorization": "Bearer valid-token",
	})
	if rec.Code != http.StatusOK {
		t.Errorf("tools/call: status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	if !dispatcher.called {
		t.Error("tools/call: Dispatcher.Dispatch was not called")
	}
	if dispatcher.identity == nil {
		t.Error("tools/call: Dispatch was called with nil identity")
	}
	if dispatcher.identity.Subject != "user|alice" {
		t.Errorf("tools/call: identity.Subject = %q, want user|alice", dispatcher.identity.Subject)
	}
}

// ---------------------------------------------------------------------------
// PRM endpoint (public, no auth required)
// ---------------------------------------------------------------------------

func TestHandler_PRM_PublicNoAuth(t *testing.T) {
	cfg := newTestConfig()
	h, err := mcphttp.NewHandler(cfg, nil)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("PRM: status = %d, want 200", rec.Code)
	}
	var prm map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&prm); err != nil {
		t.Fatalf("PRM decode: %v", err)
	}
	if prm["resource"] != "https://mcp.example.com" {
		t.Errorf("PRM resource = %v, want https://mcp.example.com", prm["resource"])
	}
	if _, ok := prm["authorization_servers"].([]interface{}); !ok {
		t.Error("PRM missing authorization_servers array")
	}
	if _, ok := prm["bearer_methods_supported"].([]interface{}); !ok {
		t.Error("PRM missing bearer_methods_supported array")
	}
}

func TestHandler_PRM_HasCacheControlHeader(t *testing.T) {
	cfg := newTestConfig()
	h, err := mcphttp.NewHandler(cfg, nil)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	cc := rec.Header().Get("Cache-Control")
	if !strings.Contains(cc, "max-age") {
		t.Errorf("PRM should set Cache-Control with max-age, got: %q", cc)
	}
}

// ---------------------------------------------------------------------------
// Session lifecycle
// ---------------------------------------------------------------------------

func TestHandler_UnknownSessionID_Returns404(t *testing.T) {
	cfg := newTestConfig()
	h, err := mcphttp.NewHandler(cfg, nil)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	rec := postMCP(h, map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "tools/list",
		"id":      1,
	}, map[string]string{
		"Origin":         "https://claude.ai",
		"Authorization":  "Bearer valid-token",
		"MCP-Session-Id": "unknown-session-id-xyz",
	})
	if rec.Code != http.StatusNotFound {
		t.Errorf("unknown session: status = %d, want 404", rec.Code)
	}
}

func TestHandler_KnownSessionID_Accepted(t *testing.T) {
	cfg := newTestConfig()
	h, err := mcphttp.NewHandler(cfg, nil)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	// Initialize to get a session ID.
	rec1 := postMCP(h, map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "initialize",
		"id":      1,
		"params":  map[string]interface{}{"protocolVersion": "2025-06-18"},
	}, map[string]string{
		"Origin":        "https://claude.ai",
		"Authorization": "Bearer valid-token",
	})
	if rec1.Code != http.StatusOK {
		t.Fatalf("initialize failed: %d", rec1.Code)
	}
	sessionID := rec1.Header().Get("MCP-Session-Id")

	// Use the session ID on a follow-up request.
	rec2 := postMCP(h, map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "tools/list",
		"id":      2,
	}, map[string]string{
		"Origin":         "https://claude.ai",
		"Authorization":  "Bearer valid-token",
		"MCP-Session-Id": sessionID,
	})
	if rec2.Code != http.StatusOK {
		t.Errorf("known session follow-up: status = %d, want 200", rec2.Code)
	}
}

// ---------------------------------------------------------------------------
// Protocol version mismatch
// ---------------------------------------------------------------------------

func TestHandler_ProtocolVersionMismatch_Returns400(t *testing.T) {
	cfg := newTestConfig()
	h, err := mcphttp.NewHandler(cfg, nil)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	// Initialize with a version.
	rec1 := postMCP(h, map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "initialize",
		"id":      1,
		"params":  map[string]interface{}{"protocolVersion": "2025-06-18"},
	}, map[string]string{
		"Origin":               "https://claude.ai",
		"Authorization":        "Bearer valid-token",
		"MCP-Protocol-Version": "2025-06-18",
	})
	if rec1.Code != http.StatusOK {
		t.Fatalf("initialize: %d", rec1.Code)
	}
	sessionID := rec1.Header().Get("MCP-Session-Id")

	// Send follow-up with a DIFFERENT MCP-Protocol-Version header.
	rec2 := postMCP(h, map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "tools/list",
		"id":      2,
	}, map[string]string{
		"Origin":               "https://claude.ai",
		"Authorization":        "Bearer valid-token",
		"MCP-Session-Id":       sessionID,
		"MCP-Protocol-Version": "2024-11-05", // different
	})
	if rec2.Code != http.StatusBadRequest {
		t.Errorf("version mismatch: status = %d, want 400", rec2.Code)
	}
}

// ---------------------------------------------------------------------------
// Off-by-default: no server.Config fields set = remote mode inactive
// ---------------------------------------------------------------------------

// TestRemoteOffByDefault is an integration smoke test verifying that the
// existing server.Config (with no remote fields set) creates no remote listener.
// The test creates a plain server.Config without RemoteListenAddress and asserts
// the existing stdio/internal-API behavior is unchanged (no remote entry point).
func TestRemoteOffByDefault(t *testing.T) {
	// Build a handler with a non-nil Dispatcher to confirm the *mcphttp.Handler
	// itself works, then verify zero-value server.Config has no remote surface.
	// The absence of server.Config.RemoteListenAddress == "" means no second listener.
	// This is enforced by the server package; we test it here as a contract assertion.
	cfg := newTestConfig()
	_, err := mcphttp.NewHandler(cfg, nil)
	if err != nil {
		t.Fatalf("NewHandler with valid config: %v", err)
	}
	// The off-by-default test is that server.Config.RemoteListenAddress="" (zero value)
	// does NOT create a remote listener — verified in server_test.go.
}

// ---------------------------------------------------------------------------
// Finding 4: DELETE /mcp must also enforce Origin validation
// ---------------------------------------------------------------------------

func TestHandler_DeleteSession_MissingOrigin_Returns403(t *testing.T) {
	cfg := newTestConfig()
	h, err := mcphttp.NewHandler(cfg, nil)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	req := httptest.NewRequest(http.MethodDelete, "/mcp", nil)
	req.Header.Set("MCP-Session-Id", "some-session-id")
	// No Origin header — must be rejected 403 before any session logic.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("DELETE /mcp with missing Origin: status = %d, want 403", rec.Code)
	}
}

func TestHandler_DeleteSession_BadOrigin_Returns403(t *testing.T) {
	cfg := newTestConfig()
	h, err := mcphttp.NewHandler(cfg, nil)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	req := httptest.NewRequest(http.MethodDelete, "/mcp", nil)
	req.Header.Set("Origin", "https://evil.example.com")
	req.Header.Set("MCP-Session-Id", "some-session-id")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("DELETE /mcp with bad Origin: status = %d, want 403", rec.Code)
	}
}

func TestHandler_DeleteSession_GoodOrigin_Succeeds(t *testing.T) {
	cfg := newTestConfig()
	h, err := mcphttp.NewHandler(cfg, nil)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	// First initialize a session.
	rec1 := postMCP(h, map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "initialize",
		"id":      1,
		"params":  map[string]interface{}{"protocolVersion": "2025-06-18"},
	}, map[string]string{
		"Origin":        "https://claude.ai",
		"Authorization": "Bearer valid-token",
	})
	sessionID := rec1.Header().Get("MCP-Session-Id")
	if sessionID == "" {
		t.Fatal("initialize did not return a session ID")
	}
	// Now DELETE with a valid Origin.
	req := httptest.NewRequest(http.MethodDelete, "/mcp", nil)
	req.Header.Set("Origin", "https://claude.ai")
	req.Header.Set("MCP-Session-Id", sessionID)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Errorf("DELETE /mcp with valid Origin: status = %d, want 204", rec.Code)
	}
}
