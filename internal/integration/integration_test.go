//go:build integration

// Package integration provides end-to-end integration tests for Straylight-AI.
//
// These tests exercise the complete request flow:
//
//	AI agent (MCPServer) -> ContainerClient -> HTTP API (server.Server)
//	-> mcp.Handler -> proxy.Proxy -> mock upstream service
//
// Run with:
//
//	go test -tags=integration -v -timeout=30s ./internal/integration/...
//
// The tests are self-contained: no external dependencies (Docker, OpenBao, network)
// are required. All external services are replaced with in-process fakes.
package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/straylight-ai/straylight/internal/mcp"
	"github.com/straylight-ai/straylight/internal/proxy"
	"github.com/straylight-ai/straylight/internal/sanitizer"
	"github.com/straylight-ai/straylight/internal/server"
	"github.com/straylight-ai/straylight/internal/services"
)

// testCredential is the fake API key used across all test scenarios.
// It is long enough (> 8 chars) to pass sanitizer's minimum-length guard
// and matches the Stripe test key pattern so pattern-based sanitization also fires.
const testCredential = "test_FAKECRED_not_a_real_key_000"

// testServiceName is the registry name for the mock Stripe service.
const testServiceName = "test-stripe"

// ---------------------------------------------------------------------------
// In-memory mock vault — satisfies services.VaultClient without OpenBao
// ---------------------------------------------------------------------------

// mockVault is an in-memory implementation of services.VaultClient.
// It stores secrets in a plain map so tests need no OpenBao binary.
type mockVault struct {
	secrets map[string]map[string]interface{}
	// auditLog records every credential access for Scenario 9 verification.
	auditLog []auditEntry
}

// auditEntry records one credential read event.
type auditEntry struct {
	Path      string
	Timestamp time.Time
}

// newMockVault creates an empty mockVault ready for use.
func newMockVault() *mockVault {
	return &mockVault{
		secrets:  make(map[string]map[string]interface{}),
		auditLog: nil,
	}
}

// WriteSecret stores data at path. Satisfies services.VaultClient.
func (v *mockVault) WriteSecret(path string, data map[string]interface{}) error {
	v.secrets[path] = data
	return nil
}

// ReadSecret retrieves data at path. Satisfies services.VaultClient.
// Returns an error when the path is absent so callers behave as if the
// secret does not exist in OpenBao.
func (v *mockVault) ReadSecret(path string) (map[string]interface{}, error) {
	data, ok := v.secrets[path]
	if !ok {
		return nil, fmt.Errorf("vault: secret %q not found", path)
	}
	v.auditLog = append(v.auditLog, auditEntry{
		Path:      path,
		Timestamp: time.Now(),
	})
	return data, nil
}

// DeleteSecret removes data at path. Satisfies services.VaultClient.
func (v *mockVault) DeleteSecret(path string) error {
	delete(v.secrets, path)
	return nil
}

// ListSecrets returns all keys under path. Satisfies services.VaultClient.
func (v *mockVault) ListSecrets(path string) ([]string, error) {
	prefix := strings.TrimRight(path, "/") + "/"
	var keys []string
	for k := range v.secrets {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, strings.TrimPrefix(k, prefix))
		}
	}
	return keys, nil
}

// ---------------------------------------------------------------------------
// Full system fixture — wired together in-process for every test
// ---------------------------------------------------------------------------

// testSystem holds every component of the running system in one place.
// Create one with newTestSystem; always call ts.Close() after the test.
type testSystem struct {
	// mockUpstream simulates an external API (e.g. Stripe) so tests need no
	// real network connectivity.
	mockUpstream *httptest.Server
	// appServer is the Straylight-AI HTTP API wrapped by httptest.NewServer.
	appServer *httptest.Server
	// vault is the in-memory vault backing the registry.
	vault *mockVault
	// registry holds service metadata.
	registry *services.Registry
	// san is the sanitizer registered with the test credential.
	san *sanitizer.Sanitizer
}

// newTestSystem constructs and starts the complete in-process system:
//  1. A mock upstream server (simulating Stripe's API).
//  2. An in-memory vault + service registry.
//  3. A proxy (with 0-TTL cache so every test gets a fresh credential fetch).
//  4. A sanitizer with the test credential pre-registered.
//  5. The mcp.Handler and server.Server, both wrapped in httptest.Server.
//
// The mock upstream target URL uses the HTTPS scheme that the registry
// requires, routed via a local test server using httptest.NewTLSServer so
// the proxy's HTTP client can reach it without a real certificate chain.
func newTestSystem(t *testing.T) *testSystem {
	t.Helper()

	// 1. Mock upstream: simulates Stripe (or any target API).
	//    Returns a JSON body that intentionally contains the test credential
	//    to verify the sanitizer redacts it in Scenario 6.
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Record the Authorization header so tests can assert it was injected.
		auth := r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		// Deliberately echo the credential back to prove sanitization works.
		body := fmt.Sprintf(`{"object":"balance","auth_received":%q,"secret_in_body":%q}`,
			auth, testCredential)
		fmt.Fprint(w, body)
	}))

	// 2. Vault + Registry.
	vault := newMockVault()
	registry := services.NewRegistry(vault)

	// 3. Sanitizer — pre-register the test credential for value-based redaction.
	san := sanitizer.NewSanitizer()
	san.RegisterValue(testServiceName, testCredential)

	// 4. Proxy — zero TTL forces a fresh vault read on every call (good for tests).
	prx := proxy.NewProxyWithTTL(registry, san, 0)

	// 5. MCP handler.
	mcpHandler := mcp.NewHandler(prx, registry)

	// 6. Straylight HTTP server — use the TLS client so it can reach the upstream.
	//    We pass a nil VaultStatus: health will report "unavailable" but that is
	//    fine for integration tests that don't test the health endpoint.
	srv := server.NewWithOptions(server.Config{
		ListenAddress: "127.0.0.1:0",
		Version:       "test",
		Registry:      registry,
		MCPHandler:    mcpHandler,
	}, server.Options{
		RateLimit: 1000,
		Burst:     2000,
	})

	// Wrap the server in an httptest.Server so we get a free port.
	appSrv := httptest.NewServer(srv)

	// Register the "test-stripe" service against the mock upstream (TLS).
	// The registry enforces https:// — the TLS test server satisfies this.
	err := registry.Create(services.Service{
		Name:           testServiceName,
		Type:           "http_proxy",
		Target:         upstream.URL, // already https:// (TLS test server)
		Inject:         "header",
		HeaderName:     "Authorization",
		HeaderTemplate: "Bearer {{.Secret}}",
	}, testCredential)
	if err != nil {
		t.Fatalf("newTestSystem: register service: %v", err)
	}

	// Point the proxy's HTTP client at the TLS test server.
	// We need to override the proxy's client to trust the test certificate.
	// The simplest approach: give the proxy the TLS server's client via
	// the test-only transport (httptest.Server.Client() returns one).
	prx.SetHTTPClient(upstream.Client())

	return &testSystem{
		mockUpstream: upstream,
		appServer:    appSrv,
		vault:        vault,
		registry:     registry,
		san:          san,
	}
}

// Close tears down both test servers.
func (ts *testSystem) Close() {
	ts.appServer.Close()
	ts.mockUpstream.Close()
}

// ---------------------------------------------------------------------------
// JSON-RPC helpers — simulate what the MCP host binary (straylight-mcp) does
// ---------------------------------------------------------------------------

// jsonrpcRequest is a minimal JSON-RPC 2.0 request for test helpers.
type jsonrpcRequest struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      interface{} `json:"id"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
}

// jsonrpcResponse is a minimal JSON-RPC 2.0 response for test helpers.
type jsonrpcResponse struct {
	JSONRPC string                 `json:"jsonrpc"`
	ID      interface{}            `json:"id"`
	Result  map[string]interface{} `json:"result,omitempty"`
	Error   *jsonrpcError          `json:"error,omitempty"`
}

// jsonrpcError is the error object in a JSON-RPC 2.0 error response.
type jsonrpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// newMCPServer creates an MCPServer backed by a ContainerClient that targets
// the given appServer URL. This replicates exactly what the straylight-mcp
// binary does at startup, but fully in-process.
//
// We re-use the production types from cmd/straylight-mcp by creating an
// equivalent in-process representation using the same HTTP API.
func newInProcessMCPPipeline(t *testing.T, appServerURL string) func(req jsonrpcRequest) (*jsonrpcResponse, string) {
	t.Helper()

	// The MCP pipeline: JSON-RPC line -> ContainerClient -> HTTP API.
	// We drive it by posting the request directly to the app server's HTTP API
	// rather than going through the stdio pipe, which is already tested by
	// cmd/straylight-mcp/mcp_test.go.

	client := &http.Client{Timeout: 10 * time.Second}

	return func(req jsonrpcRequest) (*jsonrpcResponse, string) {
		t.Helper()

		// Route the JSON-RPC method to the appropriate HTTP endpoint.
		switch req.Method {
		case "tools/list":
			resp, err := client.Get(appServerURL + "/api/v1/mcp/tool-list")
			if err != nil {
				return nil, fmt.Sprintf("GET tool-list error: %v", err)
			}
			defer resp.Body.Close()
			var result map[string]interface{}
			if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
				return nil, fmt.Sprintf("decode tool-list: %v", err)
			}
			return &jsonrpcResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Result:  result,
			}, ""

		case "tools/call":
			params, _ := req.Params.(map[string]interface{})
			toolName, _ := params["name"].(string)
			arguments, _ := params["arguments"].(map[string]interface{})
			if arguments == nil {
				arguments = map[string]interface{}{}
			}
			payload := map[string]interface{}{
				"tool":      toolName,
				"arguments": arguments,
			}
			body, _ := json.Marshal(payload)
			resp, err := client.Post(
				appServerURL+"/api/v1/mcp/tool-call",
				"application/json",
				bytes.NewReader(body),
			)
			if err != nil {
				return nil, fmt.Sprintf("POST tool-call error: %v", err)
			}
			defer resp.Body.Close()
			var result map[string]interface{}
			if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
				return nil, fmt.Sprintf("decode tool-call: %v", err)
			}
			return &jsonrpcResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Result:  result,
			}, ""

		default:
			return nil, fmt.Sprintf("unsupported test method: %s", req.Method)
		}
	}
}

// ---------------------------------------------------------------------------
// Core test: TestFullMCPFlow
// ---------------------------------------------------------------------------

// TestFullMCPFlow exercises all seven scenarios in sequence using the HTTP API
// (what the MCPServer delegates to). This is the integration smoke test.
func TestFullMCPFlow(t *testing.T) {
	ts := newTestSystem(t)
	defer ts.Close()

	call := newInProcessMCPPipeline(t, ts.appServer.URL)

	// Scenario 4: Tool Listing — 4 tools returned.
	t.Run("Scenario4_ToolListing", func(t *testing.T) {
		resp, raw := call(jsonrpcRequest{
			JSONRPC: "2.0",
			ID:      1,
			Method:  "tools/list",
		})
		if resp == nil {
			t.Fatalf("expected response, got: %q", raw)
		}
		if resp.Error != nil {
			t.Fatalf("unexpected error: code=%d msg=%s", resp.Error.Code, resp.Error.Message)
		}

		toolsRaw, ok := resp.Result["tools"]
		if !ok {
			t.Fatalf("result missing 'tools' key")
		}
		tools, ok := toolsRaw.([]interface{})
		if !ok {
			t.Fatalf("'tools' is not an array: %T", toolsRaw)
		}
		if len(tools) != 4 {
			t.Errorf("expected 4 tools, got %d", len(tools))
		}

		// Verify expected tool names are present.
		toolNames := make(map[string]bool)
		for _, item := range tools {
			m, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			if name, ok := m["name"].(string); ok {
				toolNames[name] = true
			}
		}
		expectedTools := []string{
			"straylight_api_call",
			"straylight_exec",
			"straylight_check",
			"straylight_services",
		}
		for _, name := range expectedTools {
			if !toolNames[name] {
				t.Errorf("missing expected tool %q in tool list", name)
			}
		}

		// Scenario 7: credential must never appear in the tools/list response.
		resultJSON, _ := json.Marshal(resp.Result)
		assertNoCredential(t, string(resultJSON), "tools/list response")
	})

	// Scenario 2: Credential Check — service reports "available".
	t.Run("Scenario2_CredentialCheck", func(t *testing.T) {
		resp, raw := call(jsonrpcRequest{
			JSONRPC: "2.0",
			ID:      2,
			Method:  "tools/call",
			Params: map[string]interface{}{
				"name": "straylight_check",
				"arguments": map[string]interface{}{
					"service": testServiceName,
				},
			},
		})
		if resp == nil {
			t.Fatalf("expected response, got: %q", raw)
		}
		if resp.Error != nil {
			t.Fatalf("unexpected RPC error: %+v", resp.Error)
		}

		content := extractTextContent(t, resp.Result)
		if strings.Contains(content, `"status":"available"`) ||
			strings.Contains(content, `"status": "available"`) {
			// pass
		} else {
			t.Errorf("expected status=available in check response, got: %s", content)
		}

		assertNoCredential(t, content, "straylight_check response")
	})

	// Scenario 1: Happy Path API Call — proxy injects credential, upstream responds.
	t.Run("Scenario1_HappyPathAPICall", func(t *testing.T) {
		resp, raw := call(jsonrpcRequest{
			JSONRPC: "2.0",
			ID:      3,
			Method:  "tools/call",
			Params: map[string]interface{}{
				"name": "straylight_api_call",
				"arguments": map[string]interface{}{
					"service": testServiceName,
					"method":  "GET",
					"path":    "/v1/balance",
				},
			},
		})
		if resp == nil {
			t.Fatalf("expected response, got: %q", raw)
		}
		if resp.Error != nil {
			t.Fatalf("unexpected RPC error: %+v", resp.Error)
		}

		content := extractTextContent(t, resp.Result)

		// The mock upstream echoes "auth_received" which contains the Bearer token.
		// The sanitizer must have replaced the credential value.
		assertNoCredential(t, content, "straylight_api_call response body")

		// The response should contain the object field indicating a successful call.
		if !strings.Contains(content, "balance") {
			t.Errorf("expected upstream response to contain 'balance', got: %s", content)
		}

		// Scenario 6: The credential in auth_received and secret_in_body fields
		// must both be replaced with [REDACTED:test-stripe].
		if !strings.Contains(content, "[REDACTED:test-stripe]") {
			t.Errorf("expected [REDACTED:test-stripe] in sanitized response, got: %s", content)
		}
	})

	// Scenario 3: Service Listing — test-stripe appears with capabilities.
	t.Run("Scenario3_ServiceListing", func(t *testing.T) {
		resp, raw := call(jsonrpcRequest{
			JSONRPC: "2.0",
			ID:      4,
			Method:  "tools/call",
			Params: map[string]interface{}{
				"name":      "straylight_services",
				"arguments": map[string]interface{}{},
			},
		})
		if resp == nil {
			t.Fatalf("expected response, got: %q", raw)
		}
		if resp.Error != nil {
			t.Fatalf("unexpected RPC error: %+v", resp.Error)
		}

		content := extractTextContent(t, resp.Result)

		if !strings.Contains(content, testServiceName) {
			t.Errorf("expected service %q in services response, got: %s", testServiceName, content)
		}
		if !strings.Contains(content, "api_call") {
			t.Errorf("expected 'api_call' capability in services response, got: %s", content)
		}

		assertNoCredential(t, content, "straylight_services response")
	})

	// Scenario 5: Unknown Service — isError=true in response.
	t.Run("Scenario5_UnknownService", func(t *testing.T) {
		resp, raw := call(jsonrpcRequest{
			JSONRPC: "2.0",
			ID:      5,
			Method:  "tools/call",
			Params: map[string]interface{}{
				"name": "straylight_api_call",
				"arguments": map[string]interface{}{
					"service": "nonexistent",
					"method":  "GET",
					"path":    "/v1/balance",
				},
			},
		})
		if resp == nil {
			t.Fatalf("expected response, got: %q", raw)
		}
		if resp.Error != nil {
			t.Fatalf("unexpected RPC error (want isError result, not RPC error): %+v", resp.Error)
		}

		isError, _ := resp.Result["isError"].(bool)
		if !isError {
			t.Errorf("expected isError=true for unknown service, got result: %+v", resp.Result)
		}

		content := extractTextContent(t, resp.Result)
		assertNoCredential(t, content, "unknown-service error response")
	})

	// Scenario 7: Credential Never in Context — verify the raw service metadata
	// endpoint (GET /api/v1/services/{name}) never exposes the credential value.
	// This is distinct from the tool responses checked above: it tests the HTTP
	// API layer independently of the MCP tool dispatch path.
	t.Run("Scenario7_CredentialNeverInContext", func(t *testing.T) {
		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Get(ts.appServer.URL + "/api/v1/services/" + testServiceName)
		if err != nil {
			t.Fatalf("GET service: %v", err)
		}
		defer resp.Body.Close()

		var result map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			t.Fatalf("decode: %v", err)
		}
		resultJSON, _ := json.Marshal(result)
		assertNoCredential(t, string(resultJSON), "GET /api/v1/services/{name} response")
	})
}

// TestScenario6_OutputSanitization verifies that when the upstream echoes the
// credential in its response body the sanitizer replaces it before the body
// reaches the caller.
func TestScenario6_OutputSanitization(t *testing.T) {
	ts := newTestSystem(t)
	defer ts.Close()

	client := &http.Client{Timeout: 10 * time.Second}

	payload := map[string]interface{}{
		"tool": "straylight_api_call",
		"arguments": map[string]interface{}{
			"service": testServiceName,
			"method":  "GET",
			"path":    "/v1/balance",
		},
	}
	body, _ := json.Marshal(payload)

	resp, err := client.Post(
		ts.appServer.URL+"/api/v1/mcp/tool-call",
		"application/json",
		bytes.NewReader(body),
	)
	if err != nil {
		t.Fatalf("POST tool-call: %v", err)
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	content := extractTextContent(t, result)

	// The mock upstream deliberately echoes the credential — sanitizer must catch it.
	if strings.Contains(content, testCredential) {
		t.Errorf("credential leaked through sanitizer: %s", content)
	}

	// The replacement token must be present for both occurrences.
	count := strings.Count(content, "[REDACTED:test-stripe]")
	if count < 2 {
		t.Errorf("expected at least 2 [REDACTED:test-stripe] tokens, found %d in: %s", count, content)
	}
}

// TestScenario9_AuditLogEntries verifies that credential accesses are recorded
// in the vault's audit log.
func TestScenario9_AuditLogEntries(t *testing.T) {
	ts := newTestSystem(t)
	defer ts.Close()

	client := &http.Client{Timeout: 10 * time.Second}

	// Make an API call that requires a credential lookup.
	payload := map[string]interface{}{
		"tool": "straylight_api_call",
		"arguments": map[string]interface{}{
			"service": testServiceName,
			"method":  "GET",
			"path":    "/v1/balance",
		},
	}
	body, _ := json.Marshal(payload)
	resp, err := client.Post(
		ts.appServer.URL+"/api/v1/mcp/tool-call",
		"application/json",
		bytes.NewReader(body),
	)
	if err != nil {
		t.Fatalf("POST tool-call: %v", err)
	}
	resp.Body.Close()

	// The vault's audit log should have at least one entry for the credential path.
	if len(ts.vault.auditLog) == 0 {
		t.Error("expected at least one vault audit log entry after API call, got none")
	}

	credentialPath := "services/" + testServiceName + "/credential"
	found := false
	for _, entry := range ts.vault.auditLog {
		if entry.Path == credentialPath {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected audit log entry for path %q, got: %+v", credentialPath, ts.vault.auditLog)
	}
}

// TestHealthEndpoint verifies the health endpoint is reachable (basic smoke test).
func TestHealthEndpoint(t *testing.T) {
	ts := newTestSystem(t)
	defer ts.Close()

	resp, err := http.Get(ts.appServer.URL + "/api/v1/health")
	if err != nil {
		t.Fatalf("GET /api/v1/health: %v", err)
	}
	defer resp.Body.Close()

	// With no VaultStatus configured the server reports "degraded" (503).
	// We just want to confirm it responds — not that it's healthy.
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("unexpected health status: %d", resp.StatusCode)
	}
}

// TestToolCallWithUnknownTool verifies that calling an unknown tool returns HTTP 400
// (tool validation at the handler level, before dispatching).
func TestToolCallWithUnknownTool(t *testing.T) {
	ts := newTestSystem(t)
	defer ts.Close()

	payload := map[string]interface{}{
		"tool":      "not_a_real_tool",
		"arguments": map[string]interface{}{},
	}
	body, _ := json.Marshal(payload)

	resp, err := http.DefaultClient.Post(
		ts.appServer.URL+"/api/v1/mcp/tool-call",
		"application/json",
		bytes.NewReader(body),
	)
	if err != nil {
		t.Fatalf("POST tool-call: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected HTTP 400 for unknown tool, got %d", resp.StatusCode)
	}
}

// TestServiceRegistry verifies basic CRUD via the HTTP API.
func TestServiceRegistry(t *testing.T) {
	ts := newTestSystem(t)
	defer ts.Close()

	// List services — test-stripe should be there.
	resp, err := http.Get(ts.appServer.URL + "/api/v1/services")
	if err != nil {
		t.Fatalf("GET /api/v1/services: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var result struct {
		Services []services.Service `json:"services"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode services: %v", err)
	}

	found := false
	for _, svc := range result.Services {
		if svc.Name == testServiceName {
			found = true
			// Credential must never appear in the service listing.
			svcJSON, _ := json.Marshal(svc)
			assertNoCredential(t, string(svcJSON), "service listing")
			break
		}
	}
	if !found {
		t.Errorf("expected %q in services list, got: %+v", testServiceName, result.Services)
	}
}

// TestExecToolReturnsStub verifies that straylight_exec returns the expected
// stub message (the feature is not yet implemented).
func TestExecToolReturnsStub(t *testing.T) {
	ts := newTestSystem(t)
	defer ts.Close()

	payload := map[string]interface{}{
		"tool": "straylight_exec",
		"arguments": map[string]interface{}{
			"service": testServiceName,
			"command": "echo hello",
		},
	}
	body, _ := json.Marshal(payload)

	resp, err := http.DefaultClient.Post(
		ts.appServer.URL+"/api/v1/mcp/tool-call",
		"application/json",
		bytes.NewReader(body),
	)
	if err != nil {
		t.Fatalf("POST tool-call: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d", resp.StatusCode)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}

	content := extractTextContent(t, result)
	if !strings.Contains(content, "not available yet") {
		t.Errorf("expected stub message for straylight_exec, got: %s", content)
	}
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

// assertNoCredential fails the test if body contains the test credential string.
// context is a human-readable label for the error message.
func assertNoCredential(t *testing.T, body, context string) {
	t.Helper()
	if strings.Contains(body, testCredential) {
		t.Errorf("credential leaked in %s:\n  body=%s", context, body)
	}
}

// extractTextContent pulls the text from the first content item in a
// MCP ToolCallResult result map. Returns empty string on parse failure.
func extractTextContent(t *testing.T, result map[string]interface{}) string {
	t.Helper()
	contentRaw, ok := result["content"]
	if !ok {
		return ""
	}
	items, ok := contentRaw.([]interface{})
	if !ok || len(items) == 0 {
		return ""
	}
	first, ok := items[0].(map[string]interface{})
	if !ok {
		return ""
	}
	text, _ := first["text"].(string)
	return text
}
