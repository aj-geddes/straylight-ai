package mcp_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/straylight-ai/straylight/internal/firewall"
	"github.com/straylight-ai/straylight/internal/mcp"
	"github.com/straylight-ai/straylight/internal/proxy"
	"github.com/straylight-ai/straylight/internal/scanner"
	"github.com/straylight-ai/straylight/internal/services"
)

// ---------------------------------------------------------------------------
// Mock dependencies
// ---------------------------------------------------------------------------

// mockProxy satisfies mcp.ProxyHandler.
type mockProxy struct {
	response *proxy.APICallResponse
	err      error
}

func (m *mockProxy) HandleAPICall(_ context.Context, _ proxy.APICallRequest) (*proxy.APICallResponse, error) {
	return m.response, m.err
}

// mockServices satisfies mcp.ServiceLister.
type mockServices struct {
	list            []services.Service
	checkStatus     string
	checkErr        error
}

func (m *mockServices) List() []services.Service {
	return m.list
}

func (m *mockServices) CheckCredential(name string) (string, error) {
	if m.checkErr != nil {
		return "", m.checkErr
	}
	return m.checkStatus, nil
}

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

func newTestHandler(p mcp.ProxyHandler, s mcp.ServiceLister) *mcp.Handler {
	return mcp.NewHandler(p, s)
}

// newRealFirewall creates a *firewall.Firewall with the given projectRoot and
// registers it as the FileReader on the handler via SetFileReader.
// It returns the Firewall so tests can configure it further if needed.
func newRealFirewall(t *testing.T, projectRoot string) *firewall.Firewall {
	t.Helper()
	cfg := firewall.DefaultConfig()
	cfg.ProjectRoot = projectRoot
	return firewall.NewFirewall(cfg)
}

// mockScannerResult is a simple mock for mcp.DirectoryScanner that returns
// pre-configured results.
type mockScannerResult struct {
	result *scanner.ScanResult
	err    error
}

func (m *mockScannerResult) ScanDirectory(_ string) (*scanner.ScanResult, error) {
	return m.result, m.err
}

// newMockScannerWithFindings creates a mockScannerResult with the given
// findings and filesScanned count.
func newMockScannerWithFindings(findings []scanner.Finding, filesScanned int) mcp.DirectoryScanner {
	return &mockScannerResult{
		result: &scanner.ScanResult{
			Findings:     findings,
			FilesScanned: filesScanned,
			FilesSkipped: 0,
			DurationMS:   1,
		},
	}
}

func doRequest(h http.Handler, method, path string, body interface{}) *httptest.ResponseRecorder {
	var reqBody *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		reqBody = bytes.NewReader(b)
	} else {
		reqBody = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, reqBody)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func decodeToolResult(t *testing.T, w *httptest.ResponseRecorder) mcp.ToolCallResult {
	t.Helper()
	var result mcp.ToolCallResult
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("decode tool result: %v (body: %s)", err, w.Body.String())
	}
	return result
}

// ---------------------------------------------------------------------------
// HandleToolList tests
// ---------------------------------------------------------------------------

func TestHandleToolList_ReturnsSixTools(t *testing.T) {
	h := newTestHandler(&mockProxy{}, &mockServices{})
	w := doRequest(h, http.MethodGet, "/api/v1/mcp/tool-list", nil)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp struct {
		Tools []mcp.ToolDefinition `json:"tools"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if len(resp.Tools) != 7 {
		t.Fatalf("expected 7 tools, got %d", len(resp.Tools))
	}
}

func TestHandleToolList_ContainsAllToolNames(t *testing.T) {
	h := newTestHandler(&mockProxy{}, &mockServices{})
	w := doRequest(h, http.MethodGet, "/api/v1/mcp/tool-list", nil)

	var resp struct {
		Tools []mcp.ToolDefinition `json:"tools"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	names := make(map[string]bool)
	for _, tool := range resp.Tools {
		names[tool.Name] = true
	}

	required := []string{"straylight_api_call", "straylight_exec", "straylight_check", "straylight_services", "straylight_scan", "straylight_read_file", "straylight_db_query"}
	for _, name := range required {
		if !names[name] {
			t.Errorf("tool %q missing from tool list", name)
		}
	}
}

func TestHandleToolList_EachToolHasDescription(t *testing.T) {
	h := newTestHandler(&mockProxy{}, &mockServices{})
	w := doRequest(h, http.MethodGet, "/api/v1/mcp/tool-list", nil)

	var resp struct {
		Tools []mcp.ToolDefinition `json:"tools"`
	}
	_ = json.NewDecoder(w.Body).Decode(&resp)

	for _, tool := range resp.Tools {
		if tool.Description == "" {
			t.Errorf("tool %q has empty description", tool.Name)
		}
	}
}

func TestHandleToolList_EachToolHasInputSchema(t *testing.T) {
	h := newTestHandler(&mockProxy{}, &mockServices{})
	w := doRequest(h, http.MethodGet, "/api/v1/mcp/tool-list", nil)

	var resp struct {
		Tools []mcp.ToolDefinition `json:"tools"`
	}
	_ = json.NewDecoder(w.Body).Decode(&resp)

	for _, tool := range resp.Tools {
		if tool.InputSchema == nil {
			t.Errorf("tool %q has nil inputSchema", tool.Name)
		}
	}
}

func TestHandleToolList_ContentTypeJSON(t *testing.T) {
	h := newTestHandler(&mockProxy{}, &mockServices{})
	w := doRequest(h, http.MethodGet, "/api/v1/mcp/tool-list", nil)

	ct := w.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("expected Content-Type application/json, got %q", ct)
	}
}

// ---------------------------------------------------------------------------
// HandleToolCall — unknown tool
// ---------------------------------------------------------------------------

func TestHandleToolCall_UnknownTool_Returns400(t *testing.T) {
	h := newTestHandler(&mockProxy{}, &mockServices{})
	w := doRequest(h, http.MethodPost, "/api/v1/mcp/tool-call", map[string]interface{}{
		"tool":      "not_a_real_tool",
		"arguments": map[string]interface{}{},
	})

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestHandleToolCall_MissingToolField_Returns400(t *testing.T) {
	h := newTestHandler(&mockProxy{}, &mockServices{})
	w := doRequest(h, http.MethodPost, "/api/v1/mcp/tool-call", map[string]interface{}{
		"arguments": map[string]interface{}{},
	})

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestHandleToolCall_InvalidJSON_Returns400(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/mcp/tool-call", strings.NewReader("{bad json"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h := newTestHandler(&mockProxy{}, &mockServices{})
	h.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

// ---------------------------------------------------------------------------
// straylight_exec tool — stub
// ---------------------------------------------------------------------------

func TestHandleToolCall_ExecReturnsStub(t *testing.T) {
	h := newTestHandler(&mockProxy{}, &mockServices{})
	w := doRequest(h, http.MethodPost, "/api/v1/mcp/tool-call", map[string]interface{}{
		"tool": "straylight_exec",
		"arguments": map[string]interface{}{
			"service": "github",
			"command": "ls",
		},
	})

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	result := decodeToolResult(t, w)
	if len(result.Content) == 0 {
		t.Fatal("expected non-empty content")
	}
	if !strings.Contains(result.Content[0].Text, "not available") {
		t.Errorf("exec stub should contain 'not available', got: %q", result.Content[0].Text)
	}
}

func TestHandleToolCall_ExecIsNotError(t *testing.T) {
	h := newTestHandler(&mockProxy{}, &mockServices{})
	w := doRequest(h, http.MethodPost, "/api/v1/mcp/tool-call", map[string]interface{}{
		"tool": "straylight_exec",
		"arguments": map[string]interface{}{
			"service": "github",
			"command": "ls",
		},
	})

	result := decodeToolResult(t, w)
	if result.IsError {
		t.Error("exec stub should not set isError=true")
	}
}

// ---------------------------------------------------------------------------
// straylight_services tool
// ---------------------------------------------------------------------------

func TestHandleToolCall_Services_ReturnsServiceNames(t *testing.T) {
	svcList := []services.Service{
		{Name: "stripe", Type: "http_proxy", Status: "available", Target: "https://api.stripe.com", Inject: "header"},
		{Name: "github", Type: "oauth", Status: "available", Target: "https://api.github.com", Inject: "header"},
	}
	h := newTestHandler(&mockProxy{}, &mockServices{list: svcList})

	w := doRequest(h, http.MethodPost, "/api/v1/mcp/tool-call", map[string]interface{}{
		"tool":      "straylight_services",
		"arguments": map[string]interface{}{},
	})

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	result := decodeToolResult(t, w)
	if len(result.Content) == 0 {
		t.Fatal("expected content")
	}

	text := result.Content[0].Text
	if !strings.Contains(text, "stripe") {
		t.Errorf("response should contain 'stripe', got: %q", text)
	}
	if !strings.Contains(text, "github") {
		t.Errorf("response should contain 'github', got: %q", text)
	}
}

func TestHandleToolCall_Services_NoCredentialValues(t *testing.T) {
	svcList := []services.Service{
		{Name: "stripe", Type: "http_proxy", Status: "available", Target: "https://api.stripe.com", Inject: "header"},
	}
	h := newTestHandler(&mockProxy{}, &mockServices{list: svcList})

	w := doRequest(h, http.MethodPost, "/api/v1/mcp/tool-call", map[string]interface{}{
		"tool":      "straylight_services",
		"arguments": map[string]interface{}{},
	})

	result := decodeToolResult(t, w)
	text := result.Content[0].Text

	// The response must not contain any credential fields
	if strings.Contains(text, "credential") {
		t.Errorf("services response should not contain 'credential', got: %q", text)
	}
}

func TestHandleToolCall_Services_EmptyList(t *testing.T) {
	h := newTestHandler(&mockProxy{}, &mockServices{list: []services.Service{}})

	w := doRequest(h, http.MethodPost, "/api/v1/mcp/tool-call", map[string]interface{}{
		"tool":      "straylight_services",
		"arguments": map[string]interface{}{},
	})

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	result := decodeToolResult(t, w)
	if len(result.Content) == 0 {
		t.Fatal("expected content even for empty list")
	}
}

func TestHandleToolCall_Services_ContentTypeIsText(t *testing.T) {
	h := newTestHandler(&mockProxy{}, &mockServices{list: []services.Service{}})

	w := doRequest(h, http.MethodPost, "/api/v1/mcp/tool-call", map[string]interface{}{
		"tool":      "straylight_services",
		"arguments": map[string]interface{}{},
	})

	result := decodeToolResult(t, w)
	for _, item := range result.Content {
		if item.Type != "text" {
			t.Errorf("content item type should be 'text', got %q", item.Type)
		}
	}
}

// ---------------------------------------------------------------------------
// straylight_services tool — WP-2.4 capability map
// ---------------------------------------------------------------------------

// servicesPayload is the decoded JSON payload from the straylight_services response text.
type servicesPayload struct {
	Services []serviceViewJSON `json:"services"`
	Total    int               `json:"total"`
	Message  string            `json:"message"`
}

type serviceViewJSON struct {
	Name         string   `json:"name"`
	Type         string   `json:"type"`
	Status       string   `json:"status"`
	Capabilities []string `json:"capabilities"`
	BaseURL      string   `json:"base_url"`
	Scopes       []string `json:"scopes"`
	Description  string   `json:"description"`
}

func decodeServicesPayload(t *testing.T, result mcp.ToolCallResult) servicesPayload {
	t.Helper()
	if len(result.Content) == 0 {
		t.Fatal("no content items in result")
	}
	var p servicesPayload
	if err := json.Unmarshal([]byte(result.Content[0].Text), &p); err != nil {
		t.Fatalf("decode services payload: %v (text: %s)", err, result.Content[0].Text)
	}
	return p
}

func TestHandleToolCall_Services_ResponseIncludesTotalCount(t *testing.T) {
	svcList := []services.Service{
		{Name: "stripe", Type: "http_proxy", Status: "available", Target: "https://api.stripe.com", Inject: "header"},
		{Name: "github", Type: "oauth", Status: "available", Target: "https://api.github.com", Inject: "header"},
	}
	h := newTestHandler(&mockProxy{}, &mockServices{list: svcList})

	w := doRequest(h, http.MethodPost, "/api/v1/mcp/tool-call", map[string]interface{}{
		"tool":      "straylight_services",
		"arguments": map[string]interface{}{},
	})

	result := decodeToolResult(t, w)
	payload := decodeServicesPayload(t, result)

	if payload.Total != 2 {
		t.Errorf("expected total=2, got %d", payload.Total)
	}
}

func TestHandleToolCall_Services_ResponseIncludesMessageWithCount(t *testing.T) {
	svcList := []services.Service{
		{Name: "stripe", Type: "http_proxy", Status: "available", Target: "https://api.stripe.com", Inject: "header"},
		{Name: "github", Type: "oauth", Status: "available", Target: "https://api.github.com", Inject: "header"},
	}
	h := newTestHandler(&mockProxy{}, &mockServices{list: svcList})

	w := doRequest(h, http.MethodPost, "/api/v1/mcp/tool-call", map[string]interface{}{
		"tool":      "straylight_services",
		"arguments": map[string]interface{}{},
	})

	result := decodeToolResult(t, w)
	payload := decodeServicesPayload(t, result)

	if !strings.Contains(payload.Message, "2") {
		t.Errorf("message should include count '2', got: %q", payload.Message)
	}
	if !strings.Contains(payload.Message, "straylight_api_call") {
		t.Errorf("message should mention straylight_api_call, got: %q", payload.Message)
	}
}

func TestHandleToolCall_Services_EmptyState_MessageAndTotal(t *testing.T) {
	h := newTestHandler(&mockProxy{}, &mockServices{list: []services.Service{}})

	w := doRequest(h, http.MethodPost, "/api/v1/mcp/tool-call", map[string]interface{}{
		"tool":      "straylight_services",
		"arguments": map[string]interface{}{},
	})

	result := decodeToolResult(t, w)
	payload := decodeServicesPayload(t, result)

	if payload.Total != 0 {
		t.Errorf("expected total=0 for empty state, got %d", payload.Total)
	}
	if !strings.Contains(payload.Message, "No services configured") {
		t.Errorf("empty state message should say 'No services configured', got: %q", payload.Message)
	}
	if !strings.Contains(payload.Message, "http://localhost:9470") {
		t.Errorf("empty state message should include UI URL, got: %q", payload.Message)
	}
}

func TestHandleToolCall_Services_ServiceViewHasDescription(t *testing.T) {
	svcList := []services.Service{
		{Name: "stripe", Type: "http_proxy", Status: "available", Target: "https://api.stripe.com", Inject: "header"},
	}
	h := newTestHandler(&mockProxy{}, &mockServices{list: svcList})

	w := doRequest(h, http.MethodPost, "/api/v1/mcp/tool-call", map[string]interface{}{
		"tool":      "straylight_services",
		"arguments": map[string]interface{}{},
	})

	result := decodeToolResult(t, w)
	payload := decodeServicesPayload(t, result)

	if len(payload.Services) == 0 {
		t.Fatal("expected at least one service")
	}
	if payload.Services[0].Description == "" {
		t.Errorf("service view should have a non-empty description")
	}
}

func TestHandleToolCall_Services_DescriptionUsesHostnameForUnknownService(t *testing.T) {
	svcList := []services.Service{
		{Name: "custom", Type: "http_proxy", Status: "available", Target: "https://myapi.example.com", Inject: "header"},
	}
	h := newTestHandler(&mockProxy{}, &mockServices{list: svcList})

	w := doRequest(h, http.MethodPost, "/api/v1/mcp/tool-call", map[string]interface{}{
		"tool":      "straylight_services",
		"arguments": map[string]interface{}{},
	})

	result := decodeToolResult(t, w)
	payload := decodeServicesPayload(t, result)

	if len(payload.Services) == 0 {
		t.Fatal("expected at least one service")
	}
	if !strings.Contains(payload.Services[0].Description, "myapi.example.com") {
		t.Errorf("unknown service description should include hostname, got: %q", payload.Services[0].Description)
	}
}

func TestHandleToolCall_Services_OAuthServiceIncludesScopes(t *testing.T) {
	svcList := []services.Service{
		{Name: "github", Type: "oauth", Status: "available", Target: "https://api.github.com", Inject: "header",
			DefaultHeaders: map[string]string{"X-GitHub-Api-Version": "2022-11-28"}},
	}
	h := newTestHandler(&mockProxy{}, &mockServices{list: svcList})

	w := doRequest(h, http.MethodPost, "/api/v1/mcp/tool-call", map[string]interface{}{
		"tool":      "straylight_services",
		"arguments": map[string]interface{}{},
	})

	result := decodeToolResult(t, w)
	payload := decodeServicesPayload(t, result)

	if len(payload.Services) == 0 {
		t.Fatal("expected at least one service")
	}
	// scopes field should be present (may be nil/empty for oauth without explicit scopes config)
	// The key test is that the JSON "scopes" key is emitted for oauth services
	raw := result.Content[0].Text
	if !strings.Contains(raw, `"scopes"`) {
		t.Errorf("oauth service response should include 'scopes' key, got: %s", raw)
	}
}

func TestHandleToolCall_Services_HttpProxyHasOnlyApiCallCapability(t *testing.T) {
	svcList := []services.Service{
		{Name: "stripe", Type: "http_proxy", Status: "available", Target: "https://api.stripe.com", Inject: "header"},
	}
	h := newTestHandler(&mockProxy{}, &mockServices{list: svcList})

	w := doRequest(h, http.MethodPost, "/api/v1/mcp/tool-call", map[string]interface{}{
		"tool":      "straylight_services",
		"arguments": map[string]interface{}{},
	})

	result := decodeToolResult(t, w)
	payload := decodeServicesPayload(t, result)

	if len(payload.Services) == 0 {
		t.Fatal("expected at least one service")
	}
	caps := payload.Services[0].Capabilities
	if len(caps) != 1 || caps[0] != "api_call" {
		t.Errorf("http_proxy without exec should have only [api_call], got: %v", caps)
	}
}

func TestHandleToolCall_Services_ServiceWithExecConfigHasExecCapability(t *testing.T) {
	svcList := []services.Service{
		{Name: "github", Type: "oauth", Status: "available", Target: "https://api.github.com",
			Inject: "header", ExecEnabled: true},
	}
	h := newTestHandler(&mockProxy{}, &mockServices{list: svcList})

	w := doRequest(h, http.MethodPost, "/api/v1/mcp/tool-call", map[string]interface{}{
		"tool":      "straylight_services",
		"arguments": map[string]interface{}{},
	})

	result := decodeToolResult(t, w)
	payload := decodeServicesPayload(t, result)

	if len(payload.Services) == 0 {
		t.Fatal("expected at least one service")
	}
	caps := payload.Services[0].Capabilities
	hasExec := false
	for _, c := range caps {
		if c == "exec" {
			hasExec = true
		}
	}
	if !hasExec {
		t.Errorf("service with ExecEnabled should have 'exec' capability, got: %v", caps)
	}
}

func TestHandleToolCall_Services_BaseURLPopulated(t *testing.T) {
	svcList := []services.Service{
		{Name: "stripe", Type: "http_proxy", Status: "available", Target: "https://api.stripe.com", Inject: "header"},
	}
	h := newTestHandler(&mockProxy{}, &mockServices{list: svcList})

	w := doRequest(h, http.MethodPost, "/api/v1/mcp/tool-call", map[string]interface{}{
		"tool":      "straylight_services",
		"arguments": map[string]interface{}{},
	})

	result := decodeToolResult(t, w)
	payload := decodeServicesPayload(t, result)

	if len(payload.Services) == 0 {
		t.Fatal("expected at least one service")
	}
	if payload.Services[0].BaseURL != "https://api.stripe.com" {
		t.Errorf("expected base_url=https://api.stripe.com, got %q", payload.Services[0].BaseURL)
	}
}

func TestHandleToolCall_Services_StatusPreserved(t *testing.T) {
	svcList := []services.Service{
		{Name: "stripe", Type: "http_proxy", Status: "expired", Target: "https://api.stripe.com", Inject: "header"},
	}
	h := newTestHandler(&mockProxy{}, &mockServices{list: svcList})

	w := doRequest(h, http.MethodPost, "/api/v1/mcp/tool-call", map[string]interface{}{
		"tool":      "straylight_services",
		"arguments": map[string]interface{}{},
	})

	result := decodeToolResult(t, w)
	payload := decodeServicesPayload(t, result)

	if len(payload.Services) == 0 {
		t.Fatal("expected at least one service")
	}
	if payload.Services[0].Status != "expired" {
		t.Errorf("expected status=expired, got %q", payload.Services[0].Status)
	}
}

// ---------------------------------------------------------------------------
// straylight_check tool
// ---------------------------------------------------------------------------

func TestHandleToolCall_Check_AvailableCredential(t *testing.T) {
	h := newTestHandler(&mockProxy{}, &mockServices{checkStatus: "available"})

	w := doRequest(h, http.MethodPost, "/api/v1/mcp/tool-call", map[string]interface{}{
		"tool":      "straylight_check",
		"arguments": map[string]interface{}{"service": "stripe"},
	})

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	result := decodeToolResult(t, w)
	if result.IsError {
		t.Error("should not be an error for available credential")
	}
	if !strings.Contains(result.Content[0].Text, "available") {
		t.Errorf("response should indicate 'available', got: %q", result.Content[0].Text)
	}
}

func TestHandleToolCall_Check_NotConfigured(t *testing.T) {
	h := newTestHandler(&mockProxy{}, &mockServices{checkStatus: "not_configured"})

	w := doRequest(h, http.MethodPost, "/api/v1/mcp/tool-call", map[string]interface{}{
		"tool":      "straylight_check",
		"arguments": map[string]interface{}{"service": "stripe"},
	})

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	result := decodeToolResult(t, w)
	if !strings.Contains(result.Content[0].Text, "not_configured") {
		t.Errorf("expected not_configured in response, got: %q", result.Content[0].Text)
	}
}

func TestHandleToolCall_Check_ServiceNotFound_IsError(t *testing.T) {
	h := newTestHandler(&mockProxy{}, &mockServices{checkErr: errors.New("services: \"unknown\" not found")})

	w := doRequest(h, http.MethodPost, "/api/v1/mcp/tool-call", map[string]interface{}{
		"tool":      "straylight_check",
		"arguments": map[string]interface{}{"service": "unknown"},
	})

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 with isError, got %d", w.Code)
	}

	result := decodeToolResult(t, w)
	if !result.IsError {
		t.Error("should set isError=true when service not found")
	}
}

func TestHandleToolCall_Check_MissingServiceArgument_IsError(t *testing.T) {
	h := newTestHandler(&mockProxy{}, &mockServices{})

	w := doRequest(h, http.MethodPost, "/api/v1/mcp/tool-call", map[string]interface{}{
		"tool":      "straylight_check",
		"arguments": map[string]interface{}{},
	})

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 with isError, got %d", w.Code)
	}

	result := decodeToolResult(t, w)
	if !result.IsError {
		t.Error("should set isError=true when service argument missing")
	}
}

// ---------------------------------------------------------------------------
// straylight_api_call tool
// ---------------------------------------------------------------------------

func TestHandleToolCall_APICall_Success(t *testing.T) {
	mockResp := &proxy.APICallResponse{
		StatusCode: 200,
		Body:       `{"object":"balance"}`,
	}
	h := newTestHandler(&mockProxy{response: mockResp}, &mockServices{})

	w := doRequest(h, http.MethodPost, "/api/v1/mcp/tool-call", map[string]interface{}{
		"tool": "straylight_api_call",
		"arguments": map[string]interface{}{
			"service": "stripe",
			"method":  "GET",
			"path":    "/v1/balance",
		},
	})

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	result := decodeToolResult(t, w)
	if result.IsError {
		t.Error("should not be an error for successful call")
	}
	if !strings.Contains(result.Content[0].Text, "balance") {
		t.Errorf("response body missing, got: %q", result.Content[0].Text)
	}
}

func TestHandleToolCall_APICall_ProxyError_IsError(t *testing.T) {
	h := newTestHandler(
		&mockProxy{err: errors.New("service \"xyz\" not found")},
		&mockServices{},
	)

	w := doRequest(h, http.MethodPost, "/api/v1/mcp/tool-call", map[string]interface{}{
		"tool": "straylight_api_call",
		"arguments": map[string]interface{}{
			"service": "xyz",
			"path":    "/v1/test",
		},
	})

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 with isError, got %d", w.Code)
	}

	result := decodeToolResult(t, w)
	if !result.IsError {
		t.Error("proxy error should set isError=true")
	}
	if !strings.Contains(result.Content[0].Text, "Error:") {
		t.Errorf("error message should start with 'Error:', got: %q", result.Content[0].Text)
	}
}

func TestHandleToolCall_APICall_MissingServiceArgument_IsError(t *testing.T) {
	h := newTestHandler(&mockProxy{}, &mockServices{})

	w := doRequest(h, http.MethodPost, "/api/v1/mcp/tool-call", map[string]interface{}{
		"tool": "straylight_api_call",
		"arguments": map[string]interface{}{
			"path": "/v1/balance",
			// missing "service"
		},
	})

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 with isError, got %d", w.Code)
	}

	result := decodeToolResult(t, w)
	if !result.IsError {
		t.Error("missing service should produce isError=true")
	}
}

func TestHandleToolCall_APICall_MissingPathArgument_IsError(t *testing.T) {
	h := newTestHandler(&mockProxy{}, &mockServices{})

	w := doRequest(h, http.MethodPost, "/api/v1/mcp/tool-call", map[string]interface{}{
		"tool": "straylight_api_call",
		"arguments": map[string]interface{}{
			"service": "stripe",
			// missing "path"
		},
	})

	result := decodeToolResult(t, w)
	if !result.IsError {
		t.Error("missing path should produce isError=true")
	}
}

func TestHandleToolCall_APICall_Upstream4xx_IsError(t *testing.T) {
	mockResp := &proxy.APICallResponse{
		StatusCode: 401,
		Body:       `{"error":"unauthorized"}`,
	}
	h := newTestHandler(&mockProxy{response: mockResp}, &mockServices{})

	w := doRequest(h, http.MethodPost, "/api/v1/mcp/tool-call", map[string]interface{}{
		"tool": "straylight_api_call",
		"arguments": map[string]interface{}{
			"service": "stripe",
			"path":    "/v1/balance",
		},
	})

	result := decodeToolResult(t, w)
	if !result.IsError {
		t.Error("upstream 4xx should set isError=true")
	}
}

func TestHandleToolCall_APICall_Upstream5xx_IsError(t *testing.T) {
	mockResp := &proxy.APICallResponse{
		StatusCode: 503,
		Body:       `{"error":"service unavailable"}`,
	}
	h := newTestHandler(&mockProxy{response: mockResp}, &mockServices{})

	w := doRequest(h, http.MethodPost, "/api/v1/mcp/tool-call", map[string]interface{}{
		"tool": "straylight_api_call",
		"arguments": map[string]interface{}{
			"service": "stripe",
			"path":    "/v1/balance",
		},
	})

	result := decodeToolResult(t, w)
	if !result.IsError {
		t.Error("upstream 5xx should set isError=true")
	}
}

func TestHandleToolCall_APICall_PassesAllArgumentsToProxy(t *testing.T) {
	var capturedReq proxy.APICallRequest
	mp := &capturingMockProxy{}
	mp.response = &proxy.APICallResponse{StatusCode: 200, Body: "ok"}

	h := newTestHandler(mp, &mockServices{})
	_ = doRequest(h, http.MethodPost, "/api/v1/mcp/tool-call", map[string]interface{}{
		"tool": "straylight_api_call",
		"arguments": map[string]interface{}{
			"service": "stripe",
			"method":  "POST",
			"path":    "/v1/charges",
			"headers": map[string]interface{}{"X-Idempotency-Key": "abc123"},
			"query":   map[string]interface{}{"expand[]": "balance_transaction"},
			"body":    map[string]interface{}{"amount": 1000},
		},
	})

	capturedReq = mp.lastReq
	if capturedReq.Service != "stripe" {
		t.Errorf("service: want stripe, got %q", capturedReq.Service)
	}
	if capturedReq.Method != "POST" {
		t.Errorf("method: want POST, got %q", capturedReq.Method)
	}
	if capturedReq.Path != "/v1/charges" {
		t.Errorf("path: want /v1/charges, got %q", capturedReq.Path)
	}
	if capturedReq.Headers["X-Idempotency-Key"] != "abc123" {
		t.Errorf("header not passed through: %v", capturedReq.Headers)
	}
}

// capturingMockProxy records the last request for assertion.
type capturingMockProxy struct {
	lastReq  proxy.APICallRequest
	response *proxy.APICallResponse
	err      error
}

func (c *capturingMockProxy) HandleAPICall(_ context.Context, req proxy.APICallRequest) (*proxy.APICallResponse, error) {
	c.lastReq = req
	return c.response, c.err
}

// ---------------------------------------------------------------------------
// Response format validation
// ---------------------------------------------------------------------------

func TestToolCallResult_ContentItemTypeIsAlwaysText(t *testing.T) {
	h := newTestHandler(
		&mockProxy{response: &proxy.APICallResponse{StatusCode: 200, Body: "data"}},
		&mockServices{},
	)

	w := doRequest(h, http.MethodPost, "/api/v1/mcp/tool-call", map[string]interface{}{
		"tool": "straylight_api_call",
		"arguments": map[string]interface{}{
			"service": "stripe",
			"path":    "/v1/balance",
		},
	})

	result := decodeToolResult(t, w)
	for _, item := range result.Content {
		if item.Type != "text" {
			t.Errorf("content item type should always be 'text', got %q", item.Type)
		}
	}
}

func TestToolCallResult_ContentIsNeverEmpty(t *testing.T) {
	tools := []string{"straylight_exec", "straylight_services"}
	for _, tool := range tools {
		t.Run(tool, func(t *testing.T) {
			h := newTestHandler(&mockProxy{}, &mockServices{list: []services.Service{}})
			w := doRequest(h, http.MethodPost, "/api/v1/mcp/tool-call", map[string]interface{}{
				"tool":      tool,
				"arguments": map[string]interface{}{},
			})

			result := decodeToolResult(t, w)
			if len(result.Content) == 0 {
				t.Errorf("tool %q returned empty content array", tool)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// straylight_scan tool — stub
// ---------------------------------------------------------------------------

func TestHandleToolCall_ScanReturnsStub(t *testing.T) {
	h := newTestHandler(&mockProxy{}, &mockServices{})
	w := doRequest(h, http.MethodPost, "/api/v1/mcp/tool-call", map[string]interface{}{
		"tool": "straylight_scan",
		"arguments": map[string]interface{}{
			"path": ".",
		},
	})

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	result := decodeToolResult(t, w)
	if len(result.Content) == 0 {
		t.Fatal("expected non-empty content for straylight_scan")
	}
}

func TestHandleToolCall_ScanIsNotError(t *testing.T) {
	h := newTestHandler(&mockProxy{}, &mockServices{})
	w := doRequest(h, http.MethodPost, "/api/v1/mcp/tool-call", map[string]interface{}{
		"tool":      "straylight_scan",
		"arguments": map[string]interface{}{},
	})

	result := decodeToolResult(t, w)
	if result.IsError {
		t.Error("straylight_scan stub should not set isError=true")
	}
}

// ---------------------------------------------------------------------------
// straylight_read_file tool
// ---------------------------------------------------------------------------

func TestHandleToolCall_ReadFile_MissingPathArgument_IsError(t *testing.T) {
	h := newTestHandler(&mockProxy{}, &mockServices{})
	w := doRequest(h, http.MethodPost, "/api/v1/mcp/tool-call", map[string]interface{}{
		"tool":      "straylight_read_file",
		"arguments": map[string]interface{}{},
	})

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 with isError, got %d", w.Code)
	}

	result := decodeToolResult(t, w)
	if !result.IsError {
		t.Error("missing path should set isError=true")
	}
}

func TestHandleToolCall_ReadFile_NonExistentFile_IsError(t *testing.T) {
	h := newTestHandler(&mockProxy{}, &mockServices{})
	w := doRequest(h, http.MethodPost, "/api/v1/mcp/tool-call", map[string]interface{}{
		"tool": "straylight_read_file",
		"arguments": map[string]interface{}{
			"path": "/nonexistent/path/to/file.txt",
		},
	})

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 with isError, got %d", w.Code)
	}

	result := decodeToolResult(t, w)
	if !result.IsError {
		t.Error("nonexistent file should set isError=true")
	}
}

func TestHandleToolCall_ReadFile_ReturnsContent(t *testing.T) {
	// Use a real Firewall with the temp dir as project root so that reading
	// a file within the temp dir is permitted.
	tmpDir := t.TempDir()
	content := "Hello, straylight!\n"
	if err := os.WriteFile(filepath.Join(tmpDir, "hello.txt"), []byte(content), 0o644); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	h := newTestHandler(&mockProxy{}, &mockServices{})
	h.SetFileReader(newRealFirewall(t, tmpDir))

	w := doRequest(h, http.MethodPost, "/api/v1/mcp/tool-call", map[string]interface{}{
		"tool": "straylight_read_file",
		"arguments": map[string]interface{}{
			"path": filepath.Join(tmpDir, "hello.txt"),
		},
	})

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	result := decodeToolResult(t, w)
	if result.IsError {
		t.Errorf("should not be an error, got: %v", result.Content)
	}
	if len(result.Content) == 0 {
		t.Fatal("expected non-empty content")
	}
	if !strings.Contains(result.Content[0].Text, "Hello, straylight!") {
		t.Errorf("expected content to contain 'Hello, straylight!', got: %q", result.Content[0].Text)
	}
}

func TestHandleToolCall_ReadFile_BlockedFile_IsError(t *testing.T) {
	// Write a temp .env file and use a real Firewall with the temp dir as root
	// so the firewall can enforce its blocked-file list.
	tmpDir := t.TempDir()
	envPath := filepath.Join(tmpDir, ".env")
	if err := os.WriteFile(envPath, []byte("SECRET=value\n"), 0600); err != nil {
		t.Fatalf("write .env file: %v", err)
	}

	h := newTestHandler(&mockProxy{}, &mockServices{})
	h.SetFileReader(newRealFirewall(t, tmpDir))

	w := doRequest(h, http.MethodPost, "/api/v1/mcp/tool-call", map[string]interface{}{
		"tool": "straylight_read_file",
		"arguments": map[string]interface{}{
			"path": envPath,
		},
	})

	result := decodeToolResult(t, w)
	if !result.IsError {
		t.Error("blocked .env file should set isError=true")
	}
	if len(result.Content) == 0 {
		t.Fatal("expected error message content")
	}
	// Error message should mention vault or blocked or sensitive.
	text := result.Content[0].Text
	if !strings.Contains(text, "vault") && !strings.Contains(text, "blocked") && !strings.Contains(text, "sensitive") {
		t.Errorf("error message should mention vault/blocked/sensitive, got: %q", text)
	}
}

func TestHandleToolCall_ReadFile_ContentTypeIsText(t *testing.T) {
	tmpDir := t.TempDir()
	goFile := filepath.Join(tmpDir, "main.go")
	if err := os.WriteFile(goFile, []byte("package main\n"), 0o644); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	h := newTestHandler(&mockProxy{}, &mockServices{})
	h.SetFileReader(newRealFirewall(t, tmpDir))
	w := doRequest(h, http.MethodPost, "/api/v1/mcp/tool-call", map[string]interface{}{
		"tool": "straylight_read_file",
		"arguments": map[string]interface{}{
			"path": goFile,
		},
	})

	result := decodeToolResult(t, w)
	for _, item := range result.Content {
		if item.Type != "text" {
			t.Errorf("content item type should be 'text', got %q", item.Type)
		}
	}
}

// ---------------------------------------------------------------------------
// straylight_scan tool
// ---------------------------------------------------------------------------

func TestHandleToolCall_Scan_MissingPath_UsesDefault(t *testing.T) {
	h := newTestHandler(&mockProxy{}, &mockServices{})
	w := doRequest(h, http.MethodPost, "/api/v1/mcp/tool-call", map[string]interface{}{
		"tool":      "straylight_scan",
		"arguments": map[string]interface{}{},
	})

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	result := decodeToolResult(t, w)
	if len(result.Content) == 0 {
		t.Fatal("expected non-empty content")
	}
	// With an empty path, the handler uses "." which may or may not produce
	// findings, but it must return a valid JSON payload (not an error about
	// a missing argument).
}

func TestHandleToolCall_Scan_NonexistentPath_IsError(t *testing.T) {
	h := newTestHandler(&mockProxy{}, &mockServices{})
	w := doRequest(h, http.MethodPost, "/api/v1/mcp/tool-call", map[string]interface{}{
		"tool": "straylight_scan",
		"arguments": map[string]interface{}{
			"path": "/does/not/exist/at/all",
		},
	})

	if w.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200 with isError, got %d", w.Code)
	}

	result := decodeToolResult(t, w)
	if !result.IsError {
		t.Error("nonexistent path should set isError=true")
	}
}

func TestHandleToolCall_Scan_ValidPath_ReturnsFindingsJSON(t *testing.T) {
	// Use a mock scanner with a pre-populated finding so we can assert the
	// JSON response structure without scanning the real filesystem.
	// The handler now rejects absolute paths, so we use "." and a mock scanner.
	mockSc := newMockScannerWithFindings([]scanner.Finding{
		{File: "creds.env", Line: 1, Pattern: "aws-access-key", Severity: "high", Match: "AKIA[...]E123"},
	}, 1)

	h := newTestHandler(&mockProxy{}, &mockServices{})
	h.SetScanner(mockSc)
	w := doRequest(h, http.MethodPost, "/api/v1/mcp/tool-call", map[string]interface{}{
		"tool": "straylight_scan",
		"arguments": map[string]interface{}{
			"path": ".", // relative path — required by security fix
		},
	})

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	result := decodeToolResult(t, w)
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}
	if len(result.Content) == 0 {
		t.Fatal("expected non-empty content")
	}

	text := result.Content[0].Text
	if !strings.Contains(text, "findings") {
		t.Errorf("response should contain 'findings' key, got: %q", text)
	}
	if !strings.Contains(text, "files_scanned") {
		t.Errorf("response should contain 'files_scanned', got: %q", text)
	}
}

func TestHandleToolCall_Scan_GenerateIgnore_IncludesIgnoreRules(t *testing.T) {
	mockSc := newMockScannerWithFindings([]scanner.Finding{
		{File: ".env", Line: 1, Pattern: "env-secret", Severity: "medium", Match: "**[...]***"},
	}, 1)

	h := newTestHandler(&mockProxy{}, &mockServices{})
	h.SetScanner(mockSc)
	w := doRequest(h, http.MethodPost, "/api/v1/mcp/tool-call", map[string]interface{}{
		"tool": "straylight_scan",
		"arguments": map[string]interface{}{
			"path":            ".", // relative path required by security fix
			"generate_ignore": true,
		},
	})

	result := decodeToolResult(t, w)
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	text := result.Content[0].Text
	if !strings.Contains(text, "ignore_rules") {
		t.Errorf("response with generate_ignore=true should contain 'ignore_rules', got: %q", text)
	}
}

func TestHandleToolCall_Scan_GenerateIgnoreFalse_NoIgnoreRulesField(t *testing.T) {
	mockSc := newMockScannerWithFindings([]scanner.Finding{}, 0)

	h := newTestHandler(&mockProxy{}, &mockServices{})
	h.SetScanner(mockSc)
	w := doRequest(h, http.MethodPost, "/api/v1/mcp/tool-call", map[string]interface{}{
		"tool": "straylight_scan",
		"arguments": map[string]interface{}{
			"path":            ".", // relative path required by security fix
			"generate_ignore": false,
		},
	})

	result := decodeToolResult(t, w)
	if result.IsError {
		t.Fatalf("expected success: %v", result.Content)
	}

	text := result.Content[0].Text
	// When generate_ignore is false, no ignore_rules field should appear
	if strings.Contains(text, "ignore_rules") {
		t.Errorf("response with generate_ignore=false should NOT contain 'ignore_rules', got: %q", text)
	}
}

func TestHandleToolCall_Scan_ContentTypeIsText(t *testing.T) {
	mockSc := newMockScannerWithFindings([]scanner.Finding{}, 0)

	h := newTestHandler(&mockProxy{}, &mockServices{})
	h.SetScanner(mockSc)
	w := doRequest(h, http.MethodPost, "/api/v1/mcp/tool-call", map[string]interface{}{
		"tool": "straylight_scan",
		"arguments": map[string]interface{}{
			"path": ".", // relative path required by security fix
		},
	})

	result := decodeToolResult(t, w)
	for _, item := range result.Content {
		if item.Type != "text" {
			t.Errorf("content type should be 'text', got %q", item.Type)
		}
	}
}

func TestHandleToolCall_Scan_SeverityFilterHigh_FiltersResults(t *testing.T) {
	mockSc := newMockScannerWithFindings([]scanner.Finding{
		{File: "creds.env", Line: 1, Pattern: "aws-access-key", Severity: "high", Match: "AKIA[...]E123"},
		{File: "other.txt", Line: 2, Pattern: "bearer-token", Severity: "medium", Match: "Bear[...]xyz"},
	}, 2)

	h := newTestHandler(&mockProxy{}, &mockServices{})
	h.SetScanner(mockSc)
	w := doRequest(h, http.MethodPost, "/api/v1/mcp/tool-call", map[string]interface{}{
		"tool": "straylight_scan",
		"arguments": map[string]interface{}{
			"path":            ".", // relative path required by security fix
			"severity_filter": "high",
		},
	})

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	result := decodeToolResult(t, w)
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}
	text := result.Content[0].Text
	if !strings.Contains(text, "findings") {
		t.Errorf("expected findings in response, got: %q", text)
	}
}

func TestHandleToolCall_Scan_SeverityFilterMedium_IncludesMediumAndHigh(t *testing.T) {
	mockSc := newMockScannerWithFindings([]scanner.Finding{
		{File: "curl.sh", Line: 1, Pattern: "bearer-token", Severity: "medium", Match: "Bear[...]xyz"},
	}, 1)

	h := newTestHandler(&mockProxy{}, &mockServices{})
	h.SetScanner(mockSc)
	w := doRequest(h, http.MethodPost, "/api/v1/mcp/tool-call", map[string]interface{}{
		"tool": "straylight_scan",
		"arguments": map[string]interface{}{
			"path":            ".", // relative path required by security fix
			"severity_filter": "medium",
		},
	})

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	result := decodeToolResult(t, w)
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}
}
