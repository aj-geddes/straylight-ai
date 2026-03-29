package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/straylight-ai/straylight/internal/mcp"
	"github.com/straylight-ai/straylight/internal/proxy"
	"github.com/straylight-ai/straylight/internal/server"
	"github.com/straylight-ai/straylight/internal/services"
)

// ---------------------------------------------------------------------------
// Mock dependencies used by MCP route tests
// ---------------------------------------------------------------------------

type mcpMockProxy struct {
	response *proxy.APICallResponse
	err      error
}

func (m *mcpMockProxy) HandleAPICall(_ context.Context, _ proxy.APICallRequest) (*proxy.APICallResponse, error) {
	return m.response, m.err
}

type mcpMockServices struct {
	list        []services.Service
	checkStatus string
}

func (m *mcpMockServices) List() []services.Service {
	return m.list
}

func (m *mcpMockServices) CheckCredential(_ string) (string, error) {
	return m.checkStatus, nil
}

// newTestServerWithMCP creates a server with a real MCP handler wired in.
func newTestServerWithMCP(t *testing.T) *server.Server {
	t.Helper()
	handler := mcp.NewHandler(
		&mcpMockProxy{
			response: &proxy.APICallResponse{StatusCode: 200, Body: `{"ok":true}`},
		},
		&mcpMockServices{
			list:        []services.Service{{Name: "stripe", Type: "http_proxy", Status: "available", Target: "https://api.stripe.com", Inject: "header"}},
			checkStatus: "available",
		},
	)
	return server.New(server.Config{
		ListenAddress: "127.0.0.1:0",
		Version:       "1.0.1",
		MCPHandler:    handler,
	})
}

// ---------------------------------------------------------------------------
// Route registration tests
// ---------------------------------------------------------------------------

func TestMCPRoutes_ToolListRegistered(t *testing.T) {
	srv := newTestServerWithMCP(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/mcp/tool-list", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for tool-list, got %d", w.Code)
	}

	var resp struct {
		Tools []mcp.ToolDefinition `json:"tools"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp.Tools) < 4 {
		t.Errorf("expected at least 4 tools, got %d", len(resp.Tools))
	}
}

func TestMCPRoutes_ToolCallRegistered(t *testing.T) {
	srv := newTestServerWithMCP(t)

	body, _ := json.Marshal(map[string]interface{}{
		"tool":      "straylight_services",
		"arguments": map[string]interface{}{},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/mcp/tool-call", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for tool-call, got %d (body: %s)", w.Code, w.Body.String())
	}

	var result mcp.ToolCallResult
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if len(result.Content) == 0 {
		t.Error("expected non-empty content")
	}
}

func TestMCPRoutes_ToolListWithoutHandler_Returns501(t *testing.T) {
	srv := server.New(server.Config{
		ListenAddress: "127.0.0.1:0",
		Version:       "1.0.1",
		// MCPHandler intentionally nil
	})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/mcp/tool-list", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusNotImplemented {
		t.Fatalf("expected 501 when MCPHandler is nil, got %d", w.Code)
	}
}

func TestMCPRoutes_ToolCallWithoutHandler_Returns501(t *testing.T) {
	srv := server.New(server.Config{
		ListenAddress: "127.0.0.1:0",
		Version:       "1.0.1",
	})
	body, _ := json.Marshal(map[string]interface{}{
		"tool":      "straylight_services",
		"arguments": map[string]interface{}{},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/mcp/tool-call", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusNotImplemented {
		t.Fatalf("expected 501 when MCPHandler is nil, got %d", w.Code)
	}
}

func TestMCPRoutes_ToolCallAPICall_EndToEnd(t *testing.T) {
	srv := newTestServerWithMCP(t)

	body, _ := json.Marshal(map[string]interface{}{
		"tool": "straylight_api_call",
		"arguments": map[string]interface{}{
			"service": "stripe",
			"method":  "GET",
			"path":    "/v1/balance",
		},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/mcp/tool-call", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (body: %s)", w.Code, w.Body.String())
	}

	var result mcp.ToolCallResult
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if result.IsError {
		t.Errorf("unexpected error in result: %v", result.Content)
	}
	if len(result.Content) == 0 || !strings.Contains(result.Content[0].Text, "ok") {
		t.Errorf("expected body in response, got: %v", result.Content)
	}
}

func TestMCPRoutes_ToolListPOST_MethodNotAllowed(t *testing.T) {
	srv := newTestServerWithMCP(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/mcp/tool-list", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	// Go 1.22 ServeMux returns 405 when the path matches but method doesn't.
	if w.Code == http.StatusOK {
		t.Error("POST to tool-list should not return 200")
	}
}
