// Tests for the straylight-mcp MCP host binary.
// Uses httptest.Server to simulate the container API.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// newMockContainer returns a test server simulating the container API.
func newMockContainer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("/api/v1/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, `{"status":"ok","openbao":"unsealed","services_count":2,"version":"1.0.0"}`)
	})

	mux.HandleFunc("/api/v1/mcp/tool-list", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, `{"tools":[{"name":"straylight_api_call","description":"Make an API call","inputSchema":{"type":"object","properties":{"service":{"type":"string"},"path":{"type":"string"}},"required":["service","path"]}},{"name":"straylight_services","description":"List services","inputSchema":{"type":"object","properties":{}}}]}`)
	})

	mux.HandleFunc("/api/v1/mcp/tool-call", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Tool      string                 `json:"tool"`
			Arguments map[string]interface{} `json:"arguments"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		result := fmt.Sprintf(`{"content":[{"type":"text","text":"result for %s"}]}`, req.Tool)
		fmt.Fprintln(w, result)
	})

	mux.HandleFunc("/api/v1/services", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, `{"services":[{"name":"stripe","type":"http_proxy","status":"available","capabilities":["api_call"]}]}`)
	})

	return httptest.NewServer(mux)
}

// sendRPC writes a JSON-RPC request to the server's stdin buffer and reads
// the response from the server's stdout buffer.
func sendRPC(t *testing.T, srv *MCPServer, req JSONRPCRequest) (*JSONRPCResponse, string) {
	t.Helper()

	reqBytes, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	reqBytes = append(reqBytes, '\n')

	inBuf := bytes.NewBuffer(reqBytes)
	outBuf := &bytes.Buffer{}

	scanner := bufio.NewScanner(inBuf)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		srv.handleLine(line, outBuf)
	}

	// Parse the response line.
	outStr := outBuf.String()
	lines := strings.Split(strings.TrimSpace(outStr), "\n")
	if len(lines) == 0 || lines[0] == "" {
		return nil, outStr
	}

	var resp JSONRPCResponse
	if err := json.Unmarshal([]byte(lines[0]), &resp); err != nil {
		return nil, outStr
	}
	return &resp, outStr
}

// ---------------------------------------------------------------------------
// ContainerClient tests
// ---------------------------------------------------------------------------

func TestContainerClient_Health_OK(t *testing.T) {
	srv := newMockContainer(t)
	defer srv.Close()

	client := NewContainerClient(srv.URL)
	if err := client.Health(); err != nil {
		t.Errorf("expected no error, got: %v", err)
	}
}

func TestContainerClient_Health_Unavailable(t *testing.T) {
	// Use a URL that will refuse connections.
	client := NewContainerClient("http://127.0.0.1:19999")
	client.httpClient.Timeout = 100 * time.Millisecond

	if err := client.Health(); err == nil {
		t.Error("expected error for unavailable container, got nil")
	}
}

func TestContainerClient_GetToolList(t *testing.T) {
	srv := newMockContainer(t)
	defer srv.Close()

	client := NewContainerClient(srv.URL)
	tools, err := client.GetToolList()
	if err != nil {
		t.Fatalf("GetToolList: %v", err)
	}

	if len(tools) != 2 {
		t.Errorf("expected 2 tools, got %d", len(tools))
	}
	if tools[0].Name != "straylight_api_call" {
		t.Errorf("expected first tool straylight_api_call, got %q", tools[0].Name)
	}
}

func TestContainerClient_GetToolList_Unavailable(t *testing.T) {
	client := NewContainerClient("http://127.0.0.1:19999")
	client.httpClient.Timeout = 100 * time.Millisecond

	_, err := client.GetToolList()
	if err == nil {
		t.Error("expected error for unavailable container, got nil")
	}
}

func TestContainerClient_CallTool(t *testing.T) {
	srv := newMockContainer(t)
	defer srv.Close()

	client := NewContainerClient(srv.URL)
	result, err := client.CallTool("straylight_services", map[string]interface{}{})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}

	if len(result.Content) == 0 {
		t.Error("expected non-empty content in tool call result")
	}
	if result.Content[0].Text != "result for straylight_services" {
		t.Errorf("unexpected content text: %q", result.Content[0].Text)
	}
}

func TestContainerClient_CallTool_Unavailable(t *testing.T) {
	client := NewContainerClient("http://127.0.0.1:19999")
	client.httpClient.Timeout = 100 * time.Millisecond

	_, err := client.CallTool("straylight_services", map[string]interface{}{})
	if err == nil {
		t.Error("expected error for unavailable container, got nil")
	}
}

// ---------------------------------------------------------------------------
// MCPServer JSON-RPC handler tests
// ---------------------------------------------------------------------------

func TestMCPServer_Initialize(t *testing.T) {
	srv := newMockContainer(t)
	defer srv.Close()

	server := NewMCPServer(NewContainerClient(srv.URL))

	req := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      float64(1),
		Method:  "initialize",
		Params:  nil,
	}
	resp, raw := sendRPC(t, server, req)
	if resp == nil {
		t.Fatalf("expected response, got empty output: %q", raw)
	}
	if resp.Error != nil {
		t.Fatalf("unexpected error: %+v", resp.Error)
	}

	// Result must contain protocolVersion and serverInfo.
	result, ok := resp.Result.(map[string]interface{})
	if !ok {
		t.Fatalf("result is not a map: %T", resp.Result)
	}

	version, _ := result["protocolVersion"].(string)
	if version != "2024-11-05" {
		t.Errorf("expected protocolVersion 2024-11-05, got %q", version)
	}

	serverInfo, ok := result["serverInfo"].(map[string]interface{})
	if !ok {
		t.Fatalf("serverInfo missing or wrong type")
	}
	if serverInfo["name"] != "straylight-ai" {
		t.Errorf("expected server name straylight-ai, got %v", serverInfo["name"])
	}
}

func TestMCPServer_Ping(t *testing.T) {
	srv := newMockContainer(t)
	defer srv.Close()

	server := NewMCPServer(NewContainerClient(srv.URL))

	req := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      float64(2),
		Method:  "ping",
	}
	resp, raw := sendRPC(t, server, req)
	if resp == nil {
		t.Fatalf("expected response, got empty output: %q", raw)
	}
	if resp.Error != nil {
		t.Fatalf("unexpected error: %+v", resp.Error)
	}
}

func TestMCPServer_ToolsList(t *testing.T) {
	srv := newMockContainer(t)
	defer srv.Close()

	server := NewMCPServer(NewContainerClient(srv.URL))

	req := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      float64(3),
		Method:  "tools/list",
	}
	resp, raw := sendRPC(t, server, req)
	if resp == nil {
		t.Fatalf("expected response, got empty output: %q", raw)
	}
	if resp.Error != nil {
		t.Fatalf("unexpected error: %+v", resp.Error)
	}

	result, ok := resp.Result.(map[string]interface{})
	if !ok {
		t.Fatalf("result is not a map: %T %q", resp.Result, raw)
	}

	tools, ok := result["tools"].([]interface{})
	if !ok {
		t.Fatalf("tools missing or wrong type: %T", result["tools"])
	}
	if len(tools) != 2 {
		t.Errorf("expected 2 tools, got %d", len(tools))
	}
}

func TestMCPServer_ToolsList_ContainerUnavailable(t *testing.T) {
	client := NewContainerClient("http://127.0.0.1:19999")
	client.httpClient.Timeout = 100 * time.Millisecond

	server := NewMCPServer(client)

	req := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      float64(3),
		Method:  "tools/list",
	}
	resp, _ := sendRPC(t, server, req)
	if resp == nil {
		t.Fatal("expected a response even on container failure")
	}
	// Should return an RPC error when container is unreachable.
	if resp.Error == nil {
		t.Error("expected RPC error when container is unavailable")
	}
}

func TestMCPServer_ToolsCall(t *testing.T) {
	srv := newMockContainer(t)
	defer srv.Close()

	server := NewMCPServer(NewContainerClient(srv.URL))

	params := map[string]interface{}{
		"name":      "straylight_services",
		"arguments": map[string]interface{}{},
	}
	paramsBytes, _ := json.Marshal(params)

	req := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      float64(4),
		Method:  "tools/call",
		Params:  json.RawMessage(paramsBytes),
	}
	resp, raw := sendRPC(t, server, req)
	if resp == nil {
		t.Fatalf("expected response, got empty output: %q", raw)
	}
	if resp.Error != nil {
		t.Fatalf("unexpected error: %+v", resp.Error)
	}

	result, ok := resp.Result.(map[string]interface{})
	if !ok {
		t.Fatalf("result is not a map: %T", resp.Result)
	}

	content, ok := result["content"].([]interface{})
	if !ok {
		t.Fatalf("content missing or wrong type")
	}
	if len(content) == 0 {
		t.Error("expected non-empty content")
	}
}

func TestMCPServer_ToolsCall_ContainerUnavailable(t *testing.T) {
	client := NewContainerClient("http://127.0.0.1:19999")
	client.httpClient.Timeout = 100 * time.Millisecond
	server := NewMCPServer(client)

	params := map[string]interface{}{
		"name":      "straylight_services",
		"arguments": map[string]interface{}{},
	}
	paramsBytes, _ := json.Marshal(params)

	req := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      float64(4),
		Method:  "tools/call",
		Params:  json.RawMessage(paramsBytes),
	}
	resp, _ := sendRPC(t, server, req)
	if resp == nil {
		t.Fatal("expected a response even on container failure")
	}
	// Should return an error result (isError=true in content), not an RPC-level error.
	// Per MCP spec, tool errors are returned in the result with isError=true.
	result, ok := resp.Result.(map[string]interface{})
	if !ok {
		t.Fatalf("expected result map, got %T", resp.Result)
	}
	isError, _ := result["isError"].(bool)
	if !isError {
		t.Error("expected isError=true when container is unavailable")
	}
}

func TestMCPServer_ToolsCall_MissingName(t *testing.T) {
	srv := newMockContainer(t)
	defer srv.Close()
	server := NewMCPServer(NewContainerClient(srv.URL))

	// Params without "name" field.
	params := map[string]interface{}{}
	paramsBytes, _ := json.Marshal(params)

	req := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      float64(5),
		Method:  "tools/call",
		Params:  json.RawMessage(paramsBytes),
	}
	resp, _ := sendRPC(t, server, req)
	if resp == nil {
		t.Fatal("expected response")
	}
	if resp.Error == nil {
		t.Error("expected RPC error for missing tool name")
	}
}

func TestMCPServer_NotificationsInitialized_NoResponse(t *testing.T) {
	srv := newMockContainer(t)
	defer srv.Close()
	server := NewMCPServer(NewContainerClient(srv.URL))

	req := JSONRPCRequest{
		JSONRPC: "2.0",
		// Notifications have no ID.
		Method: "notifications/initialized",
	}
	outBuf := &bytes.Buffer{}
	reqBytes, _ := json.Marshal(req)
	server.handleLine(string(reqBytes), outBuf)

	// Notifications must produce no response.
	if outBuf.Len() != 0 {
		t.Errorf("expected no response for notification, got: %q", outBuf.String())
	}
}

func TestMCPServer_UnknownMethod(t *testing.T) {
	srv := newMockContainer(t)
	defer srv.Close()
	server := NewMCPServer(NewContainerClient(srv.URL))

	req := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      float64(99),
		Method:  "unknown/method",
	}
	resp, _ := sendRPC(t, server, req)
	if resp == nil {
		t.Fatal("expected response")
	}
	if resp.Error == nil {
		t.Error("expected error for unknown method")
	}
	// JSON-RPC method not found error code is -32601.
	if resp.Error.Code != -32601 {
		t.Errorf("expected error code -32601, got %d", resp.Error.Code)
	}
}

func TestMCPServer_MalformedJSON(t *testing.T) {
	srv := newMockContainer(t)
	defer srv.Close()
	server := NewMCPServer(NewContainerClient(srv.URL))

	outBuf := &bytes.Buffer{}
	server.handleLine("{not valid json", outBuf)

	// Should write a parse-error response.
	if outBuf.Len() == 0 {
		t.Error("expected error response for malformed JSON")
	}
	var resp JSONRPCResponse
	if err := json.Unmarshal(bytes.TrimRight(outBuf.Bytes(), "\n"), &resp); err != nil {
		t.Fatalf("parse error response: %v", err)
	}
	if resp.Error == nil {
		t.Error("expected error field in response")
	}
	if resp.Error.Code != -32700 {
		t.Errorf("expected parse error code -32700, got %d", resp.Error.Code)
	}
}

// ---------------------------------------------------------------------------
// ContainerServiceLister tests
// ---------------------------------------------------------------------------

func TestContainerServiceLister_List(t *testing.T) {
	srv := newMockContainer(t)
	defer srv.Close()

	lister := NewContainerServiceLister(NewContainerClient(srv.URL))
	services := lister.List()

	if len(services) != 1 {
		t.Errorf("expected 1 service, got %d", len(services))
	}
	if services[0].Name != "stripe" {
		t.Errorf("expected service name stripe, got %q", services[0].Name)
	}
}

func TestContainerServiceLister_List_Unavailable(t *testing.T) {
	client := NewContainerClient("http://127.0.0.1:19999")
	client.httpClient.Timeout = 100 * time.Millisecond

	lister := NewContainerServiceLister(client)
	services := lister.List()

	// Should return empty slice (not panic or nil) when container is unavailable.
	if services == nil {
		t.Error("expected empty slice, got nil")
	}
}

// ---------------------------------------------------------------------------
// parseContainerURL tests
// ---------------------------------------------------------------------------

func TestParseContainerURL_Default(t *testing.T) {
	url := parseContainerURL("")
	if url != defaultContainerURL {
		t.Errorf("expected default URL %q, got %q", defaultContainerURL, url)
	}
}

func TestParseContainerURL_EnvVar(t *testing.T) {
	t.Setenv("STRAYLIGHT_URL", "http://localhost:8888")
	url := parseContainerURL("http://localhost:8888")
	if url != "http://localhost:8888" {
		t.Errorf("expected http://localhost:8888, got %q", url)
	}
}

func TestParseContainerURL_TrailingSlash(t *testing.T) {
	url := parseContainerURL("http://localhost:9470/")
	// Trailing slash should be stripped.
	if strings.HasSuffix(url, "/") {
		t.Errorf("expected trailing slash to be removed, got %q", url)
	}
}
