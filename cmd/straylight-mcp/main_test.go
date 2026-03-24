// main_test.go tests the top-level run() dispatch and runHook() logic.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// run() dispatch tests
// ---------------------------------------------------------------------------

func TestRun_DefaultIsServer(t *testing.T) {
	// run([]) should start the MCP server path and return 0 on clean stdin close.
	// We use a mock container that responds to the health check.
	srv := newMockContainer(t)
	defer srv.Close()

	t.Setenv("STRAYLIGHT_URL", srv.URL)

	// Feed a single initialize request via stdin then close.
	req := `{"jsonrpc":"2.0","id":1,"method":"initialize"}` + "\n"
	output, code := captureRun(t, []string{}, req)

	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}

	// Verify we got an initialize response on stdout.
	if !strings.Contains(output, "straylight-ai") {
		t.Errorf("expected server name in initialize response, got: %q", output)
	}
}

func TestRun_HookSubcommand_PreToolUse(t *testing.T) {
	srv := newMockContainer(t)
	defer srv.Close()

	t.Setenv("STRAYLIGHT_URL", srv.URL)

	// Valid PreToolUse input that should be allowed.
	hookInput := `{"tool_name":"Bash","tool_input":{"command":"echo hello"}}` + "\n"
	output, code := captureRun(t, []string{"hook", "pretooluse"}, hookInput)

	// 0 = allow, 2 = block. Should be 0 for safe command.
	if code != 0 {
		t.Errorf("expected exit code 0 (allow), got %d; output: %q", code, output)
	}

	var decision struct {
		Decision string `json:"decision"`
	}
	if err := json.Unmarshal([]byte(strings.TrimRight(output, "\n")), &decision); err != nil {
		t.Fatalf("parse hook output: %v; raw: %q", err, output)
	}
	if decision.Decision != "allow" {
		t.Errorf("expected decision=allow, got %q", decision.Decision)
	}
}

func TestRun_HookSubcommand_PostToolUse(t *testing.T) {
	srv := newMockContainer(t)
	defer srv.Close()

	t.Setenv("STRAYLIGHT_URL", srv.URL)

	hookInput := `{"tool_name":"Bash","tool_output":{"stdout":"normal output","stderr":""}}` + "\n"
	output, code := captureRun(t, []string{"hook", "posttooluse"}, hookInput)

	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}

	if len(output) == 0 {
		t.Error("expected output from posttooluse hook")
	}
}

func TestRun_HookSubcommand_UnknownHook(t *testing.T) {
	_, code := captureRun(t, []string{"hook", "unknownhook"}, "")
	if code == 0 {
		t.Error("expected non-zero exit code for unknown hook")
	}
}

func TestRun_HookSubcommand_PreToolUse_Blocked(t *testing.T) {
	srv := newMockContainer(t)
	defer srv.Close()

	t.Setenv("STRAYLIGHT_URL", srv.URL)

	// Command that references a credential env var — should be blocked.
	hookInput := `{"tool_name":"Bash","tool_input":{"command":"echo $STRIPE_API_KEY"}}` + "\n"
	output, code := captureRun(t, []string{"hook", "pretooluse"}, hookInput)

	// Exit code 2 = blocked.
	if code != 2 {
		t.Errorf("expected exit code 2 (block), got %d; output: %q", code, output)
	}
}

// ---------------------------------------------------------------------------
// Serve integration test
// ---------------------------------------------------------------------------

func TestMCPServer_Serve_MultipleRequests(t *testing.T) {
	srv := newMockContainer(t)
	defer srv.Close()

	server := NewMCPServer(NewContainerClient(srv.URL))

	input := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize"}`,
		`{"jsonrpc":"2.0","id":2,"method":"ping"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		"",
	}, "\n")

	outBuf := &bytes.Buffer{}
	server.Serve(strings.NewReader(input), outBuf)

	lines := strings.Split(strings.TrimSpace(outBuf.String()), "\n")
	// 3 responses (notification has no response), init + ping + tools/list.
	if len(lines) != 3 {
		t.Errorf("expected 3 response lines, got %d: %v", len(lines), lines)
	}

	// Verify each line is valid JSON.
	for i, line := range lines {
		var resp JSONRPCResponse
		if err := json.Unmarshal([]byte(line), &resp); err != nil {
			t.Errorf("line %d is not valid JSON: %v; content: %q", i, err, line)
		}
	}
}

func TestMCPServer_Serve_EmptyLinesSkipped(t *testing.T) {
	srv := newMockContainer(t)
	defer srv.Close()

	server := NewMCPServer(NewContainerClient(srv.URL))

	// Input with blank lines surrounding a valid request.
	input := "\n\n" + `{"jsonrpc":"2.0","id":1,"method":"ping"}` + "\n\n"
	outBuf := &bytes.Buffer{}
	server.Serve(strings.NewReader(input), outBuf)

	lines := strings.Split(strings.TrimSpace(outBuf.String()), "\n")
	if len(lines) != 1 {
		t.Errorf("expected exactly 1 response, got %d", len(lines))
	}
}

// ---------------------------------------------------------------------------
// logStderr test
// ---------------------------------------------------------------------------

func TestLogStderr_StructuredJSON(t *testing.T) {
	// logStderr writes to stderr — just verify it doesn't panic.
	logStderr("info", "test message", map[string]interface{}{
		"key": "value",
	})
	logStderr("warn", "another message", nil)
}

// ---------------------------------------------------------------------------
// run() with unavailable container tests
// ---------------------------------------------------------------------------

func TestRun_DefaultWithUnavailableContainer(t *testing.T) {
	// Should not fail even if container is unavailable — just log a warning.
	t.Setenv("STRAYLIGHT_URL", "http://127.0.0.1:19998")

	req := `{"jsonrpc":"2.0","id":1,"method":"ping"}` + "\n"
	_, code := captureRun(t, []string{}, req)

	if code != 0 {
		t.Errorf("expected exit code 0 even with unavailable container, got %d", code)
	}
}

// ---------------------------------------------------------------------------
// Additional ContainerClient edge case tests
// ---------------------------------------------------------------------------

func TestContainerClient_Health_NonOKStatus(t *testing.T) {
	// Server that returns 503.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprintln(w, `{"status":"degraded"}`)
	}))
	defer srv.Close()

	client := NewContainerClient(srv.URL)
	if err := client.Health(); err == nil {
		t.Error("expected error for 503 response, got nil")
	}
}

func TestContainerClient_GetToolList_BadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, `{not valid json`)
	}))
	defer srv.Close()

	client := NewContainerClient(srv.URL)
	_, err := client.GetToolList()
	if err == nil {
		t.Error("expected error for invalid JSON response")
	}
}

func TestContainerClient_GetToolList_NonOKStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(w, `{"error":"internal"}`)
	}))
	defer srv.Close()

	client := NewContainerClient(srv.URL)
	_, err := client.GetToolList()
	if err == nil {
		t.Error("expected error for 500 response")
	}
}

func TestContainerClient_CallTool_NonOKStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, `{"error":{"code":"unknown_tool","message":"tool not found"}}`)
	}))
	defer srv.Close()

	client := NewContainerClient(srv.URL)
	_, err := client.CallTool("bad_tool", map[string]interface{}{})
	if err == nil {
		t.Error("expected error for 400 response")
	}
}

func TestContainerClient_CallTool_BadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, `{not valid`)
	}))
	defer srv.Close()

	client := NewContainerClient(srv.URL)
	_, err := client.CallTool("straylight_services", map[string]interface{}{})
	if err == nil {
		t.Error("expected error for invalid JSON response")
	}
}

func TestContainerServiceLister_List_BadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, `{not valid`)
	}))
	defer srv.Close()

	lister := NewContainerServiceLister(NewContainerClient(srv.URL))
	services := lister.List()
	if services == nil {
		t.Error("expected empty slice, got nil")
	}
	if len(services) != 0 {
		t.Errorf("expected empty slice for bad JSON, got %d services", len(services))
	}
}

func TestContainerServiceLister_List_NonOKStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	lister := NewContainerServiceLister(NewContainerClient(srv.URL))
	services := lister.List()
	if services == nil {
		t.Error("expected empty slice, got nil")
	}
}

func TestMCPServer_ToolsCall_NilArguments(t *testing.T) {
	srv := newMockContainer(t)
	defer srv.Close()
	server := NewMCPServer(NewContainerClient(srv.URL))

	// Params with name but no arguments field (nil).
	params := map[string]interface{}{
		"name": "straylight_services",
	}
	paramsBytes, _ := json.Marshal(params)

	req := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      float64(10),
		Method:  "tools/call",
		Params:  json.RawMessage(paramsBytes),
	}
	resp, raw := sendRPC(t, server, req)
	if resp == nil {
		t.Fatalf("expected response, got: %q", raw)
	}
	// Should succeed with nil arguments treated as empty map.
	if resp.Error != nil {
		t.Errorf("unexpected RPC error: %+v", resp.Error)
	}
}

func TestMCPServer_ToolsCall_EmptyParams(t *testing.T) {
	srv := newMockContainer(t)
	defer srv.Close()
	server := NewMCPServer(NewContainerClient(srv.URL))

	req := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      float64(11),
		Method:  "tools/call",
		Params:  nil,
	}
	resp, _ := sendRPC(t, server, req)
	if resp == nil {
		t.Fatal("expected response")
	}
	if resp.Error == nil {
		t.Error("expected RPC error for empty params")
	}
}

// ---------------------------------------------------------------------------
// captureRun: sets up stdin/stdout pipes, calls run(args), returns stdout.
// ---------------------------------------------------------------------------

// captureRun sets up stdin/stdout pipes, calls run(args), and returns the
// captured stdout content and exit code. It handles proper pipe synchronization.
func captureRun(t *testing.T, args []string, stdinContent string) (stdout string, code int) {
	t.Helper()

	// Create stdin pipe and write content.
	stdinR, stdinW, err := os.Pipe()
	if err != nil {
		t.Fatalf("create stdin pipe: %v", err)
	}

	// Create stdout pipe.
	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		stdinR.Close()
		stdinW.Close()
		t.Fatalf("create stdout pipe: %v", err)
	}

	// Write stdin content (close write end after to signal EOF).
	go func() {
		defer stdinW.Close()
		fmt.Fprint(stdinW, stdinContent)
	}()

	// Save and replace os.Stdin/os.Stdout.
	origStdin := os.Stdin
	origStdout := os.Stdout
	os.Stdin = stdinR
	os.Stdout = stdoutW

	// Run the function.
	code = run(args)

	// Restore stdin/stdout and close the write end of stdout pipe.
	os.Stdin = origStdin
	os.Stdout = origStdout
	stdinR.Close()
	stdoutW.Close()

	// Read all captured stdout.
	var outBuf bytes.Buffer
	_, _ = outBuf.ReadFrom(stdoutR)
	stdoutR.Close()

	return outBuf.String(), code
}
