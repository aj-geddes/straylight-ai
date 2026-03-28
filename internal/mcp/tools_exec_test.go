// Package mcp_test: tests for the enhanced straylight_exec tool with real
// command wrapper and cloud credential injection.
package mcp_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/straylight-ai/straylight/internal/cmdwrap"
	"github.com/straylight-ai/straylight/internal/mcp"
	"github.com/straylight-ai/straylight/internal/services"
)

// ---------------------------------------------------------------------------
// Mock command executor
// ---------------------------------------------------------------------------

// mockExecWrapper implements mcp.CommandExecutor for tests.
type mockExecWrapper struct {
	response *cmdwrap.ExecResponse
	err      error
	lastReq  cmdwrap.ExecRequest
}

func (m *mockExecWrapper) Execute(_ context.Context, req cmdwrap.ExecRequest) (*cmdwrap.ExecResponse, error) {
	m.lastReq = req
	if m.err != nil {
		return nil, m.err
	}
	if m.response != nil {
		return m.response, nil
	}
	return &cmdwrap.ExecResponse{ExitCode: 0, Stdout: "mock output", Stderr: ""}, nil
}

// ---------------------------------------------------------------------------
// Mock cloud credential provider
// ---------------------------------------------------------------------------

// mockCloudManager implements mcp.CloudCredentialProvider for tests.
type mockCloudManager struct {
	envVars map[string]string
	err     error
}

func (m *mockCloudManager) GetCredentials(_ context.Context, _ string, _ interface{}) (map[string]string, error) {
	return m.envVars, m.err
}

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

func newExecTestHandler(exec mcp.CommandExecutor, svc mcp.ServiceLister) *mcp.Handler {
	h := mcp.NewHandler(&mockProxy{}, svc)
	h.SetCommandExecutor(exec)
	return h
}

// ---------------------------------------------------------------------------
// straylight_exec — real implementation tests
// ---------------------------------------------------------------------------

// TestHandleExec_MissingService verifies that missing service argument returns error.
func TestHandleExec_MissingService(t *testing.T) {
	svcList := &mockServices{
		list: []services.Service{{Name: "github", Type: "http_proxy", Status: "available"}},
	}
	w := doRequest(newExecTestHandler(&mockExecWrapper{}, svcList), http.MethodPost, "/api/v1/mcp/tool-call", map[string]interface{}{
		"tool": "straylight_exec",
		"arguments": map[string]interface{}{
			"command": "ls",
			// "service" is missing
		},
	})

	result := decodeToolResult(t, w)
	if !result.IsError {
		t.Error("expected isError=true for missing service")
	}
}

// TestHandleExec_MissingCommand verifies that missing command argument returns error.
func TestHandleExec_MissingCommand(t *testing.T) {
	svcList := &mockServices{
		list: []services.Service{{Name: "github", Type: "http_proxy", Status: "available"}},
	}
	w := doRequest(newExecTestHandler(&mockExecWrapper{}, svcList), http.MethodPost, "/api/v1/mcp/tool-call", map[string]interface{}{
		"tool": "straylight_exec",
		"arguments": map[string]interface{}{
			"service": "github",
			// "command" is missing
		},
	})

	result := decodeToolResult(t, w)
	if !result.IsError {
		t.Error("expected isError=true for missing command")
	}
}

// TestHandleExec_SuccessReturnsOutput verifies that successful execution
// returns stdout and exit code in the response.
func TestHandleExec_SuccessReturnsOutput(t *testing.T) {
	mockExec := &mockExecWrapper{
		response: &cmdwrap.ExecResponse{ExitCode: 0, Stdout: "hello world\n", Stderr: ""},
	}
	svcList := &mockServices{
		list: []services.Service{{Name: "github", Type: "http_proxy", Status: "available"}},
	}

	w := doRequest(newExecTestHandler(mockExec, svcList), http.MethodPost, "/api/v1/mcp/tool-call", map[string]interface{}{
		"tool": "straylight_exec",
		"arguments": map[string]interface{}{
			"service": "github",
			"command": "echo hello world",
		},
	})

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	result := decodeToolResult(t, w)
	if result.IsError {
		t.Errorf("expected isError=false, got true; content: %v", result.Content)
	}
	if len(result.Content) == 0 || !strings.Contains(result.Content[0].Text, "hello world") {
		t.Errorf("expected 'hello world' in content; got: %v", result.Content)
	}
}

// TestHandleExec_NonZeroExitCodeReturnsErrorResult verifies that a non-zero exit
// code is encoded as isError=true in the tool result.
func TestHandleExec_NonZeroExitCodeReturnsErrorResult(t *testing.T) {
	mockExec := &mockExecWrapper{
		response: &cmdwrap.ExecResponse{ExitCode: 1, Stdout: "", Stderr: "command failed"},
	}
	svcList := &mockServices{
		list: []services.Service{{Name: "github", Type: "http_proxy", Status: "available"}},
	}

	w := doRequest(newExecTestHandler(mockExec, svcList), http.MethodPost, "/api/v1/mcp/tool-call", map[string]interface{}{
		"tool": "straylight_exec",
		"arguments": map[string]interface{}{
			"service": "github",
			"command": "false",
		},
	})

	result := decodeToolResult(t, w)
	if !result.IsError {
		t.Error("expected isError=true for non-zero exit code")
	}
}

// TestHandleExec_WrapperErrorReturnsErrorResult verifies that a wrapper setup
// error (e.g., unknown service) is returned as an error result.
func TestHandleExec_WrapperErrorReturnsErrorResult(t *testing.T) {
	_ = services.Service{} // ensure services import is used
	mockExec := &mockExecWrapper{
		err: errors.New("cmdwrap: services: \"unknown-svc\" not found"),
	}
	svcList := &mockServices{
		list: []services.Service{},
	}

	w := doRequest(newExecTestHandler(mockExec, svcList), http.MethodPost, "/api/v1/mcp/tool-call", map[string]interface{}{
		"tool": "straylight_exec",
		"arguments": map[string]interface{}{
			"service": "unknown-svc",
			"command": "ls",
		},
	})

	result := decodeToolResult(t, w)
	if !result.IsError {
		t.Error("expected isError=true for wrapper error")
	}
}

// TestHandleExec_TimeoutReturnsErrorResult verifies that a timed-out command
// (exit code -1) returns isError=true.
func TestHandleExec_TimeoutReturnsErrorResult(t *testing.T) {
	mockExec := &mockExecWrapper{
		response: &cmdwrap.ExecResponse{ExitCode: -1, Stdout: "", Stderr: "command timed out after 1 seconds"},
	}
	svcList := &mockServices{
		list: []services.Service{{Name: "github", Type: "http_proxy", Status: "available"}},
	}

	w := doRequest(newExecTestHandler(mockExec, svcList), http.MethodPost, "/api/v1/mcp/tool-call", map[string]interface{}{
		"tool": "straylight_exec",
		"arguments": map[string]interface{}{
			"service":         "github",
			"command":         "sleep 60",
			"timeout_seconds": 1,
		},
	})

	result := decodeToolResult(t, w)
	if !result.IsError {
		t.Error("expected isError=true for timed-out command")
	}
	if len(result.Content) == 0 || !strings.Contains(result.Content[0].Text, "timed out") {
		t.Errorf("expected 'timed out' in error content; got: %v", result.Content)
	}
}

// TestHandleExec_FallsBackToStubWhenNoExecutor verifies backward compatibility:
// when no CommandExecutor is set, the stub message is returned (no panic).
func TestHandleExec_FallsBackToStubWhenNoExecutor(t *testing.T) {
	h := mcp.NewHandler(&mockProxy{}, &mockServices{})
	// No SetCommandExecutor call.

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
	if result.IsError {
		t.Error("stub should not return isError=true")
	}
}
