package mcp_test

import (
	"context"
	"strings"
	"testing"

	"github.com/straylight-ai/straylight/internal/cmdwrap"
	"github.com/straylight-ai/straylight/internal/mcp"
	"github.com/straylight-ai/straylight/internal/services"
)

// ---------------------------------------------------------------------------
// ADR-013 Phase 3: straylight_exec gate tests
// ---------------------------------------------------------------------------

// mockCommandExecutor records calls and returns a canned response.
type mockCommandExecutor struct {
	called   bool
	response *cmdwrap.ExecResponse
	err      error
}

func (m *mockCommandExecutor) Execute(_ context.Context, _ cmdwrap.ExecRequest) (*cmdwrap.ExecResponse, error) {
	m.called = true
	return m.response, m.err
}

// execGateServiceLister lists services with configurable ExecEnabled and AllowedCommands.
type execGateServiceLister struct {
	services []services.Service
}

func (m *execGateServiceLister) List() []services.Service {
	return m.services
}

func (m *execGateServiceLister) CheckCredential(name string) (string, error) {
	for _, svc := range m.services {
		if svc.Name == name {
			return "available", nil
		}
	}
	return "", nil
}

func (m *execGateServiceLister) ExecEnabledFor(name string) bool {
	for _, svc := range m.services {
		if svc.Name == name {
			return svc.ExecEnabled
		}
	}
	return false
}

// TestExecGate_ExecEnabledFalseIsRejected verifies that straylight_exec returns
// an error when the service has ExecEnabled=false (the default).
// The real CommandExecutor must NOT be called.
func TestExecGate_ExecEnabledFalseIsRejected(t *testing.T) {
	executor := &mockCommandExecutor{
		response: &cmdwrap.ExecResponse{ExitCode: 0, Stdout: "should not see this"},
	}

	svcList := &execGateServiceLister{
		services: []services.Service{
			{Name: "github", Type: "http_proxy", ExecEnabled: false},
		},
	}

	h := mcp.NewHandler(&mockProxy{}, svcList)
	h.SetCommandExecutor(executor)

	w := doRequest(h, "POST", "/api/v1/mcp/tool-call", map[string]interface{}{
		"tool": "straylight_exec",
		"arguments": map[string]interface{}{
			"service": "github",
			"command": "echo hi",
		},
	})

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	result := decodeToolResult(t, w)
	if !result.IsError {
		t.Error("expected isError=true when ExecEnabled=false")
	}
	if !strings.Contains(result.Content[0].Text, "exec") {
		t.Errorf("expected error text to mention 'exec'; got: %q", result.Content[0].Text)
	}
	if executor.called {
		t.Error("executor must NOT be called when ExecEnabled=false")
	}
}

// TestExecGate_ExecEnabledTrueAllowsExecution verifies that when ExecEnabled=true
// and a CommandExecutor is registered, exec dispatches to the real executor.
func TestExecGate_ExecEnabledTrueAllowsExecution(t *testing.T) {
	executor := &mockCommandExecutor{
		response: &cmdwrap.ExecResponse{ExitCode: 0, Stdout: "hello world"},
	}

	svcList := &execGateServiceLister{
		services: []services.Service{
			{Name: "aws-svc", Type: "cloud", ExecEnabled: true, AllowedCommands: []string{"aws"}},
		},
	}

	h := mcp.NewHandler(&mockProxy{}, svcList)
	h.SetCommandExecutor(executor)

	w := doRequest(h, "POST", "/api/v1/mcp/tool-call", map[string]interface{}{
		"tool": "straylight_exec",
		"arguments": map[string]interface{}{
			"service": "aws-svc",
			"command": "aws s3 ls",
		},
	})

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	if !executor.called {
		t.Error("executor must be called when ExecEnabled=true")
	}

	result := decodeToolResult(t, w)
	if result.IsError {
		t.Errorf("expected no error; got: %q", result.Content[0].Text)
	}
}
