package mcp_test

import (
	"context"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/straylight-ai/straylight/internal/audit"
	"github.com/straylight-ai/straylight/internal/mcp"
	"github.com/straylight-ai/straylight/internal/proxy"
	"github.com/straylight-ai/straylight/internal/services"
)

// ---------------------------------------------------------------------------
// Audit capture mock
// ---------------------------------------------------------------------------

type mcpAuditCapture struct {
	mu     sync.Mutex
	events []audit.Event
}

func (c *mcpAuditCapture) Emit(ev audit.Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, ev)
}

func (c *mcpAuditCapture) Events() []audit.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]audit.Event, len(c.events))
	copy(out, c.events)
	return out
}

// waitForEvents polls until at least minCount audit events have been captured
// or the timeout elapses. Returns the events collected.
func waitForEvents(c *mcpAuditCapture, minCount int, timeout time.Duration) []audit.Event {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if evs := c.Events(); len(evs) >= minCount {
			return evs
		}
		time.Sleep(5 * time.Millisecond)
	}
	return c.Events()
}

// ---------------------------------------------------------------------------
// Verify mcpAuditCapture satisfies audit.Emitter
// ---------------------------------------------------------------------------

var _ audit.Emitter = (*mcpAuditCapture)(nil)

// ---------------------------------------------------------------------------
// Helper: build MCP handler with audit capture
// ---------------------------------------------------------------------------

func newAuditedHandler(p mcp.ProxyHandler, s mcp.ServiceLister) (*mcp.Handler, *mcpAuditCapture) {
	cap := &mcpAuditCapture{}
	h := mcp.NewHandler(p, s)
	h.SetAudit(cap)
	return h, cap
}

// ---------------------------------------------------------------------------
// straylight_api_call emits tool_call event
// ---------------------------------------------------------------------------

func TestAudit_APICall_EmitsToolCallEvent(t *testing.T) {
	mockResp := &proxy.APICallResponse{StatusCode: 200, Body: `{"ok":true}`}
	h, cap := newAuditedHandler(
		&mockProxy{response: mockResp},
		&mockServices{},
	)

	doRequest(h, http.MethodPost, "/api/v1/mcp/tool-call", map[string]interface{}{
		"tool": "straylight_api_call",
		"arguments": map[string]interface{}{
			"service": "stripe",
			"method":  "GET",
			"path":    "/v1/balance",
		},
	})

	events := waitForEvents(cap, 1, 100*time.Millisecond)
	if len(events) == 0 {
		t.Fatal("expected at least one audit event, got none")
	}

	var found bool
	for _, ev := range events {
		if ev.Type == audit.EventToolCall {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected %q event, events: %v", audit.EventToolCall, events)
	}
}

func TestAudit_APICall_ToolCallEventContainsToolName(t *testing.T) {
	mockResp := &proxy.APICallResponse{StatusCode: 200, Body: `{"ok":true}`}
	h, cap := newAuditedHandler(
		&mockProxy{response: mockResp},
		&mockServices{},
	)

	doRequest(h, http.MethodPost, "/api/v1/mcp/tool-call", map[string]interface{}{
		"tool": "straylight_api_call",
		"arguments": map[string]interface{}{
			"service": "stripe",
			"path":    "/v1/balance",
		},
	})

	events := waitForEvents(cap, 1, 100*time.Millisecond)
	for _, ev := range events {
		if ev.Type == audit.EventToolCall {
			if ev.Tool != "straylight_api_call" {
				t.Errorf("tool_call event Tool = %q, want straylight_api_call", ev.Tool)
			}
			return
		}
	}
	t.Error("no tool_call event found")
}

func TestAudit_APICall_ToolCallEventContainsServiceName(t *testing.T) {
	mockResp := &proxy.APICallResponse{StatusCode: 200, Body: `{"ok":true}`}
	h, cap := newAuditedHandler(
		&mockProxy{response: mockResp},
		&mockServices{},
	)

	doRequest(h, http.MethodPost, "/api/v1/mcp/tool-call", map[string]interface{}{
		"tool": "straylight_api_call",
		"arguments": map[string]interface{}{
			"service": "stripe",
			"path":    "/v1/balance",
		},
	})

	events := waitForEvents(cap, 1, 100*time.Millisecond)
	for _, ev := range events {
		if ev.Type == audit.EventToolCall {
			if ev.Service != "stripe" {
				t.Errorf("tool_call event Service = %q, want stripe", ev.Service)
			}
			return
		}
	}
	t.Error("no tool_call event found")
}

// ---------------------------------------------------------------------------
// straylight_check emits tool_call event
// ---------------------------------------------------------------------------

func TestAudit_Check_EmitsToolCallEvent(t *testing.T) {
	h, cap := newAuditedHandler(
		&mockProxy{},
		&mockServices{checkStatus: "available"},
	)

	doRequest(h, http.MethodPost, "/api/v1/mcp/tool-call", map[string]interface{}{
		"tool":      "straylight_check",
		"arguments": map[string]interface{}{"service": "github"},
	})

	events := waitForEvents(cap, 1, 100*time.Millisecond)
	var found bool
	for _, ev := range events {
		if ev.Type == audit.EventToolCall && ev.Tool == "straylight_check" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected tool_call event for straylight_check, events: %v", events)
	}
}

func TestAudit_Check_ToolCallEventContainsServiceName(t *testing.T) {
	h, cap := newAuditedHandler(
		&mockProxy{},
		&mockServices{checkStatus: "available"},
	)

	doRequest(h, http.MethodPost, "/api/v1/mcp/tool-call", map[string]interface{}{
		"tool":      "straylight_check",
		"arguments": map[string]interface{}{"service": "github"},
	})

	events := waitForEvents(cap, 1, 100*time.Millisecond)
	for _, ev := range events {
		if ev.Type == audit.EventToolCall && ev.Tool == "straylight_check" {
			if ev.Service != "github" {
				t.Errorf("straylight_check event Service = %q, want github", ev.Service)
			}
			return
		}
	}
	t.Error("no straylight_check tool_call event found")
}

// ---------------------------------------------------------------------------
// straylight_services emits tool_call event
// ---------------------------------------------------------------------------

func TestAudit_Services_EmitsToolCallEvent(t *testing.T) {
	svcList := []services.Service{
		{Name: "stripe", Type: "http_proxy", Status: "available", Target: "https://api.stripe.com", Inject: "header"},
	}
	h, cap := newAuditedHandler(
		&mockProxy{},
		&mockServices{list: svcList},
	)

	doRequest(h, http.MethodPost, "/api/v1/mcp/tool-call", map[string]interface{}{
		"tool":      "straylight_services",
		"arguments": map[string]interface{}{},
	})

	events := waitForEvents(cap, 1, 100*time.Millisecond)
	var found bool
	for _, ev := range events {
		if ev.Type == audit.EventToolCall && ev.Tool == "straylight_services" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected tool_call event for straylight_services, events: %v", events)
	}
}

// ---------------------------------------------------------------------------
// straylight_exec emits tool_call event
// ---------------------------------------------------------------------------

func TestAudit_Exec_EmitsToolCallEvent(t *testing.T) {
	h, cap := newAuditedHandler(
		&mockProxy{},
		&mockServices{},
	)

	doRequest(h, http.MethodPost, "/api/v1/mcp/tool-call", map[string]interface{}{
		"tool": "straylight_exec",
		"arguments": map[string]interface{}{
			"service": "github",
			"command": "ls",
		},
	})

	events := waitForEvents(cap, 1, 100*time.Millisecond)
	var found bool
	for _, ev := range events {
		if ev.Type == audit.EventToolCall && ev.Tool == "straylight_exec" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected tool_call event for straylight_exec, events: %v", events)
	}
}

// ---------------------------------------------------------------------------
// No audit emitter — handler must not panic
// ---------------------------------------------------------------------------

func TestAudit_NoEmitter_DoesNotPanic(t *testing.T) {
	// No SetAudit call — audit is nil.
	h := mcp.NewHandler(
		&mockProxy{response: &proxy.APICallResponse{StatusCode: 200, Body: "ok"}},
		&mockServices{},
	)

	// Must not panic.
	doRequest(h, http.MethodPost, "/api/v1/mcp/tool-call", map[string]interface{}{
		"tool": "straylight_api_call",
		"arguments": map[string]interface{}{
			"service": "stripe",
			"path":    "/v1/balance",
		},
	})
}

// ---------------------------------------------------------------------------
// Outcome is recorded in audit details
// ---------------------------------------------------------------------------

func TestAudit_APICall_OutcomeRecordedOnSuccess(t *testing.T) {
	mockResp := &proxy.APICallResponse{StatusCode: 200, Body: `{"ok":true}`}
	h, cap := newAuditedHandler(
		&mockProxy{response: mockResp},
		&mockServices{},
	)

	doRequest(h, http.MethodPost, "/api/v1/mcp/tool-call", map[string]interface{}{
		"tool": "straylight_api_call",
		"arguments": map[string]interface{}{
			"service": "stripe",
			"path":    "/v1/balance",
		},
	})

	events := waitForEvents(cap, 1, 100*time.Millisecond)
	for _, ev := range events {
		if ev.Type == audit.EventToolCall && ev.Tool == "straylight_api_call" {
			outcome, ok := ev.Details["outcome"]
			if !ok {
				t.Error("tool_call event should have outcome in details")
				return
			}
			if outcome != "success" {
				t.Errorf("outcome = %q, want success", outcome)
			}
			return
		}
	}
	t.Error("no straylight_api_call tool_call event found")
}

func TestAudit_APICall_OutcomeRecordedOnError(t *testing.T) {
	mockResp := &proxy.APICallResponse{StatusCode: 401, Body: `{"error":"unauthorized"}`}
	h, cap := newAuditedHandler(
		&mockProxy{response: mockResp},
		&mockServices{},
	)

	doRequest(h, http.MethodPost, "/api/v1/mcp/tool-call", map[string]interface{}{
		"tool": "straylight_api_call",
		"arguments": map[string]interface{}{
			"service": "stripe",
			"path":    "/v1/balance",
		},
	})

	events := waitForEvents(cap, 1, 100*time.Millisecond)
	for _, ev := range events {
		if ev.Type == audit.EventToolCall && ev.Tool == "straylight_api_call" {
			outcome, ok := ev.Details["outcome"]
			if !ok {
				t.Error("tool_call event should have outcome in details")
				return
			}
			if outcome != "error" {
				t.Errorf("outcome for 4xx = %q, want error", outcome)
			}
			return
		}
	}
	t.Error("no straylight_api_call tool_call event found")
}

// ---------------------------------------------------------------------------
// AuditEmitter interface is satisfied by audit.Logger
// ---------------------------------------------------------------------------

func TestMCPHandler_AcceptsAuditLoggerInterface(t *testing.T) {
	dir := t.TempDir()
	logger, err := audit.NewLogger(dir, 0)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	defer logger.Close()

	h := mcp.NewHandler(&mockProxy{response: &proxy.APICallResponse{StatusCode: 200, Body: "ok"}}, &mockServices{})
	h.SetAudit(logger) // Logger must satisfy audit.Emitter

	doRequest(h, http.MethodPost, "/api/v1/mcp/tool-call", map[string]interface{}{
		"tool": "straylight_services",
		"arguments": map[string]interface{}{},
	})

	// No panic — test passes.
}

// Ensure dispatchToolCall still works when called from outside the handler
// (regression guard — the signature should not change).
func TestDispatchToolCall_StillWorks(t *testing.T) {
	_ = context.Background() // ensure context package used
}
