package mcp_test

import (
	"context"
	"testing"

	"github.com/straylight-ai/straylight/internal/audit"
	"github.com/straylight-ai/straylight/internal/mcp"
	"github.com/straylight-ai/straylight/internal/mcpauth"
	"github.com/straylight-ai/straylight/internal/mcphttp"
	"github.com/straylight-ai/straylight/internal/proxy"
	"github.com/straylight-ai/straylight/internal/services"
)

// ---------------------------------------------------------------------------
// Test stubs
// ---------------------------------------------------------------------------

// remoteStubServiceLister is a minimal ServiceLister for remote dispatch tests.
type remoteStubServiceLister struct{}

func (s *remoteStubServiceLister) List() []services.Service                 { return nil }
func (s *remoteStubServiceLister) CheckCredential(_ string) (string, error) { return "ok", nil }
func (s *remoteStubServiceLister) ExecEnabledFor(_ string) bool             { return false }

// remoteStubProxyHandler returns nil for any API call (not used by straylight_services).
type remoteStubProxyHandler struct{}

func (p *remoteStubProxyHandler) HandleAPICall(_ context.Context, _ proxy.APICallRequest) (*proxy.APICallResponse, error) {
	return nil, nil
}

// remoteCapture collects emitted audit events.
type remoteCapture struct {
	events []audit.Event
}

func (c *remoteCapture) Emit(ev audit.Event) {
	c.events = append(c.events, ev)
}

// ---------------------------------------------------------------------------
// RED tests -- will fail to compile until Dispatch() is added to *mcp.Handler.
// ---------------------------------------------------------------------------

// TestHandler_SatisfiesToolDispatcher asserts at compile time and runtime that
// *mcp.Handler satisfies the mcphttp.ToolDispatcher interface.
func TestHandler_SatisfiesToolDispatcher(t *testing.T) {
	h := mcp.NewHandler(&remoteStubProxyHandler{}, &remoteStubServiceLister{})

	// Compile-time interface satisfaction check.
	var _ mcphttp.ToolDispatcher = h

	// Runtime call must not panic and must not return an error.
	result := h.Dispatch(
		context.Background(),
		mcp.ToolCallRequest{Tool: "straylight_services", Arguments: map[string]interface{}{}},
		&mcpauth.Identity{Subject: "user|test"},
	)
	if result.IsError {
		t.Errorf("Dispatch returned IsError=true: %v", result.Content)
	}
}

// TestHandler_Dispatch_RoutesToolCall verifies that Dispatch delegates to the
// underlying dispatchToolCall logic and returns a real result.
func TestHandler_Dispatch_RoutesToolCall(t *testing.T) {
	h := mcp.NewHandler(&remoteStubProxyHandler{}, &remoteStubServiceLister{})

	result := h.Dispatch(
		context.Background(),
		mcp.ToolCallRequest{Tool: "straylight_services", Arguments: map[string]interface{}{}},
		&mcpauth.Identity{Subject: "user|alice"},
	)

	if result.IsError {
		t.Errorf("expected IsError=false, got true: %v", result.Content)
	}
	if len(result.Content) == 0 {
		t.Error("expected at least one content item in Dispatch result")
	}
}

// TestHandler_Dispatch_AuditAttributedToIdentity verifies that a remote
// tool call emits exactly one audit event with the caller's identity Subject
// in the SessionID field for attribution.
func TestHandler_Dispatch_AuditAttributedToIdentity(t *testing.T) {
	cap := &remoteCapture{}
	h := mcp.NewHandler(&remoteStubProxyHandler{}, &remoteStubServiceLister{})
	h.SetAudit(cap)

	identity := &mcpauth.Identity{
		Subject: "user|alice",
		Issuer:  "https://idp.example.com",
	}

	result := h.Dispatch(
		context.Background(),
		mcp.ToolCallRequest{Tool: "straylight_services", Arguments: map[string]interface{}{}},
		identity,
	)

	if result.IsError {
		t.Errorf("unexpected error result: %v", result.Content)
	}
	if len(cap.events) != 1 {
		t.Fatalf("expected exactly 1 audit event, got %d", len(cap.events))
	}
	ev := cap.events[0]
	if ev.SessionID != identity.Subject {
		t.Errorf("audit event SessionID = %q, want %q (identity.Subject)", ev.SessionID, identity.Subject)
	}
	if ev.Tool != "straylight_services" {
		t.Errorf("audit event Tool = %q, want straylight_services", ev.Tool)
	}
}
