package mcp_test

// dispatch_policy_test.go verifies that the dispatchToolCall gate evaluates
// per-service policy BEFORE credential injection and that denied calls never
// reach the proxy's HandleAPICall (i.e. no credential path is exercised).

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/straylight-ai/straylight/internal/audit"
	"github.com/straylight-ai/straylight/internal/mcp"
	"github.com/straylight-ai/straylight/internal/policy"
	"github.com/straylight-ai/straylight/internal/proxy"
	"github.com/straylight-ai/straylight/internal/services"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// recordingProxy wraps a mockProxy and counts HandleAPICall invocations so
// tests can assert that the proxy (and thus credential injection) was NOT
// reached on a denied call.
type recordingProxy struct {
	calls    int
	response *proxy.APICallResponse
	err      error
}

func (rp *recordingProxy) HandleAPICall(_ context.Context, _ proxy.APICallRequest) (*proxy.APICallResponse, error) {
	rp.calls++
	return rp.response, rp.err
}

// mockServiceListWithPolicy satisfies both mcp.ServiceLister and mcp.PolicyResolver.
type mockServiceListWithPolicy struct {
	list     []services.Service
	policies map[string]policy.Policy
}

func (m *mockServiceListWithPolicy) List() []services.Service { return m.list }
func (m *mockServiceListWithPolicy) CheckCredential(_ string) (string, error) {
	return "available", nil
}
func (m *mockServiceListWithPolicy) PolicyFor(service string) policy.Policy {
	return m.policies[service]
}
func (m *mockServiceListWithPolicy) TargetHostFor(service string) string {
	for _, svc := range m.list {
		if svc.Name == service {
			u, err := url.Parse(svc.Target)
			if err == nil {
				return u.Hostname()
			}
		}
	}
	return ""
}

// auditCapture collects emitted audit events for assertions.
type auditCapture struct {
	events []audit.Event
}

func (a *auditCapture) Emit(e audit.Event) { a.events = append(a.events, e) }

// newPolicyHandler creates an mcp.Handler with the policy engine and resolver
// wired, and a recording proxy.
func newPolicyHandler(rp *recordingProxy, svc services.Service, pol policy.Policy) *mcp.Handler {
	resolver := &mockServiceListWithPolicy{
		list:     []services.Service{svc},
		policies: map[string]policy.Policy{svc.Name: pol},
	}
	h := mcp.NewHandler(rp, resolver)
	h.SetPolicy(policy.New(), resolver)
	return h
}

func policyToolCallBody(tool, service, method, path string) map[string]interface{} {
	return map[string]interface{}{
		"tool": tool,
		"arguments": map[string]interface{}{
			"service": service,
			"method":  method,
			"path":    path,
		},
	}
}

func doPolicyToolCall(h http.Handler, body interface{}) *httptest.ResponseRecorder {
	return doRequest(h, http.MethodPost, "/api/v1/mcp/tool-call", body)
}

func decodePolicyToolResult(t *testing.T, rr *httptest.ResponseRecorder) mcp.ToolCallResult {
	t.Helper()
	var result mcp.ToolCallResult
	if err := json.NewDecoder(rr.Body).Decode(&result); err != nil {
		t.Fatalf("decode tool result: %v", err)
	}
	return result
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestDispatch_NoPolicy_ProxyReached verifies that when a service has no policy
// (zero Policy), the call passes through to the proxy (HandleAPICall is invoked).
func TestDispatch_NoPolicy_ProxyReached(t *testing.T) {
	rp := &recordingProxy{
		response: &proxy.APICallResponse{StatusCode: 200, Body: `{"ok":true}`},
	}
	svc := services.Service{
		Name:   "stripe",
		Type:   "http_proxy",
		Target: "https://api.stripe.com",
		Inject: "header",
	}
	h := newPolicyHandler(rp, svc, policy.Policy{}) // zero policy

	rr := doPolicyToolCall(h, policyToolCallBody("straylight_api_call", "stripe", "GET", "/v1/charges"))
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}
	result := decodePolicyToolResult(t, rr)
	if result.IsError {
		t.Errorf("zero policy: expected success, got error: %s", result.Content[0].Text)
	}
	if rp.calls != 1 {
		t.Errorf("zero policy: expected proxy called once, got %d", rp.calls)
	}
}

// TestDispatch_DeniedMethod_ProxyNotReached verifies that a method denied by policy
// returns an isError result and the proxy's HandleAPICall is NEVER invoked.
func TestDispatch_DeniedMethod_ProxyNotReached(t *testing.T) {
	rp := &recordingProxy{
		response: &proxy.APICallResponse{StatusCode: 200, Body: `{"ok":true}`},
	}
	svc := services.Service{
		Name:   "stripe",
		Type:   "http_proxy",
		Target: "https://api.stripe.com",
		Inject: "header",
	}
	pol := policy.Policy{AllowedMethods: []string{"GET"}}
	h := newPolicyHandler(rp, svc, pol)

	rr := doPolicyToolCall(h, policyToolCallBody("straylight_api_call", "stripe", "DELETE", "/v1/charges/ch_1"))
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}
	result := decodePolicyToolResult(t, rr)
	if !result.IsError {
		t.Errorf("denied method: expected isError=true, got false")
	}
	if !strings.Contains(result.Content[0].Text, "blocked by policy") {
		t.Errorf("expected 'blocked by policy' in error message, got: %s", result.Content[0].Text)
	}
	if rp.calls != 0 {
		t.Errorf("denied method: proxy must NOT be called, got %d calls", rp.calls)
	}
}

// TestDispatch_DeniedPath_ProxyNotReached verifies that a non-matching path prefix
// returns an isError result and the proxy is not invoked.
func TestDispatch_DeniedPath_ProxyNotReached(t *testing.T) {
	rp := &recordingProxy{
		response: &proxy.APICallResponse{StatusCode: 200, Body: `{"ok":true}`},
	}
	svc := services.Service{
		Name:   "stripe",
		Type:   "http_proxy",
		Target: "https://api.stripe.com",
		Inject: "header",
	}
	pol := policy.Policy{AllowedPathPrefixes: []string{"/v1/charges"}}
	h := newPolicyHandler(rp, svc, pol)

	rr := doPolicyToolCall(h, policyToolCallBody("straylight_api_call", "stripe", "GET", "/v1/refunds"))
	result := decodePolicyToolResult(t, rr)
	if !result.IsError {
		t.Errorf("denied path: expected isError=true, got false")
	}
	if !strings.Contains(result.Content[0].Text, "blocked by policy") {
		t.Errorf("expected 'blocked by policy' in error message, got: %s", result.Content[0].Text)
	}
	if rp.calls != 0 {
		t.Errorf("denied path: proxy must NOT be called, got %d calls", rp.calls)
	}
}

// TestDispatch_AllowedCall_ProxyReached verifies that a fully-matching request
// passes the policy gate and reaches the proxy.
func TestDispatch_AllowedCall_ProxyReached(t *testing.T) {
	rp := &recordingProxy{
		response: &proxy.APICallResponse{StatusCode: 200, Body: `{"id":"ch_1"}`},
	}
	svc := services.Service{
		Name:   "stripe",
		Type:   "http_proxy",
		Target: "https://api.stripe.com",
		Inject: "header",
	}
	pol := policy.Policy{
		AllowedMethods:      []string{"GET"},
		AllowedPathPrefixes: []string{"/v1/charges"},
	}
	h := newPolicyHandler(rp, svc, pol)

	rr := doPolicyToolCall(h, policyToolCallBody("straylight_api_call", "stripe", "GET", "/v1/charges/ch_1"))
	result := decodePolicyToolResult(t, rr)
	if result.IsError {
		t.Errorf("allowed call: expected success, got error: %s", result.Content[0].Text)
	}
	if rp.calls != 1 {
		t.Errorf("allowed call: expected proxy called once, got %d", rp.calls)
	}
}

// TestDispatch_PolicyDenied_AuditEmitted verifies that a policy denial emits
// a policy_denied audit event with the correct type and no credential material.
func TestDispatch_PolicyDenied_AuditEmitted(t *testing.T) {
	rp := &recordingProxy{
		response: &proxy.APICallResponse{StatusCode: 200, Body: `{"ok":true}`},
	}
	svc := services.Service{
		Name:   "stripe",
		Type:   "http_proxy",
		Target: "https://api.stripe.com",
		Inject: "header",
	}
	pol := policy.Policy{AllowedMethods: []string{"GET"}}
	resolver := &mockServiceListWithPolicy{
		list:     []services.Service{svc},
		policies: map[string]policy.Policy{"stripe": pol},
	}
	ac := &auditCapture{}
	h := mcp.NewHandler(rp, resolver)
	h.SetPolicy(policy.New(), resolver)
	h.SetAudit(ac)

	doPolicyToolCall(h, policyToolCallBody("straylight_api_call", "stripe", "DELETE", "/v1/charges/ch_1"))

	found := false
	for _, ev := range ac.events {
		if ev.Type == audit.EventPolicyDenied {
			found = true
			if ev.Service != "stripe" {
				t.Errorf("audit event service: want stripe, got %s", ev.Service)
			}
		}
	}
	if !found {
		t.Errorf("expected a policy_denied audit event, got events: %v", ac.events)
	}
}
