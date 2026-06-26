// Package mcp_test — QA Finding 2: AllowedHosts dimension is never evaluated
// because policy.Request.Host is left "" at both evaluation seams.
//
// These tests exercise the MCP dispatch seam (evaluatePolicyGate).
// The proxy seam is tested in internal/proxy/proxy_qa_host_test.go.
//
// RED: these tests FAIL before the fix because:
//   - evaluatePolicyGate does not populate polReq.Host from the service target
//   - matchHost("", "api.stripe.com") is always false
//   - a service with AllowedHosts=["api.stripe.com"] denies every call
package mcp_test

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/straylight-ai/straylight/internal/mcp"
	"github.com/straylight-ai/straylight/internal/policy"
	"github.com/straylight-ai/straylight/internal/proxy"
	"github.com/straylight-ai/straylight/internal/services"
)

// policyHostResolver implements mcp.ServiceLister + mcp.PolicyResolver and
// returns the service Target so the gate can extract the host.
type policyHostResolver struct {
	svc services.Service
	pol policy.Policy
}

func (r *policyHostResolver) List() []services.Service                 { return []services.Service{r.svc} }
func (r *policyHostResolver) CheckCredential(_ string) (string, error) { return "available", nil }
func (r *policyHostResolver) PolicyFor(_ string) policy.Policy         { return r.pol }
func (r *policyHostResolver) TargetHostFor(_ string) string {
	u, err := url.Parse(r.svc.Target)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// countingProxy counts HandleAPICall calls (used to confirm proxy is/isn't reached).
type countingProxy struct {
	calls int
}

func (cp *countingProxy) HandleAPICall(_ context.Context, _ proxy.APICallRequest) (*proxy.APICallResponse, error) {
	cp.calls++
	return &proxy.APICallResponse{StatusCode: 200, Body: `{"ok":true}`}, nil
}

// newHostPolicyHandler wires a handler with a policy gate; the resolver holds
// the full service (including Target) so the gate can derive the host.
func newHostPolicyHandler(cp *countingProxy, svc services.Service, pol policy.Policy) *mcp.Handler {
	resolver := &policyHostResolver{svc: svc, pol: pol}
	h := mcp.NewHandler(cp, resolver)
	h.SetPolicy(policy.New(), resolver)
	return h
}

// ---------------------------------------------------------------------------
// Test 1: AllowedHosts matching the service target host → ALLOWED.
// BEFORE FIX: fails because Host="" → matchHost("","api.stripe.com")=false → denied.
// AFTER FIX: Host="api.stripe.com" → matchHost("api.stripe.com","api.stripe.com")=true → allowed.
// ---------------------------------------------------------------------------

func TestDispatch_AllowedHosts_MatchesTargetHost_Allowed(t *testing.T) {
	cp := &countingProxy{}
	svc := services.Service{
		Name:   "stripe",
		Type:   "http_proxy",
		Target: "https://api.stripe.com",
		Inject: "header",
	}
	// Only AllowedHosts is set — methods and paths are unrestricted.
	pol := policy.Policy{AllowedHosts: []string{"api.stripe.com"}}
	h := newHostPolicyHandler(cp, svc, pol)

	rr := doPolicyToolCall(h, policyToolCallBody("straylight_api_call", "stripe", "GET", "/v1/charges"))
	if rr.Code != 200 {
		t.Fatalf("expected HTTP 200, got %d", rr.Code)
	}
	result := decodePolicyToolResult(t, rr)
	if result.IsError {
		t.Errorf("AllowedHosts match: expected success, got error: %s", result.Content[0].Text)
	}
	if cp.calls != 1 {
		t.Errorf("AllowedHosts match: proxy should be called once, got %d calls", cp.calls)
	}
}

// ---------------------------------------------------------------------------
// Test 2: AllowedHosts that does NOT match the service target host → DENIED.
// ---------------------------------------------------------------------------

func TestDispatch_AllowedHosts_NoMatchTargetHost_Denied(t *testing.T) {
	cp := &countingProxy{}
	svc := services.Service{
		Name:   "stripe",
		Type:   "http_proxy",
		Target: "https://api.stripe.com",
		Inject: "header",
	}
	// Target is api.stripe.com but we only allow api.other.com → deny.
	pol := policy.Policy{AllowedHosts: []string{"api.other.com"}}
	h := newHostPolicyHandler(cp, svc, pol)

	rr := doPolicyToolCall(h, policyToolCallBody("straylight_api_call", "stripe", "GET", "/v1/charges"))
	if rr.Code != 200 {
		t.Fatalf("expected HTTP 200 envelope, got %d", rr.Code)
	}
	result := decodePolicyToolResult(t, rr)
	if !result.IsError {
		t.Errorf("AllowedHosts mismatch: expected isError=true, got false")
	}
	if len(result.Content) == 0 || !strings.Contains(result.Content[0].Text, "blocked by policy") {
		t.Errorf("expected 'blocked by policy' message, got: %v", result.Content)
	}
	if cp.calls != 0 {
		t.Errorf("AllowedHosts mismatch: proxy must NOT be called, got %d calls", cp.calls)
	}
}

// ---------------------------------------------------------------------------
// Test 3: AllowedHosts-only policy (no methods, no paths) — allowed when host matches.
// This proves an operator can restrict by host alone without method/path rules.
// ---------------------------------------------------------------------------

func TestDispatch_AllowedHosts_Only_Allowed(t *testing.T) {
	cp := &countingProxy{}
	svc := services.Service{
		Name:   "github",
		Type:   "http_proxy",
		Target: "https://api.github.com",
		Inject: "header",
	}
	// Host-only policy — any method and path is fine as long as host matches.
	pol := policy.Policy{AllowedHosts: []string{"api.github.com"}}
	h := newHostPolicyHandler(cp, svc, pol)

	rr := doPolicyToolCall(h, policyToolCallBody("straylight_api_call", "github", "POST", "/repos"))
	result := decodePolicyToolResult(t, rr)
	if result.IsError {
		t.Errorf("host-only policy with matching host: expected success, got: %s", result.Content[0].Text)
	}
	if cp.calls != 1 {
		t.Errorf("host-only policy: proxy should be called once, got %d calls", cp.calls)
	}
}
