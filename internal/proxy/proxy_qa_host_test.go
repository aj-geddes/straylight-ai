// Package proxy_test — QA Finding 2: AllowedHosts policy dimension is never
// evaluated at the proxy HandleAPICall seam because policy.Request.Host=""
// (the host is not populated from svc.Target).
//
// RED: tests FAIL before the fix because:
//   - HandleAPICall creates policy.Request{Host: ""} so matchHost always returns false
//   - a service with AllowedHosts=["api.stripe.com"] denies every call even though
//     the Target IS https://api.stripe.com
package proxy_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/straylight-ai/straylight/internal/egress"
	"github.com/straylight-ai/straylight/internal/policy"
	"github.com/straylight-ai/straylight/internal/proxy"
	"github.com/straylight-ai/straylight/internal/services"
)

// ---------------------------------------------------------------------------
// Test 1: AllowedHosts set to the service target host → request ALLOWED.
// BEFORE FIX: fails because Host="" → denied ("host not permitted").
// AFTER FIX: Host="<ts.URL host>" → allowed.
// ---------------------------------------------------------------------------

func TestProxy_Policy_AllowedHosts_TargetHost_Allowed(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer ts.Close()

	// Extract the host from the test server URL.
	tsHost := strings.TrimPrefix(ts.URL, "http://")
	// tsHost is "127.0.0.1:<port>" — just the host part for AllowedHosts.
	host, _, _ := strings.Cut(tsHost, ":")
	if host == "" {
		host = "127.0.0.1"
	}
	// Use the full host:port as the AllowedHosts entry to match exactly.
	// The policy engine uses the hostname from the URL (without port) in practice;
	// in the test we use the test server host portion.
	// The fix parses svc.Target and uses u.Hostname() which strips the port.
	_ = host // host is "127.0.0.1"

	resolver := newFakeResolver()
	svc := services.Service{
		Name:   "stripe",
		Type:   "http_proxy",
		Target: ts.URL, // e.g. http://127.0.0.1:PORT
		Inject: "header",
		// AllowedHosts must match the hostname of svc.Target.
		// After fix, HandleAPICall parses Target and sets Host = u.Hostname().
		Policy: &services.ToolPolicy{
			AllowedHosts: []string{"127.0.0.1"},
		},
	}
	resolver.addService(svc, "tok")

	p := newProxyWithPolicy(resolver, policy.New())
	p.SetHTTPClient(ts.Client())

	resp, err := p.HandleAPICall(context.Background(), proxy.APICallRequest{
		Service: "stripe",
		Method:  "GET",
		Path:    "/v1/charges",
	})
	if err != nil {
		t.Fatalf("AllowedHosts match: expected success, got: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// Test 2: AllowedHosts that does NOT match the service target → DENIED.
// This confirms the policy gate is active after the fix.
// ---------------------------------------------------------------------------

func TestProxy_Policy_AllowedHosts_NonMatchingHost_Denied(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer ts.Close()

	resolver := newFakeResolver()
	svc := services.Service{
		Name:   "stripe",
		Type:   "http_proxy",
		Target: ts.URL, // target host is 127.0.0.1
		Inject: "header",
		// AllowedHosts restricts to api.stripe.com — NOT the 127.0.0.1 test server.
		Policy: &services.ToolPolicy{
			AllowedHosts: []string{"api.stripe.com"},
		},
	}
	resolver.addService(svc, "tok")

	p := newProxyWithPolicy(resolver, policy.New())
	p.SetHTTPClient(ts.Client())

	_, err := p.HandleAPICall(context.Background(), proxy.APICallRequest{
		Service: "stripe",
		Method:  "GET",
		Path:    "/v1/charges",
	})
	if err == nil {
		t.Fatal("AllowedHosts mismatch: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "blocked by policy") {
		t.Errorf("expected 'blocked by policy', got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Test 3: AllowedHosts-only policy (no methods/paths) + matching host → ALLOWED.
// ---------------------------------------------------------------------------

func TestProxy_Policy_AllowedHosts_OnlyDimension_Allowed(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"id":"ch_1"}`))
	}))
	defer ts.Close()

	resolver := newFakeResolver()
	svc := services.Service{
		Name:   "svc",
		Type:   "http_proxy",
		Target: ts.URL,
		Inject: "header",
		// Host-only policy: any method/path is allowed as long as host matches.
		Policy: &services.ToolPolicy{
			AllowedHosts: []string{"127.0.0.1"},
		},
	}
	resolver.addService(svc, "tok")

	p := newProxyWithPolicy(resolver, policy.New())
	p.SetHTTPClient(ts.Client())

	resp, err := p.HandleAPICall(context.Background(), proxy.APICallRequest{
		Service: "svc",
		Method:  "DELETE",
		Path:    "/anything",
	})
	if err != nil {
		t.Fatalf("host-only policy with matching host: expected success, got: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// Test 4: AllowedHosts with a real-world domain target (uses a real URL as
// Target to verify u.Hostname() extracts correctly — no live call is made
// because we deny before the dial).
// ---------------------------------------------------------------------------

func TestProxy_Policy_AllowedHosts_RealWorldTargetDomain_Denied(t *testing.T) {
	// Don't make a live network call. We only need to confirm the policy gate
	// fires with Host="api.stripe.com" when Target="https://api.stripe.com" and
	// AllowedHosts=["api.other.com"].
	resolver := newFakeResolver()
	svc := services.Service{
		Name:   "stripe",
		Type:   "http_proxy",
		Target: "https://api.stripe.com",
		Inject: "header",
		Policy: &services.ToolPolicy{
			AllowedHosts: []string{"api.other.com"},
		},
	}
	resolver.addService(svc, "tok")

	p := proxy.NewProxyWithGuard(resolver, nil, egress.New())
	p.SetPolicy(policy.New())

	_, err := p.HandleAPICall(context.Background(), proxy.APICallRequest{
		Service: "stripe",
		Method:  "GET",
		Path:    "/v1/charges",
	})
	if err == nil {
		t.Fatal("expected 'blocked by policy' error for non-matching host")
	}
	if !strings.Contains(err.Error(), "blocked by policy") {
		t.Errorf("expected 'blocked by policy' in error, got: %v", err)
	}
}
