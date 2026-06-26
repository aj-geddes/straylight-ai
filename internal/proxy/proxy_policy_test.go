package proxy_test

// proxy_policy_test.go verifies the authoritative pre-injection policy re-check
// at the HandleAPICall seam. The policy engine runs BEFORE credential injection;
// a denied call must never reach the injector or the upstream HTTP client.

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

// credCallTracker wraps a fakeResolver and records GetCredential calls so tests
// can assert that credential injection never happens on a denied call.
type credCallTracker struct {
	*fakeResolver
	credCallCount int
}

func newCredCallTracker() *credCallTracker {
	return &credCallTracker{fakeResolver: newFakeResolver()}
}

func (t *credCallTracker) GetCredential(name string) (string, error) {
	t.credCallCount++
	return t.fakeResolver.GetCredential(name)
}

// newProxyWithPolicy returns a Proxy wired with the given policy engine and an
// allow-loopback egress guard (for httptest server calls).
func newProxyWithPolicy(resolver proxy.ServiceResolver, eng policy.Engine) *proxy.Proxy {
	guard := egress.New()
	p := proxy.NewProxyWithGuard(resolver, nil, guard)
	p.SetPolicy(eng)
	return p
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestProxy_PolicyDenied_CredentialNotInjected verifies that HandleAPICall with a
// denied method returns an error BEFORE any credential is fetched (GetCredential
// not called) and that no upstream request is made.
func TestProxy_PolicyDenied_CredentialNotInjected(t *testing.T) {
	// Start a test server to detect if any upstream call reaches it.
	upstreamCalls := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls++
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	tracker := newCredCallTracker()
	svc := services.Service{
		Name:   "stripe",
		Type:   "http_proxy",
		Target: ts.URL,
		Inject: "header",
		Policy: &services.ToolPolicy{AllowedMethods: []string{"GET"}},
	}
	tracker.addService(svc, "sk_test_secret")

	p := newProxyWithPolicy(tracker, policy.New())
	p.SetHTTPClient(ts.Client()) // allow loopback calls in tests

	_, err := p.HandleAPICall(context.Background(), proxy.APICallRequest{
		Service: "stripe",
		Method:  "DELETE",
		Path:    "/v1/charges/ch_1",
	})

	if err == nil {
		t.Fatal("expected error on denied method, got nil")
	}
	if !strings.Contains(err.Error(), "blocked by policy") {
		t.Errorf("expected 'blocked by policy' in error, got: %v", err)
	}
	if tracker.credCallCount > 0 {
		t.Errorf("credential must NOT be fetched on denied call, got %d calls", tracker.credCallCount)
	}
	if upstreamCalls > 0 {
		t.Errorf("upstream must NOT be called on denied call, got %d calls", upstreamCalls)
	}
}

// TestProxy_PolicyAllowed_RequestProceeds verifies that an allowed method passes
// the policy gate and the upstream request is made.
func TestProxy_PolicyAllowed_RequestProceeds(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"id":"ch_1"}`)) //nolint:errcheck
	}))
	defer ts.Close()

	resolver := newFakeResolver()
	svc := services.Service{
		Name:   "stripe",
		Type:   "http_proxy",
		Target: ts.URL,
		Inject: "header",
		Policy: &services.ToolPolicy{AllowedMethods: []string{"GET"}},
	}
	resolver.addService(svc, "sk_test_secret")

	p := newProxyWithPolicy(resolver, policy.New())
	p.SetHTTPClient(ts.Client())

	resp, err := p.HandleAPICall(context.Background(), proxy.APICallRequest{
		Service: "stripe",
		Method:  "GET",
		Path:    "/v1/charges/ch_1",
	})

	if err != nil {
		t.Fatalf("allowed call: unexpected error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("allowed call: expected 200, got %d", resp.StatusCode)
	}
}

// TestProxy_NilPolicy_BackwardCompat verifies that services with Policy==nil
// are unaffected (default-allow, existing tests keep working).
func TestProxy_NilPolicy_BackwardCompat(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"ok":true}`)) //nolint:errcheck
	}))
	defer ts.Close()

	resolver := newFakeResolver()
	svc := services.Service{
		Name:   "stripe",
		Type:   "http_proxy",
		Target: ts.URL,
		Inject: "header",
		// Policy: nil — no policy configured
	}
	resolver.addService(svc, "sk_test_secret")

	p := newProxyWithPolicy(resolver, policy.New())
	p.SetHTTPClient(ts.Client())

	resp, err := p.HandleAPICall(context.Background(), proxy.APICallRequest{
		Service: "stripe",
		Method:  "DELETE",
		Path:    "/v1/charges/ch_1",
	})

	if err != nil {
		t.Fatalf("nil policy: unexpected error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("nil policy: expected 200, got %d", resp.StatusCode)
	}
}
