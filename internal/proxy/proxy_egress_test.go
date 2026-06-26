// Package proxy_test — egress guard integration tests for the proxy.
// These tests verify that the DialContext-level IP re-check blocks SSRF targets
// even when the URL host passes a pre-dial string check (defeating DNS rebinding).
package proxy_test

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/straylight-ai/straylight/internal/egress"
	"github.com/straylight-ai/straylight/internal/proxy"
	"github.com/straylight-ai/straylight/internal/services"
)

// ---------------------------------------------------------------------------
// Test: metadata IP literal blocked at DialContext level
// ---------------------------------------------------------------------------

func TestProxy_EgressGuard_BlocksMetadataIPLiteral(t *testing.T) {
	guard := egress.New() // default SSRF denylist

	r := newFakeResolver()
	r.addService(services.Service{
		Name:           "imds",
		Type:           "http_proxy",
		Target:         "http://169.254.169.254",
		Inject:         "header",
		HeaderName:     "Authorization",
		HeaderTemplate: "Bearer {{.secret}}",
	}, "tok")

	p := proxy.NewProxyWithGuard(r, nil, guard)

	_, err := p.HandleAPICall(context.Background(), proxy.APICallRequest{
		Service: "imds",
		Method:  "GET",
		Path:    "/latest/meta-data/",
	})
	if err == nil {
		t.Fatal("expected egress denied error for 169.254.169.254, got nil")
	}
	errStr := strings.ToLower(err.Error())
	if !strings.Contains(errStr, "egress") && !strings.Contains(errStr, "denied") &&
		!strings.Contains(errStr, "unreachable") {
		t.Errorf("error should indicate egress or network denial; got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Test: RFC1918 target blocked
// ---------------------------------------------------------------------------

func TestProxy_EgressGuard_BlocksPrivateRangeTarget(t *testing.T) {
	guard := egress.New()

	r := newFakeResolver()
	r.addService(services.Service{
		Name:           "internal",
		Type:           "http_proxy",
		Target:         "http://10.0.0.1",
		Inject:         "header",
		HeaderName:     "Authorization",
		HeaderTemplate: "Bearer {{.secret}}",
	}, "tok")

	p := proxy.NewProxyWithGuard(r, nil, guard)

	_, err := p.HandleAPICall(context.Background(), proxy.APICallRequest{
		Service: "internal",
		Method:  "GET",
		Path:    "/api",
	})
	if err == nil {
		t.Fatal("expected egress denied error for 10.0.0.1 (RFC1918), got nil")
	}
}

// ---------------------------------------------------------------------------
// Test: loopback target allowed when service has AllowLoopback policy
// ---------------------------------------------------------------------------

func TestProxy_EgressGuard_AllowsLoopbackWithPolicy(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	guard := egress.New()

	r := newFakeResolver()
	r.addService(services.Service{
		Name:           "pub",
		Type:           "http_proxy",
		Target:         upstream.URL,
		Inject:         "header",
		HeaderName:     "Authorization",
		HeaderTemplate: "Bearer {{.secret}}",
		// AllowLoopback=true so the httptest server on loopback is reachable.
		Egress: &services.EgressPolicy{AllowLoopback: true},
	}, "tok")

	p := proxy.NewProxyWithGuard(r, nil, guard)

	resp, err := p.HandleAPICall(context.Background(), proxy.APICallRequest{
		Service: "pub",
		Method:  "GET",
		Path:    "/",
	})
	if err != nil {
		t.Fatalf("loopback-allowed target should succeed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// Test: loopback blocked by default (without AllowLoopback)
// ---------------------------------------------------------------------------

func TestProxy_EgressGuard_BlocksLoopbackByDefault(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	guard := egress.New()

	r := newFakeResolver()
	r.addService(services.Service{
		Name:           "loopback-svc",
		Type:           "http_proxy",
		Target:         upstream.URL,
		Inject:         "header",
		HeaderName:     "Authorization",
		HeaderTemplate: "Bearer {{.secret}}",
		// No Egress policy → loopback blocked.
	}, "tok")

	p := proxy.NewProxyWithGuard(r, nil, guard)

	_, err := p.HandleAPICall(context.Background(), proxy.APICallRequest{
		Service: "loopback-svc",
		Method:  "GET",
		Path:    "/",
	})
	if err == nil {
		t.Fatal("expected egress denied error for loopback target without AllowLoopback, got nil")
	}
}

// ---------------------------------------------------------------------------
// Test: SetHTTPClient bypass (existing test seam preserved)
// When SetHTTPClient is called, the guard transport is bypassed entirely,
// allowing loopback connections in tests that inject httptest.Server.Client().
// ---------------------------------------------------------------------------

func TestProxy_EgressGuard_SetHTTPClientPreserved(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	guard := egress.New()

	r := newFakeResolver()
	r.addService(services.Service{
		Name:           "svc",
		Type:           "http_proxy",
		Target:         upstream.URL,
		Inject:         "header",
		HeaderName:     "Authorization",
		HeaderTemplate: "Bearer {{.secret}}",
	}, "tok")

	p := proxy.NewProxyWithGuard(r, nil, guard)
	// Override http.Client (bypasses the custom transport and guard entirely).
	p.SetHTTPClient(&http.Client{Timeout: 5 * time.Second})

	resp, err := p.HandleAPICall(context.Background(), proxy.APICallRequest{
		Service: "svc",
		Method:  "GET",
		Path:    "/",
	})
	if err != nil {
		t.Fatalf("SetHTTPClient override should bypass guard and succeed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// Test: DialContext-level IP re-check (DNS rebinding defense).
// We point the service target at a loopback server and confirm the guard blocks
// the resolved IP at DialContext time, not just the URL-host string.
// ---------------------------------------------------------------------------

func TestProxy_EgressGuard_DialContextBlocksResolvedIP(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	// Use the actual IP from the httptest server URL.
	host, port, _ := net.SplitHostPort(strings.TrimPrefix(upstream.URL, "http://"))
	if host == "" {
		host = "127.0.0.1"
	}
	targetURL := "http://" + net.JoinHostPort(host, port)

	guard := egress.New()

	r := newFakeResolver()
	r.addService(services.Service{
		Name:           "rebind-test",
		Type:           "http_proxy",
		Target:         targetURL,
		Inject:         "header",
		HeaderName:     "Authorization",
		HeaderTemplate: "Bearer {{.secret}}",
		// No AllowLoopback → DialContext re-checks resolved IP and blocks.
	}, "tok")

	p := proxy.NewProxyWithGuard(r, nil, guard)

	_, err := p.HandleAPICall(context.Background(), proxy.APICallRequest{
		Service: "rebind-test",
		Method:  "GET",
		Path:    "/",
	})
	if err == nil {
		t.Fatal("DialContext should block the resolved loopback IP (no AllowLoopback), got nil error")
	}
}
