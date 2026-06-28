package openapi_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/straylight-ai/straylight/internal/egress"
	"github.com/straylight-ai/straylight/internal/openapi"
)

// TestFetchSpec_InternalHostRejected verifies that fetching a spec from a loopback/
// internal host is rejected by the egress Guard before any dial occurs.
func TestFetchSpec_InternalHostRejected(t *testing.T) {
	// httptest.NewServer binds to 127.0.0.1; egress.New() denies loopback.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"openapi":"3.1.0"}`))
	}))
	defer server.Close()

	guard := egress.New() // default guard denies loopback IPs

	_, err := openapi.FetchSpec(context.Background(), guard, server.URL)
	if err == nil {
		t.Fatal("expected error when fetching from loopback host (egress.New denies 127.0.0.1)")
	}
}

// TestFetchSpec_FetchesContent verifies that FetchSpec returns the raw body when
// the Guard permits the host.
func TestFetchSpec_FetchesContent(t *testing.T) {
	expected := `{"openapi":"3.1.0","info":{"title":"Test","version":"1.0.0"},"paths":{}}`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(expected))
	}))
	defer server.Close()

	guard := egress.AllowAll() // allows all hosts including loopback

	got, err := openapi.FetchSpec(context.Background(), guard, server.URL)
	if err != nil {
		t.Fatalf("FetchSpec() error = %v", err)
	}
	if string(got) != expected {
		t.Errorf("expected %q, got %q", expected, string(got))
	}
}

// TestFetchSpec_OversizedResponseRejected verifies that a response exceeding the size
// cap (10 MiB) is rejected with an error.
func TestFetchSpec_OversizedResponseRejected(t *testing.T) {
	large := make([]byte, 11*1024*1024) // 11 MiB
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(large)
	}))
	defer server.Close()

	guard := egress.AllowAll()

	_, err := openapi.FetchSpec(context.Background(), guard, server.URL)
	if err == nil {
		t.Fatal("expected error for oversized spec (> 10 MiB)")
	}
}

// TestFetchSpec_HTTPErrorRejected verifies that a non-2xx HTTP response is an error.
func TestFetchSpec_HTTPErrorRejected(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	guard := egress.AllowAll()

	_, err := openapi.FetchSpec(context.Background(), guard, server.URL)
	if err == nil {
		t.Fatal("expected error for HTTP 404 response")
	}
}

// TestFetchSpec_RedirectToLoopbackRejected verifies the SSRF-via-redirect attack is
// blocked. The guard is AllowAll so the initial URL passes pre-check; the
// redirect destination (127.0.0.1) must be caught by the client's CheckRedirect
// or the DialContext guard, not the pre-flight host check.
func TestFetchSpec_RedirectToLoopbackRejected(t *testing.T) {
	// contentServer simulates the SSRF target on 127.0.0.1.
	contentServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"secret":"internal-data"}`))
	}))
	defer contentServer.Close()

	u, err := url.Parse(contentServer.URL)
	if err != nil {
		t.Fatalf("parse content server URL: %v", err)
	}
	port := u.Port()

	// redirectServer returns 302 → 127.0.0.1:<port>.
	redirectServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, fmt.Sprintf("http://127.0.0.1:%s/internal", port), http.StatusFound)
	}))
	defer redirectServer.Close()

	// AllowAll: initial URL passes. The fix must catch the redirect destination.
	guard := egress.AllowAll()

	_, err = openapi.FetchSpec(context.Background(), guard, redirectServer.URL)
	if err == nil {
		t.Fatal("FetchSpec followed a 302 redirect to 127.0.0.1 without error — SSRF via redirect is possible with the current implementation")
	}
}

// TestFetchSpec_RedirectToInternalIPRejected verifies that a 302 redirect to an
// RFC1918 address (10.0.0.1) is blocked — the redirect must not be followed.
// A short context timeout bounds the test in case the fix tries to dial anyway.
func TestFetchSpec_RedirectToInternalIPRejected(t *testing.T) {
	redirectServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://10.0.0.1/metadata", http.StatusFound)
	}))
	defer redirectServer.Close()

	guard := egress.AllowAll()

	// 3s deadline: the fix must reject the redirect immediately, not time out dialing.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, err := openapi.FetchSpec(ctx, guard, redirectServer.URL)
	if err == nil {
		t.Fatal("FetchSpec must return an error: redirect to RFC1918 10.0.0.1 must be blocked before any dial completes")
	}
}
