package openapi_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

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
