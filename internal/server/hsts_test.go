package server_test

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/straylight-ai/straylight/internal/server"
)

// TestSecurityHeaders_NoHSTSOverHTTP verifies that Strict-Transport-Security is
// NOT set when the request came over plain HTTP (r.TLS == nil).
// Personal tier runs on localhost HTTP, so HSTS must not be sent.
func TestSecurityHeaders_NoHSTSOverHTTP(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mw := server.SecurityHeaders(next)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	// req.TLS is nil for a plain httptest.NewRequest — simulates HTTP.
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, req)

	if got := w.Header().Get("Strict-Transport-Security"); got != "" {
		t.Errorf("HSTS header must not be set over HTTP, got %q", got)
	}
}

// TestSecurityHeaders_HSTSPresentOverTLS verifies that Strict-Transport-Security
// IS set when the request came over TLS (r.TLS != nil).
func TestSecurityHeaders_HSTSPresentOverTLS(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mw := server.SecurityHeaders(next)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	// Simulate a TLS connection by setting a non-nil TLS state.
	req.TLS = &tls.ConnectionState{}
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, req)

	hsts := w.Header().Get("Strict-Transport-Security")
	if hsts == "" {
		t.Error("expected Strict-Transport-Security header on TLS request, got empty string")
	}
	// Verify the value contains the expected max-age.
	if hsts != "max-age=63072000; includeSubDomains" {
		t.Errorf("unexpected HSTS value: %q", hsts)
	}
}

// TestSecurityHeaders_OtherHeadersUnaffectedByTLS verifies that existing security
// headers are set regardless of TLS state.
func TestSecurityHeaders_OtherHeadersUnaffectedByTLS(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mw := server.SecurityHeaders(next)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	// No TLS.
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, req)

	requiredHeaders := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
	}
	for header, want := range requiredHeaders {
		got := w.Header().Get(header)
		if got != want {
			t.Errorf("header %q: expected %q, got %q", header, want, got)
		}
	}
}
