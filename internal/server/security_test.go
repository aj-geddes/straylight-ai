package server_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/straylight-ai/straylight/internal/server"
)

// ---------------------------------------------------------------------------
// Security Headers
// ---------------------------------------------------------------------------

// TestSecurityHeaders_PresentOnAllResponses verifies that security headers are
// injected on every API response.
func TestSecurityHeaders_PresentOnAllResponses(t *testing.T) {
	srv := server.New(server.Config{
		ListenAddress: "127.0.0.1:0",
		Version:       "1.0.3",
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	requiredHeaders := map[string]string{
		"X-Content-Type-Options":    "nosniff",
		"X-Frame-Options":           "DENY",
		"Content-Security-Policy":   "default-src 'self'; img-src 'self' https://*.githubusercontent.com https://*.gravatar.com https://*.gitlab.com https://avatars.slack-edge.com https://lh3.googleusercontent.com",
		"X-Xss-Protection":          "1; mode=block",
		"Referrer-Policy":           "strict-origin-when-cross-origin",
	}

	for header, want := range requiredHeaders {
		got := w.Header().Get(header)
		if got != want {
			t.Errorf("header %q: expected %q, got %q", header, want, got)
		}
	}
}

// ---------------------------------------------------------------------------
// CORS Middleware
// ---------------------------------------------------------------------------

// TestCORS_AllowsLocalhostOrigin verifies that a request from an allowed
// localhost origin returns the correct CORS headers.
func TestCORS_AllowsLocalhostOrigin(t *testing.T) {
	srv := server.New(server.Config{
		ListenAddress: "127.0.0.1:0",
		Version:       "1.0.3",
	})

	origins := []string{
		"http://localhost:9470",
		"http://localhost:5173",
		"http://127.0.0.1:9470",
	}
	for _, origin := range origins {
		t.Run(origin, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
			req.Header.Set("Origin", origin)
			w := httptest.NewRecorder()
			srv.ServeHTTP(w, req)

			got := w.Header().Get("Access-Control-Allow-Origin")
			if got != origin {
				t.Errorf("origin %q: expected Access-Control-Allow-Origin=%q, got %q", origin, origin, got)
			}
		})
	}
}

// TestCORS_BlocksNonLocalhostOrigin verifies that a request from a disallowed
// external origin does NOT receive a permissive CORS header.
func TestCORS_BlocksNonLocalhostOrigin(t *testing.T) {
	srv := server.New(server.Config{
		ListenAddress: "127.0.0.1:0",
		Version:       "1.0.3",
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	req.Header.Set("Origin", "https://evil.example.com")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	got := w.Header().Get("Access-Control-Allow-Origin")
	if got == "*" || got == "https://evil.example.com" {
		t.Errorf("expected CORS to block evil.example.com, but got Allow-Origin=%q", got)
	}
}

// TestCORS_Preflight_Returns200 verifies that an OPTIONS preflight request
// to an allowed origin returns 200 with CORS headers and does not call the handler.
func TestCORS_Preflight_Returns200(t *testing.T) {
	srv := server.New(server.Config{
		ListenAddress: "127.0.0.1:0",
		Version:       "1.0.3",
	})

	req := httptest.NewRequest(http.MethodOptions, "/api/v1/health", nil)
	req.Header.Set("Origin", "http://localhost:9470")
	req.Header.Set("Access-Control-Request-Method", "GET")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("preflight: expected 200, got %d", w.Code)
	}
	if w.Header().Get("Access-Control-Allow-Methods") == "" {
		t.Error("preflight: expected Access-Control-Allow-Methods header to be set")
	}
}

// ---------------------------------------------------------------------------
// Rate Limiting
// ---------------------------------------------------------------------------

// TestRateLimiter_Returns429WhenExceeded verifies that sending requests beyond
// the burst limit returns HTTP 429 Too Many Requests.
func TestRateLimiter_Returns429WhenExceeded(t *testing.T) {
	// Create a server with a very tight rate limit (1 req/s, burst 1) so
	// that a second request within the same test always gets rate-limited.
	// Use VaultStatus=unsealed so health endpoint returns 200 (not 503).
	srv := server.NewWithOptions(server.Config{
		ListenAddress: "127.0.0.1:0",
		Version:       "1.0.3",
		VaultStatus:   func() string { return "unsealed" },
	}, server.Options{
		RateLimit: 1,
		Burst:     1,
	})

	// First request should succeed.
	req1 := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	w1 := httptest.NewRecorder()
	srv.ServeHTTP(w1, req1)
	if w1.Code != http.StatusOK {
		t.Fatalf("first request: expected 200, got %d", w1.Code)
	}

	// Second request immediately should be rate-limited.
	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	w2 := httptest.NewRecorder()
	srv.ServeHTTP(w2, req2)
	if w2.Code != http.StatusTooManyRequests {
		t.Errorf("second request: expected 429, got %d", w2.Code)
	}
}

// ---------------------------------------------------------------------------
// Max Body Size
// ---------------------------------------------------------------------------

// TestMaxBodySize_Returns413ForOversizedRequest verifies that a request body
// larger than 1 MB is rejected with HTTP 413.
func TestMaxBodySize_Returns413ForOversizedRequest(t *testing.T) {
	srv := server.New(server.Config{
		ListenAddress: "127.0.0.1:0",
		Version:       "1.0.3",
	})

	// Construct a body slightly over 1 MB.
	bigBody := bytes.Repeat([]byte("x"), 1<<20+1)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/services", bytes.NewReader(bigBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("expected 413 for oversized body, got %d", w.Code)
	}
}

// ---------------------------------------------------------------------------
// Input Sanitization — path traversal in service names
// ---------------------------------------------------------------------------

// TestPathTraversal_ServiceNameIsBlocked verifies that a service name
// containing path traversal characters is rejected.
func TestPathTraversal_ServiceNameIsBlocked(t *testing.T) {
	srv, _ := newTestServer()

	traversalNames := []string{
		"../etc/passwd",
		"..%2Fetc%2Fpasswd",
		"service/../etc",
		"..",
	}

	for _, name := range traversalNames {
		t.Run(name, func(t *testing.T) {
			w := postJSON(srv, "/api/v1/services", map[string]interface{}{
				"name":       name,
				"type":       "http_proxy",
				"target":     "https://api.example.com",
				"inject":     "header",
				"credential": "secret",
			})
			if w.Code == http.StatusCreated {
				t.Errorf("name %q should have been rejected (got 201)", name)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// SanitizeInput function
// ---------------------------------------------------------------------------

// TestSanitizeInput_StripControlCharacters verifies that the exported
// SanitizeInput function strips null bytes and control characters.
func TestSanitizeInput_StripControlCharacters(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"hello\x00world", "helloworld"},
		{"clean string", "clean string"},
		{"tab\there", "tab\there"},      // tab is allowed (not a control char we strip)
		{"null\x00byte", "nullbyte"},
		{"\x01\x02\x03text\x1f", "text"},
		{"newline\nok", "newline\nok"}, // newlines are kept
	}

	for _, tc := range cases {
		got := server.SanitizeInput(tc.input)
		if got != tc.want {
			t.Errorf("SanitizeInput(%q): expected %q, got %q", tc.input, tc.want, got)
		}
	}
}

// ---------------------------------------------------------------------------
// Credential Rotation
// ---------------------------------------------------------------------------

// TestRotateCredential_Returns200(t *testing.T) verifies that the rotate endpoint
// updates the credential and returns 200.
func TestRotateCredential_Returns200(t *testing.T) {
	srv, reg := newTestServer()

	// Create a service.
	postJSON(srv, "/api/v1/services", map[string]interface{}{
		"name":       "stripe",
		"type":       "http_proxy",
		"target":     "https://api.stripe.com",
		"inject":     "header",
		"credential": "old-key",
	})

	// Rotate the credential.
	b, _ := json.Marshal(map[string]string{"credential": "new-key"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/services/stripe/rotate", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("rotate: expected 200, got %d (body: %s)", w.Code, w.Body.String())
	}

	// Verify the new credential is active.
	cred, err := reg.GetCredential("stripe")
	if err != nil {
		t.Fatalf("GetCredential failed: %v", err)
	}
	if cred != "new-key" {
		t.Errorf("expected rotated credential=new-key, got %q", cred)
	}
}

// TestRotateCredential_Returns404ForUnknownService verifies that rotating a
// credential for a non-existent service returns 404.
func TestRotateCredential_Returns404ForUnknownService(t *testing.T) {
	srv, _ := newTestServer()

	b, _ := json.Marshal(map[string]string{"credential": "new-key"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/services/nonexistent/rotate", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("rotate on unknown service: expected 404, got %d", w.Code)
	}
}

// TestRotateCredential_Returns400WhenCredentialMissing verifies that an empty
// credential body is rejected.
func TestRotateCredential_Returns400WhenCredentialMissing(t *testing.T) {
	srv, _ := newTestServer()

	// Create service first.
	postJSON(srv, "/api/v1/services", map[string]interface{}{
		"name":       "stripe",
		"type":       "http_proxy",
		"target":     "https://api.stripe.com",
		"inject":     "header",
		"credential": "old-key",
	})

	b, _ := json.Marshal(map[string]string{"credential": ""})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/services/stripe/rotate", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("rotate with empty credential: expected 400, got %d", w.Code)
	}
}

// TestRotateCredential_ResponseDoesNotContainCredential verifies that the rotate
// endpoint response body never contains the credential value.
func TestRotateCredential_ResponseDoesNotContainCredential(t *testing.T) {
	srv, _ := newTestServer()

	postJSON(srv, "/api/v1/services", map[string]interface{}{
		"name":       "stripe",
		"type":       "http_proxy",
		"target":     "https://api.stripe.com",
		"inject":     "header",
		"credential": "old-key",
	})

	b, _ := json.Marshal(map[string]string{"credential": "supersecret-new-key"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/services/stripe/rotate", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if strings.Contains(w.Body.String(), "supersecret-new-key") {
		t.Error("rotate response contains the raw credential value")
	}
}

// ---------------------------------------------------------------------------
// Malformed JSON handling
// ---------------------------------------------------------------------------

// TestMalformedJSON_DoesNotCrashServer verifies that sending malformed JSON to
// a POST endpoint returns 400 and the server remains functional.
func TestMalformedJSON_DoesNotCrashServer(t *testing.T) {
	srv, _ := newTestServer()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/services",
		strings.NewReader("{this is not json}"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("malformed JSON: expected 400, got %d", w.Code)
	}

	// Server must still be alive — verify by listing services (always 200 with registry).
	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/services", nil)
	w2 := httptest.NewRecorder()
	srv.ServeHTTP(w2, req2)
	if w2.Code != http.StatusOK {
		t.Errorf("server unresponsive after malformed JSON: got %d", w2.Code)
	}
}

// ---------------------------------------------------------------------------
// RegistryRotateCredential unit
// ---------------------------------------------------------------------------

// TestRegistryRotateCredential_UpdatesVault verifies the Registry.RotateCredential
// method updates the vault credential directly.
func TestRegistryRotateCredential_UpdatesVault(t *testing.T) {
	vault := newMockVaultForRoutes()
	reg := newRegistryWithVault(vault)

	// Seed a service.
	if err := reg.Create(validService("myapi"), "initial-secret"); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Rotate.
	if err := reg.RotateCredential("myapi", "rotated-secret"); err != nil {
		t.Fatalf("RotateCredential: %v", err)
	}

	cred, err := reg.GetCredential("myapi")
	if err != nil {
		t.Fatalf("GetCredential: %v", err)
	}
	if cred != "rotated-secret" {
		t.Errorf("expected credential=rotated-secret, got %q", cred)
	}
}

// TestRegistryRotateCredential_Returns404ForMissing verifies that rotating
// a credential for a non-existent service returns an error.
func TestRegistryRotateCredential_Returns404ForMissing(t *testing.T) {
	vault := newMockVaultForRoutes()
	reg := newRegistryWithVault(vault)

	err := reg.RotateCredential("nonexistent", "new-secret")
	if err == nil {
		t.Error("expected error rotating credential for nonexistent service, got nil")
	}
}
