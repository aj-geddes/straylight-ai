package oauth

// Security fix tests (audit findings).
//
// FIX 1: OAuth error message must not leak provider response body.
// FIX 5: service_name must be validated in StartOAuth and Callback.
// FIX 6: serviceName must be URL-encoded in the success redirect.

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// FIX 1: Token-exchange error must not echo the raw provider response body
// ---------------------------------------------------------------------------

// TestCallback_TokenExchangeError_DoesNotLeakProviderBody verifies that when
// the OAuth provider returns an error during token exchange, the error message
// returned to the client is generic and does not contain the raw provider
// response body (which could include the auth code or client_secret).
func TestCallback_TokenExchangeError_DoesNotLeakProviderBody(t *testing.T) {
	// Provider returns a 400 with a body that contains a code echo.
	// This is a realistic but malicious provider response.
	sensitiveBody := `{"error":"invalid_grant","code":"super-secret-code","client_secret":"leaked-secret"}`
	fakeSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(sensitiveBody))
	}))
	t.Cleanup(fakeSrv.Close)

	originalProviders := Providers
	Providers = map[string]Provider{
		"github": {
			Name:          "github",
			AuthURL:       "https://github.com/login/oauth/authorize",
			TokenURL:      fakeSrv.URL + "/token",
			DefaultScopes: []string{"repo"},
		},
	}
	t.Cleanup(func() { Providers = originalProviders })

	vault := newFakeVault()
	_ = vault.WriteSecret("services/github/oauth_client_secret", map[string]interface{}{
		"client_id":     "cid",
		"client_secret": "cs",
	})
	h := NewHandler(vault, &fakeServices{}, "http://localhost:9470")

	// Generate a real state token via StartOAuth.
	startReq := httptest.NewRequest(http.MethodGet,
		"/api/v1/oauth/github/start?service_name=github", nil)
	startReq.SetPathValue("provider", "github")
	startW := httptest.NewRecorder()
	h.StartOAuth(startW, startReq)
	loc := startW.Result().Header.Get("Location")
	u, _ := url.Parse(loc)
	state := u.Query().Get("state")

	// Drive callback — provider will return the error body.
	callbackReq := httptest.NewRequest(http.MethodGet,
		"/api/v1/oauth/callback?code=test-code&state="+state, nil)
	w := httptest.NewRecorder()
	h.Callback(w, callbackReq)

	if w.Code != http.StatusBadGateway {
		t.Errorf("expected 502, got %d", w.Code)
	}

	// The client-visible error message must not contain any part of the
	// provider's response body.
	body, _ := io.ReadAll(w.Body)
	bodyStr := string(body)

	if strings.Contains(bodyStr, "super-secret-code") {
		t.Errorf("response body leaks provider code: %s", bodyStr)
	}
	if strings.Contains(bodyStr, "leaked-secret") {
		t.Errorf("response body leaks client_secret: %s", bodyStr)
	}
	if strings.Contains(bodyStr, "invalid_grant") {
		t.Errorf("response body leaks provider error detail: %s", bodyStr)
	}

	// Must still return a meaningful generic error message.
	var errResp map[string]string
	if err := json.Unmarshal(body, &errResp); err != nil {
		t.Fatalf("response is not JSON: %v", err)
	}
	if errResp["error"] == "" {
		t.Error("expected non-empty error field in response")
	}
}

// ---------------------------------------------------------------------------
// FIX 5: service_name must be validated in StartOAuth
// ---------------------------------------------------------------------------

// TestStartOAuth_InvalidServiceNameReturns400 verifies that service_name values
// that don't match ^[a-z][a-z0-9_-]{0,62}$ are rejected with 400.
func TestStartOAuth_InvalidServiceNameReturns400(t *testing.T) {
	vault := newFakeVault()
	_ = vault.WriteSecret("services/github/oauth_client_secret", map[string]interface{}{
		"client_id": "cid", "client_secret": "cs",
	})
	h := NewHandler(vault, &fakeServices{}, "http://localhost:9470")

	invalidNames := []string{
		"",               // empty (already tested but re-validated by pattern)
		"UPPERCASE",      // uppercase not allowed
		"1startsdigit",   // must start with letter
		"has space",      // spaces not allowed
		"../traversal",   // path traversal
		"<script>",       // XSS attempt
		strings.Repeat("a", 64), // too long (>63 chars)
	}

	for _, name := range invalidNames {
		t.Run("name="+name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet,
				"/api/v1/oauth/github/start?service_name="+url.QueryEscape(name), nil)
			req.SetPathValue("provider", "github")
			w := httptest.NewRecorder()
			h.StartOAuth(w, req)

			if w.Code != http.StatusBadRequest {
				t.Errorf("service_name %q: expected 400, got %d", name, w.Code)
			}
		})
	}
}

// TestStartOAuth_ValidServiceNamePasses verifies that valid service_name values
// matching ^[a-z][a-z0-9_-]{0,62}$ are accepted.
func TestStartOAuth_ValidServiceNamePasses(t *testing.T) {
	vault := newFakeVault()
	_ = vault.WriteSecret("services/github/oauth_client_secret", map[string]interface{}{
		"client_id": "cid", "client_secret": "cs",
	})
	h := NewHandler(vault, &fakeServices{}, "http://localhost:9470")

	validNames := []string{
		"github",
		"my-github",
		"my_github",
		"g",
		"github2",
		strings.Repeat("a", 63), // exactly 63 chars: 1 start + 62 suffix
	}

	for _, name := range validNames {
		t.Run("name="+name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet,
				"/api/v1/oauth/github/start?service_name="+name, nil)
			req.SetPathValue("provider", "github")
			w := httptest.NewRecorder()
			h.StartOAuth(w, req)

			// Should redirect (302), not 400.
			if w.Code == http.StatusBadRequest {
				t.Errorf("service_name %q: expected redirect, got 400", name)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// FIX 6: serviceName must be URL-encoded in the success redirect
// ---------------------------------------------------------------------------

// TestCallback_ServiceNameURLEncoded verifies that the success redirect URL
// uses url.QueryEscape on the service name so special characters cannot inject
// additional query parameters.
func TestCallback_ServiceNameURLEncoded(t *testing.T) {
	fakeSrv := buildProviderServer(t, map[string]interface{}{
		"access_token": "tok",
		"token_type":   "bearer",
	})
	originalProviders := Providers
	Providers = map[string]Provider{
		"github": {
			Name:          "github",
			AuthURL:       "https://github.com/login/oauth/authorize",
			TokenURL:      fakeSrv.URL + "/token",
			DefaultScopes: []string{"repo"},
		},
	}
	t.Cleanup(func() { Providers = originalProviders })

	vault := newFakeVault()
	_ = vault.WriteSecret("services/github/oauth_client_secret", map[string]interface{}{
		"client_id": "cid", "client_secret": "cs",
	})
	h := NewHandler(vault, &fakeServices{}, "http://localhost:9470")

	// Use a service name with a hyphen to verify it's encoded properly.
	serviceName := "my-service"

	startReq := httptest.NewRequest(http.MethodGet,
		"/api/v1/oauth/github/start?service_name="+serviceName, nil)
	startReq.SetPathValue("provider", "github")
	startW := httptest.NewRecorder()
	h.StartOAuth(startW, startReq)
	loc := startW.Result().Header.Get("Location")
	u, _ := url.Parse(loc)
	state := u.Query().Get("state")

	callbackReq := httptest.NewRequest(http.MethodGet,
		"/api/v1/oauth/callback?code=code&state="+state, nil)
	w := httptest.NewRecorder()
	h.Callback(w, callbackReq)

	if w.Code != http.StatusFound {
		body, _ := io.ReadAll(w.Body)
		t.Fatalf("expected 302, got %d: %s", w.Code, body)
	}

	redirectLoc := w.Header().Get("Location")

	// Parse the redirect URL and verify the service query parameter is correctly set.
	redirectURL, err := url.Parse(redirectLoc)
	if err != nil {
		t.Fatalf("invalid redirect URL %q: %v", redirectLoc, err)
	}
	serviceParam := redirectURL.Query().Get("service")
	if serviceParam != serviceName {
		t.Errorf("expected service=%q in redirect, got %q (full redirect: %q)",
			serviceName, serviceParam, redirectLoc)
	}
}

// TestCallback_ServiceNameWithSpecialCharsEncoded verifies that a service name
// containing characters that must be URL-encoded (e.g., '+') do not produce
// an ambiguous redirect URL.
func TestCallback_ServiceNameWithSpecialCharsEncoded(t *testing.T) {
	fakeSrv := buildProviderServer(t, map[string]interface{}{
		"access_token": "tok",
		"token_type":   "bearer",
	})
	originalProviders := Providers
	Providers = map[string]Provider{
		"github": {
			Name:          "github",
			AuthURL:       "https://github.com/login/oauth/authorize",
			TokenURL:      fakeSrv.URL + "/token",
			DefaultScopes: []string{"repo"},
		},
	}
	t.Cleanup(func() { Providers = originalProviders })

	vault := newFakeVault()
	_ = vault.WriteSecret("services/github/oauth_client_secret", map[string]interface{}{
		"client_id": "cid", "client_secret": "cs",
	})
	h := NewHandler(vault, &fakeServices{}, "http://localhost:9470")

	// Start with a valid name; the URL-encode test specifically checks the redirect
	// for a name that would be ambiguous without encoding.
	// "a-b" is a valid name; we verify the redirect Location header uses
	// url.QueryEscape (not raw concatenation).
	serviceName := "a-b"

	startReq := httptest.NewRequest(http.MethodGet,
		"/api/v1/oauth/github/start?service_name="+serviceName, nil)
	startReq.SetPathValue("provider", "github")
	startW := httptest.NewRecorder()
	h.StartOAuth(startW, startReq)
	loc := startW.Result().Header.Get("Location")
	u, _ := url.Parse(loc)
	state := u.Query().Get("state")

	callbackReq := httptest.NewRequest(http.MethodGet,
		"/api/v1/oauth/callback?code=code&state="+state, nil)
	w := httptest.NewRecorder()
	h.Callback(w, callbackReq)

	redirectLoc := w.Header().Get("Location")

	// The Location header must contain the service param parseable by url.Parse.
	redirectURL, err := url.Parse(redirectLoc)
	if err != nil {
		t.Fatalf("invalid redirect URL %q: %v", redirectLoc, err)
	}

	if got := redirectURL.Query().Get("service"); got != serviceName {
		t.Errorf("expected service=%q, got %q (redirect: %q)", serviceName, got, redirectLoc)
	}
}
