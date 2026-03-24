package oauth

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/straylight-ai/straylight/internal/services"
)

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

// fakeVault is an in-memory VaultClient for tests.
type fakeVault struct {
	mu      sync.RWMutex
	secrets map[string]map[string]interface{}
	errors  map[string]error
}

func newFakeVault() *fakeVault {
	return &fakeVault{
		secrets: make(map[string]map[string]interface{}),
		errors:  make(map[string]error),
	}
}

func (f *fakeVault) WriteSecret(path string, data map[string]interface{}) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err, ok := f.errors["write:"+path]; ok {
		return err
	}
	// Deep copy to avoid mutation aliasing.
	cp := make(map[string]interface{}, len(data))
	for k, v := range data {
		cp[k] = v
	}
	f.secrets[path] = cp
	return nil
}

func (f *fakeVault) ReadSecret(path string) (map[string]interface{}, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if err, ok := f.errors["read:"+path]; ok {
		return nil, err
	}
	data, ok := f.secrets[path]
	if !ok {
		return nil, fmt.Errorf("vault: secret %q not found", path)
	}
	cp := make(map[string]interface{}, len(data))
	for k, v := range data {
		cp[k] = v
	}
	return cp, nil
}

func (f *fakeVault) DeleteSecret(path string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err, ok := f.errors["delete:"+path]; ok {
		return err
	}
	delete(f.secrets, path)
	return nil
}

// fakeServices is an in-memory ServiceUpdater for tests.
type fakeServices struct {
	mu      sync.RWMutex
	updates []serviceUpdate
	err     error
}

type serviceUpdate struct {
	name       string
	svc        services.Service
	credential *string
}

func (f *fakeServices) Update(name string, svc services.Service, credential *string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.updates = append(f.updates, serviceUpdate{name: name, svc: svc, credential: credential})
	return nil
}

func (f *fakeServices) Create(svc services.Service, credential string) error {
	return nil
}

func (f *fakeServices) Get(name string) (services.Service, error) {
	return services.Service{}, fmt.Errorf("service %q not found", name)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// buildProviderServer creates an httptest.Server that acts as a fake OAuth provider.
// It records token exchange requests and returns a configurable token response.
func buildProviderServer(t *testing.T, tokenResponse map[string]interface{}) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(tokenResponse)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// startFlow drives a StartOAuth request and returns the redirect URL.
func startFlow(t *testing.T, h *Handler, provider, serviceName string) *url.URL {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/oauth/"+provider+"/start?service_name="+serviceName, nil)
	req.SetPathValue("provider", provider)

	w := httptest.NewRecorder()
	h.StartOAuth(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusFound {
		t.Fatalf("StartOAuth: expected 302, got %d", res.StatusCode)
	}
	loc := res.Header.Get("Location")
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("StartOAuth: invalid Location header %q: %v", loc, err)
	}
	return u
}

// ---------------------------------------------------------------------------
// StartOAuth tests
// ---------------------------------------------------------------------------

func TestStartOAuth_RedirectsToProviderAuthURL(t *testing.T) {
	vault := newFakeVault()
	_ = vault.WriteSecret("services/github/oauth_client_secret", map[string]interface{}{
		"client_id":     "cid",
		"client_secret": "cs",
	})
	svcUpdater := &fakeServices{}
	h := NewHandler(vault, svcUpdater, "http://localhost:9470")

	redirectURL := startFlow(t, h, "github", "github")

	if !strings.HasPrefix(redirectURL.String(), "https://github.com/login/oauth/authorize") {
		t.Errorf("unexpected redirect URL: %s", redirectURL)
	}
}

func TestStartOAuth_IncludesClientIDInRedirect(t *testing.T) {
	vault := newFakeVault()
	// Seed the client_id in vault.
	_ = vault.WriteSecret("services/github/oauth_client_secret", map[string]interface{}{
		"client_id":     "test-client-id",
		"client_secret": "test-client-secret",
	})
	h := NewHandler(vault, &fakeServices{}, "http://localhost:9470")

	redirectURL := startFlow(t, h, "github", "github")
	q := redirectURL.Query()

	if q.Get("client_id") != "test-client-id" {
		t.Errorf("expected client_id=test-client-id in redirect, got %q", q.Get("client_id"))
	}
}

func TestStartOAuth_IncludesRedirectURI(t *testing.T) {
	vault := newFakeVault()
	_ = vault.WriteSecret("services/github/oauth_client_secret", map[string]interface{}{
		"client_id":     "cid",
		"client_secret": "cs",
	})
	h := NewHandler(vault, &fakeServices{}, "http://localhost:9470")

	redirectURL := startFlow(t, h, "github", "github")
	q := redirectURL.Query()

	expectedRedirectURI := "http://localhost:9470/api/v1/oauth/callback"
	if q.Get("redirect_uri") != expectedRedirectURI {
		t.Errorf("expected redirect_uri %q, got %q", expectedRedirectURI, q.Get("redirect_uri"))
	}
}

func TestStartOAuth_IncludesStateInRedirect(t *testing.T) {
	vault := newFakeVault()
	_ = vault.WriteSecret("services/github/oauth_client_secret", map[string]interface{}{
		"client_id":     "cid",
		"client_secret": "cs",
	})
	h := NewHandler(vault, &fakeServices{}, "http://localhost:9470")

	redirectURL := startFlow(t, h, "github", "github")
	q := redirectURL.Query()

	if q.Get("state") == "" {
		t.Error("expected state parameter in redirect, got empty string")
	}
}

func TestStartOAuth_IncludesScopesInRedirect(t *testing.T) {
	vault := newFakeVault()
	_ = vault.WriteSecret("services/github/oauth_client_secret", map[string]interface{}{
		"client_id":     "cid",
		"client_secret": "cs",
	})
	h := NewHandler(vault, &fakeServices{}, "http://localhost:9470")

	redirectURL := startFlow(t, h, "github", "github")
	q := redirectURL.Query()

	scope := q.Get("scope")
	if !strings.Contains(scope, "repo") {
		t.Errorf("expected scope to contain 'repo', got %q", scope)
	}
}

func TestStartOAuth_UnknownProviderReturns400(t *testing.T) {
	h := NewHandler(newFakeVault(), &fakeServices{}, "http://localhost:9470")

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/oauth/unknown-provider/start?service_name=svc", nil)
	req.SetPathValue("provider", "unknown-provider")

	w := httptest.NewRecorder()
	h.StartOAuth(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestStartOAuth_MissingServiceNameReturns400(t *testing.T) {
	h := NewHandler(newFakeVault(), &fakeServices{}, "http://localhost:9470")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/oauth/github/start", nil)
	req.SetPathValue("provider", "github")

	w := httptest.NewRecorder()
	h.StartOAuth(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

// ---------------------------------------------------------------------------
// Callback tests
// ---------------------------------------------------------------------------

func TestCallback_ExchangesCodeAndStoresTokensInVault(t *testing.T) {
	fakeSrv := buildProviderServer(t, map[string]interface{}{
		"access_token":  "gha_test_access_token",
		"token_type":    "bearer",
		"refresh_token": "ghr_test_refresh",
		"scope":         "repo,read:org",
	})

	// Override GitHub provider token URL for this test.
	originalProviders := Providers
	Providers = map[string]Provider{
		"github": {
			Name:          "github",
			AuthURL:       "https://github.com/login/oauth/authorize",
			TokenURL:      fakeSrv.URL + "/token",
			DefaultScopes: []string{"repo", "read:org"},
		},
	}
	t.Cleanup(func() { Providers = originalProviders })

	vault := newFakeVault()
	_ = vault.WriteSecret("services/github/oauth_client_secret", map[string]interface{}{
		"client_id":     "cid",
		"client_secret": "cs",
	})

	svcUpdater := &fakeServices{}
	h := NewHandler(vault, svcUpdater, "http://localhost:9470")

	// Run start to get a real state token.
	startReq := httptest.NewRequest(http.MethodGet,
		"/api/v1/oauth/github/start?service_name=github", nil)
	startReq.SetPathValue("provider", "github")
	startW := httptest.NewRecorder()
	h.StartOAuth(startW, startReq)
	loc := startW.Result().Header.Get("Location")
	u, _ := url.Parse(loc)
	stateToken := u.Query().Get("state")

	// Now drive callback.
	callbackReq := httptest.NewRequest(http.MethodGet,
		"/api/v1/oauth/callback?code=test-code&state="+stateToken, nil)
	callbackW := httptest.NewRecorder()
	h.Callback(callbackW, callbackReq)

	res := callbackW.Result()
	if res.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(res.Body)
		t.Fatalf("expected 302 redirect, got %d: %s", res.StatusCode, body)
	}

	// Verify token stored in vault.
	data, err := vault.ReadSecret("services/github/oauth_tokens")
	if err != nil {
		t.Fatalf("expected tokens in vault, got error: %v", err)
	}
	if data["access_token"] != "gha_test_access_token" {
		t.Errorf("expected access_token in vault, got %v", data["access_token"])
	}
}

func TestCallback_RedirectsToWebUIOnSuccess(t *testing.T) {
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
		"client_id":     "cid",
		"client_secret": "cs",
	})
	h := NewHandler(vault, &fakeServices{}, "http://localhost:9470")

	startReq := httptest.NewRequest(http.MethodGet,
		"/api/v1/oauth/github/start?service_name=mygithub", nil)
	startReq.SetPathValue("provider", "github")
	startW := httptest.NewRecorder()
	h.StartOAuth(startW, startReq)
	loc := startW.Result().Header.Get("Location")
	u, _ := url.Parse(loc)
	state := u.Query().Get("state")

	callbackReq := httptest.NewRequest(http.MethodGet,
		"/api/v1/oauth/callback?code=mycode&state="+state, nil)
	callbackW := httptest.NewRecorder()
	h.Callback(callbackW, callbackReq)

	res := callbackW.Result()
	redirectLoc := res.Header.Get("Location")
	if !strings.Contains(redirectLoc, "mygithub") {
		t.Errorf("expected redirect to contain service name, got %q", redirectLoc)
	}
	if !strings.Contains(redirectLoc, "oauth=success") {
		t.Errorf("expected redirect to contain oauth=success, got %q", redirectLoc)
	}
}

func TestCallback_InvalidStateReturns400(t *testing.T) {
	h := NewHandler(newFakeVault(), &fakeServices{}, "http://localhost:9470")

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/oauth/callback?code=code&state=bad-state-token", nil)
	w := httptest.NewRecorder()
	h.Callback(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCallback_MissingCodeReturns400(t *testing.T) {
	h := NewHandler(newFakeVault(), &fakeServices{}, "http://localhost:9470")
	sm := h.stateManager
	state := sm.Generate("github", "svc")

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/oauth/callback?state="+state, nil)
	w := httptest.NewRecorder()
	h.Callback(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCallback_ExpiredStateReturns400(t *testing.T) {
	h := NewHandler(newFakeVault(), &fakeServices{}, "http://localhost:9470")

	// Manually generate and immediately expire the token.
	sm := h.stateManager
	state := sm.Generate("github", "svc")
	sm.mu.Lock()
	entry := sm.states[state]
	entry.expiresAt = time.Now().Add(-1 * time.Second)
	sm.states[state] = entry
	sm.mu.Unlock()

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/oauth/callback?code=abc&state="+state, nil)
	w := httptest.NewRecorder()
	h.Callback(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for expired state, got %d", w.Code)
	}
}

// ---------------------------------------------------------------------------
// RefreshToken tests
// ---------------------------------------------------------------------------

func TestRefreshToken_UsesRefreshTokenToGetNewAccessToken(t *testing.T) {
	fakeSrv := buildProviderServer(t, map[string]interface{}{
		"access_token":  "new_access_token",
		"token_type":    "bearer",
		"refresh_token": "new_refresh_token",
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
	// Pre-store expired tokens in vault with provider info.
	_ = vault.WriteSecret("services/mysvc/oauth_tokens", map[string]interface{}{
		"access_token":  "old_token",
		"refresh_token": "valid_refresh_token",
		"expires_at":    time.Now().Add(-1 * time.Hour).Format(time.RFC3339),
		"provider":      "github",
	})
	// OAuth App credentials are keyed by provider name, not service name.
	_ = vault.WriteSecret("services/github/oauth_client_secret", map[string]interface{}{
		"client_id":     "cid",
		"client_secret": "cs",
	})

	svcUpdater := &fakeServices{}
	h := NewHandler(vault, svcUpdater, "http://localhost:9470")

	newToken, err := h.RefreshToken("mysvc")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if newToken != "new_access_token" {
		t.Errorf("expected new_access_token, got %q", newToken)
	}
}

func TestRefreshToken_StoresNewTokensInVault(t *testing.T) {
	fakeSrv := buildProviderServer(t, map[string]interface{}{
		"access_token":  "refreshed_token",
		"refresh_token": "new_refresh",
		"token_type":    "bearer",
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
	_ = vault.WriteSecret("services/svc/oauth_tokens", map[string]interface{}{
		"access_token":  "old",
		"refresh_token": "refresh_tok",
		"expires_at":    time.Now().Add(-1 * time.Hour).Format(time.RFC3339),
		"provider":      "github",
	})
	// OAuth App credentials are keyed by provider name, not service name.
	_ = vault.WriteSecret("services/github/oauth_client_secret", map[string]interface{}{
		"client_id":     "cid",
		"client_secret": "cs",
	})

	h := NewHandler(vault, &fakeServices{}, "http://localhost:9470")
	_, _ = h.RefreshToken("svc")

	stored, err := vault.ReadSecret("services/svc/oauth_tokens")
	if err != nil {
		t.Fatalf("tokens not found in vault after refresh: %v", err)
	}
	if stored["access_token"] != "refreshed_token" {
		t.Errorf("expected refreshed_token stored, got %v", stored["access_token"])
	}
}

func TestRefreshToken_NoRefreshTokenReturnsError(t *testing.T) {
	vault := newFakeVault()
	_ = vault.WriteSecret("services/svc/oauth_tokens", map[string]interface{}{
		"access_token": "tok",
		"expires_at":   time.Now().Add(-1 * time.Hour).Format(time.RFC3339),
		"provider":     "github",
		// no refresh_token field
	})

	h := NewHandler(vault, &fakeServices{}, "http://localhost:9470")
	_, err := h.RefreshToken("svc")
	if err == nil {
		t.Fatal("expected error when no refresh_token, got nil")
	}
}

func TestRefreshToken_RefreshFailureSetsServiceStatusExpired(t *testing.T) {
	// The fake provider returns an error response.
	failSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"bad_refresh_token"}`))
	}))
	t.Cleanup(failSrv.Close)

	originalProviders := Providers
	Providers = map[string]Provider{
		"github": {
			Name:          "github",
			AuthURL:       "https://github.com/login/oauth/authorize",
			TokenURL:      failSrv.URL + "/token",
			DefaultScopes: []string{"repo"},
		},
	}
	t.Cleanup(func() { Providers = originalProviders })

	vault := newFakeVault()
	_ = vault.WriteSecret("services/svc/oauth_tokens", map[string]interface{}{
		"access_token":  "old",
		"refresh_token": "bad_refresh",
		"expires_at":    time.Now().Add(-1 * time.Hour).Format(time.RFC3339),
		"provider":      "github",
	})
	// OAuth App credentials are keyed by provider name, not service name.
	_ = vault.WriteSecret("services/github/oauth_client_secret", map[string]interface{}{
		"client_id":     "cid",
		"client_secret": "cs",
	})

	svcUpdater := &fakeServices{}
	h := NewHandler(vault, svcUpdater, "http://localhost:9470")

	_, err := h.RefreshToken("svc")
	if err == nil {
		t.Fatal("expected error on refresh failure, got nil")
	}
}

func TestRefreshToken_ServiceNotInVaultReturnsError(t *testing.T) {
	h := NewHandler(newFakeVault(), &fakeServices{}, "http://localhost:9470")

	_, err := h.RefreshToken("nonexistent-service")
	if err == nil {
		t.Fatal("expected error for missing service, got nil")
	}
}
