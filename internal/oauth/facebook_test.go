package oauth

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Facebook provider registry tests
// ---------------------------------------------------------------------------

func TestProviders_FacebookIsRegistered(t *testing.T) {
	if _, ok := Providers["facebook"]; !ok {
		t.Error("expected 'facebook' provider to be registered in Providers map")
	}
}

func TestProviders_FacebookHasCorrectAuthURL(t *testing.T) {
	p, ok := Providers["facebook"]
	if !ok {
		t.Fatal("facebook provider not registered")
	}
	const wantAuthURL = "https://www.facebook.com/v19.0/dialog/oauth"
	if p.AuthURL != wantAuthURL {
		t.Errorf("expected facebook AuthURL=%q, got %q", wantAuthURL, p.AuthURL)
	}
}

func TestProviders_FacebookHasCorrectTokenURL(t *testing.T) {
	p, ok := Providers["facebook"]
	if !ok {
		t.Fatal("facebook provider not registered")
	}
	const wantTokenURL = "https://graph.facebook.com/v19.0/oauth/access_token"
	if p.TokenURL != wantTokenURL {
		t.Errorf("expected facebook TokenURL=%q, got %q", wantTokenURL, p.TokenURL)
	}
}

func TestProviders_FacebookHasEmailAndPublicProfileScopes(t *testing.T) {
	p, ok := Providers["facebook"]
	if !ok {
		t.Fatal("facebook provider not registered")
	}
	scopes := strings.Join(p.DefaultScopes, " ")
	for _, want := range []string{"email", "public_profile"} {
		if !strings.Contains(scopes, want) {
			t.Errorf("expected facebook DefaultScopes to contain %q, got %v", want, p.DefaultScopes)
		}
	}
}

// ---------------------------------------------------------------------------
// Env var credential resolution tests (readClientID / readClientSecret)
// ---------------------------------------------------------------------------

func TestReadClientID_ReadsFromEnvVarFirst(t *testing.T) {
	t.Setenv("STRAYLIGHT_GOOGLE_CLIENT_ID", "env-google-client-id")

	vault := newFakeVault()
	// Put a different value in vault — env var should win.
	_ = vault.WriteSecret("services/google/oauth_client_secret", map[string]interface{}{
		"client_id":     "vault-client-id",
		"client_secret": "vault-client-secret",
	})
	h := NewHandler(vault, &fakeServices{}, "http://localhost:9470")

	got := h.readClientID("google")
	if got != "env-google-client-id" {
		t.Errorf("expected env var client_id=%q, got %q", "env-google-client-id", got)
	}
}

func TestReadClientID_FallsBackToVaultWhenEnvVarMissing(t *testing.T) {
	// Ensure env var is not set.
	if err := os.Unsetenv("STRAYLIGHT_GOOGLE_CLIENT_ID"); err != nil {
		t.Fatal(err)
	}

	vault := newFakeVault()
	_ = vault.WriteSecret("services/google/oauth_client_secret", map[string]interface{}{
		"client_id":     "vault-only-client-id",
		"client_secret": "vault-client-secret",
	})
	h := NewHandler(vault, &fakeServices{}, "http://localhost:9470")

	got := h.readClientID("google")
	if got != "vault-only-client-id" {
		t.Errorf("expected vault fallback client_id=%q, got %q", "vault-only-client-id", got)
	}
}

func TestReadClientID_ChecksProviderDefaultClientID(t *testing.T) {
	// Set up a provider with DefaultClientID but no env var and no vault entry.
	if err := os.Unsetenv("STRAYLIGHT_GITHUB_CLIENT_ID"); err != nil {
		t.Fatal(err)
	}

	originalProviders := Providers
	Providers = map[string]Provider{
		"github": {
			Name:            "github",
			AuthURL:         "https://github.com/login/oauth/authorize",
			TokenURL:        "https://github.com/login/oauth/access_token",
			DeviceCodeURL:   "https://github.com/login/device/code",
			DefaultScopes:   []string{"repo"},
			DefaultClientID: "baked-in-github-client-id",
		},
	}
	t.Cleanup(func() { Providers = originalProviders })

	h := NewHandler(newFakeVault(), &fakeServices{}, "http://localhost:9470")

	got := h.readClientID("github")
	if got != "baked-in-github-client-id" {
		t.Errorf("expected DefaultClientID=%q, got %q", "baked-in-github-client-id", got)
	}
}

func TestReadClientSecret_ReadsFromEnvVarFirst(t *testing.T) {
	t.Setenv("STRAYLIGHT_GOOGLE_CLIENT_SECRET", "env-google-client-secret")

	vault := newFakeVault()
	_ = vault.WriteSecret("services/google/oauth_client_secret", map[string]interface{}{
		"client_id":     "cid",
		"client_secret": "vault-client-secret",
	})
	h := NewHandler(vault, &fakeServices{}, "http://localhost:9470")

	got := h.readClientSecret("google")
	if got != "env-google-client-secret" {
		t.Errorf("expected env var client_secret=%q, got %q", "env-google-client-secret", got)
	}
}

func TestReadClientSecret_FallsBackToVaultWhenEnvVarMissing(t *testing.T) {
	if err := os.Unsetenv("STRAYLIGHT_GOOGLE_CLIENT_SECRET"); err != nil {
		t.Fatal(err)
	}

	vault := newFakeVault()
	_ = vault.WriteSecret("services/google/oauth_client_secret", map[string]interface{}{
		"client_id":     "cid",
		"client_secret": "vault-only-secret",
	})
	h := NewHandler(vault, &fakeServices{}, "http://localhost:9470")

	got := h.readClientSecret("google")
	if got != "vault-only-secret" {
		t.Errorf("expected vault fallback client_secret=%q, got %q", "vault-only-secret", got)
	}
}

func TestStartOAuth_UsesEnvVarClientIDOverVault(t *testing.T) {
	t.Setenv("STRAYLIGHT_GOOGLE_CLIENT_ID", "env-google-cid")

	vault := newFakeVault()
	// Different value in vault — env var should take priority.
	_ = vault.WriteSecret("services/google/oauth_client_secret", map[string]interface{}{
		"client_id":     "vault-google-cid",
		"client_secret": "cs",
	})

	originalProviders := Providers
	Providers = map[string]Provider{
		"google": {
			Name:          "google",
			AuthURL:       "https://accounts.google.com/o/oauth2/v2/auth",
			TokenURL:      "https://oauth2.googleapis.com/token",
			DefaultScopes: []string{"openid", "email"},
			ExtraAuthParams: map[string]string{
				"access_type": "offline",
				"prompt":      "consent",
			},
		},
	}
	t.Cleanup(func() { Providers = originalProviders })

	h := NewHandler(vault, &fakeServices{}, "http://localhost:9470")
	redirectURL := startFlow(t, h, "google", "my-google-svc")
	q := redirectURL.Query()

	if q.Get("client_id") != "env-google-cid" {
		t.Errorf("expected client_id=env-google-cid in redirect, got %q", q.Get("client_id"))
	}
}

func TestStartOAuth_FacebookRedirectsToFacebookAuthURL(t *testing.T) {
	t.Setenv("STRAYLIGHT_FACEBOOK_CLIENT_ID", "facebook-env-cid")

	originalProviders := Providers
	Providers = map[string]Provider{
		"facebook": {
			Name:          "facebook",
			AuthURL:       "https://www.facebook.com/v19.0/dialog/oauth",
			TokenURL:      "https://graph.facebook.com/v19.0/oauth/access_token",
			DefaultScopes: []string{"email", "public_profile"},
		},
	}
	t.Cleanup(func() { Providers = originalProviders })

	h := NewHandler(newFakeVault(), &fakeServices{}, "http://localhost:9470")
	redirectURL := startFlow(t, h, "facebook", "my-facebook-svc")

	if !strings.HasPrefix(redirectURL.String(), "https://www.facebook.com/v19.0/dialog/oauth") {
		t.Errorf("unexpected Facebook redirect URL: %s", redirectURL)
	}
}

func TestStartOAuth_FacebookIncludesResponseTypeCode(t *testing.T) {
	t.Setenv("STRAYLIGHT_FACEBOOK_CLIENT_ID", "facebook-env-cid")

	originalProviders := Providers
	Providers = map[string]Provider{
		"facebook": {
			Name:          "facebook",
			AuthURL:       "https://www.facebook.com/v19.0/dialog/oauth",
			TokenURL:      "https://graph.facebook.com/v19.0/oauth/access_token",
			DefaultScopes: []string{"email", "public_profile"},
		},
	}
	t.Cleanup(func() { Providers = originalProviders })

	h := NewHandler(newFakeVault(), &fakeServices{}, "http://localhost:9470")
	redirectURL := startFlow(t, h, "facebook", "my-facebook-svc")
	q := redirectURL.Query()

	if q.Get("response_type") != "code" {
		t.Errorf("expected response_type=code for Facebook, got %q", q.Get("response_type"))
	}
}

// ---------------------------------------------------------------------------
// findTemplateForProvider — Facebook template
// ---------------------------------------------------------------------------

func TestFindTemplateForProvider_FacebookReturnsGraphAPITarget(t *testing.T) {
	tmpl := findTemplateForProvider("facebook")
	if tmpl.target != "https://graph.facebook.com" {
		t.Errorf("expected facebook target=https://graph.facebook.com, got %q", tmpl.target)
	}
}

func TestFindTemplateForProvider_FacebookReturnsFacebookOAuthMethod(t *testing.T) {
	tmpl := findTemplateForProvider("facebook")
	if tmpl.authMethodID != "facebook_oauth" {
		t.Errorf("expected facebook authMethodID=facebook_oauth, got %q", tmpl.authMethodID)
	}
}

// ---------------------------------------------------------------------------
// Facebook OAuth callback end-to-end
// ---------------------------------------------------------------------------

func TestCallback_Facebook_ExchangesCodeAndStoresTokens(t *testing.T) {
	fakeSrv := buildProviderServer(t, map[string]interface{}{
		"access_token": "fb_access_token",
		"token_type":   "bearer",
		"expires_in":   5183944,
	})

	t.Setenv("STRAYLIGHT_FACEBOOK_CLIENT_ID", "fb-env-cid")
	t.Setenv("STRAYLIGHT_FACEBOOK_CLIENT_SECRET", "fb-env-secret")

	originalProviders := Providers
	Providers = map[string]Provider{
		"facebook": {
			Name:          "facebook",
			AuthURL:       "https://www.facebook.com/v19.0/dialog/oauth",
			TokenURL:      fakeSrv.URL + "/token",
			DefaultScopes: []string{"email", "public_profile"},
		},
	}
	t.Cleanup(func() { Providers = originalProviders })

	h := NewHandler(newFakeVault(), &fakeServices{}, "http://localhost:9470")

	// Start to get state token.
	startReq := httptest.NewRequest(http.MethodGet,
		"/api/v1/oauth/facebook/start?service_name=my-facebook", nil)
	startReq.SetPathValue("provider", "facebook")
	startW := httptest.NewRecorder()
	h.StartOAuth(startW, startReq)

	if startW.Code != http.StatusFound {
		t.Fatalf("StartOAuth Facebook: expected 302, got %d", startW.Code)
	}

	loc := startW.Result().Header.Get("Location")
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("invalid Location URL %q: %v", loc, err)
	}
	stateToken := u.Query().Get("state")

	// Callback.
	callbackReq := httptest.NewRequest(http.MethodGet,
		"/api/v1/oauth/callback?code=fb-code&state="+stateToken, nil)
	callbackW := httptest.NewRecorder()
	h.Callback(callbackW, callbackReq)

	res := callbackW.Result()
	if res.StatusCode != http.StatusFound {
		t.Fatalf("Callback Facebook: expected 302, got %d", res.StatusCode)
	}
}
