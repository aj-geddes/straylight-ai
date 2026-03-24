package oauth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Provider registry tests
// ---------------------------------------------------------------------------

func TestProviders_GoogleIsRegistered(t *testing.T) {
	if _, ok := Providers["google"]; !ok {
		t.Error("expected 'google' provider to be registered in Providers map")
	}
}

func TestProviders_StripeIsRegistered(t *testing.T) {
	if _, ok := Providers["stripe"]; !ok {
		t.Error("expected 'stripe' provider to be registered in Providers map")
	}
}

func TestProviders_GoogleHasCorrectAuthURL(t *testing.T) {
	p, ok := Providers["google"]
	if !ok {
		t.Fatal("google provider not registered")
	}
	const wantAuthURL = "https://accounts.google.com/o/oauth2/v2/auth"
	if p.AuthURL != wantAuthURL {
		t.Errorf("expected google AuthURL=%q, got %q", wantAuthURL, p.AuthURL)
	}
}

func TestProviders_GoogleHasCorrectTokenURL(t *testing.T) {
	p, ok := Providers["google"]
	if !ok {
		t.Fatal("google provider not registered")
	}
	const wantTokenURL = "https://oauth2.googleapis.com/token"
	if p.TokenURL != wantTokenURL {
		t.Errorf("expected google TokenURL=%q, got %q", wantTokenURL, p.TokenURL)
	}
}

func TestProviders_GoogleHasOpenIDScopes(t *testing.T) {
	p, ok := Providers["google"]
	if !ok {
		t.Fatal("google provider not registered")
	}
	scopes := strings.Join(p.DefaultScopes, " ")
	for _, want := range []string{"openid", "email", "profile"} {
		if !strings.Contains(scopes, want) {
			t.Errorf("expected google DefaultScopes to contain %q, got %v", want, p.DefaultScopes)
		}
	}
}

func TestProviders_GoogleHasExtraAuthParams(t *testing.T) {
	p, ok := Providers["google"]
	if !ok {
		t.Fatal("google provider not registered")
	}
	if p.ExtraAuthParams == nil {
		t.Fatal("expected google ExtraAuthParams to be non-nil")
	}
	if p.ExtraAuthParams["access_type"] != "offline" {
		t.Errorf("expected google ExtraAuthParams[access_type]=offline, got %q", p.ExtraAuthParams["access_type"])
	}
	if p.ExtraAuthParams["prompt"] != "consent" {
		t.Errorf("expected google ExtraAuthParams[prompt]=consent, got %q", p.ExtraAuthParams["prompt"])
	}
}

func TestProviders_StripeHasCorrectAuthURL(t *testing.T) {
	p, ok := Providers["stripe"]
	if !ok {
		t.Fatal("stripe provider not registered")
	}
	const wantAuthURL = "https://connect.stripe.com/oauth/authorize"
	if p.AuthURL != wantAuthURL {
		t.Errorf("expected stripe AuthURL=%q, got %q", wantAuthURL, p.AuthURL)
	}
}

func TestProviders_StripeHasCorrectTokenURL(t *testing.T) {
	p, ok := Providers["stripe"]
	if !ok {
		t.Fatal("stripe provider not registered")
	}
	const wantTokenURL = "https://connect.stripe.com/oauth/token"
	if p.TokenURL != wantTokenURL {
		t.Errorf("expected stripe TokenURL=%q, got %q", wantTokenURL, p.TokenURL)
	}
}

func TestProviders_StripeHasReadWriteScope(t *testing.T) {
	p, ok := Providers["stripe"]
	if !ok {
		t.Fatal("stripe provider not registered")
	}
	if len(p.DefaultScopes) == 0 {
		t.Fatal("expected stripe DefaultScopes to be non-empty")
	}
	found := false
	for _, s := range p.DefaultScopes {
		if s == "read_write" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected stripe DefaultScopes to contain 'read_write', got %v", p.DefaultScopes)
	}
}

// ---------------------------------------------------------------------------
// StartOAuth ExtraAuthParams tests
// ---------------------------------------------------------------------------

func TestStartOAuth_GoogleIncludesExtraAuthParams(t *testing.T) {
	vault := newFakeVault()
	_ = vault.WriteSecret("services/google/oauth_client_secret", map[string]interface{}{
		"client_id":     "google-client-id",
		"client_secret": "google-client-secret",
	})
	h := NewHandler(vault, &fakeServices{}, "http://localhost:9470")

	// Override Google provider to use a recognisable auth URL (no network call).
	originalProviders := Providers
	Providers = map[string]Provider{
		"google": {
			Name:          "google",
			AuthURL:       "https://accounts.google.com/o/oauth2/v2/auth",
			TokenURL:      "https://oauth2.googleapis.com/token",
			DefaultScopes: []string{"openid", "email", "profile"},
			ExtraAuthParams: map[string]string{
				"access_type": "offline",
				"prompt":      "consent",
			},
		},
	}
	t.Cleanup(func() { Providers = originalProviders })

	redirectURL := startFlow(t, h, "google", "my-google")
	q := redirectURL.Query()

	if q.Get("access_type") != "offline" {
		t.Errorf("expected access_type=offline in Google redirect, got %q", q.Get("access_type"))
	}
	if q.Get("prompt") != "consent" {
		t.Errorf("expected prompt=consent in Google redirect, got %q", q.Get("prompt"))
	}
}

func TestStartOAuth_GoogleRedirectsToGoogleAuthURL(t *testing.T) {
	vault := newFakeVault()
	_ = vault.WriteSecret("services/google/oauth_client_secret", map[string]interface{}{
		"client_id":     "google-cid",
		"client_secret": "google-cs",
	})
	h := NewHandler(vault, &fakeServices{}, "http://localhost:9470")

	originalProviders := Providers
	Providers = map[string]Provider{
		"google": {
			Name:          "google",
			AuthURL:       "https://accounts.google.com/o/oauth2/v2/auth",
			TokenURL:      "https://oauth2.googleapis.com/token",
			DefaultScopes: []string{"openid", "email", "profile"},
			ExtraAuthParams: map[string]string{
				"access_type": "offline",
				"prompt":      "consent",
			},
		},
	}
	t.Cleanup(func() { Providers = originalProviders })

	redirectURL := startFlow(t, h, "google", "my-google")

	if !strings.HasPrefix(redirectURL.String(), "https://accounts.google.com/o/oauth2/v2/auth") {
		t.Errorf("unexpected Google redirect URL: %s", redirectURL)
	}
}

func TestStartOAuth_StripeRedirectsToStripeAuthURL(t *testing.T) {
	vault := newFakeVault()
	_ = vault.WriteSecret("services/stripe/oauth_client_secret", map[string]interface{}{
		"client_id":     "stripe-cid",
		"client_secret": "stripe-cs",
	})
	h := NewHandler(vault, &fakeServices{}, "http://localhost:9470")

	originalProviders := Providers
	Providers = map[string]Provider{
		"stripe": {
			Name:          "stripe",
			AuthURL:       "https://connect.stripe.com/oauth/authorize",
			TokenURL:      "https://connect.stripe.com/oauth/token",
			DefaultScopes: []string{"read_write"},
		},
	}
	t.Cleanup(func() { Providers = originalProviders })

	redirectURL := startFlow(t, h, "stripe", "my-stripe")

	if !strings.HasPrefix(redirectURL.String(), "https://connect.stripe.com/oauth/authorize") {
		t.Errorf("unexpected Stripe redirect URL: %s", redirectURL)
	}
}

func TestStartOAuth_StripeHasNoExtraAuthParams(t *testing.T) {
	vault := newFakeVault()
	_ = vault.WriteSecret("services/stripe/oauth_client_secret", map[string]interface{}{
		"client_id":     "stripe-client-id",
		"client_secret": "stripe-client-secret",
	})
	h := NewHandler(vault, &fakeServices{}, "http://localhost:9470")

	originalProviders := Providers
	Providers = map[string]Provider{
		"stripe": {
			Name:          "stripe",
			AuthURL:       "https://connect.stripe.com/oauth/authorize",
			TokenURL:      "https://connect.stripe.com/oauth/token",
			DefaultScopes: []string{"read_write"},
		},
	}
	t.Cleanup(func() { Providers = originalProviders })

	redirectURL := startFlow(t, h, "stripe", "my-stripe")
	q := redirectURL.Query()

	// Stripe does not use access_type or prompt params.
	if q.Get("access_type") != "" {
		t.Errorf("expected no access_type param for Stripe, got %q", q.Get("access_type"))
	}
	if q.Get("prompt") != "" {
		t.Errorf("expected no prompt param for Stripe, got %q", q.Get("prompt"))
	}
}

// ---------------------------------------------------------------------------
// Google token refresh tests
// ---------------------------------------------------------------------------

func TestRefreshToken_Google_UsesRefreshTokenToGetNewAccessToken(t *testing.T) {
	fakeSrv := buildProviderServer(t, map[string]interface{}{
		"access_token":  "google_new_access_token",
		"token_type":    "Bearer",
		"refresh_token": "google_new_refresh_token",
		"expires_in":    3600,
	})

	originalProviders := Providers
	Providers = map[string]Provider{
		"google": {
			Name:          "google",
			AuthURL:       "https://accounts.google.com/o/oauth2/v2/auth",
			TokenURL:      fakeSrv.URL + "/token",
			DefaultScopes: []string{"openid", "email", "profile"},
			ExtraAuthParams: map[string]string{
				"access_type": "offline",
				"prompt":      "consent",
			},
		},
	}
	t.Cleanup(func() { Providers = originalProviders })

	vault := newFakeVault()
	_ = vault.WriteSecret("services/google-svc/oauth_tokens", map[string]interface{}{
		"access_token":  "old_google_token",
		"refresh_token": "google_refresh_token",
		"expires_at":    time.Now().Add(-1 * time.Hour).Format(time.RFC3339),
		"provider":      "google",
	})
	// OAuth App credentials are keyed by provider name, not service name.
	_ = vault.WriteSecret("services/google/oauth_client_secret", map[string]interface{}{
		"client_id":     "google-cid",
		"client_secret": "google-cs",
	})

	h := NewHandler(vault, &fakeServices{}, "http://localhost:9470")

	newToken, err := h.RefreshToken("google-svc")
	if err != nil {
		t.Fatalf("expected no error refreshing Google token, got: %v", err)
	}
	if newToken != "google_new_access_token" {
		t.Errorf("expected google_new_access_token, got %q", newToken)
	}
}

func TestRefreshToken_Google_StoresNewTokensInVault(t *testing.T) {
	fakeSrv := buildProviderServer(t, map[string]interface{}{
		"access_token":  "google_refreshed_access",
		"refresh_token": "google_refreshed_refresh",
		"token_type":    "Bearer",
		"expires_in":    3600,
	})

	originalProviders := Providers
	Providers = map[string]Provider{
		"google": {
			Name:          "google",
			AuthURL:       "https://accounts.google.com/o/oauth2/v2/auth",
			TokenURL:      fakeSrv.URL + "/token",
			DefaultScopes: []string{"openid", "email", "profile"},
			ExtraAuthParams: map[string]string{
				"access_type": "offline",
				"prompt":      "consent",
			},
		},
	}
	t.Cleanup(func() { Providers = originalProviders })

	vault := newFakeVault()
	_ = vault.WriteSecret("services/google-svc/oauth_tokens", map[string]interface{}{
		"access_token":  "old",
		"refresh_token": "google_refresh",
		"expires_at":    time.Now().Add(-1 * time.Hour).Format(time.RFC3339),
		"provider":      "google",
	})
	// OAuth App credentials are keyed by provider name, not service name.
	_ = vault.WriteSecret("services/google/oauth_client_secret", map[string]interface{}{
		"client_id":     "cid",
		"client_secret": "cs",
	})

	h := NewHandler(vault, &fakeServices{}, "http://localhost:9470")
	_, _ = h.RefreshToken("google-svc")

	stored, err := vault.ReadSecret("services/google-svc/oauth_tokens")
	if err != nil {
		t.Fatalf("tokens not found in vault after Google refresh: %v", err)
	}
	if stored["access_token"] != "google_refreshed_access" {
		t.Errorf("expected google_refreshed_access stored, got %v", stored["access_token"])
	}
	if stored["provider"] != "google" {
		t.Errorf("expected provider=google preserved in vault, got %v", stored["provider"])
	}
}

func TestRefreshToken_Google_ErrorResponseReturnsError(t *testing.T) {
	// Google returns JSON error body with "error" field.
	errorSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":             "invalid_grant",
			"error_description": "Token has been expired or revoked.",
		})
	}))
	t.Cleanup(errorSrv.Close)

	originalProviders := Providers
	Providers = map[string]Provider{
		"google": {
			Name:     "google",
			AuthURL:  "https://accounts.google.com/o/oauth2/v2/auth",
			TokenURL: errorSrv.URL + "/token",
		},
	}
	t.Cleanup(func() { Providers = originalProviders })

	vault := newFakeVault()
	_ = vault.WriteSecret("services/google-svc/oauth_tokens", map[string]interface{}{
		"access_token":  "old",
		"refresh_token": "expired_token",
		"expires_at":    time.Now().Add(-1 * time.Hour).Format(time.RFC3339),
		"provider":      "google",
	})
	// OAuth App credentials are keyed by provider name, not service name.
	_ = vault.WriteSecret("services/google/oauth_client_secret", map[string]interface{}{
		"client_id":     "cid",
		"client_secret": "cs",
	})

	h := NewHandler(vault, &fakeServices{}, "http://localhost:9470")
	_, err := h.RefreshToken("google-svc")
	if err == nil {
		t.Fatal("expected error on Google token refresh failure, got nil")
	}
}

// ---------------------------------------------------------------------------
// Stripe token refresh tests
// ---------------------------------------------------------------------------

func TestRefreshToken_Stripe_UsesRefreshTokenToGetNewAccessToken(t *testing.T) {
	fakeSrv := buildProviderServer(t, map[string]interface{}{
		"access_token":  "stripe_new_access_token",
		"token_type":    "bearer",
		"refresh_token": "stripe_new_refresh_token",
	})

	originalProviders := Providers
	Providers = map[string]Provider{
		"stripe": {
			Name:          "stripe",
			AuthURL:       "https://connect.stripe.com/oauth/authorize",
			TokenURL:      fakeSrv.URL + "/token",
			DefaultScopes: []string{"read_write"},
		},
	}
	t.Cleanup(func() { Providers = originalProviders })

	vault := newFakeVault()
	_ = vault.WriteSecret("services/stripe-svc/oauth_tokens", map[string]interface{}{
		"access_token":  "old_stripe_token",
		"refresh_token": "stripe_refresh_token",
		"expires_at":    time.Now().Add(-1 * time.Hour).Format(time.RFC3339),
		"provider":      "stripe",
	})
	// OAuth App credentials are keyed by provider name, not service name.
	_ = vault.WriteSecret("services/stripe/oauth_client_secret", map[string]interface{}{
		"client_id":     "stripe-cid",
		"client_secret": "stripe-cs",
	})

	h := NewHandler(vault, &fakeServices{}, "http://localhost:9470")

	newToken, err := h.RefreshToken("stripe-svc")
	if err != nil {
		t.Fatalf("expected no error refreshing Stripe token, got: %v", err)
	}
	if newToken != "stripe_new_access_token" {
		t.Errorf("expected stripe_new_access_token, got %q", newToken)
	}
}

func TestRefreshToken_Stripe_StoresNewTokensInVault(t *testing.T) {
	fakeSrv := buildProviderServer(t, map[string]interface{}{
		"access_token":  "stripe_refreshed_access",
		"refresh_token": "stripe_refreshed_refresh",
		"token_type":    "bearer",
	})

	originalProviders := Providers
	Providers = map[string]Provider{
		"stripe": {
			Name:          "stripe",
			AuthURL:       "https://connect.stripe.com/oauth/authorize",
			TokenURL:      fakeSrv.URL + "/token",
			DefaultScopes: []string{"read_write"},
		},
	}
	t.Cleanup(func() { Providers = originalProviders })

	vault := newFakeVault()
	_ = vault.WriteSecret("services/stripe-svc/oauth_tokens", map[string]interface{}{
		"access_token":  "old",
		"refresh_token": "stripe_refresh",
		"expires_at":    time.Now().Add(-1 * time.Hour).Format(time.RFC3339),
		"provider":      "stripe",
	})
	// OAuth App credentials are keyed by provider name, not service name.
	_ = vault.WriteSecret("services/stripe/oauth_client_secret", map[string]interface{}{
		"client_id":     "cid",
		"client_secret": "cs",
	})

	h := NewHandler(vault, &fakeServices{}, "http://localhost:9470")
	_, _ = h.RefreshToken("stripe-svc")

	stored, err := vault.ReadSecret("services/stripe-svc/oauth_tokens")
	if err != nil {
		t.Fatalf("tokens not found in vault after Stripe refresh: %v", err)
	}
	if stored["access_token"] != "stripe_refreshed_access" {
		t.Errorf("expected stripe_refreshed_access stored, got %v", stored["access_token"])
	}
	if stored["provider"] != "stripe" {
		t.Errorf("expected provider=stripe preserved in vault, got %v", stored["provider"])
	}
}

func TestRefreshToken_Stripe_ErrorResponseReturnsError(t *testing.T) {
	// Stripe returns error in the JSON body (standard OAuth2 error format).
	errorSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":             "invalid_grant",
			"error_description": "This authorization code has already been used.",
		})
	}))
	t.Cleanup(errorSrv.Close)

	originalProviders := Providers
	Providers = map[string]Provider{
		"stripe": {
			Name:     "stripe",
			AuthURL:  "https://connect.stripe.com/oauth/authorize",
			TokenURL: errorSrv.URL + "/token",
		},
	}
	t.Cleanup(func() { Providers = originalProviders })

	vault := newFakeVault()
	_ = vault.WriteSecret("services/stripe-svc/oauth_tokens", map[string]interface{}{
		"access_token":  "old",
		"refresh_token": "bad_stripe_refresh",
		"expires_at":    time.Now().Add(-1 * time.Hour).Format(time.RFC3339),
		"provider":      "stripe",
	})
	// OAuth App credentials are keyed by provider name, not service name.
	_ = vault.WriteSecret("services/stripe/oauth_client_secret", map[string]interface{}{
		"client_id":     "cid",
		"client_secret": "cs",
	})

	h := NewHandler(vault, &fakeServices{}, "http://localhost:9470")
	_, err := h.RefreshToken("stripe-svc")
	if err == nil {
		t.Fatal("expected error on Stripe token refresh failure, got nil")
	}
}

// ---------------------------------------------------------------------------
// Callback tests for Google and Stripe
// ---------------------------------------------------------------------------

func TestCallback_Google_ExchangesCodeAndStoresTokens(t *testing.T) {
	fakeSrv := buildProviderServer(t, map[string]interface{}{
		"access_token":  "google_access_token",
		"token_type":    "Bearer",
		"refresh_token": "google_refresh_token",
		"expires_in":    3600,
		"scope":         "openid email profile",
	})

	originalProviders := Providers
	Providers = map[string]Provider{
		"google": {
			Name:          "google",
			AuthURL:       "https://accounts.google.com/o/oauth2/v2/auth",
			TokenURL:      fakeSrv.URL + "/token",
			DefaultScopes: []string{"openid", "email", "profile"},
			ExtraAuthParams: map[string]string{
				"access_type": "offline",
				"prompt":      "consent",
			},
		},
	}
	t.Cleanup(func() { Providers = originalProviders })

	vault := newFakeVault()
	_ = vault.WriteSecret("services/google/oauth_client_secret", map[string]interface{}{
		"client_id":     "cid",
		"client_secret": "cs",
	})

	h := NewHandler(vault, &fakeServices{}, "http://localhost:9470")

	startReq := httptest.NewRequest(http.MethodGet,
		"/api/v1/oauth/google/start?service_name=my-google", nil)
	startReq.SetPathValue("provider", "google")
	startW := httptest.NewRecorder()
	h.StartOAuth(startW, startReq)
	loc := startW.Result().Header.Get("Location")
	u, _ := url.Parse(loc)
	stateToken := u.Query().Get("state")

	callbackReq := httptest.NewRequest(http.MethodGet,
		"/api/v1/oauth/callback?code=google-code&state="+stateToken, nil)
	callbackW := httptest.NewRecorder()
	h.Callback(callbackW, callbackReq)

	res := callbackW.Result()
	if res.StatusCode != http.StatusFound {
		t.Fatalf("expected 302 from Google callback, got %d", res.StatusCode)
	}

	data, err := vault.ReadSecret("services/my-google/oauth_tokens")
	if err != nil {
		t.Fatalf("expected Google tokens in vault, got error: %v", err)
	}
	if data["access_token"] != "google_access_token" {
		t.Errorf("expected google_access_token in vault, got %v", data["access_token"])
	}
	if data["provider"] != "google" {
		t.Errorf("expected provider=google stored in vault, got %v", data["provider"])
	}
}

func TestCallback_Stripe_ExchangesCodeAndStoresTokens(t *testing.T) {
	fakeSrv := buildProviderServer(t, map[string]interface{}{
		"access_token":  "stripe_access_token",
		"token_type":    "bearer",
		"refresh_token": "stripe_refresh_token",
		"scope":         "read_write",
	})

	originalProviders := Providers
	Providers = map[string]Provider{
		"stripe": {
			Name:          "stripe",
			AuthURL:       "https://connect.stripe.com/oauth/authorize",
			TokenURL:      fakeSrv.URL + "/token",
			DefaultScopes: []string{"read_write"},
		},
	}
	t.Cleanup(func() { Providers = originalProviders })

	vault := newFakeVault()
	_ = vault.WriteSecret("services/stripe/oauth_client_secret", map[string]interface{}{
		"client_id":     "cid",
		"client_secret": "cs",
	})

	h := NewHandler(vault, &fakeServices{}, "http://localhost:9470")

	startReq := httptest.NewRequest(http.MethodGet,
		"/api/v1/oauth/stripe/start?service_name=my-stripe", nil)
	startReq.SetPathValue("provider", "stripe")
	startW := httptest.NewRecorder()
	h.StartOAuth(startW, startReq)
	loc := startW.Result().Header.Get("Location")
	u, _ := url.Parse(loc)
	stateToken := u.Query().Get("state")

	callbackReq := httptest.NewRequest(http.MethodGet,
		"/api/v1/oauth/callback?code=stripe-code&state="+stateToken, nil)
	callbackW := httptest.NewRecorder()
	h.Callback(callbackW, callbackReq)

	res := callbackW.Result()
	if res.StatusCode != http.StatusFound {
		t.Fatalf("expected 302 from Stripe callback, got %d", res.StatusCode)
	}

	data, err := vault.ReadSecret("services/my-stripe/oauth_tokens")
	if err != nil {
		t.Fatalf("expected Stripe tokens in vault, got error: %v", err)
	}
	if data["access_token"] != "stripe_access_token" {
		t.Errorf("expected stripe_access_token in vault, got %v", data["access_token"])
	}
	if data["provider"] != "stripe" {
		t.Errorf("expected provider=stripe stored in vault, got %v", data["provider"])
	}
}
