package server_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/straylight-ai/straylight/internal/oidc"
	"github.com/straylight-ai/straylight/internal/server"
)

func TestOIDCDiscovery_ReturnsValidMetadata(t *testing.T) {
	cfg := server.Config{
		OIDCDiscovery: &oidc.Discovery{
			IssuerURL:     "https://straylight.example.com",
			JWKSURI:       "https://straylight.example.com/.well-known/jwks.json",
			SupportedAlgs: []string{"RS256"},
		},
	}

	s := server.New(cfg)
	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	w := httptest.NewRecorder()

	s.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}

	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Fatalf("expected Content-Type to contain 'application/json', got %q", ct)
	}

	var metadata map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&metadata); err != nil {
		t.Fatalf("failed to decode JSON response: %v", err)
	}

	expectedKeys := []string{"issuer", "jwks_uri", "id_token_signing_alg_values_supported"}
	for _, key := range expectedKeys {
		if _, ok := metadata[key]; !ok {
			t.Errorf("missing expected key %q in response", key)
		}
	}

	if issuer, ok := metadata["issuer"].(string); !ok || issuer != "https://straylight.example.com" {
		t.Errorf("expected issuer to be 'https://straylight.example.com', got %v", issuer)
	}

	if jwksURI, ok := metadata["jwks_uri"].(string); !ok || jwksURI != "https://straylight.example.com/.well-known/jwks.json" {
		t.Errorf("expected jwks_uri to be 'https://straylight.example.com/.well-known/jwks.json', got %v", jwksURI)
	}

	if algs, ok := metadata["id_token_signing_alg_values_supported"].([]interface{}); !ok {
		t.Errorf("expected id_token_signing_alg_values_supported to be an array, got %T", metadata["id_token_signing_alg_values_supported"])
	} else {
		found := false
		for _, alg := range algs {
			if alg == "RS256" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected 'RS256' in id_token_signing_alg_values_supported, got %v", algs)
		}
	}
}

func TestJWKS_ReturnsPublicKeys(t *testing.T) {
	cfg := server.Config{
		OIDCDiscovery: &oidc.Discovery{
			IssuerURL:     "https://straylight.example.com",
			JWKSURI:       "https://straylight.example.com/.well-known/jwks.json",
			SupportedAlgs: []string{"RS256"},
			Keys: []oidc.JWKKey{
				{Kty: "RSA", Kid: "k1", Use: "sig", Alg: "RS256"},
			},
		},
	}

	s := server.New(cfg)
	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	w := httptest.NewRecorder()

	s.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}

	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Fatalf("expected Content-Type to contain 'application/json', got %q", ct)
	}

	var jwks map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&jwks); err != nil {
		t.Fatalf("failed to decode JSON response: %v", err)
	}

	keys, ok := jwks["keys"].([]interface{})
	if !ok {
		t.Fatalf("expected 'keys' to be an array, got %T", jwks["keys"])
	}

	if len(keys) == 0 {
		t.Fatal("expected non-empty 'keys' array")
	}

	// Check at least one key has 'kty' field
	hasKty := false
	for _, key := range keys {
		if k, ok := key.(map[string]interface{}); ok {
			if _, hasK := k["kty"]; hasK {
				hasKty = true
				break
			}
		}
	}
	if !hasKty {
		t.Errorf("expected at least one key in 'keys' array to have 'kty' field")
	}
}

func TestOIDCDiscovery_NoAuthRequired(t *testing.T) {
	cfg := server.Config{
		OIDCDiscovery: &oidc.Discovery{
			IssuerURL:     "https://straylight.example.com",
			JWKSURI:       "https://straylight.example.com/.well-known/jwks.json",
			SupportedAlgs: []string{"RS256"},
		},
	}

	s := server.New(cfg)
	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	w := httptest.NewRecorder()

	s.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}
}

func TestJWKS_NoAuthRequired(t *testing.T) {
	cfg := server.Config{
		OIDCDiscovery: &oidc.Discovery{
			IssuerURL:     "https://straylight.example.com",
			JWKSURI:       "https://straylight.example.com/.well-known/jwks.json",
			SupportedAlgs: []string{"RS256"},
		},
	}

	s := server.New(cfg)
	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	w := httptest.NewRecorder()

	s.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}
}

func TestOIDCDiscovery_ExternalOriginNotBlocked(t *testing.T) {
	cfg := server.Config{
		OIDCDiscovery: &oidc.Discovery{
			IssuerURL:     "https://straylight.example.com",
			JWKSURI:       "https://straylight.example.com/.well-known/jwks.json",
			SupportedAlgs: []string{"RS256"},
		},
	}

	s := server.New(cfg)
	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	req.Header.Set("Origin", "https://oidc.eks.us-east-1.amazonaws.com")
	w := httptest.NewRecorder()

	s.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}
}

func TestOIDCEndpoints_NeverExposesSecretData(t *testing.T) {
	cfg := server.Config{
		OIDCDiscovery: &oidc.Discovery{
			IssuerURL:     "https://straylight.example.com",
			JWKSURI:       "https://straylight.example.com/.well-known/jwks.json",
			SupportedAlgs: []string{"RS256"},
		},
	}

	s := server.New(cfg)
	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	w := httptest.NewRecorder()

	s.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}

	body := w.Body.String()

	secretStrings := []string{"X-Vault-Token", "unseal_key", "secret/", "role_id"}
	for _, secret := range secretStrings {
		if strings.Contains(body, secret) {
			t.Errorf("response body contains secret data: %q", secret)
		}
	}
}

func TestOIDCDiscovery_WhenNotConfigured(t *testing.T) {
	s := server.New(server.Config{})

	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	w := httptest.NewRecorder()

	s.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound && w.Code != http.StatusNotImplemented {
		t.Fatalf("expected status 404 or 501 when OIDCDiscovery is not configured, got %d", w.Code)
	}
}

func TestJWKS_WhenNotConfigured(t *testing.T) {
	s := server.New(server.Config{})

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	w := httptest.NewRecorder()

	s.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound && w.Code != http.StatusNotImplemented {
		t.Fatalf("expected 404 or 501 when OIDCDiscovery is not configured, got %d", w.Code)
	}
}
