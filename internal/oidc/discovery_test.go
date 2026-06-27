package oidc_test

import (
	"testing"

	"github.com/straylight-ai/straylight/internal/oidc"
)

func TestDiscovery_OIDCConfig_AllFields(t *testing.T) {
	d := &oidc.Discovery{
		IssuerURL:     "https://ex.com",
		JWKSURI:       "https://ex.com/.well-known/jwks.json",
		SupportedAlgs: []string{"RS256", "ES256"},
	}
	cfg := d.OIDCConfig()

	if got, _ := cfg["issuer"].(string); got != "https://ex.com" {
		t.Errorf("issuer: got %q, want %q", got, "https://ex.com")
	}
	if got, _ := cfg["jwks_uri"].(string); got != "https://ex.com/.well-known/jwks.json" {
		t.Errorf("jwks_uri: got %q, want %q", got, "https://ex.com/.well-known/jwks.json")
	}
	algs, ok := cfg["id_token_signing_alg_values_supported"].([]string)
	if !ok {
		t.Fatal("id_token_signing_alg_values_supported is not a []string")
	}
	found := false
	for _, a := range algs {
		if a == "RS256" {
			found = true
		}
	}
	if !found {
		t.Errorf("RS256 not found in algs: %v", algs)
	}
}

func TestDiscovery_OIDCConfig_DefaultAlgs(t *testing.T) {
	d := &oidc.Discovery{IssuerURL: "https://ex.com"}
	cfg := d.OIDCConfig()

	algs, ok := cfg["id_token_signing_alg_values_supported"].([]string)
	if !ok {
		t.Fatal("id_token_signing_alg_values_supported is not a []string")
	}
	if len(algs) != 1 || algs[0] != "RS256" {
		t.Errorf("expected default algs [RS256], got %v", algs)
	}
}

func TestDiscovery_PublicJWKS_ReturnsKeys(t *testing.T) {
	d := &oidc.Discovery{
		Keys: []oidc.JWKKey{{Kty: "RSA", Kid: "k1"}},
	}
	jwks := d.PublicJWKS()

	if len(jwks.Keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(jwks.Keys))
	}
	if jwks.Keys[0].Kty != "RSA" {
		t.Errorf("expected Kty=RSA, got %q", jwks.Keys[0].Kty)
	}
}

func TestDiscovery_PublicJWKS_EmptyKeys(t *testing.T) {
	d := &oidc.Discovery{}
	jwks := d.PublicJWKS()
	// Must not panic; keys may be nil or empty.
	if len(jwks.Keys) != 0 {
		t.Errorf("expected empty keys, got %d", len(jwks.Keys))
	}
}

func TestOIDCConfig_RequiredFields(t *testing.T) {
	d := &oidc.Discovery{IssuerURL: "https://ex.com"}
	cfg := d.OIDCConfig()

	requiredFields := []string{
		"issuer",
		"jwks_uri",
		"id_token_signing_alg_values_supported",
		"response_types_supported",
		"subject_types_supported",
	}
	for _, field := range requiredFields {
		if _, ok := cfg[field]; !ok {
			t.Errorf("missing required field %q in OIDC config", field)
		}
	}
}
