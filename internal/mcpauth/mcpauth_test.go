// Package mcpauth implements OAuth 2.1 Resource Server token validation.
package mcpauth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

var testRSAKey, _ = rsa.GenerateKey(rand.Reader, 2048)

const (
	testKID                  = "test-kid-1"
	testIssuer               = "https://idp.example.com"
	testResource             = "https://mcp.example.com"
	straylightInternalIssuer = "https://straylight.internal"
)

type stubJWKSProvider struct{}

func (stubJWKSProvider) KeyFor(_ context.Context, _ string, kid string) (crypto.PublicKey, error) {
	if kid == testKID {
		return &testRSAKey.PublicKey, nil
	}
	return nil, &ValidationError{Code: "invalid_signature", Message: "unknown kid: " + kid}
}

func buildTestJWT(t *testing.T, key *rsa.PrivateKey, headerOverrides map[string]interface{}, claims map[string]interface{}) string {
	t.Helper()
	header := map[string]interface{}{
		"alg": "RS256",
		"typ": "JWT",
		"kid": testKID,
	}
	for k, v := range headerOverrides {
		if v == nil {
			delete(header, k)
		} else {
			header[k] = v
		}
	}
	headerJSON, _ := json.Marshal(header)
	claimsJSON, _ := json.Marshal(claims)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)
	signingInput := headerB64 + "." + claimsB64
	algVal, _ := header["alg"].(string)
	switch {
	case algVal == "none":
		return signingInput + "."
	case strings.HasPrefix(algVal, "HS"):
		return signingInput + "." + base64.RawURLEncoding.EncodeToString([]byte("fakehmacsig"))
	case key == nil:
		return headerB64 + "." + claimsB64
	}
	h := sha256.New()
	h.Write([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, h.Sum(nil))
	if err != nil {
		t.Fatalf("sign JWT: %v", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func defaultValidClaims() map[string]interface{} {
	now := time.Now()
	return map[string]interface{}{
		"iss":   testIssuer,
		"aud":   testResource,
		"sub":   "user|alice",
		"email": "alice@example.com",
		"scope": "straylight.mcp",
		"iat":   now.Unix(),
		"exp":   now.Add(1 * time.Hour).Unix(),
	}
}

func defaultValidatorConfig() ValidatorConfig {
	return ValidatorConfig{
		Resource:       testResource,
		TrustedIssuers: []string{testIssuer},
		AllowedAlgs:    []string{"RS256"},
		ClockSkew:      30 * time.Second,
		JWKSProvider:   stubJWKSProvider{},
	}
}

// ---------------------------------------------------------------------------
// constructor validation
// ---------------------------------------------------------------------------

func TestNew_RejectsEmptyResource(t *testing.T) {
	cfg := defaultValidatorConfig()
	cfg.Resource = ""
	if _, err := New(cfg); err == nil {
		t.Fatal("expected error for empty resource")
	}
}

func TestNew_RejectsEmptyTrustedIssuers(t *testing.T) {
	cfg := defaultValidatorConfig()
	cfg.TrustedIssuers = nil
	if _, err := New(cfg); err == nil {
		t.Fatal("expected error for empty TrustedIssuers")
	}
}

func TestNew_RejectsNilJWKSProvider(t *testing.T) {
	cfg := defaultValidatorConfig()
	cfg.JWKSProvider = nil
	if _, err := New(cfg); err == nil {
		t.Fatal("expected error for nil JWKSProvider")
	}
}

// TestNew_RoleDisjointness verifies ADR-015 invariant: TrustedIssuers MUST NOT
// contain Straylight's own OIDC issuer URL. The RS role (this pkg) validates
// tokens from external IdPs; ADR-012's issuer role mints tokens to clouds.
// These are disjoint directions and must never share configuration.
func TestNew_RoleDisjointness(t *testing.T) {
	cfg := defaultValidatorConfig()
	cfg.TrustedIssuers = append(cfg.TrustedIssuers, straylightInternalIssuer)
	_, err := New(cfg)
	if err == nil {
		t.Fatalf("expected error: TrustedIssuers must not contain Straylight internal issuer %q", straylightInternalIssuer)
	}
}

func TestNew_RejectsAllowedAlgsContainingNone(t *testing.T) {
	cfg := defaultValidatorConfig()
	cfg.AllowedAlgs = []string{"RS256", "none"}
	if _, err := New(cfg); err == nil {
		t.Fatal("expected error when AllowedAlgs includes 'none'")
	}
}

func TestNew_RejectsSymmetricAllowedAlgs(t *testing.T) {
	for _, alg := range []string{"HS256", "HS384", "HS512"} {
		cfg := defaultValidatorConfig()
		cfg.AllowedAlgs = []string{alg}
		if _, err := New(cfg); err == nil {
			t.Errorf("expected error when AllowedAlgs contains symmetric alg %q", alg)
		}
	}
}

func TestNew_RejectsWildcardIssuer(t *testing.T) {
	cfg := defaultValidatorConfig()
	cfg.TrustedIssuers = []string{"*"}
	if _, err := New(cfg); err == nil {
		t.Fatal("expected error for wildcard TrustedIssuers")
	}
}

// ---------------------------------------------------------------------------
// Validate — valid token
// ---------------------------------------------------------------------------

func TestValidate_ValidToken(t *testing.T) {
	v, err := New(defaultValidatorConfig())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	token := buildTestJWT(t, testRSAKey, nil, defaultValidClaims())
	id, err := v.Validate(context.Background(), token)
	if err != nil {
		t.Fatalf("expected success, got: %v", err)
	}
	if id.Subject != "user|alice" {
		t.Errorf("Subject = %q, want user|alice", id.Subject)
	}
	if id.Issuer != testIssuer {
		t.Errorf("Issuer = %q, want %q", id.Issuer, testIssuer)
	}
	if id.Audience != testResource {
		t.Errorf("Audience = %q, want %q", id.Audience, testResource)
	}
	if id.Email != "alice@example.com" {
		t.Errorf("Email = %q, want alice@example.com", id.Email)
	}
	if len(id.Scopes) == 0 || id.Scopes[0] != "straylight.mcp" {
		t.Errorf("Scopes = %v, want [straylight.mcp]", id.Scopes)
	}
	if id.ExpiresAt.IsZero() {
		t.Error("ExpiresAt should not be zero")
	}
}

// TestValidate_RawTokenNotRetained asserts the raw token is absent from Identity
// — no-passthrough by construction (ADR-015 §C.1).
func TestValidate_RawTokenNotRetained(t *testing.T) {
	v, err := New(defaultValidatorConfig())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	token := buildTestJWT(t, testRSAKey, nil, defaultValidClaims())
	id, err := v.Validate(context.Background(), token)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	idJSON, _ := json.Marshal(id)
	if strings.Contains(string(idJSON), token) {
		t.Error("raw token found in Identity JSON — no-passthrough violation")
	}
}

// ---------------------------------------------------------------------------
// Validate — rejection cases
// ---------------------------------------------------------------------------

func TestValidate_BadSignature(t *testing.T) {
	v, _ := New(defaultValidatorConfig())
	otherKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	token := buildTestJWT(t, otherKey, nil, defaultValidClaims())
	_, verr := v.Validate(context.Background(), token)
	assertValidationError(t, verr, "invalid_signature")
}

func TestValidate_AlgNone(t *testing.T) {
	v, _ := New(defaultValidatorConfig())
	token := buildTestJWT(t, nil, map[string]interface{}{"alg": "none"}, defaultValidClaims())
	_, verr := v.Validate(context.Background(), token)
	assertValidationError(t, verr, "invalid_algorithm")
}

func TestValidate_SymmetricAlg(t *testing.T) {
	v, _ := New(defaultValidatorConfig())
	token := buildTestJWT(t, nil, map[string]interface{}{"alg": "HS256"}, defaultValidClaims())
	_, verr := v.Validate(context.Background(), token)
	assertValidationError(t, verr, "invalid_algorithm")
}

func TestValidate_UntrustedIssuer(t *testing.T) {
	v, _ := New(defaultValidatorConfig())
	claims := defaultValidClaims()
	claims["iss"] = "https://evil.example.com"
	token := buildTestJWT(t, testRSAKey, nil, claims)
	_, verr := v.Validate(context.Background(), token)
	assertValidationError(t, verr, "invalid_issuer")
}

func TestValidate_WrongAudience(t *testing.T) {
	v, _ := New(defaultValidatorConfig())
	claims := defaultValidClaims()
	claims["aud"] = "https://other-rs.example.com"
	token := buildTestJWT(t, testRSAKey, nil, claims)
	_, verr := v.Validate(context.Background(), token)
	assertValidationError(t, verr, "invalid_audience")
}

func TestValidate_Expired(t *testing.T) {
	v, _ := New(defaultValidatorConfig())
	claims := defaultValidClaims()
	claims["exp"] = time.Now().Add(-2 * time.Minute).Unix() // beyond 30s skew
	token := buildTestJWT(t, testRSAKey, nil, claims)
	_, verr := v.Validate(context.Background(), token)
	assertValidationError(t, verr, "token_expired")
}

func TestValidate_NbfInFuture(t *testing.T) {
	v, _ := New(defaultValidatorConfig())
	claims := defaultValidClaims()
	claims["nbf"] = time.Now().Add(2 * time.Minute).Unix() // beyond 30s skew
	token := buildTestJWT(t, testRSAKey, nil, claims)
	_, verr := v.Validate(context.Background(), token)
	assertValidationError(t, verr, "token_not_yet_valid")
}

func TestValidate_EmptyToken(t *testing.T) {
	v, _ := New(defaultValidatorConfig())
	_, verr := v.Validate(context.Background(), "")
	assertValidationError(t, verr, "malformed_token")
}

func TestValidate_MalformedTwoParts(t *testing.T) {
	v, _ := New(defaultValidatorConfig())
	_, verr := v.Validate(context.Background(), "a.b")
	if verr == nil {
		t.Error("expected error for two-part token, got nil")
	}
}

func TestValidate_UnknownKID(t *testing.T) {
	v, _ := New(defaultValidatorConfig())
	token := buildTestJWT(t, testRSAKey, map[string]interface{}{"kid": "unknown-kid-xyz"}, defaultValidClaims())
	_, verr := v.Validate(context.Background(), token)
	assertValidationError(t, verr, "invalid_signature")
}

// ---------------------------------------------------------------------------
// WWW-Authenticate header formatting
// ---------------------------------------------------------------------------

func TestValidationError_WWWAuthenticateHeader(t *testing.T) {
	prmURI := testResource + "/.well-known/oauth-protected-resource"
	ve := &ValidationError{
		Code:        "invalid_token",
		Message:     "token expired",
		ResourceURI: testResource,
	}
	header := ve.WWWAuthenticateHeader(prmURI)
	if !strings.HasPrefix(header, "Bearer ") {
		t.Errorf("WWW-Authenticate must start with 'Bearer ', got: %q", header)
	}
	if !strings.Contains(header, `resource_metadata="`) {
		t.Errorf("WWW-Authenticate must contain resource_metadata, got: %q", header)
	}
	if !strings.Contains(header, prmURI) {
		t.Errorf("WWW-Authenticate must contain PRM URI, got: %q", header)
	}
	if !strings.Contains(header, `error="invalid_token"`) {
		t.Errorf("WWW-Authenticate must contain error code, got: %q", header)
	}
}

// ---------------------------------------------------------------------------
// SSRF-gated JWKS provider
// ---------------------------------------------------------------------------

type stubDenyGuard struct {
	deniedHosts map[string]bool
}

func (g *stubDenyGuard) IsHostAllowed(_ context.Context, host string) bool {
	return !g.deniedHosts[host]
}

func TestSSRFGatedJWKSProvider_RejectsInternalHosts(t *testing.T) {
	guard := &stubDenyGuard{deniedHosts: map[string]bool{
		"169.254.169.254": true,
		"10.0.0.1":        true,
		"192.168.1.1":     true,
	}}
	provider := NewSSRFGatedJWKSProvider(guard, nil)
	for host := range guard.deniedHosts {
		issuer := "http://" + host
		_, err := provider.KeyFor(context.Background(), issuer, "kid1")
		if err == nil {
			t.Errorf("expected SSRF denial for host %q, got nil", host)
		}
	}
}

// ---------------------------------------------------------------------------
// helper
// ---------------------------------------------------------------------------

func assertValidationError(t *testing.T, err error, wantCode string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected ValidationError with code %q, got nil", wantCode)
	}
	ve, ok := err.(*ValidationError)
	if !ok {
		t.Fatalf("expected *ValidationError, got %T: %v", err, err)
	}
	if ve.Code != wantCode {
		t.Errorf("ValidationError.Code = %q, want %q (message: %s)", ve.Code, wantCode, ve.Message)
	}
}

// TestNew_RoleDisjointness_RuntimeIssuer verifies that New() rejects when OwnIssuerURL
// (the real runtime issuer, e.g. "http://localhost:9470") appears in TrustedIssuers.
// The legacy sentinel alone is insufficient — the real runtime issuer must be checked.
// RED: fails until OwnIssuerURL field is added to ValidatorConfig and New() checks it.
func TestNew_RoleDisjointness_RuntimeIssuer(t *testing.T) {
	const runtimeIssuer = "http://localhost:9470"
	cfg := defaultValidatorConfig()
	cfg.OwnIssuerURL = runtimeIssuer
	cfg.TrustedIssuers = append(cfg.TrustedIssuers, runtimeIssuer)
	_, err := New(cfg)
	if err == nil {
		t.Fatalf("expected error: TrustedIssuers must not contain Straylight own runtime issuer %q", runtimeIssuer)
	}
}

// TestValidate_MissingExpClaim verifies that tokens without an exp claim are rejected.
// RFC 9068 §2.2 requires exp; an eternal token is a security vulnerability.
// RED: fails until Validate() requires exp != 0.
func TestValidate_MissingExpClaim(t *testing.T) {
	v, err := New(defaultValidatorConfig())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	claims := defaultValidClaims()
	delete(claims, "exp")
	token := buildTestJWT(t, testRSAKey, nil, claims)
	_, verr := v.Validate(context.Background(), token)
	assertValidationError(t, verr, "invalid_token")
}

// TestNew_RejectsUnsupportedAlg verifies that ES256 (and any alg not in the
// supported set) is rejected at construction with a clear error, not silently
// accepted to produce opaque failures at validation time (finding 6).
func TestNew_RejectsUnsupportedAlg(t *testing.T) {
	for _, alg := range []string{"ES256", "ES384", "PS256", "RS512"} {
		cfg := defaultValidatorConfig()
		cfg.AllowedAlgs = []string{alg}
		_, err := New(cfg)
		if err == nil {
			t.Errorf("expected error for unsupported alg %q, got nil", alg)
		}
	}
}
