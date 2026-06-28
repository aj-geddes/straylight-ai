// Package tokenexchange_test tests the GitHub App installation-token adapter.
//
// Phase 4, ADR-012: GitHub App 1-hour installation tokens.
// Tests verify:
//   - RS256 App JWT is signed correctly (iss/iat/exp) with a generated test key.
//   - The adapter calls the GitHub installations endpoint and returns a token.
//   - Concurrent callers share one mint via the Engine's single-flight.
//   - No PAT path exists; the adapter requires app_id, installation_id, private_key.
package tokenexchange_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/straylight-ai/straylight/internal/tokenexchange"
)

// generateTestRSAKey produces a 2048-bit RSA key for tests.
func generateTestRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	return key
}

// encodePrivateKeyPEM encodes an RSA private key to PKCS#8 PEM.
func encodePrivateKeyPEM(t *testing.T, key *rsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	block := &pem.Block{Type: "PRIVATE KEY", Bytes: der}
	return string(pem.EncodeToMemory(block))
}

// decodeJWTClaims decodes the payload of a signed JWT without verifying the
// signature. Used to inspect claims in test assertions.
func decodeJWTClaims(t *testing.T, token string) map[string]interface{} {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 JWT parts, got %d", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode JWT payload: %v", err)
	}
	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("unmarshal JWT claims: %v", err)
	}
	return claims
}

// decodeJWTHeader decodes the header of a JWT without verifying the signature.
func decodeJWTHeader(t *testing.T, token string) map[string]interface{} {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 JWT parts, got %d", len(parts))
	}
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode JWT header: %v", err)
	}
	var h map[string]interface{}
	if err := json.Unmarshal(header, &h); err != nil {
		t.Fatalf("unmarshal JWT header: %v", err)
	}
	return h
}

// TestSignGitHubAppJWT verifies that the signed JWT has RS256 alg, correct
// iss, iat around now, and exp = iat + 600 seconds.
func TestSignGitHubAppJWT(t *testing.T) {
	key := generateTestRSAKey(t)
	appID := "123456"

	before := time.Now().Unix()
	token, err := tokenexchange.SignGitHubAppJWT(key, appID)
	after := time.Now().Unix()

	if err != nil {
		t.Fatalf("SignGitHubAppJWT: %v", err)
	}
	if token == "" {
		t.Fatal("SignGitHubAppJWT returned empty token")
	}

	header := decodeJWTHeader(t, token)
	claims := decodeJWTClaims(t, token)

	if alg, _ := header["alg"].(string); alg != "RS256" {
		t.Errorf("alg = %q, want RS256", alg)
	}
	if typ, _ := header["typ"].(string); typ != "JWT" {
		t.Errorf("typ = %q, want JWT", typ)
	}
	if iss, _ := claims["iss"].(string); iss != appID {
		t.Errorf("iss = %q, want %q", iss, appID)
	}

	iat, ok := claims["iat"].(float64)
	if !ok {
		t.Fatalf("iat not present or not a number, claims=%v", claims)
	}
	if int64(iat) < before || int64(iat) > after {
		t.Errorf("iat = %d, want between %d and %d", int64(iat), before, after)
	}

	exp, ok := claims["exp"].(float64)
	if !ok {
		t.Fatalf("exp not present or not a number")
	}
	duration := int64(exp) - int64(iat)
	if duration < 595 || duration > 605 {
		t.Errorf("exp-iat = %d seconds, want ~600 (10 minutes)", duration)
	}
}

// TestGitHubAppAdapter_MintsInstallationToken verifies the adapter calls the
// GitHub installations endpoint and returns the token in EnvVars["token"].
func TestGitHubAppAdapter_MintsInstallationToken(t *testing.T) {
	key := generateTestRSAKey(t)
	installationID := "9876543"
	wantToken := "ghs_test_installation_token_abc123"

	var capturedAuthHeader string
	var capturedPath string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		capturedAuthHeader = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]interface{}{
			"token":      wantToken,
			"expires_at": time.Now().Add(1 * time.Hour).Format(time.RFC3339),
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	adapter := tokenexchange.NewGitHubAppAdapter(tokenexchange.GitHubAppAdapterConfig{
		BaseURL: srv.URL,
	})

	in := tokenexchange.ExchangeInput{
		Audience: "api.github.com",
		Params: map[string]string{
			"app_id":          "123456",
			"installation_id": installationID,
			"private_key":     encodePrivateKeyPEM(t, key),
		},
	}

	cred, err := adapter.Exchange(context.Background(), in)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}

	if tok := cred.EnvVars["token"]; tok != wantToken {
		t.Errorf("EnvVars[token] = %q, want %q", tok, wantToken)
	}
	if cred.ExpiresAt.IsZero() {
		t.Error("ExpiresAt is zero")
	}
	if cred.Audience != "api.github.com" {
		t.Errorf("Audience = %q, want %q", cred.Audience, "api.github.com")
	}

	wantPath := fmt.Sprintf("/app/installations/%s/access_tokens", installationID)
	if capturedPath != wantPath {
		t.Errorf("request path = %q, want %q", capturedPath, wantPath)
	}

	if !strings.HasPrefix(capturedAuthHeader, "Bearer ") {
		t.Errorf("Authorization header = %q, want Bearer <jwt>", capturedAuthHeader)
	}
	jwtParts := strings.Split(strings.TrimPrefix(capturedAuthHeader, "Bearer "), ".")
	if len(jwtParts) != 3 {
		t.Errorf("Bearer value has %d parts, want 3 (invalid JWT)", len(jwtParts))
	}
}

// TestGitHubAppAdapter_MissingParams verifies errors for missing required params.
func TestGitHubAppAdapter_MissingParams(t *testing.T) {
	adapter := tokenexchange.NewGitHubAppAdapter(tokenexchange.GitHubAppAdapterConfig{})

	tests := []struct {
		name   string
		params map[string]string
	}{
		{"missing app_id", map[string]string{
			"installation_id": "123",
			"private_key":     "key",
		}},
		{"missing installation_id", map[string]string{
			"app_id":      "456",
			"private_key": "key",
		}},
		{"missing private_key", map[string]string{
			"app_id":          "456",
			"installation_id": "123",
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := adapter.Exchange(context.Background(), tokenexchange.ExchangeInput{
				Audience: "api.github.com",
				Params:   tt.params,
			})
			if err == nil {
				t.Error("expected error for missing param, got nil")
			}
		})
	}
}

// TestGitHubAppAdapter_HTTPError verifies the adapter returns an error when
// GitHub returns a non-2xx status.
func TestGitHubAppAdapter_HTTPError(t *testing.T) {
	key := generateTestRSAKey(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"message":"A JSON web token could not be decoded"}`))
	}))
	defer srv.Close()

	adapter := tokenexchange.NewGitHubAppAdapter(tokenexchange.GitHubAppAdapterConfig{
		BaseURL: srv.URL,
	})

	_, err := adapter.Exchange(context.Background(), tokenexchange.ExchangeInput{
		Audience: "api.github.com",
		Params: map[string]string{
			"app_id":          "123456",
			"installation_id": "9876543",
			"private_key":     encodePrivateKeyPEM(t, key),
		},
	})
	if err == nil {
		t.Fatal("expected error for 401 response, got nil")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("error = %q, want it to mention status 401", err.Error())
	}
}

// TestGitHubAppAdapter_ConcurrentCalls_ShareOneMint verifies that N concurrent
// Engine.Credential calls for the same service share one mint (single-flight).
func TestGitHubAppAdapter_ConcurrentCalls_ShareOneMint(t *testing.T) {
	key := generateTestRSAKey(t)

	var callCount int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&callCount, 1)
		time.Sleep(20 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]interface{}{
			"token":      "ghs_concurrent_token",
			"expires_at": time.Now().Add(1 * time.Hour).Format(time.RFC3339),
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	adapter := tokenexchange.NewGitHubAppAdapter(tokenexchange.GitHubAppAdapterConfig{
		BaseURL: srv.URL,
	})

	engine := tokenexchange.NewEngine(tokenexchange.EngineConfig{
		Source: &testStaticIdentitySource{},
		Adapters: map[string]tokenexchange.ExchangeAdapter{
			"github_app": adapter,
		},
		RefreshWindow: 5 * time.Minute,
		CheckInterval: 1 * time.Hour,
	})
	defer engine.Close()

	in := tokenexchange.ExchangeInput{
		Audience: "api.github.com",
		Params: map[string]string{
			"app_id":          "123456",
			"installation_id": "9876543",
			"private_key":     encodePrivateKeyPEM(t, key),
		},
	}

	const n = 20
	var wg sync.WaitGroup
	var mu sync.Mutex
	var tokens []string

	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			cred, err := engine.Credential(context.Background(), "my-github-svc", "github_app", in)
			if err != nil {
				t.Errorf("Credential: %v", err)
				return
			}
			mu.Lock()
			tokens = append(tokens, cred.EnvVars["token"])
			mu.Unlock()
		}()
	}
	wg.Wait()

	if count := atomic.LoadInt32(&callCount); count != 1 {
		t.Errorf("GitHub endpoint called %d times, want 1 (single-flight)", count)
	}
	for i, tok := range tokens {
		if tok != "ghs_concurrent_token" {
			t.Errorf("tokens[%d] = %q, want %q", i, tok, "ghs_concurrent_token")
		}
	}
}

// TestGitHubAppAdapter_ProviderType verifies the adapter identifies as "github_app".
func TestGitHubAppAdapter_ProviderType(t *testing.T) {
	adapter := tokenexchange.NewGitHubAppAdapter(tokenexchange.GitHubAppAdapterConfig{})
	if pt := adapter.ProviderType(); pt != "github_app" {
		t.Errorf("ProviderType() = %q, want %q", pt, "github_app")
	}
}

// testStaticIdentitySource is a test stub IdentitySource that returns a fixed
// proof. Used by engine-based tests in this file.
type testStaticIdentitySource struct{}

func (s *testStaticIdentitySource) Identity(_ context.Context, _ tokenexchange.IdentityRequest) (*tokenexchange.IdentityProof, error) {
	return &tokenexchange.IdentityProof{
		Token:     "test-identity-token",
		TokenType: "urn:ietf:params:oauth:token-type:jwt",
		Issuer:    "http://localhost",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}, nil
}

func (s *testStaticIdentitySource) SourceType() string { return "test" }
