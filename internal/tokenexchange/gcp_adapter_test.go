// Package tokenexchange_test tests the GCPWIFAdapter.
package tokenexchange_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/straylight-ai/straylight/internal/tokenexchange"
)

// fakeGCPSTSClient implements tokenexchange.GCPSTSClient for tests.
type fakeGCPSTSClient struct {
	lastInput tokenexchange.GCPTokenExchangeInput
	called    bool
	err       error
	token     *tokenexchange.GCPFederatedToken
}

func (f *fakeGCPSTSClient) ExchangeToken(
	_ context.Context,
	in tokenexchange.GCPTokenExchangeInput,
) (*tokenexchange.GCPFederatedToken, error) {
	f.called = true
	f.lastInput = in
	if f.err != nil {
		return nil, f.err
	}
	if f.token != nil {
		return f.token, nil
	}
	return &tokenexchange.GCPFederatedToken{
		AccessToken: "ya29.federated-default",
		ExpiresIn:   3600,
	}, nil
}

// ---------------------------------------------------------------------------
// TestGCPWIFAdapter_ProviderType — returns "gcp".
// ---------------------------------------------------------------------------

func TestGCPWIFAdapter_ProviderType(t *testing.T) {
	a := tokenexchange.NewGCPWIFAdapter(&fakeGCPSTSClient{})
	if got := a.ProviderType(); got != "gcp" {
		t.Errorf("ProviderType() = %q, want %q", got, "gcp")
	}
}

// ---------------------------------------------------------------------------
// TestGCPWIFAdapter_Exchange_Success — GCP STS returns a federated token;
// assert identity token is forwarded as subject_token (RFC 8693) and env vars
// are set correctly.
// ---------------------------------------------------------------------------

func TestGCPWIFAdapter_Exchange_Success(t *testing.T) {
	wifAudience := "//iam.googleapis.com/projects/123456/locations/global/workloadIdentityPools/my-pool/providers/my-provider"

	fakeGCP := &fakeGCPSTSClient{
		token: &tokenexchange.GCPFederatedToken{
			AccessToken: "ya29.test-federated-token",
			ExpiresIn:   3600,
		},
	}
	a := tokenexchange.NewGCPWIFAdapter(fakeGCP)

	in := tokenexchange.ExchangeInput{
		Proof: &tokenexchange.IdentityProof{
			Token:     "oidc-identity-token-abc",
			TokenType: "urn:ietf:params:oauth:token-type:jwt",
			Issuer:    "https://openbao.example",
			ExpiresAt: time.Now().Add(5 * time.Minute),
		},
		Audience: wifAudience,
		Params: map[string]string{
			"audience": wifAudience,
			"project":  "my-gcp-project",
		},
		RequestedTTL: time.Hour,
	}

	cred, err := a.Exchange(context.Background(), in)
	if err != nil {
		t.Fatalf("Exchange() error = %v, want nil", err)
	}

	// Env vars must be present.
	if _, ok := cred.EnvVars["CLOUDSDK_AUTH_ACCESS_TOKEN"]; !ok {
		t.Error("EnvVars missing CLOUDSDK_AUTH_ACCESS_TOKEN")
	}
	if _, ok := cred.EnvVars["CLOUDSDK_CORE_PROJECT"]; !ok {
		t.Error("EnvVars missing CLOUDSDK_CORE_PROJECT")
	}

	if cred.EnvVars["CLOUDSDK_AUTH_ACCESS_TOKEN"] != "ya29.test-federated-token" {
		t.Errorf("CLOUDSDK_AUTH_ACCESS_TOKEN = %q, want %q",
			cred.EnvVars["CLOUDSDK_AUTH_ACCESS_TOKEN"], "ya29.test-federated-token")
	}
	if cred.EnvVars["CLOUDSDK_CORE_PROJECT"] != "my-gcp-project" {
		t.Errorf("CLOUDSDK_CORE_PROJECT = %q, want %q",
			cred.EnvVars["CLOUDSDK_CORE_PROJECT"], "my-gcp-project")
	}

	// The identity proof token must be forwarded as subject_token (RFC 8693).
	if fakeGCP.lastInput.SubjectToken != "oidc-identity-token-abc" {
		t.Errorf("SubjectToken = %q, want %q",
			fakeGCP.lastInput.SubjectToken, "oidc-identity-token-abc")
	}

	// Audience forwarded to GCP STS.
	if fakeGCP.lastInput.Audience != wifAudience {
		t.Errorf("Audience = %q, want %q", fakeGCP.lastInput.Audience, wifAudience)
	}

	if cred.ExpiresAt.IsZero() {
		t.Error("ExpiresAt must not be zero")
	}
	if cred.Audience != wifAudience {
		t.Errorf("Audience = %q, want %q", cred.Audience, wifAudience)
	}
}

// ---------------------------------------------------------------------------
// TestGCPWIFAdapter_NoPassthrough — the identity proof token must never appear
// as an env var value in the returned credential (MCP no-passthrough).
// ---------------------------------------------------------------------------

func TestGCPWIFAdapter_NoPassthrough(t *testing.T) {
	a := tokenexchange.NewGCPWIFAdapter(&fakeGCPSTSClient{})

	identityToken := "SENSITIVE-openbao-identity-token"
	in := tokenexchange.ExchangeInput{
		Proof: &tokenexchange.IdentityProof{
			Token:     identityToken,
			ExpiresAt: time.Now().Add(5 * time.Minute),
		},
		Audience: "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/pr",
		Params: map[string]string{
			"audience": "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/pr",
		},
	}

	cred, err := a.Exchange(context.Background(), in)
	if err != nil {
		t.Fatalf("Exchange() error = %v", err)
	}

	for k, v := range cred.EnvVars {
		if v == identityToken {
			t.Errorf("env var %q leaks the identity proof token — MCP no-passthrough violation", k)
		}
	}
}

// ---------------------------------------------------------------------------
// TestGCPWIFAdapter_MissingAudience — missing audience in params returns a
// meaningful error without calling GCP STS.
// ---------------------------------------------------------------------------

func TestGCPWIFAdapter_MissingAudience(t *testing.T) {
	fakeGCP := &fakeGCPSTSClient{}
	a := tokenexchange.NewGCPWIFAdapter(fakeGCP)

	in := tokenexchange.ExchangeInput{
		Proof: &tokenexchange.IdentityProof{
			Token:     "tok",
			ExpiresAt: time.Now().Add(5 * time.Minute),
		},
		Audience: "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/pr",
		Params:   map[string]string{}, // audience absent
	}

	_, err := a.Exchange(context.Background(), in)
	if err == nil {
		t.Fatal("Exchange() expected error for missing audience param, got nil")
	}
	if fakeGCP.called {
		t.Error("GCP STS should not be called when audience param is missing")
	}
}

// ---------------------------------------------------------------------------
// TestGCPWIFAdapter_STSError — GCP STS error bubbles up wrapped.
// ---------------------------------------------------------------------------

func TestGCPWIFAdapter_STSError(t *testing.T) {
	stsErr := errors.New("GCP STS: permission_denied")
	a := tokenexchange.NewGCPWIFAdapter(&fakeGCPSTSClient{err: stsErr})

	in := tokenexchange.ExchangeInput{
		Proof: &tokenexchange.IdentityProof{
			Token:     "token",
			ExpiresAt: time.Now().Add(5 * time.Minute),
		},
		Audience: "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/pr",
		Params: map[string]string{
			"audience": "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/pr",
		},
	}

	_, err := a.Exchange(context.Background(), in)
	if err == nil {
		t.Fatal("Exchange() expected error, got nil")
	}
	if !errors.Is(err, stsErr) {
		t.Errorf("error %v does not wrap %v", err, stsErr)
	}
}
