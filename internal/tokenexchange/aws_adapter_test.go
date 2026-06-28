// Package tokenexchange_test tests the AWSWebIdentityAdapter.
package tokenexchange_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/straylight-ai/straylight/internal/tokenexchange"
)

// fakeSTSWebIdentityClient implements tokenexchange.STSWebIdentityClient for tests.
type fakeSTSWebIdentityClient struct {
	lastInput tokenexchange.STSAssumeRoleWithWebIdentityInput
	called    bool
	err       error
}

func (f *fakeSTSWebIdentityClient) AssumeRoleWithWebIdentity(
	_ context.Context,
	in tokenexchange.STSAssumeRoleWithWebIdentityInput,
) (*tokenexchange.STSWebIdentityCredentials, error) {
	f.lastInput = in
	f.called = true
	if f.err != nil {
		return nil, f.err
	}
	return &tokenexchange.STSWebIdentityCredentials{
		AccessKeyID:     "ASIA111",
		SecretAccessKey: "secret123",
		SessionToken:    "sesstoken456",
		Expiration:      time.Now().Add(15 * time.Minute),
	}, nil
}

// ---------------------------------------------------------------------------
// TestAWSWebIdentityAdapter_ProviderType — returns "aws".
// ---------------------------------------------------------------------------

func TestAWSWebIdentityAdapter_ProviderType(t *testing.T) {
	a := tokenexchange.NewAWSWebIdentityAdapter(&fakeSTSWebIdentityClient{})
	if got := a.ProviderType(); got != "aws" {
		t.Errorf("ProviderType() = %q, want %q", got, "aws")
	}
}

// ---------------------------------------------------------------------------
// TestAWSWebIdentityAdapter_Exchange_Success — STS returns creds mapped to
// AWS_* env vars; WebIdentityToken matches the identity proof token.
// ---------------------------------------------------------------------------

func TestAWSWebIdentityAdapter_Exchange_Success(t *testing.T) {
	fakeSTS := &fakeSTSWebIdentityClient{}
	a := tokenexchange.NewAWSWebIdentityAdapter(fakeSTS)

	in := tokenexchange.ExchangeInput{
		Proof: &tokenexchange.IdentityProof{
			Token:     "oidc-identity-token-xyz",
			TokenType: "urn:ietf:params:oauth:token-type:jwt",
			Issuer:    "https://openbao.example",
			ExpiresAt: time.Now().Add(5 * time.Minute),
		},
		Audience: "sts.amazonaws.com",
		Params: map[string]string{
			"role_arn":     "arn:aws:iam::123456789012:role/StrayLight",
			"session_name": "straylight-exec",
		},
		RequestedTTL: 15 * time.Minute,
	}

	cred, err := a.Exchange(context.Background(), in)
	if err != nil {
		t.Fatalf("Exchange() error = %v, want nil", err)
	}

	// Env vars must be present.
	for _, key := range []string{
		"AWS_ACCESS_KEY_ID",
		"AWS_SECRET_ACCESS_KEY",
		"AWS_SESSION_TOKEN",
		"AWS_DEFAULT_REGION",
	} {
		if _, ok := cred.EnvVars[key]; !ok {
			t.Errorf("EnvVars missing %q", key)
		}
	}

	if cred.EnvVars["AWS_ACCESS_KEY_ID"] != "ASIA111" {
		t.Errorf("AWS_ACCESS_KEY_ID = %q, want %q", cred.EnvVars["AWS_ACCESS_KEY_ID"], "ASIA111")
	}

	// WebIdentityToken must equal the proof token.
	if fakeSTS.lastInput.WebIdentityToken != "oidc-identity-token-xyz" {
		t.Errorf("WebIdentityToken = %q, want %q",
			fakeSTS.lastInput.WebIdentityToken, "oidc-identity-token-xyz")
	}

	// RoleARN forwarded from params.
	if fakeSTS.lastInput.RoleARN != "arn:aws:iam::123456789012:role/StrayLight" {
		t.Errorf("RoleARN = %q, want arn:aws:iam::123456789012:role/StrayLight",
			fakeSTS.lastInput.RoleARN)
	}

	if cred.ExpiresAt.IsZero() {
		t.Error("ExpiresAt must not be zero")
	}
	if cred.Audience != "sts.amazonaws.com" {
		t.Errorf("Audience = %q, want %q", cred.Audience, "sts.amazonaws.com")
	}
}

// ---------------------------------------------------------------------------
// TestAWSWebIdentityAdapter_Exchange_STSError — STS error bubbles up.
// ---------------------------------------------------------------------------

func TestAWSWebIdentityAdapter_Exchange_STSError(t *testing.T) {
	stsErr := errors.New("STS: AccessDenied")
	a := tokenexchange.NewAWSWebIdentityAdapter(&fakeSTSWebIdentityClient{err: stsErr})

	in := tokenexchange.ExchangeInput{
		Proof: &tokenexchange.IdentityProof{
			Token:     "token",
			ExpiresAt: time.Now().Add(5 * time.Minute),
		},
		Audience: "sts.amazonaws.com",
		Params: map[string]string{
			"role_arn": "arn:aws:iam::123456789012:role/R",
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

// ---------------------------------------------------------------------------
// TestAWSWebIdentityAdapter_NoPassthrough — the identity proof token must
// never appear as an env var value in the returned credential.
// ---------------------------------------------------------------------------

func TestAWSWebIdentityAdapter_NoPassthrough(t *testing.T) {
	a := tokenexchange.NewAWSWebIdentityAdapter(&fakeSTSWebIdentityClient{})

	identityToken := "SENSITIVE-identity-proof-token"
	in := tokenexchange.ExchangeInput{
		Proof: &tokenexchange.IdentityProof{
			Token:     identityToken,
			ExpiresAt: time.Now().Add(5 * time.Minute),
		},
		Audience: "sts.amazonaws.com",
		Params: map[string]string{
			"role_arn": "arn:aws:iam::123456789012:role/R",
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
// TestAWSWebIdentityAdapter_MissingRoleARN — missing role_arn in params
// returns a meaningful error without calling STS.
// ---------------------------------------------------------------------------

func TestAWSWebIdentityAdapter_MissingRoleARN(t *testing.T) {
	fakeSTS := &fakeSTSWebIdentityClient{}
	a := tokenexchange.NewAWSWebIdentityAdapter(fakeSTS)

	in := tokenexchange.ExchangeInput{
		Proof: &tokenexchange.IdentityProof{
			Token:     "tok",
			ExpiresAt: time.Now().Add(5 * time.Minute),
		},
		Audience: "sts.amazonaws.com",
		Params:   map[string]string{}, // role_arn absent
	}

	_, err := a.Exchange(context.Background(), in)
	if err == nil {
		t.Fatal("Exchange() expected error for missing role_arn, got nil")
	}
	if fakeSTS.called {
		t.Error("STS should not be called when role_arn is missing")
	}
}

// ---------------------------------------------------------------------------
// TestAWSWebIdentityAdapter_DurationSecs_Cap — duration_secs above the STS max
// of 43200 must be clamped to 43200 (never sent as-is to avoid a clear STS
// error; reject-on-misconfiguration makes failures visible immediately).
// ---------------------------------------------------------------------------

// TestAWSWebIdentityAdapter_DurationSecs_Clamped verifies that a duration_secs
// above the STS maximum of 43200 is clamped to 43200.
func TestAWSWebIdentityAdapter_DurationSecs_Clamped(t *testing.T) {
	fakeSTS := &fakeSTSWebIdentityClient{}
	a := tokenexchange.NewAWSWebIdentityAdapter(fakeSTS)

	in := tokenexchange.ExchangeInput{
		Proof: &tokenexchange.IdentityProof{
			Token:     "tok",
			ExpiresAt: time.Now().Add(5 * time.Minute),
		},
		Audience: "sts.amazonaws.com",
		Params: map[string]string{
			"role_arn":      "arn:aws:iam::123456789012:role/R",
			"duration_secs": "99999", // over the STS maximum of 43200
		},
	}

	_, err := a.Exchange(context.Background(), in)
	if err != nil {
		t.Fatalf("Exchange() error = %v; expected clamp, not error", err)
	}

	// The value forwarded to STS must be clamped at 43200.
	const awsSTSMaxDurationSecs = int32(43200)
	if fakeSTS.lastInput.DurationSeconds > awsSTSMaxDurationSecs {
		t.Errorf("DurationSeconds = %d forwarded to STS; must be <= %d (STS max)",
			fakeSTS.lastInput.DurationSeconds, awsSTSMaxDurationSecs)
	}
}

// TestAWSWebIdentityAdapter_DurationSecs_ExactMax verifies that exactly 43200
// passes through unchanged.
func TestAWSWebIdentityAdapter_DurationSecs_ExactMax(t *testing.T) {
	fakeSTS := &fakeSTSWebIdentityClient{}
	a := tokenexchange.NewAWSWebIdentityAdapter(fakeSTS)

	in := tokenexchange.ExchangeInput{
		Proof: &tokenexchange.IdentityProof{
			Token:     "tok",
			ExpiresAt: time.Now().Add(5 * time.Minute),
		},
		Audience: "sts.amazonaws.com",
		Params: map[string]string{
			"role_arn":      "arn:aws:iam::123456789012:role/R",
			"duration_secs": "43200",
		},
	}

	_, err := a.Exchange(context.Background(), in)
	if err != nil {
		t.Fatalf("Exchange() error = %v", err)
	}

	if fakeSTS.lastInput.DurationSeconds != 43200 {
		t.Errorf("DurationSeconds = %d, want 43200", fakeSTS.lastInput.DurationSeconds)
	}
}
