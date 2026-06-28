// Package cloud_test — keyless AWS path tests (Phase 2, ADR-012).
//
// RED phase: these tests MUST FAIL until the implementation is added.
package cloud_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/straylight-ai/straylight/internal/cloud"
	"github.com/straylight-ai/straylight/internal/tokenexchange"
)

// ---------------------------------------------------------------------------
// Backward-compat characterization test (MUST keep passing forever).
//
// A service configured with static keys and web_identity=false (default) uses
// the existing AssumeRole path. The new AssumeRoleWithWebIdentity path is
// never invoked.
// ---------------------------------------------------------------------------

// TestAWSProvider_StaticPath_Unchanged is the backward-compatibility golden
// test: when WebIdentity is nil (default), only AssumeRole is called; the
// env-var map is byte-identical to pre-ADR-012 behavior.
func TestAWSProvider_StaticPath_Unchanged(t *testing.T) {
	expiry := time.Now().Add(15 * time.Minute)
	mockSTS := &mockSTSClientFull{
		assumeRoleResult: &cloud.STSCredentials{
			AccessKeyID:     "AKIASTATIC",
			SecretAccessKey: "staticSecret",
			SessionToken:    "staticToken",
			Expiration:      expiry,
		},
	}

	p := cloud.NewAWSProvider(cloud.AWSProviderConfig{
		STSClient: mockSTS,
	})

	cfg := cloud.ServiceConfig{
		Engine: "aws",
		AWS: &cloud.AWSConfig{
			RoleARN:             "arn:aws:iam::111111111111:role/StaticRole",
			Region:              "eu-west-1",
			SessionDurationSecs: 3600,
			// WebIdentity is nil — static path
		},
	}

	creds, err := p.GenerateCredentials(context.Background(), cfg)
	if err != nil {
		t.Fatalf("GenerateCredentials() error = %v", err)
	}

	// Verify env-var map matches the static AssumeRole path output exactly.
	checkEnvVar(t, creds.EnvVars, "AWS_ACCESS_KEY_ID", "AKIASTATIC")
	checkEnvVar(t, creds.EnvVars, "AWS_SECRET_ACCESS_KEY", "staticSecret")
	checkEnvVar(t, creds.EnvVars, "AWS_SESSION_TOKEN", "staticToken")
	checkEnvVar(t, creds.EnvVars, "AWS_DEFAULT_REGION", "eu-west-1")

	// AssumeRole was called.
	if !mockSTS.assumeRoleCalled {
		t.Error("AssumeRole must be called on the static path")
	}
	// AssumeRoleWithWebIdentity must NOT be called.
	if mockSTS.assumeRoleWithWebIdentityCalled {
		t.Error("AssumeRoleWithWebIdentity must NOT be called on the static path")
	}
}

// ---------------------------------------------------------------------------
// Keyless path tests.
// ---------------------------------------------------------------------------

// TestAWSProvider_KeylessPath_UsesWebIdentity verifies that when AWSConfig
// has a non-nil WebIdentity block, GenerateCredentials calls STS
// AssumeRoleWithWebIdentity (keyless) instead of AssumeRole.
func TestAWSProvider_KeylessPath_UsesWebIdentity(t *testing.T) {
	expiry := time.Now().Add(15 * time.Minute)

	// The token-exchange engine is pre-seeded with a fake identity source and
	// a fake STS adapter that records what it receives.
	fakeSTS := &fakeSTSWebIdentityClientForCloud{
		result: &tokenexchange.STSWebIdentityCredentials{
			AccessKeyID:     "ASIAKEYLESS",
			SecretAccessKey: "keylessSecret",
			SessionToken:    "keylessToken",
			Expiration:      expiry,
		},
	}
	adapter := tokenexchange.NewAWSWebIdentityAdapter(fakeSTS)
	engine := tokenexchange.NewEngine(tokenexchange.EngineConfig{
		Source: &fakeIdentitySourceForCloud{token: "fake-oidc-token"},
		Adapters: map[string]tokenexchange.ExchangeAdapter{
			"aws": adapter,
		},
		RefreshWindow: 5 * time.Minute,
		CheckInterval: 30 * time.Second,
	})
	t.Cleanup(engine.Close)

	p := cloud.NewAWSProvider(cloud.AWSProviderConfig{
		STSClient: &mockSTSClientFull{}, // static client — must NOT be called
		Engine:    engine,
	})

	cfg := cloud.ServiceConfig{
		Engine: "aws",
		AWS: &cloud.AWSConfig{
			RoleARN: "arn:aws:iam::123456789012:role/KeylessRole",
			Region:  "us-east-1",
			WebIdentity: &cloud.AWSWebIdentityConfig{
				Audience: "sts.amazonaws.com",
			},
		},
	}

	creds, err := p.GenerateCredentials(context.Background(), cfg)
	if err != nil {
		t.Fatalf("GenerateCredentials() keyless error = %v", err)
	}

	checkEnvVar(t, creds.EnvVars, "AWS_ACCESS_KEY_ID", "ASIAKEYLESS")
	checkEnvVar(t, creds.EnvVars, "AWS_SECRET_ACCESS_KEY", "keylessSecret")
	checkEnvVar(t, creds.EnvVars, "AWS_SESSION_TOKEN", "keylessToken")
	checkEnvVar(t, creds.EnvVars, "AWS_DEFAULT_REGION", "us-east-1")

	// The identity proof token must never appear in env vars (no-passthrough).
	for k, v := range creds.EnvVars {
		if v == "fake-oidc-token" {
			t.Errorf("env var %q leaks identity proof token — no-passthrough violation", k)
		}
	}

	// AssumeRoleWithWebIdentity must have been called with our OIDC token.
	if fakeSTS.lastInput.WebIdentityToken != "fake-oidc-token" {
		t.Errorf("WebIdentityToken = %q, want %q",
			fakeSTS.lastInput.WebIdentityToken, "fake-oidc-token")
	}
}

// TestAWSProvider_KeylessPath_BranchSelection verifies that the keyless branch
// is selected only when WebIdentity config is present; a nil WebIdentity
// selects the static path even when an Engine is wired.
func TestAWSProvider_KeylessPath_BranchSelection(t *testing.T) {
	expiry := time.Now().Add(15 * time.Minute)
	staticSTS := &mockSTSClientFull{
		assumeRoleResult: &cloud.STSCredentials{
			AccessKeyID:     "AKIABRANCH",
			SecretAccessKey: "branchSecret",
			SessionToken:    "branchToken",
			Expiration:      expiry,
		},
	}

	engine := tokenexchange.NewEngine(tokenexchange.EngineConfig{
		Source: &fakeIdentitySourceForCloud{token: "tok"},
		Adapters: map[string]tokenexchange.ExchangeAdapter{
			"aws": tokenexchange.NewAWSWebIdentityAdapter(&fakeSTSWebIdentityClientForCloud{}),
		},
		RefreshWindow: 5 * time.Minute,
		CheckInterval: 30 * time.Second,
	})
	t.Cleanup(engine.Close)

	p := cloud.NewAWSProvider(cloud.AWSProviderConfig{
		STSClient: staticSTS,
		Engine:    engine, // engine is wired but should NOT activate keyless path
	})

	cfg := cloud.ServiceConfig{
		Engine: "aws",
		AWS: &cloud.AWSConfig{
			RoleARN: "arn:aws:iam::111111111111:role/BranchRole",
			Region:  "us-east-1",
			// WebIdentity is nil — static path despite engine being wired
		},
	}

	_, err := p.GenerateCredentials(context.Background(), cfg)
	if err != nil {
		t.Fatalf("GenerateCredentials() error = %v", err)
	}

	if !staticSTS.assumeRoleCalled {
		t.Error("AssumeRole must be called when WebIdentity config is nil")
	}
	if staticSTS.assumeRoleWithWebIdentityCalled {
		t.Error("AssumeRoleWithWebIdentity must NOT be called when WebIdentity config is nil")
	}
}

// TestAWSProvider_KeylessPath_STSError — STS error on keyless path surfaces.
func TestAWSProvider_KeylessPath_STSError(t *testing.T) {
	stsErr := errors.New("sts: access denied via web identity")
	fakeSTS := &fakeSTSWebIdentityClientForCloud{err: stsErr}

	engine := tokenexchange.NewEngine(tokenexchange.EngineConfig{
		Source: &fakeIdentitySourceForCloud{token: "tok"},
		Adapters: map[string]tokenexchange.ExchangeAdapter{
			"aws": tokenexchange.NewAWSWebIdentityAdapter(fakeSTS),
		},
		RefreshWindow: 5 * time.Minute,
		CheckInterval: 30 * time.Second,
	})
	t.Cleanup(engine.Close)

	p := cloud.NewAWSProvider(cloud.AWSProviderConfig{
		STSClient: &mockSTSClientFull{},
		Engine:    engine,
	})

	cfg := cloud.ServiceConfig{
		Engine: "aws",
		AWS: &cloud.AWSConfig{
			RoleARN: "arn:aws:iam::123456789012:role/ErrRole",
			Region:  "us-east-1",
			WebIdentity: &cloud.AWSWebIdentityConfig{
				Audience: "sts.amazonaws.com",
			},
		},
	}

	_, err := p.GenerateCredentials(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected error from keyless STS failure, got nil")
	}
}

// ---------------------------------------------------------------------------
// Fakes used only in keyless tests.
// ---------------------------------------------------------------------------

// mockSTSClientFull implements cloud.STSClient and also tracks whether
// AssumeRoleWithWebIdentity was called. It satisfies cloud.STSClient (which
// only requires AssumeRole) via embedding / structural satisfaction.
type mockSTSClientFull struct {
	assumeRoleResult                *cloud.STSCredentials
	assumeRoleCalled                bool
	assumeRoleWithWebIdentityCalled bool
	err                             error
}

func (m *mockSTSClientFull) AssumeRole(_ context.Context, input cloud.STSAssumeRoleInput) (*cloud.STSCredentials, error) {
	m.assumeRoleCalled = true
	if m.err != nil {
		return nil, m.err
	}
	if m.assumeRoleResult != nil {
		return m.assumeRoleResult, nil
	}
	return &cloud.STSCredentials{
		AccessKeyID:     "AKIADEFAULT",
		SecretAccessKey: "defaultSecret",
		SessionToken:    "defaultToken",
		Expiration:      time.Now().Add(15 * time.Minute),
	}, nil
}

// fakeIdentitySourceForCloud is a trivial IdentitySource for cloud tests.
type fakeIdentitySourceForCloud struct {
	token string
	err   error
}

func (f *fakeIdentitySourceForCloud) Identity(_ context.Context, req tokenexchange.IdentityRequest) (*tokenexchange.IdentityProof, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &tokenexchange.IdentityProof{
		Token:     f.token,
		TokenType: "urn:ietf:params:oauth:token-type:jwt",
		Issuer:    "https://openbao.test",
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}, nil
}

func (f *fakeIdentitySourceForCloud) SourceType() string { return "fake" }

// fakeSTSWebIdentityClientForCloud implements tokenexchange.STSWebIdentityClient.
type fakeSTSWebIdentityClientForCloud struct {
	lastInput tokenexchange.STSAssumeRoleWithWebIdentityInput
	result    *tokenexchange.STSWebIdentityCredentials
	err       error
}

func (f *fakeSTSWebIdentityClientForCloud) AssumeRoleWithWebIdentity(
	_ context.Context,
	in tokenexchange.STSAssumeRoleWithWebIdentityInput,
) (*tokenexchange.STSWebIdentityCredentials, error) {
	f.lastInput = in
	if f.err != nil {
		return nil, f.err
	}
	if f.result != nil {
		return f.result, nil
	}
	return &tokenexchange.STSWebIdentityCredentials{
		AccessKeyID:     "ASIAFAKE",
		SecretAccessKey: "fakeSecret",
		SessionToken:    "fakeToken",
		Expiration:      time.Now().Add(15 * time.Minute),
	}, nil
}
