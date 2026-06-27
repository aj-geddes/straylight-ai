// Package cloud_test — keyless GCP path tests (Phase 2, ADR-012).
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
// A service configured with static SA-JSON and no WebIdentity uses the existing
// SA-JSON path. The keyless branch is never invoked.
// ---------------------------------------------------------------------------

// TestGCPProvider_StaticPath_Unchanged is the backward-compatibility golden
// test: when WebIdentity is nil (default), only the SA-JSON token path is
// used; the env-var map is byte-identical to pre-ADR-012 behavior.
func TestGCPProvider_StaticPath_Unchanged(t *testing.T) {
	srv := gcpTokenServer(t, "ya29.static-token", 3600)
	defer srv.Close()

	p := cloud.NewGCPProvider(cloud.GCPProviderConfig{
		TokenEndpointOverride: srv.URL,
		// Engine is nil — no engine wired
	})

	cfg := cloud.ServiceConfig{
		Engine: "gcp",
		GCP: &cloud.GCPConfig{
			ServiceAccountJSON: validServiceAccountJSON(t, srv.URL),
			ProjectID:          "static-project",
			// WebIdentity is nil — static path
		},
	}

	creds, err := p.GenerateCredentials(context.Background(), cfg)
	if err != nil {
		t.Fatalf("GenerateCredentials() error = %v", err)
	}

	// Env-var map must match static path output exactly (byte-identical contract).
	checkEnvVar(t, creds.EnvVars, "CLOUDSDK_AUTH_ACCESS_TOKEN", "ya29.static-token")
	checkEnvVar(t, creds.EnvVars, "CLOUDSDK_CORE_PROJECT", "static-project")

	if creds.ExpiresAt.IsZero() {
		t.Error("ExpiresAt must not be zero")
	}
	if creds.Provider != "gcp" {
		t.Errorf("Provider = %q, want %q", creds.Provider, "gcp")
	}
}

// ---------------------------------------------------------------------------
// Keyless path tests.
// ---------------------------------------------------------------------------

// TestGCPProvider_KeylessPath_UsesWIF verifies that when GCPConfig has a
// non-nil WebIdentity block, GenerateCredentials calls the Engine/GCP WIF
// adapter (keyless) instead of the static SA-JSON path.
func TestGCPProvider_KeylessPath_UsesWIF(t *testing.T) {
	expiry := time.Now().Add(time.Hour)

	fakeGCP := &fakeGCPSTSClientForCloud{
		result: &tokenexchange.GCPFederatedToken{
			AccessToken: "ya29.keyless-token",
			ExpiresIn:   3600,
		},
	}
	adapter := tokenexchange.NewGCPWIFAdapter(fakeGCP)
	engine := tokenexchange.NewEngine(tokenexchange.EngineConfig{
		Source: &fakeIdentitySourceForCloud{token: "fake-oidc-token"},
		Adapters: map[string]tokenexchange.ExchangeAdapter{
			"gcp": adapter,
		},
		RefreshWindow: 5 * time.Minute,
		CheckInterval: 30 * time.Second,
	})
	t.Cleanup(engine.Close)

	_ = expiry // used via fakeGCP result

	p := cloud.NewGCPProvider(cloud.GCPProviderConfig{
		Engine: engine,
	})

	wifAudience := "//iam.googleapis.com/projects/123456/locations/global/workloadIdentityPools/my-pool/providers/my-provider"
	cfg := cloud.ServiceConfig{
		Engine: "gcp",
		GCP: &cloud.GCPConfig{
			ProjectID: "keyless-project",
			WebIdentity: &cloud.GCPWebIdentityConfig{
				Audience: wifAudience,
			},
		},
	}

	creds, err := p.GenerateCredentials(context.Background(), cfg)
	if err != nil {
		t.Fatalf("GenerateCredentials() keyless error = %v", err)
	}

	checkEnvVar(t, creds.EnvVars, "CLOUDSDK_AUTH_ACCESS_TOKEN", "ya29.keyless-token")
	checkEnvVar(t, creds.EnvVars, "CLOUDSDK_CORE_PROJECT", "keyless-project")

	// The identity proof token must never appear in env vars (no-passthrough).
	for k, v := range creds.EnvVars {
		if v == "fake-oidc-token" {
			t.Errorf("env var %q leaks identity proof token — no-passthrough violation", k)
		}
	}

	// GCP WIF adapter must have received our OIDC identity token as subject_token.
	if fakeGCP.lastInput.SubjectToken != "fake-oidc-token" {
		t.Errorf("SubjectToken = %q, want %q",
			fakeGCP.lastInput.SubjectToken, "fake-oidc-token")
	}
}

// TestGCPProvider_KeylessPath_BranchSelection verifies that the keyless branch
// is selected only when WebIdentity config is present; a nil WebIdentity uses
// the static SA-JSON path even when an Engine is wired.
func TestGCPProvider_KeylessPath_BranchSelection(t *testing.T) {
	srv := gcpTokenServer(t, "ya29.branch-static", 3600)
	defer srv.Close()

	engine := tokenexchange.NewEngine(tokenexchange.EngineConfig{
		Source: &fakeIdentitySourceForCloud{token: "tok"},
		Adapters: map[string]tokenexchange.ExchangeAdapter{
			"gcp": tokenexchange.NewGCPWIFAdapter(&fakeGCPSTSClientForCloud{}),
		},
		RefreshWindow: 5 * time.Minute,
		CheckInterval: 30 * time.Second,
	})
	t.Cleanup(engine.Close)

	p := cloud.NewGCPProvider(cloud.GCPProviderConfig{
		TokenEndpointOverride: srv.URL,
		Engine:                engine, // wired but should NOT activate keyless path
	})

	cfg := cloud.ServiceConfig{
		Engine: "gcp",
		GCP: &cloud.GCPConfig{
			ServiceAccountJSON: validServiceAccountJSON(t, srv.URL),
			ProjectID:          "branch-project",
			// WebIdentity is nil — static path despite engine being wired
		},
	}

	creds, err := p.GenerateCredentials(context.Background(), cfg)
	if err != nil {
		t.Fatalf("GenerateCredentials() error = %v", err)
	}

	checkEnvVar(t, creds.EnvVars, "CLOUDSDK_AUTH_ACCESS_TOKEN", "ya29.branch-static")
}

// TestGCPProvider_KeylessPath_STSError — GCP STS error on keyless path surfaces.
func TestGCPProvider_KeylessPath_STSError(t *testing.T) {
	stsErr := errors.New("gcp sts: permission_denied via workload identity")
	fakeGCP := &fakeGCPSTSClientForCloud{err: stsErr}

	engine := tokenexchange.NewEngine(tokenexchange.EngineConfig{
		Source: &fakeIdentitySourceForCloud{token: "tok"},
		Adapters: map[string]tokenexchange.ExchangeAdapter{
			"gcp": tokenexchange.NewGCPWIFAdapter(fakeGCP),
		},
		RefreshWindow: 5 * time.Minute,
		CheckInterval: 30 * time.Second,
	})
	t.Cleanup(engine.Close)

	p := cloud.NewGCPProvider(cloud.GCPProviderConfig{
		Engine: engine,
	})

	cfg := cloud.ServiceConfig{
		Engine: "gcp",
		GCP: &cloud.GCPConfig{
			ProjectID: "err-project",
			WebIdentity: &cloud.GCPWebIdentityConfig{
				Audience: "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/pr",
			},
		},
	}

	_, err := p.GenerateCredentials(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected error from keyless GCP WIF failure, got nil")
	}
}

// ---------------------------------------------------------------------------
// Fakes used only in GCP keyless tests.
// ---------------------------------------------------------------------------

// fakeGCPSTSClientForCloud implements tokenexchange.GCPSTSClient.
type fakeGCPSTSClientForCloud struct {
	lastInput tokenexchange.GCPTokenExchangeInput
	result    *tokenexchange.GCPFederatedToken
	err       error
}

func (f *fakeGCPSTSClientForCloud) ExchangeToken(
	_ context.Context,
	in tokenexchange.GCPTokenExchangeInput,
) (*tokenexchange.GCPFederatedToken, error) {
	f.lastInput = in
	if f.err != nil {
		return nil, f.err
	}
	if f.result != nil {
		return f.result, nil
	}
	return &tokenexchange.GCPFederatedToken{
		AccessToken: "ya29.keyless-token",
		ExpiresIn:   3600,
	}, nil
}
