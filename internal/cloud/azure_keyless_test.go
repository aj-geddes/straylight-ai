// Package cloud_test — keyless Azure path tests (Phase 2, ADR-012).
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
// A service configured with a static client_secret and no WebIdentity uses the
// existing client_credentials path. The keyless branch is never invoked.
// ---------------------------------------------------------------------------

// TestAzureProvider_StaticPath_Unchanged is the backward-compatibility golden
// test: when WebIdentity is nil (default), only the static client_credentials
// flow is used; the env-var map is byte-identical to pre-ADR-012 behavior.
func TestAzureProvider_StaticPath_Unchanged(t *testing.T) {
	srv := azureTokenServer(t, "static-azure-token")
	defer srv.Close()

	p := cloud.NewAzureProvider(cloud.AzureProviderConfig{
		TokenEndpointOverride: srv.URL,
		// Engine is nil — no keyless engine wired
	})

	cfg := cloud.ServiceConfig{
		Engine: "azure",
		Azure: &cloud.AzureConfig{
			TenantID:       "static-tenant-id",
			ClientID:       "static-client-id",
			ClientSecret:   "static-client-secret",
			SubscriptionID: "static-subscription-id",
			Scope:          "https://management.azure.com/.default",
			// WebIdentity is nil — static path
		},
	}

	creds, err := p.GenerateCredentials(context.Background(), cfg)
	if err != nil {
		t.Fatalf("GenerateCredentials() error = %v", err)
	}

	// Env-var map must match static path output exactly (byte-identical contract).
	checkEnvVar(t, creds.EnvVars, "AZURE_ACCESS_TOKEN", "static-azure-token")
	checkEnvVar(t, creds.EnvVars, "AZURE_TENANT_ID", "static-tenant-id")
	checkEnvVar(t, creds.EnvVars, "AZURE_SUBSCRIPTION_ID", "static-subscription-id")
	checkEnvVar(t, creds.EnvVars, "AZURE_CLIENT_ID", "static-client-id")

	// Client secret must never appear in output.
	for k, v := range creds.EnvVars {
		if v == "static-client-secret" {
			t.Errorf("env var %q leaks client_secret — static credential must never appear in output", k)
		}
	}

	if creds.ExpiresAt.IsZero() {
		t.Error("ExpiresAt must not be zero")
	}
	if creds.Provider != "azure" {
		t.Errorf("Provider = %q, want %q", creds.Provider, "azure")
	}
}

// ---------------------------------------------------------------------------
// Keyless path tests.
// ---------------------------------------------------------------------------

// TestAzureProvider_KeylessPath_UsesFIC verifies that when AzureConfig has a
// non-nil WebIdentity block, GenerateCredentials calls the Engine/Azure FIC
// adapter (keyless) instead of the static client_credentials path.
func TestAzureProvider_KeylessPath_UsesFIC(t *testing.T) {
	fakeAzure := &fakeAzureTokenClientForCloud{
		result: &tokenexchange.AzureFederatedToken{
			AccessToken: "keyless-azure-token",
			ExpiresIn:   3600,
		},
	}
	adapter := tokenexchange.NewAzureFICAdapter(fakeAzure)
	engine := tokenexchange.NewEngine(tokenexchange.EngineConfig{
		Source: &fakeIdentitySourceForCloud{token: "fake-oidc-token"},
		Adapters: map[string]tokenexchange.ExchangeAdapter{
			"azure": adapter,
		},
		RefreshWindow: 5 * time.Minute,
		CheckInterval: 30 * time.Second,
	})
	t.Cleanup(engine.Close)

	p := cloud.NewAzureProvider(cloud.AzureProviderConfig{
		Engine: engine,
	})

	cfg := cloud.ServiceConfig{
		Engine: "azure",
		Azure: &cloud.AzureConfig{
			TenantID:       "keyless-tenant-id",
			ClientID:       "keyless-client-id",
			SubscriptionID: "keyless-subscription-id",
			// ClientSecret is intentionally absent — keyless path
			WebIdentity: &cloud.AzureWebIdentityConfig{
				ClientID:       "keyless-client-id",
				TenantID:       "keyless-tenant-id",
				Audience:       "api://AzureADTokenExchange",
				SubscriptionID: "keyless-subscription-id",
			},
		},
	}

	creds, err := p.GenerateCredentials(context.Background(), cfg)
	if err != nil {
		t.Fatalf("GenerateCredentials() keyless error = %v", err)
	}

	checkEnvVar(t, creds.EnvVars, "AZURE_ACCESS_TOKEN", "keyless-azure-token")

	// The identity proof token must never appear in env vars (no-passthrough).
	for k, v := range creds.EnvVars {
		if v == "fake-oidc-token" {
			t.Errorf("env var %q leaks identity proof token — no-passthrough violation", k)
		}
	}

	// The FIC adapter must have received the identity token as ClientAssertion.
	if fakeAzure.lastInput.ClientAssertion != "fake-oidc-token" {
		t.Errorf("ClientAssertion = %q, want %q",
			fakeAzure.lastInput.ClientAssertion, "fake-oidc-token")
	}
}

// TestAzureProvider_KeylessPath_BranchSelection verifies that the keyless
// branch is selected only when WebIdentity config is present; a nil WebIdentity
// uses the static client_credentials path even when an Engine is wired.
func TestAzureProvider_KeylessPath_BranchSelection(t *testing.T) {
	srv := azureTokenServer(t, "branch-static-token")
	defer srv.Close()

	engine := tokenexchange.NewEngine(tokenexchange.EngineConfig{
		Source: &fakeIdentitySourceForCloud{token: "tok"},
		Adapters: map[string]tokenexchange.ExchangeAdapter{
			"azure": tokenexchange.NewAzureFICAdapter(&fakeAzureTokenClientForCloud{}),
		},
		RefreshWindow: 5 * time.Minute,
		CheckInterval: 30 * time.Second,
	})
	t.Cleanup(engine.Close)

	p := cloud.NewAzureProvider(cloud.AzureProviderConfig{
		TokenEndpointOverride: srv.URL,
		Engine:                engine, // wired but should NOT activate keyless path
	})

	cfg := cloud.ServiceConfig{
		Engine: "azure",
		Azure: &cloud.AzureConfig{
			TenantID:     "branch-tenant-id",
			ClientID:     "branch-client-id",
			ClientSecret: "branch-client-secret",
			Scope:        "https://management.azure.com/.default",
			// WebIdentity is nil — static path despite engine being wired
		},
	}

	creds, err := p.GenerateCredentials(context.Background(), cfg)
	if err != nil {
		t.Fatalf("GenerateCredentials() error = %v", err)
	}

	checkEnvVar(t, creds.EnvVars, "AZURE_ACCESS_TOKEN", "branch-static-token")
}

// TestAzureProvider_KeylessPath_AdapterError — FIC adapter error on keyless path surfaces.
func TestAzureProvider_KeylessPath_AdapterError(t *testing.T) {
	ficErr := errors.New("azure AD: AADSTS70011 invalid scope")
	fakeAzure := &fakeAzureTokenClientForCloud{err: ficErr}

	engine := tokenexchange.NewEngine(tokenexchange.EngineConfig{
		Source: &fakeIdentitySourceForCloud{token: "tok"},
		Adapters: map[string]tokenexchange.ExchangeAdapter{
			"azure": tokenexchange.NewAzureFICAdapter(fakeAzure),
		},
		RefreshWindow: 5 * time.Minute,
		CheckInterval: 30 * time.Second,
	})
	t.Cleanup(engine.Close)

	p := cloud.NewAzureProvider(cloud.AzureProviderConfig{
		Engine: engine,
	})

	cfg := cloud.ServiceConfig{
		Engine: "azure",
		Azure: &cloud.AzureConfig{
			TenantID: "err-tenant-id",
			ClientID: "err-client-id",
			WebIdentity: &cloud.AzureWebIdentityConfig{
				TenantID: "err-tenant-id",
				ClientID: "err-client-id",
				Audience: "api://AzureADTokenExchange",
			},
		},
	}

	_, err := p.GenerateCredentials(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected error from keyless FIC failure, got nil")
	}
}

// ---------------------------------------------------------------------------
// Fakes used only in Azure keyless tests.
// ---------------------------------------------------------------------------

// fakeAzureTokenClientForCloud implements tokenexchange.AzureTokenClient.
type fakeAzureTokenClientForCloud struct {
	lastInput tokenexchange.AzureTokenExchangeInput
	result    *tokenexchange.AzureFederatedToken
	err       error
}

func (f *fakeAzureTokenClientForCloud) ExchangeToken(
	_ context.Context,
	in tokenexchange.AzureTokenExchangeInput,
) (*tokenexchange.AzureFederatedToken, error) {
	f.lastInput = in
	if f.err != nil {
		return nil, f.err
	}
	if f.result != nil {
		return f.result, nil
	}
	return &tokenexchange.AzureFederatedToken{
		AccessToken: "keyless-azure-token",
		ExpiresIn:   3600,
	}, nil
}
