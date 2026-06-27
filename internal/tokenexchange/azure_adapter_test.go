// Package tokenexchange_test tests the AzureFICAdapter.
package tokenexchange_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/straylight-ai/straylight/internal/tokenexchange"
)

// fakeAzureTokenClient implements tokenexchange.AzureTokenClient for tests.
type fakeAzureTokenClient struct {
	lastInput tokenexchange.AzureTokenExchangeInput
	called    bool
	err       error
	token     *tokenexchange.AzureFederatedToken
}

func (f *fakeAzureTokenClient) ExchangeToken(
	_ context.Context,
	in tokenexchange.AzureTokenExchangeInput,
) (*tokenexchange.AzureFederatedToken, error) {
	f.called = true
	f.lastInput = in
	if f.err != nil {
		return nil, f.err
	}
	if f.token != nil {
		return f.token, nil
	}
	return &tokenexchange.AzureFederatedToken{
		AccessToken: "azure-test-token",
		ExpiresIn:   3600,
	}, nil
}

// TestAzureFICAdapter_ProviderType returns "azure".
func TestAzureFICAdapter_ProviderType(t *testing.T) {
	a := tokenexchange.NewAzureFICAdapter(&fakeAzureTokenClient{})
	if got := a.ProviderType(); got != "azure" {
		t.Errorf("ProviderType() = %q, want %q", got, "azure")
	}
}

// TestAzureFICAdapter_Exchange_Success verifies that the identity token is
// forwarded as ClientAssertion (jwt-bearer) and all env vars are set.
func TestAzureFICAdapter_Exchange_Success(t *testing.T) {
	fakeClient := &fakeAzureTokenClient{
		token: &tokenexchange.AzureFederatedToken{
			AccessToken: "eyJ0eXAiOiJKV1Q.azure-access-token",
			ExpiresIn:   3600,
		},
	}
	a := tokenexchange.NewAzureFICAdapter(fakeClient)

	in := tokenexchange.ExchangeInput{
		Proof: &tokenexchange.IdentityProof{
			Token:     "openbao-oidc-identity-token",
			TokenType: "urn:ietf:params:oauth:token-type:jwt",
			Issuer:    "https://openbao.example",
			ExpiresAt: time.Now().Add(5 * time.Minute),
		},
		Audience: "https://management.azure.com/.default",
		Params: map[string]string{
			"tenant_id":       "11111111-1111-1111-1111-111111111111",
			"client_id":       "22222222-2222-2222-2222-222222222222",
			"scope":           "https://management.azure.com/.default",
			"subscription_id": "33333333-3333-3333-3333-333333333333",
		},
		RequestedTTL: time.Hour,
	}

	cred, err := a.Exchange(context.Background(), in)
	if err != nil {
		t.Fatalf("Exchange() error = %v, want nil", err)
	}

	// Required env vars.
	for _, key := range []string{"AZURE_ACCESS_TOKEN", "AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_SUBSCRIPTION_ID"} {
		if _, ok := cred.EnvVars[key]; !ok {
			t.Errorf("EnvVars missing %q", key)
		}
	}

	if cred.EnvVars["AZURE_ACCESS_TOKEN"] != "eyJ0eXAiOiJKV1Q.azure-access-token" {
		t.Errorf("AZURE_ACCESS_TOKEN = %q, want %q", cred.EnvVars["AZURE_ACCESS_TOKEN"], "eyJ0eXAiOiJKV1Q.azure-access-token")
	}
	if cred.EnvVars["AZURE_TENANT_ID"] != "11111111-1111-1111-1111-111111111111" {
		t.Errorf("AZURE_TENANT_ID = %q, want %q", cred.EnvVars["AZURE_TENANT_ID"], "11111111-1111-1111-1111-111111111111")
	}
	if cred.EnvVars["AZURE_CLIENT_ID"] != "22222222-2222-2222-2222-222222222222" {
		t.Errorf("AZURE_CLIENT_ID = %q, want %q", cred.EnvVars["AZURE_CLIENT_ID"], "22222222-2222-2222-2222-222222222222")
	}
	if cred.EnvVars["AZURE_SUBSCRIPTION_ID"] != "33333333-3333-3333-3333-333333333333" {
		t.Errorf("AZURE_SUBSCRIPTION_ID = %q, want %q", cred.EnvVars["AZURE_SUBSCRIPTION_ID"], "33333333-3333-3333-3333-333333333333")
	}

	// Identity proof token must be forwarded as ClientAssertion (jwt-bearer, not client_secret).
	if fakeClient.lastInput.ClientAssertion != "openbao-oidc-identity-token" {
		t.Errorf("ClientAssertion = %q, want %q", fakeClient.lastInput.ClientAssertion, "openbao-oidc-identity-token")
	}
	if fakeClient.lastInput.TenantID != "11111111-1111-1111-1111-111111111111" {
		t.Errorf("TenantID = %q, want %q", fakeClient.lastInput.TenantID, "11111111-1111-1111-1111-111111111111")
	}
	if fakeClient.lastInput.ClientID != "22222222-2222-2222-2222-222222222222" {
		t.Errorf("ClientID = %q, want %q", fakeClient.lastInput.ClientID, "22222222-2222-2222-2222-222222222222")
	}
	if fakeClient.lastInput.Scope != "https://management.azure.com/.default" {
		t.Errorf("Scope = %q, want %q", fakeClient.lastInput.Scope, "https://management.azure.com/.default")
	}

	if cred.ExpiresAt.IsZero() {
		t.Error("ExpiresAt must not be zero")
	}
	if cred.Audience != "https://management.azure.com/.default" {
		t.Errorf("Audience = %q, want %q", cred.Audience, "https://management.azure.com/.default")
	}
}

// TestAzureFICAdapter_Exchange_DefaultScope verifies that when scope param is
// absent the adapter defaults to https://management.azure.com/.default.
func TestAzureFICAdapter_Exchange_DefaultScope(t *testing.T) {
	fakeClient := &fakeAzureTokenClient{}
	a := tokenexchange.NewAzureFICAdapter(fakeClient)

	in := tokenexchange.ExchangeInput{
		Proof: &tokenexchange.IdentityProof{
			Token:     "tok",
			ExpiresAt: time.Now().Add(5 * time.Minute),
		},
		Audience: "https://management.azure.com/.default",
		Params: map[string]string{
			"tenant_id": "tid",
			"client_id": "cid",
			// scope deliberately absent
		},
	}

	_, err := a.Exchange(context.Background(), in)
	if err != nil {
		t.Fatalf("Exchange() error = %v", err)
	}
	if fakeClient.lastInput.Scope != "https://management.azure.com/.default" {
		t.Errorf("Scope = %q, want default %q", fakeClient.lastInput.Scope, "https://management.azure.com/.default")
	}
}

// TestAzureFICAdapter_NoPassthrough verifies the identity proof token is never
// echoed in the returned env vars (MCP no-passthrough).
func TestAzureFICAdapter_NoPassthrough(t *testing.T) {
	a := tokenexchange.NewAzureFICAdapter(&fakeAzureTokenClient{})

	identityToken := "SENSITIVE-openbao-identity-token"
	in := tokenexchange.ExchangeInput{
		Proof: &tokenexchange.IdentityProof{
			Token:     identityToken,
			ExpiresAt: time.Now().Add(5 * time.Minute),
		},
		Audience: "https://management.azure.com/.default",
		Params: map[string]string{
			"tenant_id": "tid",
			"client_id": "cid",
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

// TestAzureFICAdapter_MissingTenantID verifies that missing tenant_id in
// params returns a meaningful error without calling the Azure endpoint.
func TestAzureFICAdapter_MissingTenantID(t *testing.T) {
	fakeClient := &fakeAzureTokenClient{}
	a := tokenexchange.NewAzureFICAdapter(fakeClient)

	in := tokenexchange.ExchangeInput{
		Proof: &tokenexchange.IdentityProof{
			Token:     "tok",
			ExpiresAt: time.Now().Add(5 * time.Minute),
		},
		Audience: "https://management.azure.com/.default",
		Params: map[string]string{
			"client_id": "cid",
			// tenant_id absent
		},
	}

	_, err := a.Exchange(context.Background(), in)
	if err == nil {
		t.Fatal("Exchange() expected error for missing tenant_id, got nil")
	}
	if fakeClient.called {
		t.Error("Azure endpoint should not be called when tenant_id is missing")
	}
}

// TestAzureFICAdapter_MissingClientID verifies that missing client_id in
// params returns a meaningful error without calling the Azure endpoint.
func TestAzureFICAdapter_MissingClientID(t *testing.T) {
	fakeClient := &fakeAzureTokenClient{}
	a := tokenexchange.NewAzureFICAdapter(fakeClient)

	in := tokenexchange.ExchangeInput{
		Proof: &tokenexchange.IdentityProof{
			Token:     "tok",
			ExpiresAt: time.Now().Add(5 * time.Minute),
		},
		Audience: "https://management.azure.com/.default",
		Params: map[string]string{
			"tenant_id": "tid",
			// client_id absent
		},
	}

	_, err := a.Exchange(context.Background(), in)
	if err == nil {
		t.Fatal("Exchange() expected error for missing client_id, got nil")
	}
	if fakeClient.called {
		t.Error("Azure endpoint should not be called when client_id is missing")
	}
}

// TestAzureFICAdapter_TokenEndpointError verifies that Azure endpoint errors
// bubble up wrapped (errors.Is check).
func TestAzureFICAdapter_TokenEndpointError(t *testing.T) {
	azureErr := errors.New("azure AD: AADSTS70011 invalid scope")
	a := tokenexchange.NewAzureFICAdapter(&fakeAzureTokenClient{err: azureErr})

	in := tokenexchange.ExchangeInput{
		Proof: &tokenexchange.IdentityProof{
			Token:     "tok",
			ExpiresAt: time.Now().Add(5 * time.Minute),
		},
		Audience: "https://management.azure.com/.default",
		Params: map[string]string{
			"tenant_id": "tid",
			"client_id": "cid",
		},
	}

	_, err := a.Exchange(context.Background(), in)
	if err == nil {
		t.Fatal("Exchange() expected error, got nil")
	}
	if !errors.Is(err, azureErr) {
		t.Errorf("error %v does not wrap %v", err, azureErr)
	}
}

// TestAzureFICAdapter_NoSubscriptionID verifies that when subscription_id
// param is absent, AZURE_SUBSCRIPTION_ID is not set in the returned env vars.
func TestAzureFICAdapter_NoSubscriptionID(t *testing.T) {
	a := tokenexchange.NewAzureFICAdapter(&fakeAzureTokenClient{})

	in := tokenexchange.ExchangeInput{
		Proof: &tokenexchange.IdentityProof{
			Token:     "tok",
			ExpiresAt: time.Now().Add(5 * time.Minute),
		},
		Audience: "https://management.azure.com/.default",
		Params: map[string]string{
			"tenant_id": "tid",
			"client_id": "cid",
			// subscription_id absent
		},
	}

	cred, err := a.Exchange(context.Background(), in)
	if err != nil {
		t.Fatalf("Exchange() error = %v", err)
	}
	if v, ok := cred.EnvVars["AZURE_SUBSCRIPTION_ID"]; ok {
		t.Errorf("AZURE_SUBSCRIPTION_ID should not be set when subscription_id param absent; got %q", v)
	}
}
