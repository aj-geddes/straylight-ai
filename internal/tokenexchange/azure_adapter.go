package tokenexchange

import (
	"context"
	"fmt"
	"time"
)

const (
	// azureDefaultScope is the default OAuth2 scope for Azure management APIs.
	azureDefaultScope = "https://management.azure.com/.default"

	// azureDefaultTokenLifetimeSecs is the fallback TTL for Azure federated tokens
	// when the token endpoint response does not include expires_in.
	azureDefaultTokenLifetimeSecs = 3600
)

// AzureTokenExchangeInput holds the parameters for an Azure AD token endpoint
// call using the jwt-bearer client assertion flow, keeping the HTTP call behind
// the AzureTokenClient interface for testability.
type AzureTokenExchangeInput struct {
	// TenantID is the Azure AD tenant (directory) ID.
	TenantID string
	// ClientID is the application (client) ID of the federated workload identity.
	ClientID string
	// Scope is the OAuth2 scope / resource audience to request.
	Scope string
	// ClientAssertion is the signed OIDC JWT (the OpenBao identity proof).
	// It is presented as the client_assertion in the jwt-bearer assertion flow
	// and is never echoed in the returned credential (MCP no-passthrough).
	ClientAssertion string
}

// AzureFederatedToken holds the short-lived access token returned by the Azure
// AD token endpoint when using the jwt-bearer client assertion flow.
type AzureFederatedToken struct {
	// AccessToken is the bearer token to inject as AZURE_ACCESS_TOKEN.
	AccessToken string
	// ExpiresIn is the token lifetime in seconds as reported by Azure AD.
	ExpiresIn int
}

// AzureTokenClient is the narrow Azure AD interface for the keyless FIC path.
// The real HTTP implementation and test mocks both satisfy this interface.
// It is intentionally separate from the cloud package so that the tokenexchange
// package has no import dependency on internal/cloud.
type AzureTokenClient interface {
	// ExchangeToken exchanges an OIDC identity token for a short-lived Azure
	// access token using the jwt-bearer client assertion flow without requiring
	// a static client_secret.
	ExchangeToken(ctx context.Context, in AzureTokenExchangeInput) (*AzureFederatedToken, error)
}

// AzureFICAdapter implements ExchangeAdapter for Azure Federated Identity
// Credentials (FIC) using the client-credentials flow with
// client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer.
// It is the keyless Azure exchange: an OpenBao OIDC identity token is presented
// to Azure AD as the client_assertion; no static client_secret is required.
//
// ExchangeInput.Params keys:
//   - "tenant_id"       (required) — Azure AD tenant (directory) ID.
//   - "client_id"       (required) — Application (client) ID.
//   - "scope"           (optional) — OAuth2 scope; defaults to "https://management.azure.com/.default".
//   - "subscription_id" (optional) — Azure subscription ID for AZURE_SUBSCRIPTION_ID.
type AzureFICAdapter struct {
	client AzureTokenClient
}

// NewAzureFICAdapter creates an AzureFICAdapter backed by the given AzureTokenClient.
func NewAzureFICAdapter(client AzureTokenClient) *AzureFICAdapter {
	return &AzureFICAdapter{client: client}
}

// ProviderType implements ExchangeAdapter.
func (a *AzureFICAdapter) ProviderType() string { return "azure" }

// Exchange implements ExchangeAdapter. It calls the Azure AD token endpoint
// using the jwt-bearer client assertion flow and returns a short-lived access
// token as AZURE_* environment variables.
//
// The identity proof token is forwarded to Azure AD as the client_assertion; it
// is never included in the returned EnvVars (MCP no-passthrough).
func (a *AzureFICAdapter) Exchange(ctx context.Context, in ExchangeInput) (*ExchangedCredential, error) {
	tenantID := in.Params["tenant_id"]
	if tenantID == "" {
		return nil, fmt.Errorf("tokenexchange: azure fic adapter: tenant_id is required in Params")
	}

	clientID := in.Params["client_id"]
	if clientID == "" {
		return nil, fmt.Errorf("tokenexchange: azure fic adapter: client_id is required in Params")
	}

	scope := in.Params["scope"]
	if scope == "" {
		scope = azureDefaultScope
	}

	clientIn := AzureTokenExchangeInput{
		TenantID:        tenantID,
		ClientID:        clientID,
		Scope:           scope,
		ClientAssertion: in.Proof.Token, // never echoed in output
	}

	result, err := a.client.ExchangeToken(ctx, clientIn)
	if err != nil {
		return nil, fmt.Errorf("tokenexchange: azure fic: %w", err)
	}

	expiresIn := result.ExpiresIn
	if expiresIn <= 0 {
		expiresIn = azureDefaultTokenLifetimeSecs
	}
	expiresAt := time.Now().Add(time.Duration(expiresIn) * time.Second)

	envVars := map[string]string{
		"AZURE_ACCESS_TOKEN": result.AccessToken,
		"AZURE_TENANT_ID":    tenantID,
		"AZURE_CLIENT_ID":    clientID,
	}
	if sub := in.Params["subscription_id"]; sub != "" {
		envVars["AZURE_SUBSCRIPTION_ID"] = sub
	}

	return &ExchangedCredential{
		EnvVars:   envVars,
		ExpiresAt: expiresAt,
		Audience:  in.Audience,
		Scope:     fmt.Sprintf("azure fic tenant=%s client=%s scope=%s", tenantID, clientID, scope),
	}, nil
}
