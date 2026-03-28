package cloud

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	// azureDefaultScope is the default token scope for Azure management APIs.
	azureDefaultScope = "https://management.azure.com/.default"

	// azureDefaultTokenLifetimeSecs is the default Azure access token TTL (1 hour).
	azureDefaultTokenLifetimeSecs = 3600
)

// AzureProviderConfig holds dependencies for the AzureProvider.
type AzureProviderConfig struct {
	// TokenEndpointOverride overrides the Azure AD token endpoint for testing.
	// When empty, the standard endpoint is used:
	// https://login.microsoftonline.com/{tenantID}/oauth2/v2.0/token
	TokenEndpointOverride string

	// HTTPClient is an optional custom HTTP client. When nil, http.DefaultClient is used.
	HTTPClient *http.Client
}

// AzureProvider generates temporary Azure credentials using client credentials flow.
type AzureProvider struct {
	tokenEndpoint string
	httpClient    *http.Client
}

// NewAzureProvider creates an AzureProvider with the given configuration.
func NewAzureProvider(cfg AzureProviderConfig) *AzureProvider {
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &AzureProvider{
		tokenEndpoint: cfg.TokenEndpointOverride,
		httpClient:    client,
	}
}

// CloudType implements Provider.
func (p *AzureProvider) CloudType() string { return "azure" }

// GenerateCredentials obtains an Azure access token using the client credentials
// flow and returns it as AZURE_ACCESS_TOKEN, along with AZURE_TENANT_ID and
// AZURE_SUBSCRIPTION_ID environment variables.
//
// The client secret is never included in the returned Credentials struct — only
// the short-lived access token is returned.
func (p *AzureProvider) GenerateCredentials(ctx context.Context, cfg ServiceConfig) (*Credentials, error) {
	if cfg.Azure == nil {
		return nil, fmt.Errorf("cloud: azure config is required for engine %q", cfg.Engine)
	}

	azureCfg := cfg.Azure

	scope := azureCfg.Scope
	if scope == "" {
		scope = azureDefaultScope
	}

	// Determine the token endpoint.
	tokenEndpoint := p.tokenEndpoint
	if tokenEndpoint == "" {
		tokenEndpoint = fmt.Sprintf(
			"https://login.microsoftonline.com/%s/oauth2/v2.0/token",
			url.PathEscape(azureCfg.TenantID),
		)
	}

	token, expiresIn, err := p.fetchToken(ctx, tokenEndpoint, azureCfg.ClientID, azureCfg.ClientSecret, scope)
	if err != nil {
		return nil, fmt.Errorf("cloud: azure: fetch token for tenant %q: %w", azureCfg.TenantID, err)
	}

	expiresAt := time.Now().Add(time.Duration(expiresIn) * time.Second)

	envVars := map[string]string{
		"AZURE_ACCESS_TOKEN": token,
		"AZURE_TENANT_ID":    azureCfg.TenantID,
	}
	if azureCfg.SubscriptionID != "" {
		envVars["AZURE_SUBSCRIPTION_ID"] = azureCfg.SubscriptionID
	}
	if azureCfg.ClientID != "" {
		envVars["AZURE_CLIENT_ID"] = azureCfg.ClientID
	}

	auditScope := fmt.Sprintf("azure client-credentials tenant=%s scope=%s", azureCfg.TenantID, scope)

	return &Credentials{
		EnvVars:   envVars,
		ExpiresAt: expiresAt,
		Provider:  "azure",
		Scope:     auditScope,
	}, nil
}

// azureTokenResponse is the JSON body returned by the Azure AD token endpoint.
type azureTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    string `json:"expires_in"`
	ExtExpiresIn string `json:"ext_expires_in"`
	Error        string `json:"error,omitempty"`
	ErrorDesc    string `json:"error_description,omitempty"`
}

// fetchToken requests an access token from the Azure AD token endpoint using
// the client credentials flow (grant_type=client_credentials).
// The client_secret is posted to Azure AD and never stored in the returned token.
func (p *AzureProvider) fetchToken(ctx context.Context, tokenEndpoint, clientID, clientSecret, scope string) (string, int, error) {
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)
	form.Set("scope", scope)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, fmt.Errorf("build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("token request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", 0, fmt.Errorf("read token response: %w", err)
	}

	var tokenResp azureTokenResponse
	if jsonErr := json.Unmarshal(body, &tokenResp); jsonErr != nil {
		// Non-JSON error body (e.g. HTML 401 page).
		return "", 0, fmt.Errorf("token endpoint returned HTTP %d: %s", resp.StatusCode, body)
	}

	if resp.StatusCode != http.StatusOK {
		errMsg := tokenResp.Error
		if tokenResp.ErrorDesc != "" {
			errMsg += ": " + tokenResp.ErrorDesc
		}
		if errMsg == "" {
			errMsg = string(body)
		}
		return "", 0, fmt.Errorf("token endpoint returned HTTP %d: %s", resp.StatusCode, errMsg)
	}

	if tokenResp.AccessToken == "" {
		return "", 0, fmt.Errorf("token endpoint returned empty access_token")
	}

	// Azure returns expires_in as a string (e.g. "3600").
	expiresIn := 0
	_, _ = fmt.Sscanf(tokenResp.ExpiresIn, "%d", &expiresIn)
	if expiresIn <= 0 {
		expiresIn = azureDefaultTokenLifetimeSecs
	}

	return tokenResp.AccessToken, expiresIn, nil
}
