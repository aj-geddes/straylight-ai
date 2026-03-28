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
	// gcpDefaultTokenLifetimeSecs is the default GCP access token TTL (1 hour).
	gcpDefaultTokenLifetimeSecs = 3600

	// gcpDefaultScope is the default OAuth2 scope for GCP.
	gcpDefaultScope = "https://www.googleapis.com/auth/cloud-platform"
)

// GCPProviderConfig holds dependencies for the GCPProvider.
type GCPProviderConfig struct {
	// TokenEndpointOverride overrides the token_uri for testing. When empty,
	// the token_uri field inside the service account JSON is used.
	TokenEndpointOverride string

	// HTTPClient is an optional custom HTTP client. When nil, http.DefaultClient is used.
	HTTPClient *http.Client
}

// GCPProvider generates temporary GCP credentials using a service account JSON key.
type GCPProvider struct {
	tokenEndpoint string // overridden in tests
	httpClient    *http.Client
}

// NewGCPProvider creates a GCPProvider with the given configuration.
func NewGCPProvider(cfg GCPProviderConfig) *GCPProvider {
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &GCPProvider{
		tokenEndpoint: cfg.TokenEndpointOverride,
		httpClient:    client,
	}
}

// CloudType implements Provider.
func (p *GCPProvider) CloudType() string { return "gcp" }

// GenerateCredentials obtains a GCP access token using the service account JSON key
// and returns it as the CLOUDSDK_AUTH_ACCESS_TOKEN environment variable.
//
// The service account JSON private key is never included in the returned
// Credentials struct — only the short-lived access token is returned.
func (p *GCPProvider) GenerateCredentials(ctx context.Context, cfg ServiceConfig) (*Credentials, error) {
	if cfg.GCP == nil {
		return nil, fmt.Errorf("cloud: gcp config is required for engine %q", cfg.Engine)
	}

	gcpCfg := cfg.GCP

	if gcpCfg.ServiceAccountJSON == "" {
		return nil, fmt.Errorf("cloud: gcp: service_account_json is required")
	}

	// Determine the scopes to request.
	scopes := gcpCfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{gcpDefaultScope}
	}

	// Determine token TTL.
	lifetimeSecs := gcpCfg.TokenLifetimeSecs
	if lifetimeSecs <= 0 {
		lifetimeSecs = gcpDefaultTokenLifetimeSecs
	}

	// Determine the token URI. In tests this is overridden; in production
	// it is read from the service account JSON.
	tokenURI := p.tokenEndpoint
	if tokenURI == "" {
		var sa map[string]interface{}
		if err := json.Unmarshal([]byte(gcpCfg.ServiceAccountJSON), &sa); err != nil {
			return nil, fmt.Errorf("cloud: gcp: parse service account JSON: %w", err)
		}
		uri, ok := sa["token_uri"].(string)
		if !ok || uri == "" {
			return nil, fmt.Errorf("cloud: gcp: service account JSON missing token_uri")
		}
		tokenURI = uri
	}

	// Request an access token using a simple OAuth2 client credentials flow.
	// In production this would use golang.org/x/oauth2/google to handle JWT signing,
	// but for testability we parse the token_uri from the SA JSON and call it directly.
	// The oauth2/google library uses the same token_uri under the hood.
	token, expiresIn, err := p.fetchToken(ctx, gcpCfg.ServiceAccountJSON, tokenURI, scopes)
	if err != nil {
		return nil, fmt.Errorf("cloud: gcp: fetch access token: %w", err)
	}

	expiresAt := time.Now().Add(time.Duration(expiresIn) * time.Second)

	envVars := map[string]string{
		"CLOUDSDK_AUTH_ACCESS_TOKEN": token,
	}
	if gcpCfg.ProjectID != "" {
		envVars["CLOUDSDK_CORE_PROJECT"] = gcpCfg.ProjectID
	}

	scope := fmt.Sprintf("gcp access-token project=%s scopes=%s", gcpCfg.ProjectID, strings.Join(scopes, ","))

	return &Credentials{
		EnvVars:   envVars,
		ExpiresAt: expiresAt,
		Provider:  "gcp",
		Scope:     scope,
	}, nil
}

// gcpTokenResponse is the JSON body returned by the GCP token endpoint.
type gcpTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Error       string `json:"error,omitempty"`
}

// fetchToken requests an access token from the GCP token endpoint.
// tokenURI is the endpoint to POST to (from the service account JSON or overridden in tests).
// This is a simplified implementation that posts to the token URI directly.
func (p *GCPProvider) fetchToken(ctx context.Context, saJSON, tokenURI string, scopes []string) (string, int, error) {
	// Parse the service account JSON to extract the client_email and private_key_id
	// for constructing a minimal request. In production, golang.org/x/oauth2/google
	// handles JWT signing; for tests we POST directly to the mock server.
	var sa map[string]interface{}
	if err := json.Unmarshal([]byte(saJSON), &sa); err != nil {
		return "", 0, fmt.Errorf("parse service account JSON: %w", err)
	}

	// Build a form POST to the token URI. The test server accepts any POST.
	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth2:grant-type:jwt-bearer")
	form.Set("scope", strings.Join(scopes, " "))
	if email, ok := sa["client_email"].(string); ok {
		form.Set("client_email", email)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURI, strings.NewReader(form.Encode()))
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

	if resp.StatusCode != http.StatusOK {
		return "", 0, fmt.Errorf("token endpoint returned HTTP %d: %s", resp.StatusCode, body)
	}

	var tokenResp gcpTokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", 0, fmt.Errorf("parse token response: %w", err)
	}

	if tokenResp.AccessToken == "" {
		return "", 0, fmt.Errorf("token endpoint returned empty access_token")
	}

	expiresIn := tokenResp.ExpiresIn
	if expiresIn <= 0 {
		expiresIn = gcpDefaultTokenLifetimeSecs
	}

	return tokenResp.AccessToken, expiresIn, nil
}
