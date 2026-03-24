// Package oauth implements the OAuth 2.0 authorization code flow for services
// that use OAuth instead of static API keys.
//
// Implemented in WP-1.7.
package oauth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/straylight-ai/straylight/internal/services"
)

// serviceNamePattern matches valid service names: starts with a lowercase letter,
// followed by up to 62 lowercase alphanumeric, hyphen, or underscore characters.
var serviceNamePattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,62}$`)

// oauthTokenTTL is the assumed lifetime of a new access token when the
// provider does not supply an expires_in field. GitHub tokens do not expire,
// but we use a generous default for providers that do.
const oauthTokenTTL = 8 * time.Hour

// VaultClient is the interface the Handler uses for token storage and retrieval.
// Implemented by *vault.Client; use a mock in tests.
type VaultClient interface {
	WriteSecret(path string, data map[string]interface{}) error
	ReadSecret(path string) (map[string]interface{}, error)
	DeleteSecret(path string) error
}

// ServiceManager is the interface the Handler uses to create or update
// services after a successful OAuth flow.
type ServiceManager interface {
	Create(svc services.Service, credential string) error
	Update(name string, svc services.Service, credential *string) error
	Get(name string) (services.Service, error)
}

// ServiceUpdater is kept as an alias for backward compatibility with tests.
type ServiceUpdater = ServiceManager

// Handler holds the dependencies for the OAuth HTTP handlers.
type Handler struct {
	vault        VaultClient
	services     ServiceUpdater
	baseURL      string
	stateManager *StateManager
	logger       *slog.Logger
	httpClient   *http.Client
}

// NewHandler constructs an oauth Handler.
//
// baseURL is the publicly reachable base URL of this server (e.g., "http://localhost:9470").
// It is used to build the redirect_uri sent to the OAuth provider.
func NewHandler(vault VaultClient, svcUpdater ServiceUpdater, baseURL string) *Handler {
	return &Handler{
		vault:        vault,
		services:     svcUpdater,
		baseURL:      strings.TrimRight(baseURL, "/"),
		stateManager: NewStateManager(),
		logger:       slog.Default(),
		httpClient:   &http.Client{Timeout: 15 * time.Second},
	}
}

// ---------------------------------------------------------------------------
// StartOAuth — GET /api/v1/oauth/{provider}/start?service_name={name}
// ---------------------------------------------------------------------------

// StartOAuth initiates the OAuth authorization code flow.
// It validates the provider, generates a CSRF state token, builds the
// provider's authorization URL, and redirects the browser to it.
func (h *Handler) StartOAuth(w http.ResponseWriter, r *http.Request) {
	providerName := r.PathValue("provider")
	serviceName := r.URL.Query().Get("service_name")

	if serviceName == "" {
		writeOAuthError(w, http.StatusBadRequest, "service_name query parameter is required")
		return
	}
	if !serviceNamePattern.MatchString(serviceName) {
		writeOAuthError(w, http.StatusBadRequest, "invalid service_name")
		return
	}

	provider, ok := Providers[providerName]
	if !ok {
		writeOAuthError(w, http.StatusBadRequest, fmt.Sprintf("unknown provider %q", providerName))
		return
	}

	// Retrieve client_id from vault. OAuth App credentials are keyed by
	// provider name (not service instance name) since they are shared across
	// all service instances for the same provider.
	clientID := h.readClientID(providerName)
	if clientID == "" {
		writeOAuthError(w, http.StatusBadRequest,
			fmt.Sprintf(
				"OAuth not configured for provider %q. "+
					"Please configure OAuth App credentials first at /api/v1/oauth/%s/config",
				providerName, providerName,
			),
		)
		return
	}

	state := h.stateManager.Generate(providerName, serviceName)

	redirectURI := h.baseURL + "/api/v1/oauth/callback"
	scope := strings.Join(provider.DefaultScopes, " ")

	authURL, err := url.Parse(provider.AuthURL)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "invalid provider auth URL")
		return
	}

	q := authURL.Query()
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", scope)
	q.Set("state", state)
	for k, v := range provider.ExtraAuthParams {
		q.Set(k, v)
	}
	authURL.RawQuery = q.Encode()

	http.Redirect(w, r, authURL.String(), http.StatusFound)
}

// ---------------------------------------------------------------------------
// Callback — GET /api/v1/oauth/callback?code={code}&state={state}
// ---------------------------------------------------------------------------

// Callback handles the provider's authorization redirect.
// It validates the CSRF state token, exchanges the authorization code for
// access tokens, stores the tokens in OpenBao, updates the service status,
// and redirects the browser to the Web UI.
func (h *Handler) Callback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	if code == "" {
		writeOAuthError(w, http.StatusBadRequest, "missing code parameter")
		return
	}
	if state == "" {
		writeOAuthError(w, http.StatusBadRequest, "missing state parameter")
		return
	}

	providerName, serviceName, err := h.stateManager.Validate(state)
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid or expired state parameter: "+err.Error())
		return
	}

	provider, ok := Providers[providerName]
	if !ok {
		writeOAuthError(w, http.StatusBadRequest, fmt.Sprintf("unknown provider %q", providerName))
		return
	}

	tokens, err := h.exchangeCode(provider, code)
	if err != nil {
		h.logger.Error("oauth callback: token exchange failed",
			"provider", providerName,
			"service", serviceName,
			"error", err,
		)
		writeOAuthError(w, http.StatusBadGateway, "token exchange failed; check server logs for details")
		return
	}

	// Persist tokens in OpenBao, including provider name so RefreshToken can
	// look up the correct TokenURL without additional state.
	tokenData := map[string]interface{}{
		"access_token":  tokens.AccessToken,
		"refresh_token": tokens.RefreshToken,
		"token_type":    tokens.TokenType,
		"scope":         tokens.Scope,
		"expires_at":    tokens.ExpiresAt.Format(time.RFC3339),
		"provider":      providerName,
	}
	if err := h.vault.WriteSecret(oauthTokenPath(serviceName), tokenData); err != nil {
		h.logger.Error("oauth callback: vault write failed",
			"service", serviceName,
			"error", err,
		)
		writeOAuthError(w, http.StatusInternalServerError, "failed to store tokens")
		return
	}

	// Create the service if it doesn't exist, or update its status if it does.
	// The access token is stored as the credential so the proxy can use it.
	_, getErr := h.services.Get(serviceName)
	if getErr != nil {
		// Service doesn't exist — create it from the provider template.
		tmpl := findTemplateForProvider(providerName)
		svc := services.Service{
			Name:           serviceName,
			Type:           "http_proxy",
			Target:         tmpl.target,
			AuthMethodID:   tmpl.authMethodID,
			Inject:         "header",
			HeaderTemplate: "Bearer {{.secret}}",
			DefaultHeaders: tmpl.defaultHeaders,
			Status:         "available",
		}
		if createErr := h.services.Create(svc, tokens.AccessToken); createErr != nil {
			h.logger.Warn("oauth callback: service create failed",
				"service", serviceName,
				"error", createErr,
			)
		}
	} else if err := h.services.Update(serviceName, services.Service{
		Name:   serviceName,
		Status: "available",
	}, &tokens.AccessToken); err != nil {
		h.logger.Warn("oauth callback: service update failed",
			"service", serviceName,
			"error", err,
		)
	}

	redirectURL := "/?oauth=success&service=" + url.QueryEscape(serviceName)
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// ---------------------------------------------------------------------------
// RefreshToken — internal, called by the proxy
// ---------------------------------------------------------------------------

// RefreshToken reads the stored OAuth tokens for serviceName from OpenBao and
// attempts to refresh them using the provider's token endpoint.
// Returns the new access token or an error.
// On refresh failure it returns an error; callers are responsible for updating
// service status to "expired" when appropriate.
func (h *Handler) RefreshToken(serviceName string) (string, error) {
	data, err := h.vault.ReadSecret(oauthTokenPath(serviceName))
	if err != nil {
		return "", fmt.Errorf("oauth: read tokens for %q: %w", serviceName, err)
	}

	refreshToken, _ := data["refresh_token"].(string)
	if refreshToken == "" {
		return "", fmt.Errorf("oauth: no refresh_token stored for service %q", serviceName)
	}

	providerName, _ := data["provider"].(string)
	provider, ok := Providers[providerName]
	if !ok {
		return "", fmt.Errorf("oauth: unknown provider %q for service %q", providerName, serviceName)
	}

	clientID := h.readClientID(providerName)
	clientSecret := h.readClientSecret(providerName)

	tokens, err := h.doTokenRequest(provider.TokenURL, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
	})
	if err != nil {
		return "", fmt.Errorf("oauth: refresh failed for %q: %w", serviceName, err)
	}

	// Preserve provider name in the updated token record.
	tokenData := map[string]interface{}{
		"access_token":  tokens.AccessToken,
		"refresh_token": tokens.RefreshToken,
		"token_type":    tokens.TokenType,
		"scope":         tokens.Scope,
		"expires_at":    tokens.ExpiresAt.Format(time.RFC3339),
		"provider":      providerName,
	}
	if err := h.vault.WriteSecret(oauthTokenPath(serviceName), tokenData); err != nil {
		return "", fmt.Errorf("oauth: store refreshed tokens for %q: %w", serviceName, err)
	}

	return tokens.AccessToken, nil
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// providerTemplate holds the minimal template info needed to create a service
// from an OAuth callback.
type providerTemplate struct {
	target         string
	authMethodID   string
	defaultHeaders map[string]string
}

// findTemplateForProvider returns the target URL and auth method ID for a
// provider's OAuth flow. Falls back to sensible defaults if no template matches.
func findTemplateForProvider(provider string) providerTemplate {
	defaults := map[string]providerTemplate{
		"github": {
			target:       "https://api.github.com",
			authMethodID: "github_oauth",
			defaultHeaders: map[string]string{
				"Accept":               "application/vnd.github+json",
				"X-GitHub-Api-Version": "2022-11-28",
			},
		},
		"google": {
			target:       "https://www.googleapis.com",
			authMethodID: "google_oauth",
		},
		"microsoft": {
			target:       "https://graph.microsoft.com",
			authMethodID: "microsoft_oauth",
			defaultHeaders: map[string]string{
				"Content-Type": "application/json",
			},
		},
		"stripe": {
			target:       "https://api.stripe.com",
			authMethodID: "stripe_connect_oauth",
		},
		"facebook": {
			target:       "https://graph.facebook.com",
			authMethodID: "facebook_oauth",
		},
	}
	if t, ok := defaults[provider]; ok {
		return t
	}
	return providerTemplate{target: "https://" + provider + ".example.com", authMethodID: provider + "_oauth"}
}

// oauthTokens holds the token fields returned by a provider.
type oauthTokens struct {
	AccessToken  string
	RefreshToken string
	TokenType    string
	Scope        string
	ExpiresAt    time.Time
}

// oauthTokenPath returns the OpenBao KV path for a service's OAuth tokens.
func oauthTokenPath(serviceName string) string {
	return "services/" + serviceName + "/oauth_tokens"
}

// oauthClientSecretPath returns the OpenBao KV path for a service's OAuth client credentials.
func oauthClientSecretPath(serviceName string) string {
	return "services/" + serviceName + "/oauth_client_secret"
}

// readClientID reads the OAuth client_id for the given provider.
// Resolution order:
//  1. Environment variable STRAYLIGHT_{PROVIDER}_CLIENT_ID.
//  2. Provider's baked-in DefaultClientID.
//  3. Vault (legacy per-provider storage at services/{provider}/oauth_client_secret).
//
// Returns an empty string if not found.
func (h *Handler) readClientID(providerName string) string {
	// 1. Check env var first.
	envKey := "STRAYLIGHT_" + strings.ToUpper(providerName) + "_CLIENT_ID"
	if v := os.Getenv(envKey); v != "" {
		return v
	}
	// 2. Check provider default.
	if p, ok := Providers[providerName]; ok && p.DefaultClientID != "" {
		return p.DefaultClientID
	}
	// 3. Fall back to vault.
	data, err := h.vault.ReadSecret(oauthClientSecretPath(providerName))
	if err != nil {
		return ""
	}
	v, _ := data["client_id"].(string)
	return v
}

// readClientSecret reads the OAuth client_secret for the given provider.
// Resolution order:
//  1. Environment variable STRAYLIGHT_{PROVIDER}_CLIENT_SECRET.
//  2. Vault (legacy per-provider storage at services/{provider}/oauth_client_secret).
//
// Returns an empty string if not found.
func (h *Handler) readClientSecret(providerName string) string {
	// 1. Check env var first.
	envKey := "STRAYLIGHT_" + strings.ToUpper(providerName) + "_CLIENT_SECRET"
	if v := os.Getenv(envKey); v != "" {
		return v
	}
	// 2. Fall back to vault.
	data, err := h.vault.ReadSecret(oauthClientSecretPath(providerName))
	if err != nil {
		return ""
	}
	v, _ := data["client_secret"].(string)
	return v
}

// exchangeCode performs the authorization code → token exchange with the provider.
// OAuth App credentials (client_id/secret) are keyed by provider name.
func (h *Handler) exchangeCode(provider Provider, code string) (*oauthTokens, error) {
	clientID := h.readClientID(provider.Name)
	clientSecret := h.readClientSecret(provider.Name)
	redirectURI := h.baseURL + "/api/v1/oauth/callback"

	return h.doTokenRequest(provider.TokenURL, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
	})
}

// tokenResponse is the raw JSON response from a provider token endpoint.
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	Scope        string `json:"scope"`
	ExpiresIn    int    `json:"expires_in"`
	Error        string `json:"error"`
	ErrorDesc    string `json:"error_description"`
}

// doTokenRequest sends a POST to the token URL with the given form values and
// parses the response into an oauthTokens struct. Returns an error if the
// provider returns an error field or a non-2xx status.
func (h *Handler) doTokenRequest(tokenURL string, params url.Values) (*oauthTokens, error) {
	req, err := http.NewRequest(http.MethodPost, tokenURL, bytes.NewBufferString(params.Encode()))
	if err != nil {
		return nil, fmt.Errorf("build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, fmt.Errorf("read token response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("token endpoint returned status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, fmt.Errorf("decode token response: %w", err)
	}
	if tr.Error != "" {
		return nil, fmt.Errorf("provider error %q: %s", tr.Error, tr.ErrorDesc)
	}
	if tr.AccessToken == "" {
		return nil, fmt.Errorf("provider returned empty access_token")
	}

	expiresAt := time.Now().Add(oauthTokenTTL)
	if tr.ExpiresIn > 0 {
		expiresAt = time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second)
	}

	return &oauthTokens{
		AccessToken:  tr.AccessToken,
		RefreshToken: tr.RefreshToken,
		TokenType:    tr.TokenType,
		Scope:        tr.Scope,
		ExpiresAt:    expiresAt,
	}, nil
}

// writeOAuthError writes a JSON error response.
func writeOAuthError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
