package tokenexchange

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// githubAppJWTLifetime is the lifetime of a GitHub App JWT (GitHub max is 10 min).
const githubAppJWTLifetime = 10 * time.Minute

// githubAPIBaseURL is the default GitHub API base URL.
const githubAPIBaseURL = "https://api.github.com"

// GitHubAppAdapterConfig configures a GitHubAppAdapter.
type GitHubAppAdapterConfig struct {
	// BaseURL overrides the GitHub API base URL (default: https://api.github.com).
	// Used in tests to redirect to a mock server.
	BaseURL string
	// HTTPClient overrides the HTTP client used for API calls. Defaults to
	// http.DefaultClient with a 15s timeout.
	HTTPClient *http.Client
}

// GitHubAppAdapter implements ExchangeAdapter for GitHub App installation tokens.
//
// It reads app_id, installation_id, and a PKCS#8 PEM private key from
// ExchangeInput.Params, signs a short-lived RS256 JWT (iss=app_id, iat, exp
// ~10 min), then POSTs to GitHub's installation-token endpoint to obtain a
// 1-hour token. The token is returned in EnvVars["token"]; no PAT is ever
// stored or returned.
//
// ExchangeInput.Params keys:
//   - "app_id"          (required) — GitHub App ID.
//   - "installation_id" (required) — GitHub App installation ID.
//   - "private_key"     (required) — PKCS#8 PEM-encoded RSA private key.
type GitHubAppAdapter struct {
	baseURL    string
	httpClient *http.Client
}

// NewGitHubAppAdapter creates a GitHubAppAdapter.
func NewGitHubAppAdapter(cfg GitHubAppAdapterConfig) *GitHubAppAdapter {
	baseURL := cfg.BaseURL
	if baseURL == "" {
		baseURL = githubAPIBaseURL
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	return &GitHubAppAdapter{
		baseURL:    strings.TrimRight(baseURL, "/"),
		httpClient: client,
	}
}

// ProviderType implements ExchangeAdapter.
func (a *GitHubAppAdapter) ProviderType() string { return "github_app" }

// Exchange implements ExchangeAdapter. It signs a GitHub App JWT with the
// stored private key and exchanges it for a 1-hour installation token.
//
// The private key is read from in.Params["private_key"] on each call; it is
// never cached. The installation token is returned under EnvVars["token"].
// The identity proof (in.Proof) is not used — GitHub App auth is self-contained.
func (a *GitHubAppAdapter) Exchange(ctx context.Context, in ExchangeInput) (*ExchangedCredential, error) {
	appID := in.Params["app_id"]
	if appID == "" {
		return nil, fmt.Errorf("tokenexchange: github_app: app_id is required in Params")
	}
	installationID := in.Params["installation_id"]
	if installationID == "" {
		return nil, fmt.Errorf("tokenexchange: github_app: installation_id is required in Params")
	}
	privateKeyPEM := in.Params["private_key"]
	if privateKeyPEM == "" {
		return nil, fmt.Errorf("tokenexchange: github_app: private_key is required in Params")
	}

	key, err := parseRSAPrivateKey(privateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("tokenexchange: github_app: parse private key: %w", err)
	}

	appJWT, err := SignGitHubAppJWT(key, appID)
	if err != nil {
		return nil, fmt.Errorf("tokenexchange: github_app: sign app JWT: %w", err)
	}

	installationToken, expiresAt, err := a.mintInstallationToken(ctx, installationID, appJWT)
	if err != nil {
		return nil, err
	}

	return &ExchangedCredential{
		EnvVars:   map[string]string{"token": installationToken},
		ExpiresAt: expiresAt,
		Audience:  in.Audience,
		Scope:     fmt.Sprintf("github app installation %s", installationID),
	}, nil
}

// mintInstallationToken POSTs to GitHub's installation access-token endpoint
// using the provided App JWT for authentication.
func (a *GitHubAppAdapter) mintInstallationToken(ctx context.Context, installationID, appJWT string) (string, time.Time, error) {
	url := fmt.Sprintf("%s/app/installations/%s/access_tokens", a.baseURL, installationID)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("tokenexchange: github_app: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+appJWT)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("tokenexchange: github_app: request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("tokenexchange: github_app: read response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return "", time.Time{}, fmt.Errorf("tokenexchange: github_app: status %d: %s",
			resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var result struct {
		Token     string `json:"token"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", time.Time{}, fmt.Errorf("tokenexchange: github_app: decode response: %w", err)
	}
	if result.Token == "" {
		return "", time.Time{}, fmt.Errorf("tokenexchange: github_app: empty token in response")
	}

	expiresAt := time.Now().Add(1 * time.Hour) // GitHub default
	if result.ExpiresAt != "" {
		if t, err := time.Parse(time.RFC3339, result.ExpiresAt); err == nil {
			expiresAt = t
		}
	}

	return result.Token, expiresAt, nil
}

// ---------------------------------------------------------------------------
// SignGitHubAppJWT — exported so tests can verify the JWT directly.
// ---------------------------------------------------------------------------

// SignGitHubAppJWT signs a short-lived RS256 JWT suitable for authenticating
// as the GitHub App. The JWT expires 10 minutes from now (GitHub's maximum).
//
// The JWT header contains: alg=RS256, typ=JWT.
// The JWT payload contains: iss=appID, iat=now, exp=now+600.
func SignGitHubAppJWT(key *rsa.PrivateKey, appID string) (string, error) {
	now := time.Now().Unix()

	// Build header.
	headerJSON, err := json.Marshal(map[string]string{
		"alg": "RS256",
		"typ": "JWT",
	})
	if err != nil {
		return "", fmt.Errorf("marshal JWT header: %w", err)
	}
	header := base64.RawURLEncoding.EncodeToString(headerJSON)

	// Build payload.
	payloadJSON, err := json.Marshal(map[string]interface{}{
		"iss": appID,
		"iat": now,
		"exp": now + int64(githubAppJWTLifetime.Seconds()),
	})
	if err != nil {
		return "", fmt.Errorf("marshal JWT payload: %w", err)
	}
	payload := base64.RawURLEncoding.EncodeToString(payloadJSON)

	// Sign header.payload with RS256.
	signingInput := header + "." + payload
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("sign JWT: %w", err)
	}

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// ---------------------------------------------------------------------------
// parseRSAPrivateKey parses a PKCS#8 or PKCS#1 PEM-encoded RSA private key.
// ---------------------------------------------------------------------------

func parseRSAPrivateKey(pemData string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}

	// Try PKCS#8 first (the format we write in tests and ADR spec).
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("PKCS#8 key is not RSA")
		}
		return rsaKey, nil
	}

	// Fall back to PKCS#1 (traditional RSA PRIVATE KEY block).
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}
