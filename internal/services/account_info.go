// Package services — account info fetcher.
// FetchAccountInfo makes a single best-effort API call to retrieve identity
// information for a service after credential storage.
package services

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// accountInfoTimeout is the maximum time allowed for an account info fetch.
const accountInfoTimeout = 5 * time.Second

// FetchAccountInfo makes a test API call to the service to retrieve account
// and identity information. This is called once after credential storage to
// enrich the service display.
//
// Parameters:
//   - target: the service base URL (e.g. "https://api.github.com")
//   - credential: the raw credential value (never logged)
//   - authMethodID: the ID of the chosen auth method (used to determine service type)
//   - defaultHeaders: extra headers to include in the request (e.g. service-level defaults)
//
// Returns nil if the fetch fails for any reason — enrichment is best-effort and
// must never cause service creation to fail.
func FetchAccountInfo(target string, credential string, authMethodID string, defaultHeaders map[string]string) *AccountInfo {
	fetcher := resolveAccountFetcher(authMethodID, target)
	if fetcher == nil {
		return nil
	}
	return fetcher(target, credential, defaultHeaders)
}

// accountFetchFunc is the function type for service-specific account fetchers.
type accountFetchFunc func(target, credential string, defaultHeaders map[string]string) *AccountInfo

// accountFetchers maps auth method IDs to their service-specific fetch functions.
// Auth method IDs are registered here when the corresponding service template
// supports account info enrichment.
var accountFetchers = map[string]accountFetchFunc{
	// GitHub
	"github_pat_classic":    fetchGitHubAccountInfo,
	"github_fine_grained_pat": fetchGitHubAccountInfo,
	// OpenAI
	"openai_api_key":     fetchOpenAIAccountInfo,
	"openai_project_key": fetchOpenAIAccountInfo,
	// Anthropic
	"anthropic_api_key": fetchAnthropicAccountInfo,
	// Stripe
	"stripe_api_key":        fetchStripeAccountInfo,
	"stripe_restricted_key": fetchStripeAccountInfo,
	// Slack
	"slack_bot_token":  fetchSlackAccountInfo,
	"slack_user_token": fetchSlackAccountInfo,
	// GitLab
	"gitlab_pat": fetchGitLabAccountInfo,
	// Google
	"google_api_key": fetchGoogleAccountInfo,
}

// targetFetchers maps target URL prefixes to fetch functions for legacy services.
var targetFetchers = map[string]accountFetchFunc{
	"https://api.github.com":  fetchGitHubAccountInfo,
	"https://api.openai.com":  fetchOpenAIAccountInfo,
	"https://api.anthropic.com": fetchAnthropicAccountInfo,
	"https://api.stripe.com":  fetchStripeAccountInfo,
	"https://slack.com":       fetchSlackAccountInfo,
	"https://gitlab.com":      fetchGitLabAccountInfo,
}

// resolveAccountFetcher returns the fetcher function for the given auth method ID,
// or nil if the auth method is not recognized. For "legacy" auth methods, it
// falls back to matching the target URL prefix.
func resolveAccountFetcher(authMethodID string, target ...string) accountFetchFunc {
	if f, ok := accountFetchers[authMethodID]; ok {
		return f
	}
	// Legacy fallback: match by target URL prefix
	if len(target) > 0 {
		for prefix, f := range targetFetchers {
			if len(target[0]) >= len(prefix) && target[0][:len(prefix)] == prefix {
				return f
			}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// GitHub
// ---------------------------------------------------------------------------

// githubUserResponse is the relevant subset of the GitHub /user API response.
type githubUserResponse struct {
	Login     string `json:"login"`
	Name      string `json:"name"`
	AvatarURL string `json:"avatar_url"`
	HTMLURL   string `json:"html_url"`
	PublicRepos int  `json:"public_repos"`
	Followers int    `json:"followers"`
	Plan      *struct {
		Name string `json:"name"`
	} `json:"plan"`
}

func fetchGitHubAccountInfo(target, credential string, defaultHeaders map[string]string) *AccountInfo {
	resp, err := doAccountRequest(target+"/user", "Bearer "+credential, defaultHeaders)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil
	}

	var u githubUserResponse
	if err := json.NewDecoder(resp.Body).Decode(&u); err != nil {
		return nil
	}

	info := &AccountInfo{
		DisplayName: u.Name,
		Username:    u.Login,
		AvatarURL:   u.AvatarURL,
		URL:         u.HTMLURL,
		Extra: map[string]string{
			"public_repos": fmt.Sprintf("%d", u.PublicRepos),
			"followers":    fmt.Sprintf("%d", u.Followers),
		},
	}
	if u.Plan != nil && u.Plan.Name != "" {
		info.Plan = u.Plan.Name
	}
	return info
}

// ---------------------------------------------------------------------------
// OpenAI
// ---------------------------------------------------------------------------

func fetchOpenAIAccountInfo(target, credential string, defaultHeaders map[string]string) *AccountInfo {
	resp, err := doAccountRequest(target+"/v1/models", "Bearer "+credential, defaultHeaders)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil
	}
	// Drain body to allow connection reuse.
	_, _ = io.Copy(io.Discard, resp.Body)

	return &AccountInfo{
		DisplayName: "OpenAI API",
		Extra:       map[string]string{"models_available": "true"},
	}
}

// ---------------------------------------------------------------------------
// Anthropic
// ---------------------------------------------------------------------------

func fetchAnthropicAccountInfo(target, credential string, defaultHeaders map[string]string) *AccountInfo {
	// Anthropic uses x-api-key header, not Authorization Bearer.
	req, err := buildAccountRequest(target+"/v1/models", defaultHeaders)
	if err != nil {
		return nil
	}
	req.Header.Set("x-api-key", credential)
	req.Header.Set("anthropic-version", "2023-06-01")

	client := &http.Client{Timeout: accountInfoTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil
	}
	_, _ = io.Copy(io.Discard, resp.Body)

	return &AccountInfo{
		DisplayName: "Anthropic API",
		Extra:       map[string]string{"models_available": "true"},
	}
}

// ---------------------------------------------------------------------------
// Stripe
// ---------------------------------------------------------------------------

// stripeBalanceResponse is the relevant subset of the Stripe /v1/balance response.
type stripeBalanceResponse struct {
	Available []struct {
		Currency string `json:"currency"`
		Amount   int    `json:"amount"`
	} `json:"available"`
}

func fetchStripeAccountInfo(target, credential string, defaultHeaders map[string]string) *AccountInfo {
	resp, err := doAccountRequest(target+"/v1/balance", "Bearer "+credential, defaultHeaders)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil
	}

	var b stripeBalanceResponse
	if err := json.NewDecoder(resp.Body).Decode(&b); err != nil {
		return nil
	}

	info := &AccountInfo{DisplayName: "Stripe Account"}
	if len(b.Available) > 0 {
		info.Extra = map[string]string{
			"currency":  b.Available[0].Currency,
			"available": fmt.Sprintf("$%.2f", float64(b.Available[0].Amount)/100),
		}
	}
	return info
}

// ---------------------------------------------------------------------------
// Slack
// ---------------------------------------------------------------------------

// slackAuthTestResponse is the relevant subset of the Slack /api/auth.test response.
type slackAuthTestResponse struct {
	OK   bool   `json:"ok"`
	URL  string `json:"url"`
	Team string `json:"team"`
	User string `json:"user"`
}

func fetchSlackAccountInfo(target, credential string, defaultHeaders map[string]string) *AccountInfo {
	resp, err := doAccountRequest(target+"/auth.test", "Bearer "+credential, defaultHeaders)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil
	}

	var s slackAuthTestResponse
	if err := json.NewDecoder(resp.Body).Decode(&s); err != nil {
		return nil
	}
	if !s.OK {
		return nil
	}

	return &AccountInfo{
		DisplayName: s.User,
		Username:    s.User,
		URL:         s.URL,
		Extra:       map[string]string{"team": s.Team},
	}
}

// ---------------------------------------------------------------------------
// GitLab
// ---------------------------------------------------------------------------

// gitlabUserResponse is the relevant subset of the GitLab /api/v4/user response.
type gitlabUserResponse struct {
	Name      string `json:"name"`
	Username  string `json:"username"`
	AvatarURL string `json:"avatar_url"`
	WebURL    string `json:"web_url"`
}

func fetchGitLabAccountInfo(target, credential string, defaultHeaders map[string]string) *AccountInfo {
	req, err := buildAccountRequest(target+"/user", defaultHeaders)
	if err != nil {
		return nil
	}
	// GitLab uses PRIVATE-TOKEN header.
	req.Header.Set("PRIVATE-TOKEN", credential)

	client := &http.Client{Timeout: accountInfoTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil
	}

	var u gitlabUserResponse
	if err := json.NewDecoder(resp.Body).Decode(&u); err != nil {
		return nil
	}

	return &AccountInfo{
		DisplayName: u.Name,
		Username:    u.Username,
		AvatarURL:   u.AvatarURL,
		URL:         u.WebURL,
	}
}

// ---------------------------------------------------------------------------
// Google
// ---------------------------------------------------------------------------

func fetchGoogleAccountInfo(target, credential string, defaultHeaders map[string]string) *AccountInfo {
	// Google API keys are passed as query parameters. We do a simple
	// validation request against the Discovery API.
	reqURL := target + "/discovery/v1/apis"
	parsed, err := url.Parse(reqURL)
	if err != nil {
		return nil
	}
	q := parsed.Query()
	q.Set("key", credential)
	parsed.RawQuery = q.Encode()

	req, err := buildAccountRequest(parsed.String(), defaultHeaders)
	if err != nil {
		return nil
	}

	client := &http.Client{Timeout: accountInfoTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil
	}
	_, _ = io.Copy(io.Discard, resp.Body)

	return &AccountInfo{
		DisplayName: "Google API Key",
	}
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

// doAccountRequest sends a GET request with the given Authorization header value
// and default headers. Returns the raw response for the caller to close.
func doAccountRequest(rawURL, authHeader string, defaultHeaders map[string]string) (*http.Response, error) {
	req, err := buildAccountRequest(rawURL, defaultHeaders)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", authHeader)

	client := &http.Client{Timeout: accountInfoTimeout}
	return client.Do(req)
}

// buildAccountRequest creates a GET *http.Request with default headers applied.
func buildAccountRequest(rawURL string, defaultHeaders map[string]string) (*http.Request, error) {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range defaultHeaders {
		req.Header.Set(k, v)
	}
	return req, nil
}
