package oauth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/straylight-ai/straylight/internal/services"
)

// DeviceCodeResponse is the JSON payload returned by POST .../device/start.
// It contains everything the frontend needs to display the device flow UI.
type DeviceCodeResponse struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
	// Message is an optional human-readable string provided by some providers
	// (e.g., Microsoft) with instructions for the user.
	Message string `json:"message,omitempty"`
}

// rawDeviceCodeResponse is the raw JSON from a provider's device code endpoint.
// It handles both "verification_uri" (GitHub, Microsoft) and "verification_url"
// (Google) field names, normalizing them into a single DeviceCodeResponse.
type rawDeviceCodeResponse struct {
	DeviceCode          string `json:"device_code"`
	UserCode            string `json:"user_code"`
	VerificationURI     string `json:"verification_uri"`
	VerificationURL     string `json:"verification_url"`
	ExpiresIn           int    `json:"expires_in"`
	Interval            int    `json:"interval"`
	Message             string `json:"message,omitempty"`
}

// normalize converts a rawDeviceCodeResponse into a DeviceCodeResponse,
// mapping Google's "verification_url" to the canonical "verification_uri".
func (r rawDeviceCodeResponse) normalize() DeviceCodeResponse {
	uri := r.VerificationURI
	if uri == "" {
		uri = r.VerificationURL
	}
	return DeviceCodeResponse{
		DeviceCode:      r.DeviceCode,
		UserCode:        r.UserCode,
		VerificationURI: uri,
		ExpiresIn:       r.ExpiresIn,
		Interval:        r.Interval,
		Message:         r.Message,
	}
}

// devicePollRequest is the JSON body for POST .../device/poll.
type devicePollRequest struct {
	DeviceCode  string `json:"device_code"`
	ServiceName string `json:"service_name"`
}

// devicePollResponse is the JSON payload returned by POST .../device/poll.
type devicePollResponse struct {
	Status string `json:"status"`
}

// deviceCodeGrant is the OAuth 2.0 grant type for device authorization (RFC 8628).
const deviceCodeGrant = "urn:ietf:params:oauth:grant-type:device_code"

// githubClientIDEnvVar is kept for backward compatibility with existing tests
// that reference it directly. New code uses resolveDeviceClientID which builds
// the env var name dynamically per provider.
const githubClientIDEnvVar = "STRAYLIGHT_GITHUB_CLIENT_ID"

// ---------------------------------------------------------------------------
// StartDeviceFlow — POST /api/v1/oauth/{provider}/device/start
// ---------------------------------------------------------------------------

// StartDeviceFlow initiates the Device Authorization Flow (RFC 8628) for the
// given provider. It POSTs to the provider's device code endpoint and returns
// user_code, verification_uri, device_code, expires_in, and interval to the
// frontend. Provider-specific field name differences (e.g., Google's
// verification_url vs verification_uri) are normalized before responding.
//
// The frontend is responsible for showing the user the code and polling
// PollDeviceFlow every interval seconds until the user authorizes or the code
// expires.
func (h *Handler) StartDeviceFlow(w http.ResponseWriter, r *http.Request) {
	providerName := r.PathValue("provider")

	provider, ok := Providers[providerName]
	if !ok {
		writeOAuthError(w, http.StatusBadRequest,
			fmt.Sprintf("unknown provider %q", providerName))
		return
	}

	if provider.DeviceCodeURL == "" {
		writeOAuthError(w, http.StatusBadRequest,
			fmt.Sprintf(
				"provider %q does not support device authorization flow; "+
					"use the standard OAuth flow at /api/v1/oauth/%s/start instead",
				providerName, providerName,
			),
		)
		return
	}

	clientID := h.resolveDeviceClientID(providerName, provider)
	if clientID == "" {
		envKey := "STRAYLIGHT_" + strings.ToUpper(providerName) + "_CLIENT_ID"
		writeOAuthError(w, http.StatusBadRequest,
			fmt.Sprintf(
				"no client_id configured for provider %q device flow. "+
					"Set the %s environment variable or configure it at "+
					"/api/v1/oauth/%s/config",
				providerName, envKey, providerName,
			),
		)
		return
	}

	scopes := strings.Join(provider.DefaultScopes, " ")
	params := url.Values{
		"client_id": {clientID},
		"scope":     {scopes},
	}

	req, err := http.NewRequest(http.MethodPost, provider.DeviceCodeURL,
		bytes.NewBufferString(params.Encode()))
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "build device code request: "+err.Error())
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := h.httpClient.Do(req)
	if err != nil {
		writeOAuthError(w, http.StatusBadGateway, "device code request failed: "+err.Error())
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "read device code response: "+err.Error())
		return
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		writeOAuthError(w, http.StatusBadGateway,
			fmt.Sprintf("device code endpoint returned status %d: %s",
				resp.StatusCode, strings.TrimSpace(string(body))))
		return
	}

	var raw rawDeviceCodeResponse
	if err := json.Unmarshal(body, &raw); err != nil {
		writeOAuthError(w, http.StatusInternalServerError,
			"decode device code response: "+err.Error())
		return
	}

	dcr := raw.normalize()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(dcr)
}

// ---------------------------------------------------------------------------
// PollDeviceFlow — POST /api/v1/oauth/{provider}/device/poll
// ---------------------------------------------------------------------------

// PollDeviceFlow checks whether the user has authorized the device.
// The frontend calls this endpoint every interval seconds after StartDeviceFlow.
//
// Response status values:
//   - "pending"  — user has not yet authorized (also returned for slow_down)
//   - "expired"  — the device code has expired; user must restart
//   - "complete" — authorization granted; token stored and service created
func (h *Handler) PollDeviceFlow(w http.ResponseWriter, r *http.Request) {
	providerName := r.PathValue("provider")

	provider, ok := Providers[providerName]
	if !ok {
		writeOAuthError(w, http.StatusBadRequest,
			fmt.Sprintf("unknown provider %q", providerName))
		return
	}

	var req devicePollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}

	if req.DeviceCode == "" {
		writeOAuthError(w, http.StatusBadRequest, "device_code is required")
		return
	}
	if req.ServiceName == "" {
		writeOAuthError(w, http.StatusBadRequest, "service_name is required")
		return
	}

	clientID := h.resolveDeviceClientID(providerName, provider)
	if clientID == "" {
		writeOAuthError(w, http.StatusBadRequest,
			fmt.Sprintf("no client_id configured for provider %q device flow", providerName))
		return
	}

	params := url.Values{
		"client_id":   {clientID},
		"device_code": {req.DeviceCode},
		"grant_type":  {deviceCodeGrant},
	}

	// Some providers (e.g., Google) require client_secret in the poll request.
	// GitHub does not. Include it only when configured via env var.
	if secret := h.resolveClientSecret(provider); secret != "" {
		params.Set("client_secret", secret)
	}

	tokenReq, err := http.NewRequest(http.MethodPost, provider.TokenURL,
		bytes.NewBufferString(params.Encode()))
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "build poll request: "+err.Error())
		return
	}
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenReq.Header.Set("Accept", "application/json")

	resp, err := h.httpClient.Do(tokenReq)
	if err != nil {
		writeOAuthError(w, http.StatusBadGateway, "poll request failed: "+err.Error())
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "read poll response: "+err.Error())
		return
	}

	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		writeOAuthError(w, http.StatusInternalServerError,
			"decode poll response: "+err.Error())
		return
	}

	switch tr.Error {
	case "authorization_pending", "slow_down":
		writePollResponse(w, "pending")
		return
	case "expired_token":
		writePollResponse(w, "expired")
		return
	case "":
		// No error — fall through to token handling below.
	default:
		writeOAuthError(w, http.StatusBadGateway,
			fmt.Sprintf("provider error %q: %s", tr.Error, tr.ErrorDesc))
		return
	}

	if tr.AccessToken == "" {
		writeOAuthError(w, http.StatusBadGateway, "provider returned empty access_token")
		return
	}

	// Some providers (e.g., GitHub) do not include expires_in; use the default TTL.
	expiresAt := time.Now().Add(oauthTokenTTL)
	if tr.ExpiresIn > 0 {
		expiresAt = time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second)
	}

	tokenData := map[string]interface{}{
		"access_token":  tr.AccessToken,
		"refresh_token": tr.RefreshToken,
		"token_type":    tr.TokenType,
		"scope":         tr.Scope,
		"expires_at":    expiresAt.Format(time.RFC3339),
		"provider":      providerName,
	}
	if err := h.vault.WriteSecret(oauthTokenPath(req.ServiceName), tokenData); err != nil {
		h.logger.Error("device flow: vault write failed",
			"provider", providerName,
			"service", req.ServiceName,
			"error", err,
		)
		writeOAuthError(w, http.StatusInternalServerError, "failed to store tokens")
		return
	}

	// Create or update the service, matching the behavior of the regular OAuth callback.
	_, getErr := h.services.Get(req.ServiceName)
	if getErr != nil {
		tmpl := findTemplateForProvider(providerName)
		svc := services.Service{
			Name:           req.ServiceName,
			Type:           "http_proxy",
			Target:         tmpl.target,
			AuthMethodID:   tmpl.authMethodID,
			Inject:         "header",
			HeaderTemplate: "Bearer {{.secret}}",
			DefaultHeaders: tmpl.defaultHeaders,
			Status:         "available",
		}
		if createErr := h.services.Create(svc, tr.AccessToken); createErr != nil {
			h.logger.Warn("device flow: service create failed",
				"service", req.ServiceName,
				"error", createErr,
			)
		}
	} else {
		if updateErr := h.services.Update(req.ServiceName, services.Service{
			Name:   req.ServiceName,
			Status: "available",
		}, &tr.AccessToken); updateErr != nil {
			h.logger.Warn("device flow: service update failed",
				"service", req.ServiceName,
				"error", updateErr,
			)
		}
	}

	writePollResponse(w, "complete")
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// resolveDeviceClientID returns the client_id to use for the device flow.
// Resolution order:
//  1. Environment variable STRAYLIGHT_{PROVIDER}_CLIENT_ID (e.g., STRAYLIGHT_GITHUB_CLIENT_ID).
//  2. Provider's baked-in DefaultClientID.
//  3. Vault (same path as the regular OAuth App credentials).
func (h *Handler) resolveDeviceClientID(providerName string, provider Provider) string {
	envKey := "STRAYLIGHT_" + strings.ToUpper(providerName) + "_CLIENT_ID"
	if v := os.Getenv(envKey); v != "" {
		return v
	}
	if provider.DefaultClientID != "" {
		return provider.DefaultClientID
	}
	return h.readClientID(providerName)
}

// resolveClientSecret returns the OAuth client_secret for the device flow, if any.
// It reads STRAYLIGHT_{PROVIDER}_CLIENT_SECRET from the environment.
// Returns an empty string when not configured (e.g., GitHub does not require one).
func (h *Handler) resolveClientSecret(provider Provider) string {
	envKey := "STRAYLIGHT_" + strings.ToUpper(provider.Name) + "_CLIENT_SECRET"
	return os.Getenv(envKey)
}

// writePollResponse writes a { "status": status } JSON response with 200 OK.
func writePollResponse(w http.ResponseWriter, status string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(devicePollResponse{Status: status})
}
