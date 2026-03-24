package oauth

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// oauthConfigRequest is the JSON body for POST /api/v1/oauth/{provider}/config.
type oauthConfigRequest struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

// oauthConfigResponse is the JSON response for GET/POST /api/v1/oauth/{provider}/config.
// client_secret is never included.
type oauthConfigResponse struct {
	Provider   string `json:"provider"`
	Configured bool   `json:"configured"`
	ClientID   string `json:"client_id,omitempty"`
}

// ---------------------------------------------------------------------------
// GetOAuthConfig — GET /api/v1/oauth/{provider}/config
// ---------------------------------------------------------------------------

// GetOAuthConfig returns whether OAuth App credentials have been configured
// for the given provider. The client_secret is never returned.
func (h *Handler) GetOAuthConfig(w http.ResponseWriter, r *http.Request) {
	providerName := r.PathValue("provider")

	if _, ok := Providers[providerName]; !ok {
		writeOAuthError(w, http.StatusBadRequest,
			fmt.Sprintf("unknown provider %q", providerName))
		return
	}

	clientID := h.readClientID(providerName)
	resp := oauthConfigResponse{
		Provider:   providerName,
		Configured: clientID != "",
		ClientID:   clientID,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// ---------------------------------------------------------------------------
// SaveOAuthConfig — POST /api/v1/oauth/{provider}/config
// ---------------------------------------------------------------------------

// SaveOAuthConfig stores the OAuth App client_id and client_secret in vault
// for the given provider. These are application-level credentials that the
// user obtains by registering an OAuth App with the provider.
func (h *Handler) SaveOAuthConfig(w http.ResponseWriter, r *http.Request) {
	providerName := r.PathValue("provider")

	if _, ok := Providers[providerName]; !ok {
		writeOAuthError(w, http.StatusBadRequest,
			fmt.Sprintf("unknown provider %q", providerName))
		return
	}

	var req oauthConfigRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}

	if req.ClientID == "" {
		writeOAuthError(w, http.StatusBadRequest, "client_id is required")
		return
	}
	if req.ClientSecret == "" {
		writeOAuthError(w, http.StatusBadRequest, "client_secret is required")
		return
	}

	if err := h.vault.WriteSecret(oauthClientSecretPath(providerName), map[string]interface{}{
		"client_id":     req.ClientID,
		"client_secret": req.ClientSecret,
	}); err != nil {
		h.logger.Error("oauth config: vault write failed",
			"provider", providerName,
			"error", err,
		)
		writeOAuthError(w, http.StatusInternalServerError, "failed to store OAuth credentials")
		return
	}

	resp := oauthConfigResponse{
		Provider:   providerName,
		Configured: true,
		ClientID:   req.ClientID,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// ---------------------------------------------------------------------------
// DeleteOAuthConfig — DELETE /api/v1/oauth/{provider}/config
// ---------------------------------------------------------------------------

// DeleteOAuthConfig removes the stored OAuth App credentials for the given
// provider from vault.
func (h *Handler) DeleteOAuthConfig(w http.ResponseWriter, r *http.Request) {
	providerName := r.PathValue("provider")

	if _, ok := Providers[providerName]; !ok {
		writeOAuthError(w, http.StatusBadRequest,
			fmt.Sprintf("unknown provider %q", providerName))
		return
	}

	if err := h.vault.DeleteSecret(oauthClientSecretPath(providerName)); err != nil {
		h.logger.Error("oauth config: vault delete failed",
			"provider", providerName,
			"error", err,
		)
		writeOAuthError(w, http.StatusInternalServerError, "failed to delete OAuth credentials")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
