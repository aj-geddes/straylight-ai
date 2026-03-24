package oauth

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// ---------------------------------------------------------------------------
// GetOAuthConfig tests
// ---------------------------------------------------------------------------

func TestGetOAuthConfig_ReturnsConfiguredTrueWhenClientIDSet(t *testing.T) {
	vault := newFakeVault()
	_ = vault.WriteSecret("services/github/oauth_client_secret", map[string]interface{}{
		"client_id":     "my-client-id",
		"client_secret": "my-client-secret",
	})
	h := NewHandler(vault, &fakeServices{}, "http://localhost:9470")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/oauth/github/config", nil)
	req.SetPathValue("provider", "github")
	w := httptest.NewRecorder()
	h.GetOAuthConfig(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d (body: %s)", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["provider"] != "github" {
		t.Errorf("expected provider=github, got %v", resp["provider"])
	}
	if resp["configured"] != true {
		t.Errorf("expected configured=true, got %v", resp["configured"])
	}
	if resp["client_id"] != "my-client-id" {
		t.Errorf("expected client_id=my-client-id, got %v", resp["client_id"])
	}
}

func TestGetOAuthConfig_ReturnsConfiguredFalseWhenNotSet(t *testing.T) {
	vault := newFakeVault()
	h := NewHandler(vault, &fakeServices{}, "http://localhost:9470")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/oauth/github/config", nil)
	req.SetPathValue("provider", "github")
	w := httptest.NewRecorder()
	h.GetOAuthConfig(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["configured"] != false {
		t.Errorf("expected configured=false, got %v", resp["configured"])
	}
}

func TestGetOAuthConfig_NeverReturnsClientSecret(t *testing.T) {
	vault := newFakeVault()
	_ = vault.WriteSecret("services/github/oauth_client_secret", map[string]interface{}{
		"client_id":     "cid",
		"client_secret": "super-secret",
	})
	h := NewHandler(vault, &fakeServices{}, "http://localhost:9470")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/oauth/github/config", nil)
	req.SetPathValue("provider", "github")
	w := httptest.NewRecorder()
	h.GetOAuthConfig(w, req)

	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if _, hasSecret := resp["client_secret"]; hasSecret {
		t.Error("client_secret must never appear in GetOAuthConfig response")
	}
}

func TestGetOAuthConfig_UnknownProviderReturns400(t *testing.T) {
	h := NewHandler(newFakeVault(), &fakeServices{}, "http://localhost:9470")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/oauth/badprovider/config", nil)
	req.SetPathValue("provider", "badprovider")
	w := httptest.NewRecorder()
	h.GetOAuthConfig(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for unknown provider, got %d", w.Code)
	}
}

// ---------------------------------------------------------------------------
// SaveOAuthConfig tests
// ---------------------------------------------------------------------------

func TestSaveOAuthConfig_StoresClientIDAndSecretInVault(t *testing.T) {
	vault := newFakeVault()
	h := NewHandler(vault, &fakeServices{}, "http://localhost:9470")

	body, _ := json.Marshal(map[string]string{
		"client_id":     "new-client-id",
		"client_secret": "new-client-secret",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/github/config", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("provider", "github")
	w := httptest.NewRecorder()
	h.SaveOAuthConfig(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d (body: %s)", w.Code, w.Body.String())
	}

	// Verify stored in vault.
	stored, err := vault.ReadSecret("services/github/oauth_client_secret")
	if err != nil {
		t.Fatalf("expected secret in vault, got: %v", err)
	}
	if stored["client_id"] != "new-client-id" {
		t.Errorf("expected client_id=new-client-id in vault, got %v", stored["client_id"])
	}
	if stored["client_secret"] != "new-client-secret" {
		t.Errorf("expected client_secret stored in vault, got %v", stored["client_secret"])
	}
}

func TestSaveOAuthConfig_ReturnsProviderAndConfiguredTrue(t *testing.T) {
	vault := newFakeVault()
	h := NewHandler(vault, &fakeServices{}, "http://localhost:9470")

	body, _ := json.Marshal(map[string]string{
		"client_id":     "cid",
		"client_secret": "cs",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/github/config", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("provider", "github")
	w := httptest.NewRecorder()
	h.SaveOAuthConfig(w, req)

	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["provider"] != "github" {
		t.Errorf("expected provider=github, got %v", resp["provider"])
	}
	if resp["configured"] != true {
		t.Errorf("expected configured=true, got %v", resp["configured"])
	}
}

func TestSaveOAuthConfig_MissingClientIDReturns400(t *testing.T) {
	vault := newFakeVault()
	h := NewHandler(vault, &fakeServices{}, "http://localhost:9470")

	body, _ := json.Marshal(map[string]string{
		"client_secret": "cs",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/github/config", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("provider", "github")
	w := httptest.NewRecorder()
	h.SaveOAuthConfig(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing client_id, got %d", w.Code)
	}
}

func TestSaveOAuthConfig_MissingClientSecretReturns400(t *testing.T) {
	vault := newFakeVault()
	h := NewHandler(vault, &fakeServices{}, "http://localhost:9470")

	body, _ := json.Marshal(map[string]string{
		"client_id": "cid",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/github/config", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("provider", "github")
	w := httptest.NewRecorder()
	h.SaveOAuthConfig(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing client_secret, got %d", w.Code)
	}
}

func TestSaveOAuthConfig_UnknownProviderReturns400(t *testing.T) {
	vault := newFakeVault()
	h := NewHandler(vault, &fakeServices{}, "http://localhost:9470")

	body, _ := json.Marshal(map[string]string{
		"client_id":     "cid",
		"client_secret": "cs",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/badprovider/config", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("provider", "badprovider")
	w := httptest.NewRecorder()
	h.SaveOAuthConfig(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for unknown provider, got %d", w.Code)
	}
}

func TestSaveOAuthConfig_InvalidJSONReturns400(t *testing.T) {
	vault := newFakeVault()
	h := NewHandler(vault, &fakeServices{}, "http://localhost:9470")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/github/config",
		bytes.NewReader([]byte("not-json")))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("provider", "github")
	w := httptest.NewRecorder()
	h.SaveOAuthConfig(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid JSON, got %d", w.Code)
	}
}

// ---------------------------------------------------------------------------
// DeleteOAuthConfig tests
// ---------------------------------------------------------------------------

func TestDeleteOAuthConfig_RemovesStoredCredentials(t *testing.T) {
	vault := newFakeVault()
	_ = vault.WriteSecret("services/github/oauth_client_secret", map[string]interface{}{
		"client_id":     "cid",
		"client_secret": "cs",
	})
	h := NewHandler(vault, &fakeServices{}, "http://localhost:9470")

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/oauth/github/config", nil)
	req.SetPathValue("provider", "github")
	w := httptest.NewRecorder()
	h.DeleteOAuthConfig(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d", w.Code)
	}

	// Verify it's gone.
	_, err := vault.ReadSecret("services/github/oauth_client_secret")
	if err == nil {
		t.Error("expected vault secret to be removed after delete")
	}
}

func TestDeleteOAuthConfig_UnknownProviderReturns400(t *testing.T) {
	h := NewHandler(newFakeVault(), &fakeServices{}, "http://localhost:9470")

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/oauth/badprovider/config", nil)
	req.SetPathValue("provider", "badprovider")
	w := httptest.NewRecorder()
	h.DeleteOAuthConfig(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for unknown provider, got %d", w.Code)
	}
}

// ---------------------------------------------------------------------------
// StartOAuth tests — missing client_id returns 400 (not silently redirect)
// ---------------------------------------------------------------------------

func TestStartOAuth_MissingClientIDReturns400(t *testing.T) {
	vault := newFakeVault()
	// No client_id stored — vault is empty.
	h := NewHandler(vault, &fakeServices{}, "http://localhost:9470")

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/oauth/github/start?service_name=github", nil)
	req.SetPathValue("provider", "github")
	w := httptest.NewRecorder()
	h.StartOAuth(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 when client_id is empty, got %d (body: %s)", w.Code, w.Body.String())
	}
}

func TestStartOAuth_IncludesResponseTypeCode(t *testing.T) {
	vault := newFakeVault()
	_ = vault.WriteSecret("services/github/oauth_client_secret", map[string]interface{}{
		"client_id":     "cid",
		"client_secret": "cs",
	})
	h := NewHandler(vault, &fakeServices{}, "http://localhost:9470")

	redirectURL := startFlow(t, h, "github", "github")
	q := redirectURL.Query()

	if q.Get("response_type") != "code" {
		t.Errorf("expected response_type=code in redirect, got %q", q.Get("response_type"))
	}
}
