package services_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/straylight-ai/straylight/internal/services"
)

// ---------------------------------------------------------------------------
// FetchAccountInfo tests — use httptest.Server as a mock API
// ---------------------------------------------------------------------------

// makeTestServer returns an httptest.Server that responds with the given JSON
// body and status code for any request.
func makeTestServer(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
}

// makeTestServerWithAuth returns an httptest.Server that records received
// headers and responds with the given JSON body.
func makeTestServerWithAuth(t *testing.T, status int, body string, receivedHeader *string, headerName string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if receivedHeader != nil {
			*receivedHeader = r.Header.Get(headerName)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
}

// TestFetchAccountInfo_GitHub_ParsesUserResponse verifies that a GitHub-like
// /user response is parsed into the expected AccountInfo fields.
func TestFetchAccountInfo_GitHub_ParsesUserResponse(t *testing.T) {
	body := `{
		"login": "aj-geddes",
		"name": "AJ Geddes",
		"avatar_url": "https://avatars.githubusercontent.com/u/123",
		"html_url": "https://github.com/aj-geddes",
		"public_repos": 26,
		"followers": 10,
		"plan": {"name": "pro"}
	}`
	srv := makeTestServer(t, http.StatusOK, body)
	defer srv.Close()

	// Override the GitHub target to point to our test server.
	info := services.FetchAccountInfo(srv.URL, "ghp_testtoken", "github_pat_classic", nil)

	if info == nil {
		t.Fatal("expected non-nil AccountInfo for GitHub response, got nil")
	}
	if info.Username != "aj-geddes" {
		t.Errorf("expected username=aj-geddes, got %q", info.Username)
	}
	if info.DisplayName != "AJ Geddes" {
		t.Errorf("expected display_name=AJ Geddes, got %q", info.DisplayName)
	}
	if info.AvatarURL != "https://avatars.githubusercontent.com/u/123" {
		t.Errorf("expected avatar_url set, got %q", info.AvatarURL)
	}
	if info.URL != "https://github.com/aj-geddes" {
		t.Errorf("expected url=https://github.com/aj-geddes, got %q", info.URL)
	}
	if info.Plan != "pro" {
		t.Errorf("expected plan=pro, got %q", info.Plan)
	}
	if info.Extra["public_repos"] != "26" {
		t.Errorf("expected extra.public_repos=26, got %q", info.Extra["public_repos"])
	}
	if info.Extra["followers"] != "10" {
		t.Errorf("expected extra.followers=10, got %q", info.Extra["followers"])
	}
}

// TestFetchAccountInfo_GitHub_MissingPlan_OmitsPlanField verifies that a
// GitHub response without a plan does not set the Plan field.
func TestFetchAccountInfo_GitHub_MissingPlan_OmitsPlanField(t *testing.T) {
	body := `{"login": "tester", "name": "Tester", "avatar_url": "", "html_url": ""}`
	srv := makeTestServer(t, http.StatusOK, body)
	defer srv.Close()

	info := services.FetchAccountInfo(srv.URL, "ghp_testtoken", "github_fine_grained_pat", nil)
	if info == nil {
		t.Fatal("expected non-nil AccountInfo")
	}
	if info.Plan != "" {
		t.Errorf("expected empty plan when absent, got %q", info.Plan)
	}
}

// TestFetchAccountInfo_OpenAI_ReturnsDisplayName verifies OpenAI enrichment.
func TestFetchAccountInfo_OpenAI_ReturnsDisplayName(t *testing.T) {
	body := `{"object": "list", "data": []}`
	srv := makeTestServer(t, http.StatusOK, body)
	defer srv.Close()

	info := services.FetchAccountInfo(srv.URL, "sk-testkey", "openai_api_key", nil)
	if info == nil {
		t.Fatal("expected non-nil AccountInfo for OpenAI response")
	}
	if info.DisplayName != "OpenAI API" {
		t.Errorf("expected display_name=OpenAI API, got %q", info.DisplayName)
	}
	if info.Extra["models_available"] != "true" {
		t.Errorf("expected extra.models_available=true, got %q", info.Extra["models_available"])
	}
}

// TestFetchAccountInfo_Anthropic_ReturnsDisplayName verifies Anthropic enrichment.
func TestFetchAccountInfo_Anthropic_ReturnsDisplayName(t *testing.T) {
	body := `{"type": "list", "data": []}`
	srv := makeTestServer(t, http.StatusOK, body)
	defer srv.Close()

	info := services.FetchAccountInfo(srv.URL, "sk-ant-testkey", "anthropic_api_key", nil)
	if info == nil {
		t.Fatal("expected non-nil AccountInfo for Anthropic response")
	}
	if info.DisplayName != "Anthropic API" {
		t.Errorf("expected display_name=Anthropic API, got %q", info.DisplayName)
	}
	if info.Extra["models_available"] != "true" {
		t.Errorf("expected extra.models_available=true, got %q", info.Extra["models_available"])
	}
}

// TestFetchAccountInfo_Stripe_ParsesBalanceResponse verifies Stripe enrichment.
func TestFetchAccountInfo_Stripe_ParsesBalanceResponse(t *testing.T) {
	body := `{
		"object": "balance",
		"available": [{"currency": "usd", "amount": 500}],
		"pending": []
	}`
	srv := makeTestServer(t, http.StatusOK, body)
	defer srv.Close()

	info := services.FetchAccountInfo(srv.URL, "sk_test_abc", "stripe_api_key", nil)
	if info == nil {
		t.Fatal("expected non-nil AccountInfo for Stripe response")
	}
	if info.DisplayName != "Stripe Account" {
		t.Errorf("expected display_name=Stripe Account, got %q", info.DisplayName)
	}
	if info.Extra["currency"] != "usd" {
		t.Errorf("expected extra.currency=usd, got %q", info.Extra["currency"])
	}
}

// TestFetchAccountInfo_Slack_ParsesAuthTestResponse verifies Slack enrichment.
func TestFetchAccountInfo_Slack_ParsesAuthTestResponse(t *testing.T) {
	body := `{
		"ok": true,
		"url": "https://myteam.slack.com/",
		"team": "My Team",
		"user": "slackbot",
		"user_id": "U12345"
	}`
	srv := makeTestServer(t, http.StatusOK, body)
	defer srv.Close()

	info := services.FetchAccountInfo(srv.URL, "xoxb-test", "slack_bot_token", nil)
	if info == nil {
		t.Fatal("expected non-nil AccountInfo for Slack response")
	}
	if info.DisplayName != "slackbot" {
		t.Errorf("expected display_name=slackbot, got %q", info.DisplayName)
	}
	if info.Username != "slackbot" {
		t.Errorf("expected username=slackbot, got %q", info.Username)
	}
	if info.URL != "https://myteam.slack.com/" {
		t.Errorf("expected url set, got %q", info.URL)
	}
	if info.Extra["team"] != "My Team" {
		t.Errorf("expected extra.team=My Team, got %q", info.Extra["team"])
	}
}

// TestFetchAccountInfo_GitLab_ParsesUserResponse verifies GitLab enrichment.
func TestFetchAccountInfo_GitLab_ParsesUserResponse(t *testing.T) {
	body := `{
		"id": 1,
		"username": "gl-user",
		"name": "GL User",
		"avatar_url": "https://gitlab.com/uploads/user/avatar/1/avatar.png",
		"web_url": "https://gitlab.com/gl-user"
	}`
	srv := makeTestServer(t, http.StatusOK, body)
	defer srv.Close()

	info := services.FetchAccountInfo(srv.URL, "glpat-test", "gitlab_pat", nil)
	if info == nil {
		t.Fatal("expected non-nil AccountInfo for GitLab response")
	}
	if info.DisplayName != "GL User" {
		t.Errorf("expected display_name=GL User, got %q", info.DisplayName)
	}
	if info.Username != "gl-user" {
		t.Errorf("expected username=gl-user, got %q", info.Username)
	}
	if info.AvatarURL != "https://gitlab.com/uploads/user/avatar/1/avatar.png" {
		t.Errorf("expected avatar_url set, got %q", info.AvatarURL)
	}
	if info.URL != "https://gitlab.com/gl-user" {
		t.Errorf("expected url=https://gitlab.com/gl-user, got %q", info.URL)
	}
}

// TestFetchAccountInfo_Google_ReturnsDisplayName verifies Google enrichment.
func TestFetchAccountInfo_Google_ReturnsDisplayName(t *testing.T) {
	// Google just verifies the key works — any 200 response is fine.
	srv := makeTestServer(t, http.StatusOK, `{}`)
	defer srv.Close()

	info := services.FetchAccountInfo(srv.URL, "AIza-testkey", "google_api_key", nil)
	if info == nil {
		t.Fatal("expected non-nil AccountInfo for Google response")
	}
	if info.DisplayName != "Google API Key" {
		t.Errorf("expected display_name=Google API Key, got %q", info.DisplayName)
	}
}

// TestFetchAccountInfo_UnknownAuthMethod_ReturnsNil verifies that unknown
// auth method IDs return nil (no enrichment for unrecognized services).
func TestFetchAccountInfo_UnknownAuthMethod_ReturnsNil(t *testing.T) {
	srv := makeTestServer(t, http.StatusOK, `{}`)
	defer srv.Close()

	info := services.FetchAccountInfo(srv.URL, "sometoken", "unknown_custom_method", nil)
	if info != nil {
		t.Errorf("expected nil for unknown auth method, got %+v", info)
	}
}

// TestFetchAccountInfo_HTTPError_ReturnsNil verifies that a non-2xx response
// results in nil (best-effort, never fail service creation).
func TestFetchAccountInfo_HTTPError_ReturnsNil(t *testing.T) {
	srv := makeTestServer(t, http.StatusUnauthorized, `{"error": "unauthorized"}`)
	defer srv.Close()

	info := services.FetchAccountInfo(srv.URL, "bad-token", "github_pat_classic", nil)
	if info != nil {
		t.Errorf("expected nil on 401 response, got %+v", info)
	}
}

// TestFetchAccountInfo_InvalidJSON_ReturnsNil verifies that malformed JSON
// from the upstream API results in nil (best-effort).
func TestFetchAccountInfo_InvalidJSON_ReturnsNil(t *testing.T) {
	srv := makeTestServer(t, http.StatusOK, `not-valid-json{`)
	defer srv.Close()

	info := services.FetchAccountInfo(srv.URL, "ghp_testtoken", "github_pat_classic", nil)
	if info != nil {
		t.Errorf("expected nil on invalid JSON, got %+v", info)
	}
}

// TestFetchAccountInfo_DefaultHeaders_AreApplied verifies that default headers
// passed to FetchAccountInfo are included in the outgoing request.
func TestFetchAccountInfo_DefaultHeaders_AreApplied(t *testing.T) {
	var receivedHeader string
	srv := makeTestServerWithAuth(t, http.StatusOK, `{"login":"u","name":"U","avatar_url":"","html_url":""}`,
		&receivedHeader, "X-Custom-Header")
	defer srv.Close()

	defaultHeaders := map[string]string{"X-Custom-Header": "custom-value"}
	info := services.FetchAccountInfo(srv.URL, "ghp_testtoken", "github_pat_classic", defaultHeaders)
	if info == nil {
		t.Fatal("expected non-nil AccountInfo")
	}
	if receivedHeader != "custom-value" {
		t.Errorf("expected X-Custom-Header=custom-value in request, got %q", receivedHeader)
	}
}

// TestFetchAccountInfo_CredentialNotLogged verifies the function signature
// accepts credential without returning it or including it in AccountInfo.
// (Structural test — credential must not appear in returned struct.)
func TestFetchAccountInfo_CredentialNotExposedInResult(t *testing.T) {
	secretCred := "super-secret-credential-12345"
	body := `{"login":"u","name":"User","avatar_url":"","html_url":""}`
	srv := makeTestServer(t, http.StatusOK, body)
	defer srv.Close()

	info := services.FetchAccountInfo(srv.URL, secretCred, "github_pat_classic", nil)
	if info == nil {
		t.Fatal("expected non-nil AccountInfo")
	}

	// Serialize the result and verify the credential does not appear.
	b, err := json.Marshal(info)
	if err != nil {
		t.Fatalf("failed to marshal AccountInfo: %v", err)
	}
	if string(b) != "" && contains(string(b), secretCred) {
		t.Errorf("credential value leaked into AccountInfo JSON output")
	}
}

// contains is a helper to check substring without importing strings package
// at the top level (kept local to test file).
func contains(s, sub string) bool {
	return len(sub) > 0 && len(s) >= len(sub) && (s == sub || len(s) > 0 && containsHelper(s, sub))
}

func containsHelper(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// SetAccountInfo tests
// ---------------------------------------------------------------------------

// TestRegistry_SetAccountInfo_UpdatesServiceInMemory verifies SetAccountInfo
// stores the AccountInfo on an existing service.
func TestRegistry_SetAccountInfo_UpdatesServiceInMemory(t *testing.T) {
	vault := newMockVault()
	reg := services.NewRegistry(vault)

	svc := services.Service{
		Name:   "github",
		Type:   "http_proxy",
		Target: "https://api.github.com",
		Inject: "header",
	}
	if err := reg.Create(svc, "ghp_token"); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	info := &services.AccountInfo{
		DisplayName: "AJ Geddes",
		Username:    "aj-geddes",
	}
	if err := reg.SetAccountInfo("github", info); err != nil {
		t.Fatalf("SetAccountInfo failed: %v", err)
	}

	retrieved, err := reg.Get("github")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if retrieved.AccountInfo == nil {
		t.Fatal("expected AccountInfo to be set, got nil")
	}
	if retrieved.AccountInfo.Username != "aj-geddes" {
		t.Errorf("expected username=aj-geddes, got %q", retrieved.AccountInfo.Username)
	}
	if retrieved.AccountInfo.DisplayName != "AJ Geddes" {
		t.Errorf("expected display_name=AJ Geddes, got %q", retrieved.AccountInfo.DisplayName)
	}
}

// TestRegistry_SetAccountInfo_ServiceNotFound_ReturnsError verifies that
// SetAccountInfo returns an error for a non-existent service name.
func TestRegistry_SetAccountInfo_ServiceNotFound_ReturnsError(t *testing.T) {
	vault := newMockVault()
	reg := services.NewRegistry(vault)

	info := &services.AccountInfo{DisplayName: "Test"}
	err := reg.SetAccountInfo("nonexistent", info)
	if err == nil {
		t.Error("expected error for nonexistent service, got nil")
	}
}

// TestRegistry_SetAccountInfo_NilInfo_ClearsExistingInfo verifies that nil
// AccountInfo can be used to clear previously set account info.
func TestRegistry_SetAccountInfo_NilInfo_ClearsExistingInfo(t *testing.T) {
	vault := newMockVault()
	reg := services.NewRegistry(vault)

	svc := services.Service{
		Name:   "github",
		Type:   "http_proxy",
		Target: "https://api.github.com",
		Inject: "header",
	}
	if err := reg.Create(svc, "ghp_token"); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Set then clear.
	_ = reg.SetAccountInfo("github", &services.AccountInfo{DisplayName: "Test"})
	if err := reg.SetAccountInfo("github", nil); err != nil {
		t.Fatalf("SetAccountInfo(nil) failed: %v", err)
	}

	retrieved, _ := reg.Get("github")
	if retrieved.AccountInfo != nil {
		t.Errorf("expected AccountInfo to be nil after clearing, got %+v", retrieved.AccountInfo)
	}
}

// TestRegistry_SetAccountInfo_NotStoredInVault verifies that account info is
// stored only in memory and the vault is not written.
func TestRegistry_SetAccountInfo_NotStoredInVault(t *testing.T) {
	vault := newMockVault()
	reg := services.NewRegistry(vault)

	svc := services.Service{
		Name:   "github",
		Type:   "http_proxy",
		Target: "https://api.github.com",
		Inject: "header",
	}
	if err := reg.Create(svc, "ghp_token"); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	secretsBefore := mockVaultSecretCount(vault)
	info := &services.AccountInfo{DisplayName: "AJ Geddes"}
	if err := reg.SetAccountInfo("github", info); err != nil {
		t.Fatalf("SetAccountInfo failed: %v", err)
	}
	secretsAfter := mockVaultSecretCount(vault)

	if secretsAfter != secretsBefore {
		t.Errorf("expected vault secret count to remain %d after SetAccountInfo, got %d",
			secretsBefore, secretsAfter)
	}
}

// TestFetchAccountInfo_Stripe_ZeroBalance_ReturnsNoAvailable verifies Stripe
// enrichment when there are no available balances.
func TestFetchAccountInfo_Stripe_ZeroBalance_ReturnsDisplayName(t *testing.T) {
	body := `{"object": "balance", "available": [], "pending": []}`
	srv := makeTestServer(t, http.StatusOK, body)
	defer srv.Close()

	info := services.FetchAccountInfo(srv.URL, "sk_test_abc", "stripe_api_key", nil)
	if info == nil {
		t.Fatal("expected non-nil AccountInfo for Stripe with empty balance")
	}
	if info.DisplayName != "Stripe Account" {
		t.Errorf("expected display_name=Stripe Account, got %q", info.DisplayName)
	}
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// mockVaultSecretCount returns the number of secrets currently stored in the
// mock vault. Used to verify that SetAccountInfo does not write to the vault.
func mockVaultSecretCount(v *mockVault) int {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return len(v.secrets)
}
