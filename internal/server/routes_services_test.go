package server_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/straylight-ai/straylight/internal/server"
	"github.com/straylight-ai/straylight/internal/services"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// mockVaultForRoutes is a simple in-memory vault mock for server-level tests.
type mockVaultForRoutes struct {
	mu      sync.RWMutex
	secrets map[string]map[string]interface{}
}

func newMockVaultForRoutes() *mockVaultForRoutes {
	return &mockVaultForRoutes{secrets: make(map[string]map[string]interface{})}
}

func (m *mockVaultForRoutes) WriteSecret(path string, data map[string]interface{}) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	clone := make(map[string]interface{}, len(data))
	for k, v := range data {
		clone[k] = v
	}
	m.secrets[path] = clone
	return nil
}

func (m *mockVaultForRoutes) ReadSecret(path string) (map[string]interface{}, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	data, ok := m.secrets[path]
	if !ok {
		return nil, errors.New("secret not found")
	}
	clone := make(map[string]interface{}, len(data))
	for k, v := range data {
		clone[k] = v
	}
	return clone, nil
}

func (m *mockVaultForRoutes) DeleteSecret(path string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.secrets, path)
	return nil
}

func (m *mockVaultForRoutes) ListSecrets(path string) ([]string, error) {
	return []string{}, nil
}

// newTestServer creates a server with a real Registry backed by a mock vault.
func newTestServer() (*server.Server, *services.Registry) {
	vault := newMockVaultForRoutes()
	reg := services.NewRegistry(vault)
	srv := server.New(server.Config{
		ListenAddress: "127.0.0.1:0",
		Version:       "1.0.1",
		Registry:      reg,
	})
	return srv, reg
}

// postJSON is a helper that sends a POST with JSON body and returns the recorder.
func postJSON(srv *server.Server, path string, body interface{}) *httptest.ResponseRecorder {
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	return w
}

// putJSON is a helper that sends a PUT with JSON body and returns the recorder.
func putJSON(srv *server.Server, path string, body interface{}) *httptest.ResponseRecorder {
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPut, path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	return w
}

// getPath sends a GET request and returns the recorder.
func getPath(srv *server.Server, path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	return w
}

// deletePath sends a DELETE request and returns the recorder.
func deletePath(srv *server.Server, path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodDelete, path, nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	return w
}

// decodeJSON decodes the recorder body into a map.
func decodeJSON(t *testing.T, w *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()
	var m map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&m); err != nil {
		t.Fatalf("failed to decode JSON response: %v", err)
	}
	return m
}

// ---------------------------------------------------------------------------
// POST /api/v1/services
// ---------------------------------------------------------------------------

func TestCreateService_Returns201WithServiceObject(t *testing.T) {
	srv, _ := newTestServer()

	w := postJSON(srv, "/api/v1/services", map[string]interface{}{
		"name":       "stripe",
		"type":       "http_proxy",
		"target":     "https://api.stripe.com",
		"inject":     "header",
		"credential": "sk_test_abc123",
	})

	if w.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d (body: %s)", w.Code, w.Body.String())
	}

	body := decodeJSON(t, w)
	if body["name"] != "stripe" {
		t.Errorf("expected name=stripe in response, got %v", body["name"])
	}
	if _, hasCredential := body["credential"]; hasCredential {
		t.Error("response must NOT contain credential field")
	}
}

func TestCreateService_Returns409WhenNameExists(t *testing.T) {
	srv, _ := newTestServer()

	payload := map[string]interface{}{
		"name":       "stripe",
		"type":       "http_proxy",
		"target":     "https://api.stripe.com",
		"inject":     "header",
		"credential": "sk_test_abc",
	}
	postJSON(srv, "/api/v1/services", payload)

	w := postJSON(srv, "/api/v1/services", payload)
	if w.Code != http.StatusConflict {
		t.Errorf("expected 409 for duplicate, got %d (body: %s)", w.Code, w.Body.String())
	}
}

func TestCreateService_Returns400WhenCredentialMissing(t *testing.T) {
	srv, _ := newTestServer()

	w := postJSON(srv, "/api/v1/services", map[string]interface{}{
		"name":   "stripe",
		"type":   "http_proxy",
		"target": "https://api.stripe.com",
		"inject": "header",
		// no credential
	})

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 when credential missing, got %d", w.Code)
	}
}

func TestCreateService_Returns400ForInvalidName(t *testing.T) {
	srv, _ := newTestServer()

	w := postJSON(srv, "/api/v1/services", map[string]interface{}{
		"name":       "INVALID NAME",
		"type":       "http_proxy",
		"target":     "https://api.stripe.com",
		"inject":     "header",
		"credential": "sk_test_abc",
	})

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid name, got %d", w.Code)
	}
}

func TestCreateService_Returns400ForHttpTarget(t *testing.T) {
	srv, _ := newTestServer()

	w := postJSON(srv, "/api/v1/services", map[string]interface{}{
		"name":       "mysvc",
		"type":       "http_proxy",
		"target":     "http://api.example.com",
		"inject":     "header",
		"credential": "key123",
	})

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for http:// target, got %d", w.Code)
	}
}

func TestCreateService_ResponseHasNoCredentialField(t *testing.T) {
	srv, _ := newTestServer()

	w := postJSON(srv, "/api/v1/services", map[string]interface{}{
		"name":       "openai",
		"type":       "http_proxy",
		"target":     "https://api.openai.com",
		"inject":     "header",
		"credential": "sk-supersecret",
	})

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", w.Code)
	}

	body := decodeJSON(t, w)

	// These fields must not be in the response.
	for _, forbidden := range []string{"credential", "api_key", "secret", "token"} {
		if _, found := body[forbidden]; found {
			t.Errorf("response contains forbidden field %q — credential leaked!", forbidden)
		}
	}
}

// ---------------------------------------------------------------------------
// GET /api/v1/services
// ---------------------------------------------------------------------------

func TestListServices_ReturnsEmptyListInitially(t *testing.T) {
	srv, _ := newTestServer()

	w := getPath(srv, "/api/v1/services")
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	body := decodeJSON(t, w)
	svcList, ok := body["services"]
	if !ok {
		t.Fatal("expected 'services' key in response")
	}
	list, ok := svcList.([]interface{})
	if !ok {
		t.Fatalf("expected 'services' to be an array, got %T", svcList)
	}
	if len(list) != 0 {
		t.Errorf("expected 0 services, got %d", len(list))
	}
}

func TestListServices_ReturnsPreviouslyCreatedServices(t *testing.T) {
	srv, _ := newTestServer()

	for _, name := range []string{"stripe", "openai"} {
		postJSON(srv, "/api/v1/services", map[string]interface{}{
			"name":       name,
			"type":       "http_proxy",
			"target":     "https://api." + name + ".com",
			"inject":     "header",
			"credential": "cred-" + name,
		})
	}

	w := getPath(srv, "/api/v1/services")
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	body := decodeJSON(t, w)
	list, ok := body["services"].([]interface{})
	if !ok {
		t.Fatal("expected 'services' array in response")
	}
	if len(list) != 2 {
		t.Errorf("expected 2 services, got %d", len(list))
	}
}

func TestListServices_ContentTypeIsJSON(t *testing.T) {
	srv, _ := newTestServer()
	w := getPath(srv, "/api/v1/services")
	ct := w.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("expected Content-Type=application/json, got %q", ct)
	}
}

// ---------------------------------------------------------------------------
// GET /api/v1/services/{name}
// ---------------------------------------------------------------------------

func TestGetService_Returns200WithServiceData(t *testing.T) {
	srv, _ := newTestServer()

	postJSON(srv, "/api/v1/services", map[string]interface{}{
		"name":       "github",
		"type":       "http_proxy",
		"target":     "https://api.github.com",
		"inject":     "header",
		"credential": "ghp_token",
	})

	w := getPath(srv, "/api/v1/services/github")
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d (body: %s)", w.Code, w.Body.String())
	}

	body := decodeJSON(t, w)
	if body["name"] != "github" {
		t.Errorf("expected name=github, got %v", body["name"])
	}
}

func TestGetService_Returns404ForUnknownService(t *testing.T) {
	srv, _ := newTestServer()
	w := getPath(srv, "/api/v1/services/nonexistent")
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestGetService_NeverReturnsCredential(t *testing.T) {
	srv, _ := newTestServer()

	postJSON(srv, "/api/v1/services", map[string]interface{}{
		"name":       "stripe",
		"type":       "http_proxy",
		"target":     "https://api.stripe.com",
		"inject":     "header",
		"credential": "sk_live_TOPSECRET",
	})

	w := getPath(srv, "/api/v1/services/stripe")
	body := decodeJSON(t, w)

	for _, field := range []string{"credential", "api_key", "secret", "token", "value"} {
		if val, found := body[field]; found {
			t.Errorf("GET /services/{name} leaked credential in field %q = %v", field, val)
		}
	}
}

// ---------------------------------------------------------------------------
// PUT /api/v1/services/{name}
// ---------------------------------------------------------------------------

func TestUpdateService_Returns200WithUpdatedService(t *testing.T) {
	srv, _ := newTestServer()

	postJSON(srv, "/api/v1/services", map[string]interface{}{
		"name":       "stripe",
		"type":       "http_proxy",
		"target":     "https://api.stripe.com",
		"inject":     "header",
		"credential": "old-key",
	})

	w := putJSON(srv, "/api/v1/services/stripe", map[string]interface{}{
		"type":   "http_proxy",
		"target": "https://api.stripe.com/v2",
		"inject": "header",
	})

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d (body: %s)", w.Code, w.Body.String())
	}

	body := decodeJSON(t, w)
	if body["target"] != "https://api.stripe.com/v2" {
		t.Errorf("expected updated target, got %v", body["target"])
	}
}

func TestUpdateService_Returns404ForUnknownService(t *testing.T) {
	srv, _ := newTestServer()

	w := putJSON(srv, "/api/v1/services/nonexistent", map[string]interface{}{
		"type":   "http_proxy",
		"target": "https://example.com",
		"inject": "header",
	})

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestUpdateService_WithCredential_UpdatesVault(t *testing.T) {
	srv, reg := newTestServer()

	postJSON(srv, "/api/v1/services", map[string]interface{}{
		"name":       "stripe",
		"type":       "http_proxy",
		"target":     "https://api.stripe.com",
		"inject":     "header",
		"credential": "old-key",
	})

	w := putJSON(srv, "/api/v1/services/stripe", map[string]interface{}{
		"type":       "http_proxy",
		"target":     "https://api.stripe.com",
		"inject":     "header",
		"credential": "new-key",
	})

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	cred, err := reg.GetCredential("stripe")
	if err != nil {
		t.Fatalf("GetCredential() failed: %v", err)
	}
	if cred != "new-key" {
		t.Errorf("expected credential=new-key after update, got %q", cred)
	}
}

// ---------------------------------------------------------------------------
// DELETE /api/v1/services/{name}
// ---------------------------------------------------------------------------

func TestDeleteService_Returns204(t *testing.T) {
	srv, _ := newTestServer()

	postJSON(srv, "/api/v1/services", map[string]interface{}{
		"name":       "stripe",
		"type":       "http_proxy",
		"target":     "https://api.stripe.com",
		"inject":     "header",
		"credential": "sk_test",
	})

	w := deletePath(srv, "/api/v1/services/stripe")
	if w.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d", w.Code)
	}
}

func TestDeleteService_Returns404ForUnknownService(t *testing.T) {
	srv, _ := newTestServer()
	w := deletePath(srv, "/api/v1/services/nonexistent")
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestDeleteService_ServiceGone_AfterDelete(t *testing.T) {
	srv, _ := newTestServer()

	postJSON(srv, "/api/v1/services", map[string]interface{}{
		"name":       "stripe",
		"type":       "http_proxy",
		"target":     "https://api.stripe.com",
		"inject":     "header",
		"credential": "sk_test",
	})

	deletePath(srv, "/api/v1/services/stripe")

	w := getPath(srv, "/api/v1/services/stripe")
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 after delete, got %d", w.Code)
	}
}

// ---------------------------------------------------------------------------
// GET /api/v1/services/{name}/check
// ---------------------------------------------------------------------------

func TestCheckCredential_ReturnsAvailable(t *testing.T) {
	srv, _ := newTestServer()

	postJSON(srv, "/api/v1/services", map[string]interface{}{
		"name":       "stripe",
		"type":       "http_proxy",
		"target":     "https://api.stripe.com",
		"inject":     "header",
		"credential": "sk_test",
	})

	w := getPath(srv, "/api/v1/services/stripe/check")
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d (body: %s)", w.Code, w.Body.String())
	}

	body := decodeJSON(t, w)
	if body["status"] != "available" {
		t.Errorf("expected status=available, got %v", body["status"])
	}
	if body["name"] != "stripe" {
		t.Errorf("expected name=stripe, got %v", body["name"])
	}
}

func TestCheckCredential_Returns404ForUnknownService(t *testing.T) {
	srv, _ := newTestServer()
	w := getPath(srv, "/api/v1/services/nonexistent/check")
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestCheckCredential_NeverReturnsCredentialValue(t *testing.T) {
	srv, _ := newTestServer()

	postJSON(srv, "/api/v1/services", map[string]interface{}{
		"name":       "stripe",
		"type":       "http_proxy",
		"target":     "https://api.stripe.com",
		"inject":     "header",
		"credential": "sk_live_VERYSECRET",
	})

	w := getPath(srv, "/api/v1/services/stripe/check")
	body := decodeJSON(t, w)

	for _, field := range []string{"credential", "api_key", "secret", "token", "value"} {
		if val, found := body[field]; found {
			t.Errorf("check endpoint leaked credential in field %q = %v", field, val)
		}
	}

	// Also verify the response body string doesn't contain the secret value.
	respStr := w.Body.String()
	if bytes.Contains([]byte(respStr), []byte("sk_live_VERYSECRET")) {
		t.Error("check endpoint body contains raw credential value")
	}
}

// ---------------------------------------------------------------------------
// GET /api/v1/templates
// ---------------------------------------------------------------------------

func TestListTemplates_Returns200WithTemplateList(t *testing.T) {
	srv, _ := newTestServer()

	w := getPath(srv, "/api/v1/templates")
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d (body: %s)", w.Code, w.Body.String())
	}

	body := decodeJSON(t, w)
	templates, ok := body["templates"].([]interface{})
	if !ok {
		t.Fatalf("expected 'templates' array in response, got %T", body["templates"])
	}
	if len(templates) == 0 {
		t.Error("expected at least one template, got empty list")
	}
}

func TestListTemplates_ContainsStripeTemplate(t *testing.T) {
	srv, _ := newTestServer()
	w := getPath(srv, "/api/v1/templates")
	body := decodeJSON(t, w)
	templates, _ := body["templates"].([]interface{})

	found := false
	for _, tmpl := range templates {
		m, ok := tmpl.(map[string]interface{})
		if !ok {
			continue
		}
		// Templates now use "id" (not "name") per the ServiceTemplate type.
		if m["id"] == "stripe" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected stripe template to be present in /api/v1/templates")
	}
}

func TestListTemplates_ContentTypeIsJSON(t *testing.T) {
	srv, _ := newTestServer()
	w := getPath(srv, "/api/v1/templates")
	ct := w.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("expected Content-Type=application/json, got %q", ct)
	}
}

// ---------------------------------------------------------------------------
// Backward compatibility: service placeholder still returns 501 without registry
// ---------------------------------------------------------------------------

func TestServicesEndpoints_WithNilRegistry_Return501(t *testing.T) {
	srv := server.New(server.Config{
		ListenAddress: "127.0.0.1:0",
		Version:       "1.0.1",
		// Registry is nil — stub mode
	})

	w := getPath(srv, "/api/v1/services")
	if w.Code != http.StatusNotImplemented {
		t.Errorf("expected 501 when registry is nil, got %d", w.Code)
	}
}
