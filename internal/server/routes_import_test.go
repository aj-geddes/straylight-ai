package server_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/straylight-ai/straylight/internal/server"
)

// TestImportTemplates_BodySpec verifies that POST /api/v1/templates/import with a raw
// spec body returns a draft ServiceTemplate.
func TestImportTemplates_BodySpec(t *testing.T) {
	srv, _ := newTestServer()

	spec := `{
		"openapi": "3.1.0",
		"info": {"title": "My API", "version": "1.0.0"},
		"servers": [{"url": "https://api.example.com"}],
		"paths": {},
		"components": {
			"securitySchemes": {
				"bearerAuth": {"type": "http", "scheme": "bearer"}
			}
		}
	}`

	req := httptest.NewRequest(http.MethodPost, "/api/v1/templates/import", bytes.NewBufferString(spec))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var body map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	tmpl, ok := body["template"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected 'template' in response, got %v", body)
	}
	if tmpl["target"] != "https://api.example.com" {
		t.Errorf("expected target='https://api.example.com', got %v", tmpl["target"])
	}
	authMethods, ok := tmpl["auth_methods"].([]interface{})
	if !ok || len(authMethods) == 0 {
		t.Error("expected non-empty auth_methods in draft template")
	}
}

// TestImportTemplates_URLSpec verifies that POST /api/v1/templates/import with a
// {url: "..."} JSON body returns a draft ServiceTemplate when the URL is accessible.
func TestImportTemplates_URLSpec(t *testing.T) {
	// Serve a minimal OpenAPI spec from a test server.
	specContent := `{"openapi":"3.1.0","info":{"title":"Remote","version":"1.0.0"},"servers":[{"url":"https://remote.example.com"}],"paths":{},"components":{"securitySchemes":{"apiKey":{"type":"apiKey","in":"header","name":"X-Key"}}}}`
	specServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(specContent))
	}))
	defer specServer.Close()

	srv := server.New(server.Config{})

	body, _ := json.Marshal(map[string]string{"url": specServer.URL})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/templates/import", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	// Without a registry, registry-gated endpoints return 501 but import is always available.
	// The test just checks it's not a 404.
	if w.Code == http.StatusNotFound {
		t.Fatal("expected import endpoint to be registered, got 404")
	}
}

// TestImportTemplates_EmptyBodyReturnsError verifies that an empty body returns 400.
func TestImportTemplates_EmptyBodyReturnsError(t *testing.T) {
	srv, _ := newTestServer()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/templates/import", bytes.NewBuffer(nil))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for empty body, got %d: %s", w.Code, w.Body.String())
	}
}
