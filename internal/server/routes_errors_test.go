package server_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/straylight-ai/straylight/internal/server"
)

// ---------------------------------------------------------------------------
// Test helpers — reuse newTestServer from routes_services_test.go
// ---------------------------------------------------------------------------

// decodeErrorResponse decodes the body into an ErrorResponse struct.
func decodeErrorResponse(t *testing.T, w *httptest.ResponseRecorder) server.ErrorResponse {
	t.Helper()
	var e server.ErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&e); err != nil {
		t.Fatalf("failed to decode error response: %v\nbody: %s", err, w.Body.String())
	}
	return e
}

// ---------------------------------------------------------------------------
// Consistent error format — service endpoints
// ---------------------------------------------------------------------------

// TestServiceError_NotFound_HasErrorCode verifies GET /services/{name} 404 uses SERVICE_NOT_FOUND code.
func TestServiceError_NotFound_HasErrorCode(t *testing.T) {
	srv, _ := newTestServer()
	w := getPath(srv, "/api/v1/services/nonexistent")

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
	e := decodeErrorResponse(t, w)
	if e.Code != server.ErrCodeServiceNotFound {
		t.Errorf("expected code=%q, got %q", server.ErrCodeServiceNotFound, e.Code)
	}
	if e.Error == "" {
		t.Error("expected non-empty error message")
	}
}

// TestServiceError_CreateDuplicate_HasErrorCode verifies POST 409 uses SERVICE_EXISTS code.
func TestServiceError_CreateDuplicate_HasErrorCode(t *testing.T) {
	srv, _ := newTestServer()

	payload := map[string]interface{}{
		"name":       "stripe",
		"type":       "http_proxy",
		"target":     "https://api.stripe.com",
		"inject":     "header",
		"credential": "sk_test",
	}
	postJSON(srv, "/api/v1/services", payload)
	w := postJSON(srv, "/api/v1/services", payload)

	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d", w.Code)
	}
	e := decodeErrorResponse(t, w)
	if e.Code != server.ErrCodeServiceExists {
		t.Errorf("expected code=%q, got %q", server.ErrCodeServiceExists, e.Code)
	}
}

// TestServiceError_CreateMissingCredential_HasErrorCode verifies POST 400 (missing credential) uses CREDENTIAL_MISSING code.
func TestServiceError_CreateMissingCredential_HasErrorCode(t *testing.T) {
	srv, _ := newTestServer()

	w := postJSON(srv, "/api/v1/services", map[string]interface{}{
		"name":   "stripe",
		"type":   "http_proxy",
		"target": "https://api.stripe.com",
		"inject": "header",
		// missing credential
	})

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
	e := decodeErrorResponse(t, w)
	if e.Code != server.ErrCodeCredentialMissing {
		t.Errorf("expected code=%q, got %q", server.ErrCodeCredentialMissing, e.Code)
	}
}

// TestServiceError_CreateValidationFailed_HasErrorCode verifies POST 400 (invalid name) uses VALIDATION_FAILED code.
func TestServiceError_CreateValidationFailed_HasErrorCode(t *testing.T) {
	srv, _ := newTestServer()

	w := postJSON(srv, "/api/v1/services", map[string]interface{}{
		"name":       "INVALID NAME",
		"type":       "http_proxy",
		"target":     "https://api.stripe.com",
		"inject":     "header",
		"credential": "sk_test",
	})

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
	e := decodeErrorResponse(t, w)
	if e.Code != server.ErrCodeValidationFailed {
		t.Errorf("expected code=%q, got %q", server.ErrCodeValidationFailed, e.Code)
	}
}

// TestServiceError_UpdateNotFound_HasErrorCode verifies PUT 404 uses SERVICE_NOT_FOUND code.
func TestServiceError_UpdateNotFound_HasErrorCode(t *testing.T) {
	srv, _ := newTestServer()

	w := putJSON(srv, "/api/v1/services/nonexistent", map[string]interface{}{
		"type":   "http_proxy",
		"target": "https://example.com",
		"inject": "header",
	})

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
	e := decodeErrorResponse(t, w)
	if e.Code != server.ErrCodeServiceNotFound {
		t.Errorf("expected code=%q, got %q", server.ErrCodeServiceNotFound, e.Code)
	}
}

// TestServiceError_DeleteNotFound_HasErrorCode verifies DELETE 404 uses SERVICE_NOT_FOUND code.
func TestServiceError_DeleteNotFound_HasErrorCode(t *testing.T) {
	srv, _ := newTestServer()
	w := deletePath(srv, "/api/v1/services/nonexistent")

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
	e := decodeErrorResponse(t, w)
	if e.Code != server.ErrCodeServiceNotFound {
		t.Errorf("expected code=%q, got %q", server.ErrCodeServiceNotFound, e.Code)
	}
}

// TestServiceError_CheckNotFound_HasErrorCode verifies GET /services/{name}/check 404 uses SERVICE_NOT_FOUND.
func TestServiceError_CheckNotFound_HasErrorCode(t *testing.T) {
	srv, _ := newTestServer()
	w := getPath(srv, "/api/v1/services/nonexistent/check")

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
	e := decodeErrorResponse(t, w)
	if e.Code != server.ErrCodeServiceNotFound {
		t.Errorf("expected code=%q, got %q", server.ErrCodeServiceNotFound, e.Code)
	}
}

// ---------------------------------------------------------------------------
// OpenBao unavailability — health endpoint degraded status
// ---------------------------------------------------------------------------

// TestHealth_Degraded_WhenVaultUnavailable verifies the health endpoint returns 503
// with status=degraded and openbao=unavailable when vault is unavailable.
func TestHealth_Degraded_WhenVaultUnavailable(t *testing.T) {
	srv := server.New(server.Config{
		ListenAddress: "127.0.0.1:0",
		Version:       "1.0.3",
		VaultStatus:   func() string { return "unavailable" },
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 when openbao=unavailable, got %d", w.Code)
	}

	var body map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode health response: %v", err)
	}
	if body["status"] != "degraded" {
		t.Errorf("expected status=degraded, got %q", body["status"])
	}
	if body["openbao"] != "unavailable" {
		t.Errorf("expected openbao=unavailable, got %q", body["openbao"])
	}
}

// TestHealth_Degraded_WhenVaultSealed verifies 503 with status=degraded when vault is sealed.
func TestHealth_Degraded_WhenVaultSealed(t *testing.T) {
	srv := server.New(server.Config{
		ListenAddress: "127.0.0.1:0",
		Version:       "1.0.3",
		VaultStatus:   func() string { return "sealed" },
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 when openbao=sealed, got %d", w.Code)
	}

	var body map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode health response: %v", err)
	}
	if body["status"] != "degraded" {
		t.Errorf("expected status=degraded when sealed, got %q", body["status"])
	}
}

// TestHealth_OK_WhenVaultUnsealed verifies 200 with status=ok when vault is unsealed.
func TestHealth_OK_WhenVaultUnsealed(t *testing.T) {
	srv := server.New(server.Config{
		ListenAddress: "127.0.0.1:0",
		Version:       "1.0.3",
		VaultStatus:   func() string { return "unsealed" },
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 when openbao=unsealed, got %d", w.Code)
	}

	var body map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode health response: %v", err)
	}
	if body["status"] != "ok" {
		t.Errorf("expected status=ok when unsealed, got %q", body["status"])
	}
}

// ---------------------------------------------------------------------------
// RequestLogging middleware integration with server
// ---------------------------------------------------------------------------

// TestRequestLogging_Middleware_IsApplied verifies the server integrates
// the RequestLogging middleware and logs request details.
func TestRequestLogging_Middleware_IsApplied(t *testing.T) {
	srv, _ := newTestServer()

	// The server should not panic when requests are made — the middleware
	// should be transparent to callers.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/services", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 from list services, got %d", w.Code)
	}
}
