package server_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/straylight-ai/straylight/internal/server"
)

// ---------------------------------------------------------------------------
// WriteError
// ---------------------------------------------------------------------------

// TestWriteError_SetsStatusCode verifies WriteError sets the given HTTP status.
func TestWriteError_SetsStatusCode(t *testing.T) {
	w := httptest.NewRecorder()
	server.WriteError(w, http.StatusBadRequest, server.ErrCodeValidationFailed, "bad input")
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", w.Code)
	}
}

// TestWriteError_SetsContentTypeJSON verifies WriteError sets Content-Type to application/json.
func TestWriteError_SetsContentTypeJSON(t *testing.T) {
	w := httptest.NewRecorder()
	server.WriteError(w, http.StatusNotFound, server.ErrCodeServiceNotFound, "not found")
	ct := w.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("expected Content-Type=application/json, got %q", ct)
	}
}

// TestWriteError_BodyHasErrorField verifies the response body has an "error" field.
func TestWriteError_BodyHasErrorField(t *testing.T) {
	w := httptest.NewRecorder()
	server.WriteError(w, http.StatusNotFound, server.ErrCodeServiceNotFound, "service not found")

	var body map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if _, ok := body["error"]; !ok {
		t.Error("expected 'error' field in response body")
	}
}

// TestWriteError_BodyHasCodeField verifies the response body has a "code" field.
func TestWriteError_BodyHasCodeField(t *testing.T) {
	w := httptest.NewRecorder()
	server.WriteError(w, http.StatusNotFound, server.ErrCodeServiceNotFound, "service not found")

	var body map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	code, ok := body["code"]
	if !ok {
		t.Error("expected 'code' field in response body")
	}
	if code != server.ErrCodeServiceNotFound {
		t.Errorf("expected code=%q, got %q", server.ErrCodeServiceNotFound, code)
	}
}

// TestWriteError_BodyMessageMatchesInput verifies the error message is preserved.
func TestWriteError_BodyMessageMatchesInput(t *testing.T) {
	w := httptest.NewRecorder()
	server.WriteError(w, http.StatusConflict, server.ErrCodeServiceExists, "service already exists")

	var body server.ErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if body.Error != "service already exists" {
		t.Errorf("expected error message 'service already exists', got %q", body.Error)
	}
	if body.Code != server.ErrCodeServiceExists {
		t.Errorf("expected code=%q, got %q", server.ErrCodeServiceExists, body.Code)
	}
}

// TestWriteError_NoDetailsFieldWhenEmpty verifies that an absent details does not produce a "details" key.
func TestWriteError_NoDetailsFieldWhenEmpty(t *testing.T) {
	w := httptest.NewRecorder()
	server.WriteError(w, http.StatusBadRequest, server.ErrCodeValidationFailed, "invalid input")

	var body map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if _, ok := body["details"]; ok {
		t.Error("expected no 'details' field when not provided")
	}
}

// ---------------------------------------------------------------------------
// WriteErrorWithDetails
// ---------------------------------------------------------------------------

// TestWriteErrorWithDetails_IncludesDetailsField verifies that details is serialised.
func TestWriteErrorWithDetails_IncludesDetailsField(t *testing.T) {
	w := httptest.NewRecorder()
	server.WriteErrorWithDetails(w, http.StatusBadRequest, server.ErrCodeValidationFailed, "invalid input", "field 'name' is required")

	var body server.ErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if body.Details != "field 'name' is required" {
		t.Errorf("expected details='field name is required', got %q", body.Details)
	}
}

// TestWriteErrorWithDetails_SetsAllFields verifies all three fields are set.
func TestWriteErrorWithDetails_SetsAllFields(t *testing.T) {
	w := httptest.NewRecorder()
	server.WriteErrorWithDetails(w, http.StatusServiceUnavailable, server.ErrCodeVaultUnavailable, "vault down", "openbao unreachable")

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected status 503, got %d", w.Code)
	}
	var body server.ErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if body.Error != "vault down" {
		t.Errorf("expected error='vault down', got %q", body.Error)
	}
	if body.Code != server.ErrCodeVaultUnavailable {
		t.Errorf("expected code=%q, got %q", server.ErrCodeVaultUnavailable, body.Code)
	}
	if body.Details != "openbao unreachable" {
		t.Errorf("expected details='openbao unreachable', got %q", body.Details)
	}
}

// ---------------------------------------------------------------------------
// Error code constants
// ---------------------------------------------------------------------------

// TestErrorCodes_AllDefined verifies all required error code constants are non-empty.
func TestErrorCodes_AllDefined(t *testing.T) {
	codes := []string{
		server.ErrCodeServiceNotFound,
		server.ErrCodeServiceExists,
		server.ErrCodeCredentialMissing,
		server.ErrCodeVaultUnavailable,
		server.ErrCodeValidationFailed,
		server.ErrCodeUpstreamError,
		server.ErrCodeUpstreamTimeout,
		server.ErrCodeOAuthFailed,
		server.ErrCodeCommandFailed,
		server.ErrCodeInternalError,
	}
	for _, code := range codes {
		if code == "" {
			t.Errorf("error code constant is empty: %q", code)
		}
	}
}

// TestErrorCodes_ExpectedValues verifies the string values match the spec.
func TestErrorCodes_ExpectedValues(t *testing.T) {
	cases := []struct {
		constant string
		expected string
	}{
		{server.ErrCodeServiceNotFound, "SERVICE_NOT_FOUND"},
		{server.ErrCodeServiceExists, "SERVICE_EXISTS"},
		{server.ErrCodeCredentialMissing, "CREDENTIAL_MISSING"},
		{server.ErrCodeVaultUnavailable, "VAULT_UNAVAILABLE"},
		{server.ErrCodeValidationFailed, "VALIDATION_FAILED"},
		{server.ErrCodeUpstreamError, "UPSTREAM_ERROR"},
		{server.ErrCodeUpstreamTimeout, "UPSTREAM_TIMEOUT"},
		{server.ErrCodeOAuthFailed, "OAUTH_FAILED"},
		{server.ErrCodeCommandFailed, "COMMAND_FAILED"},
		{server.ErrCodeInternalError, "INTERNAL_ERROR"},
	}
	for _, tc := range cases {
		if tc.constant != tc.expected {
			t.Errorf("expected error code %q, got %q", tc.expected, tc.constant)
		}
	}
}
