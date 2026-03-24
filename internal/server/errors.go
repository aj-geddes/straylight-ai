// Package server provides the HTTP server for Straylight-AI.
package server

import (
	"encoding/json"
	"net/http"
)

// Standard error codes used across all HTTP handlers.
const (
	ErrCodeServiceNotFound   = "SERVICE_NOT_FOUND"
	ErrCodeServiceExists     = "SERVICE_EXISTS"
	ErrCodeCredentialMissing = "CREDENTIAL_MISSING"
	ErrCodeVaultUnavailable  = "VAULT_UNAVAILABLE"
	ErrCodeValidationFailed  = "VALIDATION_FAILED"
	ErrCodeUpstreamError     = "UPSTREAM_ERROR"
	ErrCodeUpstreamTimeout   = "UPSTREAM_TIMEOUT"
	ErrCodeOAuthFailed       = "OAUTH_FAILED"
	ErrCodeCommandFailed     = "COMMAND_FAILED"
	ErrCodeInternalError     = "INTERNAL_ERROR"
)

// ErrorResponse is the canonical JSON error body returned by all HTTP handlers.
// It is exported so tests can decode it directly.
type ErrorResponse struct {
	Error   string `json:"error"`
	Code    string `json:"code"`
	Details string `json:"details,omitempty"`
}

// WriteError writes a structured JSON error response with the given HTTP status
// code, error code constant, and human-readable message.
func WriteError(w http.ResponseWriter, statusCode int, code string, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(ErrorResponse{
		Error: message,
		Code:  code,
	})
}

// WriteErrorWithDetails writes a structured JSON error response that includes
// an optional details field for additional context (e.g., validation field names).
func WriteErrorWithDetails(w http.ResponseWriter, statusCode int, code string, message string, details string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(ErrorResponse{
		Error:   message,
		Code:    code,
		Details: details,
	})
}
