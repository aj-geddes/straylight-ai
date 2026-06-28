// Package cloud_test — SSRF fix tests for GCP static-path token_uri validation (issue #17).
//
// RED phase: these tests MUST FAIL until validateTokenURI is added to gcp.go.
package cloud_test

import (
	"context"
	"strings"
	"testing"

	"github.com/straylight-ai/straylight/internal/cloud"
)

// buildSAJSONWithTokenURI returns minimal service account JSON with the given
// token_uri. Unlike validServiceAccountJSON, this helper is intended for
// SSRF/validation tests where the token_uri is crafted to be malicious or
// invalid. The private_key field contains a placeholder; the provider validates
// the URI before attempting any crypto or network operation, so the key is
// never used in the validation tests.
func buildSAJSONWithTokenURI(t *testing.T, tokenURI string) string {
	t.Helper()
	// Re-use validServiceAccountJSON — it already produces the correct JSON
	// structure. The test controls what value goes in token_uri.
	return validServiceAccountJSON(t, tokenURI)
}

// TestGCPProvider_TokenURIValidation_RejectsIMDS verifies that a token_uri
// pointing at the AWS/GCP IMDS endpoint (169.254.169.254) is rejected with a
// clear "not an allowed Google endpoint" error before any HTTP request is made.
func TestGCPProvider_TokenURIValidation_RejectsIMDS(t *testing.T) {
	saJSON := buildSAJSONWithTokenURI(t, "http://169.254.169.254/latest/meta-data/iam/security-credentials/")

	// No TokenEndpointOverride — forces the SA-JSON token_uri validation path.
	p := cloud.NewGCPProvider(cloud.GCPProviderConfig{})

	cfg := cloud.ServiceConfig{
		Engine: "gcp",
		GCP: &cloud.GCPConfig{
			ServiceAccountJSON: saJSON,
			ProjectID:          "test-project",
		},
	}

	_, err := p.GenerateCredentials(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected error for IMDS token_uri, got nil")
	}
	if !strings.Contains(err.Error(), "not an allowed Google endpoint") {
		t.Errorf("expected error to contain %q, got: %v", "not an allowed Google endpoint", err)
	}
}

// TestGCPProvider_TokenURIValidation_RejectsEvilHTTPS verifies that an https
// token_uri pointing at a non-Google host is rejected even though the scheme is
// correct.
func TestGCPProvider_TokenURIValidation_RejectsEvilHTTPS(t *testing.T) {
	saJSON := buildSAJSONWithTokenURI(t, "https://evil.example.com/token")

	p := cloud.NewGCPProvider(cloud.GCPProviderConfig{})

	cfg := cloud.ServiceConfig{
		Engine: "gcp",
		GCP: &cloud.GCPConfig{
			ServiceAccountJSON: saJSON,
			ProjectID:          "test-project",
		},
	}

	_, err := p.GenerateCredentials(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected error for non-Google https token_uri, got nil")
	}
	if !strings.Contains(err.Error(), "not an allowed Google endpoint") {
		t.Errorf("expected error to contain %q, got: %v", "not an allowed Google endpoint", err)
	}
}

// TestGCPProvider_TokenURIValidation_RejectsNonHTTPS verifies that a token_uri
// using http (not https) is rejected even when the host is a legitimate Google
// domain.
func TestGCPProvider_TokenURIValidation_RejectsNonHTTPS(t *testing.T) {
	saJSON := buildSAJSONWithTokenURI(t, "http://oauth2.googleapis.com/token")

	p := cloud.NewGCPProvider(cloud.GCPProviderConfig{})

	cfg := cloud.ServiceConfig{
		Engine: "gcp",
		GCP: &cloud.GCPConfig{
			ServiceAccountJSON: saJSON,
			ProjectID:          "test-project",
		},
	}

	_, err := p.GenerateCredentials(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected error for http (non-https) Google token_uri, got nil")
	}
	if !strings.Contains(err.Error(), "not an allowed Google endpoint") {
		t.Errorf("expected error to contain %q, got: %v", "not an allowed Google endpoint", err)
	}
}

// TestGCPProvider_TokenURIValidation_AllowsLegitimate verifies that a
// token_uri of https://oauth2.googleapis.com/token passes validation. The
// request will fail at the network level (no real token server), but the error
// must NOT be the "not an allowed Google endpoint" validation error.
//
// This confirms the validation allowlist permits legitimate Google endpoints.
func TestGCPProvider_TokenURIValidation_AllowsLegitimate(t *testing.T) {
	saJSON := buildSAJSONWithTokenURI(t, "https://oauth2.googleapis.com/token")

	// No TokenEndpointOverride — SA JSON token_uri will be validated then used.
	p := cloud.NewGCPProvider(cloud.GCPProviderConfig{})

	cfg := cloud.ServiceConfig{
		Engine: "gcp",
		GCP: &cloud.GCPConfig{
			ServiceAccountJSON: saJSON,
			ProjectID:          "test-project",
		},
	}

	_, err := p.GenerateCredentials(context.Background(), cfg)
	// The call WILL error (no real token server), but the error must be from
	// the HTTP request layer, not from URI validation.
	if err == nil {
		t.Fatal("expected network error, got nil")
	}
	if strings.Contains(err.Error(), "not an allowed Google endpoint") {
		t.Errorf("validation incorrectly rejected a legitimate Google token_uri: %v", err)
	}
}
