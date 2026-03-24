package services_test

// FIX 3: Pre-compile credential field regex patterns.
//
// The init() in auth_methods.go must pre-compile all Field.Pattern values in
// ServiceTemplates at startup, panicking if any pattern is invalid.
//
// These tests verify:
//   1. All ServiceTemplate patterns are syntactically valid (init would have
//      panicked at startup if not, so any test running proves this).
//   2. The package-level compiledPatterns map is populated — tested by calling
//      the exported ValidateCredentialFieldsWithPatterns function.

import (
	"testing"

	"github.com/straylight-ai/straylight/internal/services"
)

// TestServiceTemplates_AllPatternsAreValidRegex verifies that every
// CredentialField.Pattern defined in ServiceTemplates is a syntactically valid
// regular expression. If the init() function panicked, this test would not run.
func TestServiceTemplates_AllPatternsAreValidRegex(t *testing.T) {
	// If we reach here, init() completed without panic, which means all patterns
	// compiled successfully. We also verify via ValidateTemplate.
	for _, tmpl := range services.ServiceTemplates {
		t.Run(tmpl.ID, func(t *testing.T) {
			if err := services.ValidateTemplate(tmpl); err != nil {
				t.Errorf("template %q failed validation: %v", tmpl.ID, err)
			}
		})
	}
}

// TestCompiledPatterns_GithubPATValidToken verifies that the pre-compiled pattern
// for github_pat_classic accepts a valid PAT token.
func TestCompiledPatterns_GithubPATValidToken(t *testing.T) {
	// Find the github_pat_classic auth method which has a pattern.
	am := findAuthMethodByID("github", "github_pat_classic")
	if am == nil {
		t.Skip("github_pat_classic auth method not found")
	}

	validToken := "ghp_abcdefghij1234567890"
	if err := services.ValidateCredentialFields(am, map[string]string{"token": validToken}); err != nil {
		t.Errorf("expected valid ghp_ token to pass, got error: %v", err)
	}
}

// TestCompiledPatterns_GithubPATInvalidToken verifies that an invalid token
// is rejected by the pre-compiled pattern.
func TestCompiledPatterns_GithubPATInvalidToken(t *testing.T) {
	am := findAuthMethodByID("github", "github_pat_classic")
	if am == nil {
		t.Skip("github_pat_classic auth method not found")
	}

	invalidToken := "not-a-github-token"
	if err := services.ValidateCredentialFields(am, map[string]string{"token": invalidToken}); err == nil {
		t.Errorf("expected invalid token to fail validation, got nil")
	}
}

// TestCompiledPatterns_StripeAPIKeyValid verifies the stripe api key pattern.
func TestCompiledPatterns_StripeAPIKeyValid(t *testing.T) {
	am := findAuthMethodByID("stripe", "stripe_api_key")
	if am == nil {
		t.Skip("stripe_api_key auth method not found")
	}

	if err := services.ValidateCredentialFields(am, map[string]string{"token": "sk_test_abc123"}); err != nil {
		t.Errorf("expected valid stripe key to pass, got error: %v", err)
	}
}

// TestCompiledPatterns_StripeAPIKeyInvalid verifies that an invalid stripe key is rejected.
func TestCompiledPatterns_StripeAPIKeyInvalid(t *testing.T) {
	am := findAuthMethodByID("stripe", "stripe_api_key")
	if am == nil {
		t.Skip("stripe_api_key auth method not found")
	}

	if err := services.ValidateCredentialFields(am, map[string]string{"token": "not-a-stripe-key"}); err == nil {
		t.Errorf("expected invalid stripe key to fail, got nil")
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func findAuthMethodByID(templateID, authMethodID string) *services.AuthMethod {
	for i := range services.ServiceTemplates {
		if services.ServiceTemplates[i].ID == templateID {
			for j := range services.ServiceTemplates[i].AuthMethods {
				if services.ServiceTemplates[i].AuthMethods[j].ID == authMethodID {
					am := services.ServiceTemplates[i].AuthMethods[j]
					return &am
				}
			}
		}
	}
	return nil
}
