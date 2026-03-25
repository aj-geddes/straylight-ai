package services_test

import (
	"testing"

	"github.com/straylight-ai/straylight/internal/services"
)

// ---------------------------------------------------------------------------
// FilterTemplatesForPersonalTier tests
// ---------------------------------------------------------------------------

// TestFilterTemplatesForPersonalTier_RemovesOAuthMethods verifies that auth
// methods with InjectionOAuth type are excluded from every template.
func TestFilterTemplatesForPersonalTier_RemovesOAuthMethods(t *testing.T) {
	input := []services.ServiceTemplate{
		{
			ID:          "myservice",
			DisplayName: "My Service",
			Target:      "https://api.example.com",
			AuthMethods: []services.AuthMethod{
				{
					ID:        "api_key",
					Name:      "API Key",
					Fields:    []services.CredentialField{{Key: "token", Label: "Token", Type: services.FieldPassword, Required: true}},
					Injection: services.InjectionConfig{Type: services.InjectionBearerHeader},
				},
				{
					ID:        "oauth_method",
					Name:      "OAuth",
					Fields:    []services.CredentialField{},
					Injection: services.InjectionConfig{Type: services.InjectionOAuth},
				},
			},
		},
	}

	result := services.FilterTemplatesForPersonalTier(input)

	if len(result) != 1 {
		t.Fatalf("expected 1 template, got %d", len(result))
	}
	if len(result[0].AuthMethods) != 1 {
		t.Fatalf("expected 1 auth method after filtering, got %d", len(result[0].AuthMethods))
	}
	if result[0].AuthMethods[0].ID != "api_key" {
		t.Errorf("expected remaining method to be api_key, got %q", result[0].AuthMethods[0].ID)
	}
}

// TestFilterTemplatesForPersonalTier_RemovesNamedStrategyMethods verifies that
// auth methods with InjectionNamedStrategy type are excluded.
func TestFilterTemplatesForPersonalTier_RemovesNamedStrategyMethods(t *testing.T) {
	input := []services.ServiceTemplate{
		{
			ID:          "myservice",
			DisplayName: "My Service",
			Target:      "https://api.example.com",
			AuthMethods: []services.AuthMethod{
				{
					ID:        "bearer_key",
					Name:      "Bearer Key",
					Fields:    []services.CredentialField{{Key: "token", Label: "Token", Type: services.FieldPassword, Required: true}},
					Injection: services.InjectionConfig{Type: services.InjectionBearerHeader},
				},
				{
					ID:        "app_jwt",
					Name:      "App JWT",
					Fields:    []services.CredentialField{{Key: "pk", Label: "Private Key", Type: services.FieldTextarea, Required: true}},
					Injection: services.InjectionConfig{Type: services.InjectionNamedStrategy, Strategy: "github_app_jwt"},
				},
			},
		},
	}

	result := services.FilterTemplatesForPersonalTier(input)

	if len(result) != 1 {
		t.Fatalf("expected 1 template, got %d", len(result))
	}
	if len(result[0].AuthMethods) != 1 {
		t.Errorf("expected 1 auth method, got %d", len(result[0].AuthMethods))
	}
	if result[0].AuthMethods[0].ID != "bearer_key" {
		t.Errorf("expected remaining method to be bearer_key, got %q", result[0].AuthMethods[0].ID)
	}
}

// TestFilterTemplatesForPersonalTier_ExcludesTemplatesWithNoRemainingMethods
// verifies that templates whose every auth method is filtered out are dropped
// entirely from the result.
func TestFilterTemplatesForPersonalTier_ExcludesTemplatesWithNoRemainingMethods(t *testing.T) {
	input := []services.ServiceTemplate{
		{
			ID:          "oauth_only",
			DisplayName: "OAuth Only Service",
			Target:      "https://api.example.com",
			AuthMethods: []services.AuthMethod{
				{
					ID:        "oauth_method",
					Name:      "OAuth",
					Fields:    []services.CredentialField{},
					Injection: services.InjectionConfig{Type: services.InjectionOAuth},
				},
			},
		},
		{
			ID:          "has_key",
			DisplayName: "Service With Key",
			Target:      "https://api.other.com",
			AuthMethods: []services.AuthMethod{
				{
					ID:        "api_key",
					Name:      "API Key",
					Fields:    []services.CredentialField{{Key: "token", Label: "Token", Type: services.FieldPassword, Required: true}},
					Injection: services.InjectionConfig{Type: services.InjectionBearerHeader},
				},
			},
		},
	}

	result := services.FilterTemplatesForPersonalTier(input)

	if len(result) != 1 {
		t.Fatalf("expected 1 template (oauth_only dropped), got %d", len(result))
	}
	if result[0].ID != "has_key" {
		t.Errorf("expected remaining template to be has_key, got %q", result[0].ID)
	}
}

// TestFilterTemplatesForPersonalTier_ReturnsNilForEmptyInput verifies graceful
// handling of an empty input slice.
func TestFilterTemplatesForPersonalTier_ReturnsNilForEmptyInput(t *testing.T) {
	result := services.FilterTemplatesForPersonalTier([]services.ServiceTemplate{})
	if len(result) != 0 {
		t.Errorf("expected empty result for empty input, got %d templates", len(result))
	}
}

// TestFilterTemplatesForPersonalTier_PreservesNonOAuthMethods verifies that
// bearer_header, custom_header, query_param, multi_header, and basic_auth
// injection types all survive filtering.
func TestFilterTemplatesForPersonalTier_PreservesNonOAuthMethods(t *testing.T) {
	input := []services.ServiceTemplate{
		{
			ID:          "multi",
			DisplayName: "Multi Method Service",
			Target:      "https://api.example.com",
			AuthMethods: []services.AuthMethod{
				{
					ID:        "bearer",
					Name:      "Bearer",
					Fields:    []services.CredentialField{{Key: "token", Label: "Token", Type: services.FieldPassword, Required: true}},
					Injection: services.InjectionConfig{Type: services.InjectionBearerHeader},
				},
				{
					ID:        "custom",
					Name:      "Custom Header",
					Fields:    []services.CredentialField{{Key: "token", Label: "Token", Type: services.FieldPassword, Required: true}},
					Injection: services.InjectionConfig{Type: services.InjectionCustomHeader, HeaderName: "x-api-key"},
				},
				{
					ID:        "query",
					Name:      "Query Param",
					Fields:    []services.CredentialField{{Key: "token", Label: "Token", Type: services.FieldPassword, Required: true}},
					Injection: services.InjectionConfig{Type: services.InjectionQueryParam, QueryParam: "api_key"},
				},
				{
					ID:        "basic",
					Name:      "Basic Auth",
					Fields:    []services.CredentialField{{Key: "user", Label: "User", Type: services.FieldText, Required: true}},
					Injection: services.InjectionConfig{Type: services.InjectionBasicAuth},
				},
			},
		},
	}

	result := services.FilterTemplatesForPersonalTier(input)

	if len(result) != 1 {
		t.Fatalf("expected 1 template, got %d", len(result))
	}
	if len(result[0].AuthMethods) != 4 {
		t.Errorf("expected 4 auth methods preserved, got %d", len(result[0].AuthMethods))
	}
}

// ---------------------------------------------------------------------------
// FilterTemplatesForPersonalTier applied to built-in ServiceTemplates
// ---------------------------------------------------------------------------

// TestFilterTemplatesForPersonalTier_GitHubHasTwoMethods verifies that GitHub
// retains only PAT classic and fine-grained PAT (github_app and github_oauth
// are both filtered out).
func TestFilterTemplatesForPersonalTier_GitHubHasTwoMethods(t *testing.T) {
	result := services.FilterTemplatesForPersonalTier(services.ServiceTemplates)
	tmpl := findFilteredTemplate(t, result, "github")
	if len(tmpl.AuthMethods) != 2 {
		t.Errorf("expected github to have 2 methods after filtering, got %d", len(tmpl.AuthMethods))
	}
	expectMethodPresent(t, tmpl, "github_pat_classic")
	expectMethodPresent(t, tmpl, "github_fine_grained_pat")
}

// TestFilterTemplatesForPersonalTier_StripeHasTwoMethods verifies that Stripe
// retains API Key and Restricted Key (stripe_connect_oauth is filtered).
func TestFilterTemplatesForPersonalTier_StripeHasTwoMethods(t *testing.T) {
	result := services.FilterTemplatesForPersonalTier(services.ServiceTemplates)
	tmpl := findFilteredTemplate(t, result, "stripe")
	if len(tmpl.AuthMethods) != 2 {
		t.Errorf("expected stripe to have 2 methods after filtering, got %d", len(tmpl.AuthMethods))
	}
	expectMethodPresent(t, tmpl, "stripe_api_key")
	expectMethodPresent(t, tmpl, "stripe_restricted_key")
}

// TestFilterTemplatesForPersonalTier_OpenAIHasTwoMethods verifies that OpenAI
// retains both API Key methods (no OAuth to filter).
func TestFilterTemplatesForPersonalTier_OpenAIHasTwoMethods(t *testing.T) {
	result := services.FilterTemplatesForPersonalTier(services.ServiceTemplates)
	tmpl := findFilteredTemplate(t, result, "openai")
	if len(tmpl.AuthMethods) != 2 {
		t.Errorf("expected openai to have 2 methods after filtering, got %d", len(tmpl.AuthMethods))
	}
}

// TestFilterTemplatesForPersonalTier_AnthropicHasOneMethod verifies that
// Anthropic retains its single API key method.
func TestFilterTemplatesForPersonalTier_AnthropicHasOneMethod(t *testing.T) {
	result := services.FilterTemplatesForPersonalTier(services.ServiceTemplates)
	tmpl := findFilteredTemplate(t, result, "anthropic")
	if len(tmpl.AuthMethods) != 1 {
		t.Errorf("expected anthropic to have 1 method after filtering, got %d", len(tmpl.AuthMethods))
	}
	expectMethodPresent(t, tmpl, "anthropic_api_key")
}

// TestFilterTemplatesForPersonalTier_SlackHasTwoMethods verifies that Slack
// retains both token methods (no OAuth to filter).
func TestFilterTemplatesForPersonalTier_SlackHasTwoMethods(t *testing.T) {
	result := services.FilterTemplatesForPersonalTier(services.ServiceTemplates)
	tmpl := findFilteredTemplate(t, result, "slack")
	if len(tmpl.AuthMethods) != 2 {
		t.Errorf("expected slack to have 2 methods after filtering, got %d", len(tmpl.AuthMethods))
	}
}

// TestFilterTemplatesForPersonalTier_GitLabHasOneMethod verifies that GitLab
// retains only the PAT method (gitlab_oauth is filtered).
func TestFilterTemplatesForPersonalTier_GitLabHasOneMethod(t *testing.T) {
	result := services.FilterTemplatesForPersonalTier(services.ServiceTemplates)
	tmpl := findFilteredTemplate(t, result, "gitlab")
	if len(tmpl.AuthMethods) != 1 {
		t.Errorf("expected gitlab to have 1 method after filtering, got %d", len(tmpl.AuthMethods))
	}
	expectMethodPresent(t, tmpl, "gitlab_pat")
}

// TestFilterTemplatesForPersonalTier_GoogleHasOneMethod verifies that Google
// retains only the API key method (google_service_account uses named_strategy
// and google_oauth uses OAuth — both are filtered).
func TestFilterTemplatesForPersonalTier_GoogleHasOneMethod(t *testing.T) {
	result := services.FilterTemplatesForPersonalTier(services.ServiceTemplates)
	tmpl := findFilteredTemplate(t, result, "google")
	if len(tmpl.AuthMethods) != 1 {
		t.Errorf("expected google to have 1 method after filtering, got %d", len(tmpl.AuthMethods))
	}
	expectMethodPresent(t, tmpl, "google_api_key")
}

// TestFilterTemplatesForPersonalTier_MicrosoftExcluded verifies that Microsoft
// is dropped entirely because it only has OAuth auth methods.
func TestFilterTemplatesForPersonalTier_MicrosoftExcluded(t *testing.T) {
	result := services.FilterTemplatesForPersonalTier(services.ServiceTemplates)
	for _, tmpl := range result {
		if tmpl.ID == "microsoft" {
			t.Error("expected 'microsoft' template to be excluded from personal tier (OAuth only)")
		}
	}
}

// TestFilterTemplatesForPersonalTier_FacebookExcluded verifies that Facebook
// is dropped entirely because it only has OAuth auth methods.
func TestFilterTemplatesForPersonalTier_FacebookExcluded(t *testing.T) {
	result := services.FilterTemplatesForPersonalTier(services.ServiceTemplates)
	for _, tmpl := range result {
		if tmpl.ID == "facebook" {
			t.Error("expected 'facebook' template to be excluded from personal tier (OAuth only)")
		}
	}
}

// TestFilterTemplatesForPersonalTier_AWSIncluded verifies that AWS is included
// because its auth methods use connection_string strategy (allowed in personal tier).
func TestFilterTemplatesForPersonalTier_AWSIncluded(t *testing.T) {
	result := services.FilterTemplatesForPersonalTier(services.ServiceTemplates)
	found := false
	for _, tmpl := range result {
		if tmpl.ID == "aws" {
			found = true
		}
	}
	if !found {
		t.Error("expected 'aws' template to be present in personal tier (connection_string strategy)")
	}
}

// TestFilterTemplatesForPersonalTier_CustomServicePresent verifies that the
// Custom Service template survives filtering (it has bearer, basic, query methods).
func TestFilterTemplatesForPersonalTier_CustomServicePresent(t *testing.T) {
	result := services.FilterTemplatesForPersonalTier(services.ServiceTemplates)
	findFilteredTemplate(t, result, "custom") // fatals if missing
}

// TestFilterTemplatesForPersonalTier_DoesNotMutateInput verifies that the
// original ServiceTemplates slice is not modified.
func TestFilterTemplatesForPersonalTier_DoesNotMutateInput(t *testing.T) {
	// Count original github methods before filtering.
	var githubOriginal int
	for _, tmpl := range services.ServiceTemplates {
		if tmpl.ID == "github" {
			githubOriginal = len(tmpl.AuthMethods)
			break
		}
	}

	services.FilterTemplatesForPersonalTier(services.ServiceTemplates)

	// Count after filtering — must be unchanged.
	var githubAfter int
	for _, tmpl := range services.ServiceTemplates {
		if tmpl.ID == "github" {
			githubAfter = len(tmpl.AuthMethods)
			break
		}
	}
	if githubOriginal != githubAfter {
		t.Errorf("FilterTemplatesForPersonalTier mutated input: github had %d methods before, %d after",
			githubOriginal, githubAfter)
	}
}

// ---------------------------------------------------------------------------
// Helpers for filter tests
// ---------------------------------------------------------------------------

func findFilteredTemplate(t *testing.T, templates []services.ServiceTemplate, id string) services.ServiceTemplate {
	t.Helper()
	for _, tmpl := range templates {
		if tmpl.ID == id {
			return tmpl
		}
	}
	t.Fatalf("template %q not found in filtered result", id)
	return services.ServiceTemplate{}
}

func expectMethodPresent(t *testing.T, tmpl services.ServiceTemplate, methodID string) {
	t.Helper()
	for _, am := range tmpl.AuthMethods {
		if am.ID == methodID {
			return
		}
	}
	t.Errorf("expected auth method %q to be present in template %q, but it was not", methodID, tmpl.ID)
}
