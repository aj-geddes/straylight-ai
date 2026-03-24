package services_test

import (
	"testing"

	"github.com/straylight-ai/straylight/internal/services"
)

// ---------------------------------------------------------------------------
// ValidateAuthMethod tests
// ---------------------------------------------------------------------------

func TestValidateAuthMethod_AcceptsValidBearerAuthMethod(t *testing.T) {
	am := services.AuthMethod{
		ID:   "pat",
		Name: "Personal Access Token",
		Fields: []services.CredentialField{
			{Key: "token", Label: "Token", Type: services.FieldPassword, Required: true},
		},
		Injection: services.InjectionConfig{
			Type: services.InjectionBearerHeader,
		},
	}
	if err := services.ValidateAuthMethod(am); err != nil {
		t.Errorf("ValidateAuthMethod() returned unexpected error for valid method: %v", err)
	}
}

func TestValidateAuthMethod_RejectsEmptyID(t *testing.T) {
	am := services.AuthMethod{
		ID:   "",
		Name: "Some Method",
		Fields: []services.CredentialField{
			{Key: "token", Label: "Token", Type: services.FieldPassword, Required: true},
		},
		Injection: services.InjectionConfig{
			Type: services.InjectionBearerHeader,
		},
	}
	if err := services.ValidateAuthMethod(am); err == nil {
		t.Error("ValidateAuthMethod() expected error for empty ID, got nil")
	}
}

func TestValidateAuthMethod_RejectsIDWithUppercase(t *testing.T) {
	am := services.AuthMethod{
		ID:   "MyMethod",
		Name: "Some Method",
		Fields: []services.CredentialField{
			{Key: "token", Label: "Token", Type: services.FieldPassword, Required: true},
		},
		Injection: services.InjectionConfig{
			Type: services.InjectionBearerHeader,
		},
	}
	if err := services.ValidateAuthMethod(am); err == nil {
		t.Error("ValidateAuthMethod() expected error for ID with uppercase, got nil")
	}
}

func TestValidateAuthMethod_RejectsIDStartingWithDigit(t *testing.T) {
	am := services.AuthMethod{
		ID:   "1invalid",
		Name: "Some Method",
		Fields: []services.CredentialField{
			{Key: "token", Label: "Token", Type: services.FieldPassword, Required: true},
		},
		Injection: services.InjectionConfig{
			Type: services.InjectionBearerHeader,
		},
	}
	if err := services.ValidateAuthMethod(am); err == nil {
		t.Error("ValidateAuthMethod() expected error for ID starting with digit, got nil")
	}
}

func TestValidateAuthMethod_RejectsEmptyName(t *testing.T) {
	am := services.AuthMethod{
		ID:   "pat",
		Name: "",
		Fields: []services.CredentialField{
			{Key: "token", Label: "Token", Type: services.FieldPassword, Required: true},
		},
		Injection: services.InjectionConfig{
			Type: services.InjectionBearerHeader,
		},
	}
	if err := services.ValidateAuthMethod(am); err == nil {
		t.Error("ValidateAuthMethod() expected error for empty name, got nil")
	}
}

func TestValidateAuthMethod_RejectsReservedFieldKeyAuthMethod(t *testing.T) {
	am := services.AuthMethod{
		ID:   "pat",
		Name: "PAT",
		Fields: []services.CredentialField{
			{Key: "auth_method", Label: "Token", Type: services.FieldPassword, Required: true},
		},
		Injection: services.InjectionConfig{
			Type: services.InjectionBearerHeader,
		},
	}
	if err := services.ValidateAuthMethod(am); err == nil {
		t.Error("ValidateAuthMethod() expected error for reserved field key 'auth_method', got nil")
	}
}

func TestValidateAuthMethod_RejectsReservedFieldKeyType(t *testing.T) {
	am := services.AuthMethod{
		ID:   "pat",
		Name: "PAT",
		Fields: []services.CredentialField{
			{Key: "type", Label: "Token", Type: services.FieldPassword, Required: true},
		},
		Injection: services.InjectionConfig{
			Type: services.InjectionBearerHeader,
		},
	}
	if err := services.ValidateAuthMethod(am); err == nil {
		t.Error("ValidateAuthMethod() expected error for reserved field key 'type', got nil")
	}
}

func TestValidateAuthMethod_RejectsDuplicateFieldKeys(t *testing.T) {
	am := services.AuthMethod{
		ID:   "basic",
		Name: "Basic Auth",
		Fields: []services.CredentialField{
			{Key: "token", Label: "Token", Type: services.FieldPassword, Required: true},
			{Key: "token", Label: "Another Token", Type: services.FieldText, Required: true},
		},
		Injection: services.InjectionConfig{
			Type: services.InjectionBearerHeader,
		},
	}
	if err := services.ValidateAuthMethod(am); err == nil {
		t.Error("ValidateAuthMethod() expected error for duplicate field keys, got nil")
	}
}

func TestValidateAuthMethod_RejectsInvalidInjectionType(t *testing.T) {
	am := services.AuthMethod{
		ID:   "pat",
		Name: "PAT",
		Fields: []services.CredentialField{
			{Key: "token", Label: "Token", Type: services.FieldPassword, Required: true},
		},
		Injection: services.InjectionConfig{
			Type: services.InjectionType("invalid_type"),
		},
	}
	if err := services.ValidateAuthMethod(am); err == nil {
		t.Error("ValidateAuthMethod() expected error for invalid injection type, got nil")
	}
}

func TestValidateAuthMethod_RejectsCustomHeaderWithoutHeaderName(t *testing.T) {
	am := services.AuthMethod{
		ID:   "api_key",
		Name: "API Key",
		Fields: []services.CredentialField{
			{Key: "token", Label: "Token", Type: services.FieldPassword, Required: true},
		},
		Injection: services.InjectionConfig{
			Type: services.InjectionCustomHeader,
			// HeaderName intentionally empty
		},
	}
	if err := services.ValidateAuthMethod(am); err == nil {
		t.Error("ValidateAuthMethod() expected error for custom_header without header_name, got nil")
	}
}

func TestValidateAuthMethod_AcceptsCustomHeaderWithHeaderName(t *testing.T) {
	am := services.AuthMethod{
		ID:   "api_key",
		Name: "API Key",
		Fields: []services.CredentialField{
			{Key: "token", Label: "Token", Type: services.FieldPassword, Required: true},
		},
		Injection: services.InjectionConfig{
			Type:       services.InjectionCustomHeader,
			HeaderName: "x-api-key",
		},
	}
	if err := services.ValidateAuthMethod(am); err != nil {
		t.Errorf("ValidateAuthMethod() returned unexpected error: %v", err)
	}
}

func TestValidateAuthMethod_RejectsQueryParamWithoutQueryParam(t *testing.T) {
	am := services.AuthMethod{
		ID:   "api_key",
		Name: "API Key",
		Fields: []services.CredentialField{
			{Key: "token", Label: "Token", Type: services.FieldPassword, Required: true},
		},
		Injection: services.InjectionConfig{
			Type: services.InjectionQueryParam,
			// QueryParam intentionally empty
		},
	}
	if err := services.ValidateAuthMethod(am); err == nil {
		t.Error("ValidateAuthMethod() expected error for query_param without query_param field, got nil")
	}
}

func TestValidateAuthMethod_RejectsNamedStrategyWithoutStrategy(t *testing.T) {
	am := services.AuthMethod{
		ID:     "github_app",
		Name:   "GitHub App",
		Fields: []services.CredentialField{},
		Injection: services.InjectionConfig{
			Type: services.InjectionNamedStrategy,
			// Strategy intentionally empty
		},
	}
	if err := services.ValidateAuthMethod(am); err == nil {
		t.Error("ValidateAuthMethod() expected error for named_strategy without strategy, got nil")
	}
}

func TestValidateAuthMethod_RejectsOAuthWithNonEmptyFields(t *testing.T) {
	am := services.AuthMethod{
		ID:   "oauth",
		Name: "OAuth",
		Fields: []services.CredentialField{
			{Key: "token", Label: "Token", Type: services.FieldPassword, Required: true},
		},
		Injection: services.InjectionConfig{
			Type: services.InjectionOAuth,
		},
	}
	if err := services.ValidateAuthMethod(am); err == nil {
		t.Error("ValidateAuthMethod() expected error for oauth method with non-empty fields, got nil")
	}
}

func TestValidateAuthMethod_AcceptsOAuthWithEmptyFields(t *testing.T) {
	am := services.AuthMethod{
		ID:        "oauth",
		Name:      "OAuth",
		Fields:    []services.CredentialField{},
		Injection: services.InjectionConfig{Type: services.InjectionOAuth},
	}
	if err := services.ValidateAuthMethod(am); err != nil {
		t.Errorf("ValidateAuthMethod() returned unexpected error for oauth with empty fields: %v", err)
	}
}

// ---------------------------------------------------------------------------
// ValidateTemplate tests
// ---------------------------------------------------------------------------

func TestValidateTemplate_AcceptsTemplateWithOneAuthMethod(t *testing.T) {
	tmpl := services.ServiceTemplate{
		ID:          "myservice",
		DisplayName: "My Service",
		Target:      "https://api.example.com",
		AuthMethods: []services.AuthMethod{
			{
				ID:   "api_key",
				Name: "API Key",
				Fields: []services.CredentialField{
					{Key: "token", Label: "Token", Type: services.FieldPassword, Required: true},
				},
				Injection: services.InjectionConfig{Type: services.InjectionBearerHeader},
			},
		},
	}
	if err := services.ValidateTemplate(tmpl); err != nil {
		t.Errorf("ValidateTemplate() returned unexpected error: %v", err)
	}
}

func TestValidateTemplate_RejectsTemplateWithZeroAuthMethods(t *testing.T) {
	tmpl := services.ServiceTemplate{
		ID:          "myservice",
		DisplayName: "My Service",
		Target:      "https://api.example.com",
		AuthMethods: []services.AuthMethod{},
	}
	if err := services.ValidateTemplate(tmpl); err == nil {
		t.Error("ValidateTemplate() expected error for template with zero auth methods, got nil")
	}
}

func TestValidateTemplate_RejectsDuplicateAuthMethodIDs(t *testing.T) {
	method := services.AuthMethod{
		ID:   "api_key",
		Name: "API Key",
		Fields: []services.CredentialField{
			{Key: "token", Label: "Token", Type: services.FieldPassword, Required: true},
		},
		Injection: services.InjectionConfig{Type: services.InjectionBearerHeader},
	}
	tmpl := services.ServiceTemplate{
		ID:          "myservice",
		DisplayName: "My Service",
		Target:      "https://api.example.com",
		AuthMethods: []services.AuthMethod{method, method},
	}
	if err := services.ValidateTemplate(tmpl); err == nil {
		t.Error("ValidateTemplate() expected error for duplicate auth method IDs, got nil")
	}
}

func TestValidateTemplate_PropagatesAuthMethodValidationErrors(t *testing.T) {
	tmpl := services.ServiceTemplate{
		ID:          "myservice",
		DisplayName: "My Service",
		Target:      "https://api.example.com",
		AuthMethods: []services.AuthMethod{
			{
				ID:   "", // invalid: empty ID
				Name: "API Key",
				Fields: []services.CredentialField{
					{Key: "token", Label: "Token", Type: services.FieldPassword, Required: true},
				},
				Injection: services.InjectionConfig{Type: services.InjectionBearerHeader},
			},
		},
	}
	if err := services.ValidateTemplate(tmpl); err == nil {
		t.Error("ValidateTemplate() expected error for invalid auth method, got nil")
	}
}

// ---------------------------------------------------------------------------
// ServiceTemplates built-in templates pass validation
// ---------------------------------------------------------------------------

func TestServiceTemplates_AllPassValidation(t *testing.T) {
	for _, tmpl := range services.ServiceTemplates {
		t.Run(tmpl.ID, func(t *testing.T) {
			if err := services.ValidateTemplate(tmpl); err != nil {
				t.Errorf("built-in template %q failed validation: %v", tmpl.ID, err)
			}
		})
	}
}

func TestServiceTemplates_GitHubHasFourAuthMethods(t *testing.T) {
	tmpl := findTemplate(t, "github")
	if len(tmpl.AuthMethods) != 4 {
		t.Errorf("expected github to have 4 auth methods, got %d", len(tmpl.AuthMethods))
	}
}

func TestServiceTemplates_GitHubPATAuthMethodHasBearerInjection(t *testing.T) {
	tmpl := findTemplate(t, "github")
	am := findAuthMethod(t, tmpl, "github_pat_classic")
	if am.Injection.Type != services.InjectionBearerHeader {
		t.Errorf("expected github PAT injection=bearer_header, got %q", am.Injection.Type)
	}
}

func TestServiceTemplates_GitHubAppAuthMethodHasNamedStrategy(t *testing.T) {
	tmpl := findTemplate(t, "github")
	am := findAuthMethod(t, tmpl, "github_app")
	if am.Injection.Type != services.InjectionNamedStrategy {
		t.Errorf("expected github_app injection=named_strategy, got %q", am.Injection.Type)
	}
	if am.Injection.Strategy != "github_app_jwt" {
		t.Errorf("expected github_app strategy=github_app_jwt, got %q", am.Injection.Strategy)
	}
}

func TestServiceTemplates_GitHubOAuthHasOAuthInjection(t *testing.T) {
	tmpl := findTemplate(t, "github")
	am := findAuthMethod(t, tmpl, "github_oauth")
	if am.Injection.Type != services.InjectionOAuth {
		t.Errorf("expected github_oauth injection=oauth, got %q", am.Injection.Type)
	}
}

func TestServiceTemplates_AnthropicUsesCustomHeader(t *testing.T) {
	tmpl := findTemplate(t, "anthropic")
	am := findAuthMethod(t, tmpl, "anthropic_api_key")
	if am.Injection.Type != services.InjectionCustomHeader {
		t.Errorf("expected anthropic api_key injection=custom_header, got %q", am.Injection.Type)
	}
	if am.Injection.HeaderName != "x-api-key" {
		t.Errorf("expected anthropic header_name=x-api-key, got %q", am.Injection.HeaderName)
	}
}

func TestServiceTemplates_GoogleAPIKeyUsesQueryParam(t *testing.T) {
	tmpl := findTemplate(t, "google")
	am := findAuthMethod(t, tmpl, "google_api_key")
	if am.Injection.Type != services.InjectionQueryParam {
		t.Errorf("expected google api_key injection=query_param, got %q", am.Injection.Type)
	}
	if am.Injection.QueryParam != "key" {
		t.Errorf("expected google api_key query_param=key, got %q", am.Injection.QueryParam)
	}
}

func TestServiceTemplates_AWSAccessKeyHasNamedStrategy(t *testing.T) {
	tmpl := findTemplate(t, "aws")
	am := findAuthMethod(t, tmpl, "aws_access_key")
	if am.Injection.Type != services.InjectionNamedStrategy {
		t.Errorf("expected aws access_key injection=named_strategy, got %q", am.Injection.Type)
	}
	if am.Injection.Strategy != "aws_sigv4" {
		t.Errorf("expected aws_sigv4 strategy, got %q", am.Injection.Strategy)
	}
}

func TestServiceTemplates_StripeHasThreeAuthMethods(t *testing.T) {
	tmpl := findTemplate(t, "stripe")
	if len(tmpl.AuthMethods) != 3 {
		t.Errorf("expected stripe to have 3 auth methods, got %d", len(tmpl.AuthMethods))
	}
}

func TestServiceTemplates_SlackBotTokenHasBearerInjection(t *testing.T) {
	tmpl := findTemplate(t, "slack")
	am := findAuthMethod(t, tmpl, "slack_bot_token")
	if am.Injection.Type != services.InjectionBearerHeader {
		t.Errorf("expected slack bot_token injection=bearer_header, got %q", am.Injection.Type)
	}
}

func TestServiceTemplates_GitLabPATUsesCustomHeader(t *testing.T) {
	tmpl := findTemplate(t, "gitlab")
	am := findAuthMethod(t, tmpl, "gitlab_pat")
	if am.Injection.Type != services.InjectionCustomHeader {
		t.Errorf("expected gitlab PAT injection=custom_header, got %q", am.Injection.Type)
	}
	if am.Injection.HeaderName != "PRIVATE-TOKEN" {
		t.Errorf("expected gitlab PAT header_name=PRIVATE-TOKEN, got %q", am.Injection.HeaderName)
	}
}

// ---------------------------------------------------------------------------
// InjectionType constants existence
// ---------------------------------------------------------------------------

func TestInjectionTypeConstants_AllDefined(t *testing.T) {
	types := []services.InjectionType{
		services.InjectionBearerHeader,
		services.InjectionCustomHeader,
		services.InjectionMultiHeader,
		services.InjectionQueryParam,
		services.InjectionBasicAuth,
		services.InjectionOAuth,
		services.InjectionNamedStrategy,
	}
	for _, it := range types {
		if it == "" {
			t.Error("expected non-empty InjectionType constant")
		}
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func findTemplate(t *testing.T, id string) services.ServiceTemplate {
	t.Helper()
	for _, tmpl := range services.ServiceTemplates {
		if tmpl.ID == id {
			return tmpl
		}
	}
	t.Fatalf("template %q not found in ServiceTemplates", id)
	return services.ServiceTemplate{}
}

func findAuthMethod(t *testing.T, tmpl services.ServiceTemplate, id string) services.AuthMethod {
	t.Helper()
	for _, am := range tmpl.AuthMethods {
		if am.ID == id {
			return am
		}
	}
	t.Fatalf("auth method %q not found in template %q", id, tmpl.ID)
	return services.AuthMethod{}
}
