package services_test

import (
	"strings"
	"testing"

	"github.com/straylight-ai/straylight/internal/services"
)

// ---------------------------------------------------------------------------
// Templates registry tests
// ---------------------------------------------------------------------------

func TestTemplates_GoogleOAuthTemplateExists(t *testing.T) {
	if _, ok := services.Templates["google"]; !ok {
		t.Error("expected 'google' OAuth template to be registered in Templates map")
	}
}

func TestTemplates_StripeConnectOAuthTemplateExists(t *testing.T) {
	if _, ok := services.Templates["stripe-connect"]; !ok {
		t.Error("expected 'stripe-connect' OAuth template to be registered in Templates map")
	}
}

func TestTemplates_GoogleTemplateHasOAuthType(t *testing.T) {
	tmpl, ok := services.Templates["google"]
	if !ok {
		t.Fatal("google template not registered")
	}
	if tmpl.Type != "oauth" {
		t.Errorf("expected google template Type=oauth, got %q", tmpl.Type)
	}
}

func TestTemplates_StripeConnectTemplateHasOAuthType(t *testing.T) {
	tmpl, ok := services.Templates["stripe-connect"]
	if !ok {
		t.Fatal("stripe-connect template not registered")
	}
	if tmpl.Type != "oauth" {
		t.Errorf("expected stripe-connect template Type=oauth, got %q", tmpl.Type)
	}
}

func TestTemplates_GoogleTemplateTargetsGoogleAPIs(t *testing.T) {
	tmpl, ok := services.Templates["google"]
	if !ok {
		t.Fatal("google template not registered")
	}
	if tmpl.Target != "https://www.googleapis.com" {
		t.Errorf("expected google template Target=https://www.googleapis.com, got %q", tmpl.Target)
	}
}

func TestTemplates_StripeConnectTemplateTargetsStripeAPI(t *testing.T) {
	tmpl, ok := services.Templates["stripe-connect"]
	if !ok {
		t.Fatal("stripe-connect template not registered")
	}
	if tmpl.Target != "https://api.stripe.com" {
		t.Errorf("expected stripe-connect template Target=https://api.stripe.com, got %q", tmpl.Target)
	}
}

func TestTemplates_GoogleTemplateUsesHeaderInject(t *testing.T) {
	tmpl, ok := services.Templates["google"]
	if !ok {
		t.Fatal("google template not registered")
	}
	if tmpl.Inject != "header" {
		t.Errorf("expected google template Inject=header, got %q", tmpl.Inject)
	}
}

func TestTemplates_StripeConnectTemplateUsesHeaderInject(t *testing.T) {
	tmpl, ok := services.Templates["stripe-connect"]
	if !ok {
		t.Fatal("stripe-connect template not registered")
	}
	if tmpl.Inject != "header" {
		t.Errorf("expected stripe-connect template Inject=header, got %q", tmpl.Inject)
	}
}

func TestTemplates_GoogleTemplateHasBearerHeaderTemplate(t *testing.T) {
	tmpl, ok := services.Templates["google"]
	if !ok {
		t.Fatal("google template not registered")
	}
	if !strings.Contains(tmpl.HeaderTemplate, "Bearer") {
		t.Errorf("expected google template HeaderTemplate to contain 'Bearer', got %q", tmpl.HeaderTemplate)
	}
	if !strings.Contains(tmpl.HeaderTemplate, "{{.secret}}") {
		t.Errorf("expected google template HeaderTemplate to contain '{{.secret}}', got %q", tmpl.HeaderTemplate)
	}
}

func TestTemplates_StripeConnectTemplateHasBearerHeaderTemplate(t *testing.T) {
	tmpl, ok := services.Templates["stripe-connect"]
	if !ok {
		t.Fatal("stripe-connect template not registered")
	}
	if !strings.Contains(tmpl.HeaderTemplate, "Bearer") {
		t.Errorf("expected stripe-connect template HeaderTemplate to contain 'Bearer', got %q", tmpl.HeaderTemplate)
	}
	if !strings.Contains(tmpl.HeaderTemplate, "{{.secret}}") {
		t.Errorf("expected stripe-connect template HeaderTemplate to contain '{{.secret}}', got %q", tmpl.HeaderTemplate)
	}
}

func TestTemplates_GoogleTemplateHasCorrectName(t *testing.T) {
	tmpl, ok := services.Templates["google"]
	if !ok {
		t.Fatal("google template not registered")
	}
	if tmpl.Name != "google" {
		t.Errorf("expected google template Name=google, got %q", tmpl.Name)
	}
}

func TestTemplates_StripeConnectTemplateHasCorrectName(t *testing.T) {
	tmpl, ok := services.Templates["stripe-connect"]
	if !ok {
		t.Fatal("stripe-connect template not registered")
	}
	if tmpl.Name != "stripe-connect" {
		t.Errorf("expected stripe-connect template Name=stripe-connect, got %q", tmpl.Name)
	}
}

// ---------------------------------------------------------------------------
// Existing templates are unchanged
// ---------------------------------------------------------------------------

func TestTemplates_ExistingStripeTemplateUnchanged(t *testing.T) {
	tmpl, ok := services.Templates["stripe"]
	if !ok {
		t.Fatal("stripe (API key) template not registered — must not be removed")
	}
	if tmpl.Type != "http_proxy" {
		t.Errorf("expected original stripe template Type=http_proxy (unchanged), got %q", tmpl.Type)
	}
}

func TestTemplates_ExistingGithubTemplateUnchanged(t *testing.T) {
	tmpl, ok := services.Templates["github"]
	if !ok {
		t.Fatal("github template not registered — must not be removed")
	}
	if tmpl.Type != "http_proxy" {
		t.Errorf("expected github template Type=http_proxy (unchanged), got %q", tmpl.Type)
	}
}
