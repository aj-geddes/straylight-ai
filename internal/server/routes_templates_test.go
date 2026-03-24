package server_test

import (
	"testing"
)

// ---------------------------------------------------------------------------
// GET /api/v1/templates — multi-auth format
// ---------------------------------------------------------------------------

// TestListTemplates_ReturnsAuthMethods verifies that each template in the
// response contains an "auth_methods" array with at least one entry.
func TestListTemplates_ReturnsAuthMethods(t *testing.T) {
	srv, _ := newTestServer()
	w := getPath(srv, "/api/v1/templates")

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	body := decodeJSON(t, w)
	templates, ok := body["templates"].([]interface{})
	if !ok {
		t.Fatalf("expected 'templates' array, got %T", body["templates"])
	}
	if len(templates) == 0 {
		t.Fatal("expected at least one template")
	}

	for _, rawTmpl := range templates {
		tmpl, ok := rawTmpl.(map[string]interface{})
		if !ok {
			t.Fatalf("expected template to be an object, got %T", rawTmpl)
		}
		authMethods, ok := tmpl["auth_methods"]
		if !ok {
			t.Errorf("template %v is missing 'auth_methods' field", tmpl["id"])
			continue
		}
		methods, ok := authMethods.([]interface{})
		if !ok {
			t.Errorf("template %v auth_methods is not an array", tmpl["id"])
			continue
		}
		if len(methods) == 0 {
			t.Errorf("template %v has zero auth methods", tmpl["id"])
		}
	}
}

// TestListTemplates_TemplatesHaveIDField verifies the new ServiceTemplate shape
// uses "id" (not "name") as the primary identifier.
func TestListTemplates_TemplatesHaveIDField(t *testing.T) {
	srv, _ := newTestServer()
	w := getPath(srv, "/api/v1/templates")
	body := decodeJSON(t, w)
	templates, _ := body["templates"].([]interface{})

	for _, rawTmpl := range templates {
		tmpl, ok := rawTmpl.(map[string]interface{})
		if !ok {
			continue
		}
		id, hasID := tmpl["id"]
		if !hasID {
			t.Errorf("template missing 'id' field: %v", tmpl)
			continue
		}
		if id == "" {
			t.Error("template has empty 'id' field")
		}
	}
}

// TestListTemplates_ContainsGitHubWithAuthMethods verifies GitHub template
// is returned with only its personal-tier auth methods (PAT classic and
// fine-grained PAT). OAuth and named-strategy methods are filtered out.
func TestListTemplates_ContainsGitHubWithAuthMethods(t *testing.T) {
	srv, _ := newTestServer()
	w := getPath(srv, "/api/v1/templates")
	body := decodeJSON(t, w)
	templates, _ := body["templates"].([]interface{})

	var githubTmpl map[string]interface{}
	for _, rawTmpl := range templates {
		tmpl, ok := rawTmpl.(map[string]interface{})
		if !ok {
			continue
		}
		if tmpl["id"] == "github" {
			githubTmpl = tmpl
			break
		}
	}

	if githubTmpl == nil {
		t.Fatal("expected 'github' template to be present")
	}

	methods, ok := githubTmpl["auth_methods"].([]interface{})
	if !ok {
		t.Fatal("expected github auth_methods to be an array")
	}
	// Personal tier: only PAT classic and fine-grained PAT survive filtering.
	// OAuth (github_oauth) and named_strategy (github_app) are excluded.
	if len(methods) != 2 {
		t.Errorf("expected github to have exactly 2 personal-tier auth methods, got %d", len(methods))
	}
}

// TestListTemplates_AuthMethodsHaveRequiredFields verifies that each auth method
// in every template has id, name, fields, and injection sub-objects.
func TestListTemplates_AuthMethodsHaveRequiredFields(t *testing.T) {
	srv, _ := newTestServer()
	w := getPath(srv, "/api/v1/templates")
	body := decodeJSON(t, w)
	templates, _ := body["templates"].([]interface{})

	for _, rawTmpl := range templates {
		tmpl, ok := rawTmpl.(map[string]interface{})
		if !ok {
			continue
		}
		methods, ok := tmpl["auth_methods"].([]interface{})
		if !ok {
			continue
		}
		for _, rawMethod := range methods {
			method, ok := rawMethod.(map[string]interface{})
			if !ok {
				t.Errorf("auth_method is not an object: %v", rawMethod)
				continue
			}
			for _, field := range []string{"id", "name", "fields", "injection"} {
				if _, has := method[field]; !has {
					t.Errorf("template %v auth_method %v missing field %q", tmpl["id"], method["id"], field)
				}
			}
		}
	}
}

// TestListTemplates_AnthropicHasXAPIKeyHeader verifies that the Anthropic
// template uses custom_header injection with x-api-key header name.
func TestListTemplates_AnthropicHasXAPIKeyHeader(t *testing.T) {
	srv, _ := newTestServer()
	w := getPath(srv, "/api/v1/templates")
	body := decodeJSON(t, w)
	templates, _ := body["templates"].([]interface{})

	var anthropicTmpl map[string]interface{}
	for _, rawTmpl := range templates {
		tmpl, ok := rawTmpl.(map[string]interface{})
		if !ok {
			continue
		}
		if tmpl["id"] == "anthropic" {
			anthropicTmpl = tmpl
			break
		}
	}
	if anthropicTmpl == nil {
		t.Fatal("expected 'anthropic' template to be present")
	}

	methods, ok := anthropicTmpl["auth_methods"].([]interface{})
	if !ok || len(methods) == 0 {
		t.Fatal("expected anthropic to have at least one auth method")
	}

	first, ok := methods[0].(map[string]interface{})
	if !ok {
		t.Fatal("expected first auth method to be an object")
	}

	injection, ok := first["injection"].(map[string]interface{})
	if !ok {
		t.Fatal("expected injection to be an object")
	}

	if injection["type"] != "custom_header" {
		t.Errorf("expected anthropic injection type=custom_header, got %v", injection["type"])
	}
	if injection["header_name"] != "x-api-key" {
		t.Errorf("expected anthropic header_name=x-api-key, got %v", injection["header_name"])
	}
}
