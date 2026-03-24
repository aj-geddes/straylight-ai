package server_test

// WP-MA-4: Multi-auth-method API endpoint tests.
//
// RED phase: all tests in this file are written before the corresponding
// implementation is added to routes.go. They must FAIL until implementation
// is complete.

import (
	"bytes"
	"net/http"
	"testing"
)

// ---------------------------------------------------------------------------
// POST /api/v1/services — new multi-auth-method path
// ---------------------------------------------------------------------------

// TestCreateService_WithTemplateAndAuthMethod_Returns201 verifies that a service
// can be created using the template + auth_method + credentials format.
func TestCreateService_WithTemplateAndAuthMethod_Returns201(t *testing.T) {
	srv, _ := newTestServer()

	w := postJSON(srv, "/api/v1/services", map[string]interface{}{
		"name":        "github",
		"template":    "github",
		"auth_method": "github_pat_classic",
		"credentials": map[string]string{
			"token": "ghp_abc123xyz456abc123xyz456abc123xyz456",
		},
	})

	if w.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d (body: %s)", w.Code, w.Body.String())
	}

	body := decodeJSON(t, w)
	if body["name"] != "github" {
		t.Errorf("expected name=github in response, got %v", body["name"])
	}
}

// TestCreateService_WithTemplateAndAuthMethod_SetsAuthMethodID verifies that
// the created service has auth_method_id set in its response.
func TestCreateService_WithTemplateAndAuthMethod_SetsAuthMethodID(t *testing.T) {
	srv, _ := newTestServer()

	w := postJSON(srv, "/api/v1/services", map[string]interface{}{
		"name":        "github",
		"template":    "github",
		"auth_method": "github_pat_classic",
		"credentials": map[string]string{
			"token": "ghp_abc123xyz456abc123xyz456abc123xyz456",
		},
	})

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d (body: %s)", w.Code, w.Body.String())
	}

	body := decodeJSON(t, w)
	if body["auth_method_id"] != "github_pat_classic" {
		t.Errorf("expected auth_method_id=github_pat_classic, got %v", body["auth_method_id"])
	}
}

// TestCreateService_WithCredentialsMap_StoresMultiFieldCredentials verifies
// that multi-field credentials are stored in vault using CreateWithAuth.
func TestCreateService_WithCredentialsMap_StoresMultiFieldCredentials(t *testing.T) {
	srv, reg := newTestServer()

	w := postJSON(srv, "/api/v1/services", map[string]interface{}{
		"name":        "myapi",
		"template":    "custom",
		"auth_method": "basic_auth",
		// custom template has an empty target, so the user must provide one.
		"target": "https://api.example.com",
		"credentials": map[string]string{
			"username": "admin",
			"password": "s3cr3t",
		},
	})

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d (body: %s)", w.Code, w.Body.String())
	}

	// Verify credentials were stored via ReadCredentials (multi-field path).
	authMethod, fields, err := reg.ReadCredentials("myapi")
	if err != nil {
		t.Fatalf("ReadCredentials failed: %v", err)
	}
	if authMethod != "basic_auth" {
		t.Errorf("expected auth_method=basic_auth, got %q", authMethod)
	}
	if fields["username"] != "admin" {
		t.Errorf("expected username=admin, got %q", fields["username"])
	}
	if fields["password"] != "s3cr3t" {
		t.Errorf("expected password=s3cr3t, got %q", fields["password"])
	}
}

// TestCreateService_WithTemplateAuthMethod_TypeAndTargetFromTemplate verifies
// that type and target are derived from the template when not explicitly provided.
func TestCreateService_WithTemplateAuthMethod_TypeAndTargetFromTemplate(t *testing.T) {
	srv, _ := newTestServer()

	w := postJSON(srv, "/api/v1/services", map[string]interface{}{
		"name":        "github",
		"template":    "github",
		"auth_method": "github_pat_classic",
		"credentials": map[string]string{
			"token": "ghp_abc123xyz456abc123xyz456abc123xyz456",
		},
	})

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d (body: %s)", w.Code, w.Body.String())
	}

	body := decodeJSON(t, w)
	if body["type"] != "http_proxy" {
		t.Errorf("expected type=http_proxy from template, got %v", body["type"])
	}
	if body["target"] != "https://api.github.com" {
		t.Errorf("expected target=https://api.github.com from template, got %v", body["target"])
	}
}

// TestCreateService_WithUnknownTemplate_Returns400 verifies that an unknown
// template name returns 400 with a descriptive error.
func TestCreateService_WithUnknownTemplate_Returns400(t *testing.T) {
	srv, _ := newTestServer()

	w := postJSON(srv, "/api/v1/services", map[string]interface{}{
		"name":        "mysvc",
		"template":    "nonexistent-template",
		"auth_method": "some_method",
		"credentials": map[string]string{
			"token": "abc123",
		},
	})

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for unknown template, got %d (body: %s)", w.Code, w.Body.String())
	}
}

// TestCreateService_WithUnknownAuthMethod_Returns400 verifies that an unknown
// auth method ID returns 400 with a descriptive error.
func TestCreateService_WithUnknownAuthMethod_Returns400(t *testing.T) {
	srv, _ := newTestServer()

	w := postJSON(srv, "/api/v1/services", map[string]interface{}{
		"name":        "github",
		"template":    "github",
		"auth_method": "nonexistent_method",
		"credentials": map[string]string{
			"token": "ghp_abc123xyz456abc123xyz456abc123xyz456",
		},
	})

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for unknown auth method, got %d (body: %s)", w.Code, w.Body.String())
	}
}

// TestCreateService_WithMissingRequiredField_Returns400 verifies that when
// a required credential field is absent, the API returns 400.
func TestCreateService_WithMissingRequiredField_Returns400(t *testing.T) {
	srv, _ := newTestServer()

	w := postJSON(srv, "/api/v1/services", map[string]interface{}{
		"name":        "github",
		"template":    "github",
		"auth_method": "github_pat_classic",
		// "token" field is required but omitted
		"credentials": map[string]string{},
	})

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing required field, got %d (body: %s)", w.Code, w.Body.String())
	}
}

// TestCreateService_WithInvalidPattern_Returns400 verifies that a credential
// field value that does not match the field's regex pattern returns 400.
func TestCreateService_WithInvalidPattern_Returns400(t *testing.T) {
	srv, _ := newTestServer()

	w := postJSON(srv, "/api/v1/services", map[string]interface{}{
		"name":        "github",
		"template":    "github",
		"auth_method": "github_pat_classic",
		"credentials": map[string]string{
			// github_pat_classic requires "^ghp_[a-zA-Z0-9]{36}$"
			"token": "not-a-valid-ghp-token",
		},
	})

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for pattern mismatch, got %d (body: %s)", w.Code, w.Body.String())
	}
}

// TestCreateService_WithPatternMatch_Returns201 verifies that a credential
// field value matching its pattern succeeds.
func TestCreateService_WithPatternMatch_Returns201(t *testing.T) {
	srv, _ := newTestServer()

	w := postJSON(srv, "/api/v1/services", map[string]interface{}{
		"name":        "github",
		"template":    "github",
		"auth_method": "github_pat_classic",
		"credentials": map[string]string{
			// Matches "^ghp_[a-zA-Z0-9]{36}$"
			"token": "ghp_abc123xyz456abc123xyz456abc123xyz456",
		},
	})

	if w.Code != http.StatusCreated {
		t.Errorf("expected 201 for valid pattern, got %d (body: %s)", w.Code, w.Body.String())
	}
}

// TestCreateService_WithMultipleFieldsForAuthMethod_Returns201 verifies that
// all required multi-field credentials (e.g., Basic Auth) are accepted.
func TestCreateService_WithMultipleFieldsForAuthMethod_Returns201(t *testing.T) {
	srv, _ := newTestServer()

	w := postJSON(srv, "/api/v1/services", map[string]interface{}{
		"name":        "myapi",
		"template":    "custom",
		"auth_method": "basic_auth",
		// custom template has an empty target, so the user must provide one.
		"target": "https://api.example.com",
		"credentials": map[string]string{
			"username": "admin",
			"password": "s3cr3t",
		},
	})

	if w.Code != http.StatusCreated {
		t.Errorf("expected 201 for multi-field basic auth, got %d (body: %s)", w.Code, w.Body.String())
	}
}

// TestCreateService_WithMissingBasicAuthField_Returns400 verifies that
// missing one of two required fields for Basic Auth returns 400.
func TestCreateService_WithMissingBasicAuthField_Returns400(t *testing.T) {
	srv, _ := newTestServer()

	w := postJSON(srv, "/api/v1/services", map[string]interface{}{
		"name":        "myapi",
		"template":    "custom",
		"auth_method": "basic_auth",
		"target":      "https://api.example.com",
		"credentials": map[string]string{
			"username": "admin",
			// "password" is required but omitted
		},
	})

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing password field, got %d (body: %s)", w.Code, w.Body.String())
	}
}

// TestCreateService_ResponseDoesNotLeakCredentials verifies that credential
// values are NEVER returned in any POST response, even for multi-field creds.
func TestCreateService_ResponseDoesNotLeakCredentials(t *testing.T) {
	srv, _ := newTestServer()

	w := postJSON(srv, "/api/v1/services", map[string]interface{}{
		"name":        "myapi",
		"template":    "custom",
		"auth_method": "basic_auth",
		"target":      "https://api.example.com",
		"credentials": map[string]string{
			"username": "admin-user",
			"password": "super-secret-pass",
		},
	})

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", w.Code)
	}

	respBody := w.Body.String()
	if bytes.Contains([]byte(respBody), []byte("super-secret-pass")) {
		t.Error("response body contains credential value 'super-secret-pass'")
	}
	if bytes.Contains([]byte(respBody), []byte("admin-user")) {
		t.Error("response body contains credential field 'admin-user'")
	}
}

// ---------------------------------------------------------------------------
// Legacy backward compatibility — existing single-credential format still works
// ---------------------------------------------------------------------------

// TestCreateService_LegacyCredentialField_StillWorks verifies the old
// {"credential": "..."} format still creates services correctly.
func TestCreateService_LegacyCredentialField_StillWorks(t *testing.T) {
	srv, _ := newTestServer()

	w := postJSON(srv, "/api/v1/services", map[string]interface{}{
		"name":       "stripe",
		"type":       "http_proxy",
		"target":     "https://api.stripe.com",
		"inject":     "header",
		"credential": "sk_test_abc123",
	})

	if w.Code != http.StatusCreated {
		t.Errorf("expected 201 for legacy credential, got %d (body: %s)", w.Code, w.Body.String())
	}
}

// TestCreateService_CredentialsMapTakesPrecedenceOverCredential verifies that
// when both "credential" (string) and "credentials" (map) are provided in the
// request, the "credentials" map takes precedence.
func TestCreateService_CredentialsMapTakesPrecedenceOverCredential(t *testing.T) {
	srv, reg := newTestServer()

	w := postJSON(srv, "/api/v1/services", map[string]interface{}{
		"name":        "github",
		"template":    "github",
		"auth_method": "github_pat_classic",
		// Both provided — credentials map takes precedence.
		"credential": "old-single-token",
		"credentials": map[string]string{
			"token": "ghp_abc123xyz456abc123xyz456abc123xyz456",
		},
	})

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d (body: %s)", w.Code, w.Body.String())
	}

	// The multi-field path should have been used.
	authMethod, fields, err := reg.ReadCredentials("github")
	if err != nil {
		t.Fatalf("ReadCredentials failed: %v", err)
	}
	if authMethod != "github_pat_classic" {
		t.Errorf("expected auth_method=github_pat_classic, got %q", authMethod)
	}
	if fields["token"] != "ghp_abc123xyz456abc123xyz456abc123xyz456" {
		t.Errorf("expected credentials map token to be used, got %q", fields["token"])
	}
}

// TestCreateService_NeitherCredentialNorCredentials_Returns400 verifies that
// a request with no credential data at all returns 400.
func TestCreateService_NeitherCredentialNorCredentials_Returns400(t *testing.T) {
	srv, _ := newTestServer()

	w := postJSON(srv, "/api/v1/services", map[string]interface{}{
		"name":        "github",
		"template":    "github",
		"auth_method": "github_pat_classic",
		// No credential or credentials provided.
	})

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 when no credentials provided, got %d (body: %s)", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// GET /api/v1/services/{name} — includes auth_method_id
// ---------------------------------------------------------------------------

// TestGetService_IncludesAuthMethodID verifies that a service created with
// an auth_method_id returns that field in the GET response.
func TestGetService_IncludesAuthMethodID(t *testing.T) {
	srv, _ := newTestServer()

	postJSON(srv, "/api/v1/services", map[string]interface{}{
		"name":        "github",
		"template":    "github",
		"auth_method": "github_pat_classic",
		"credentials": map[string]string{
			"token": "ghp_abc123xyz456abc123xyz456abc123xyz456",
		},
	})

	w := getPath(srv, "/api/v1/services/github")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (body: %s)", w.Code, w.Body.String())
	}

	body := decodeJSON(t, w)
	if body["auth_method_id"] != "github_pat_classic" {
		t.Errorf("expected auth_method_id=github_pat_classic in GET response, got %v", body["auth_method_id"])
	}
}

// TestGetService_LegacyService_AuthMethodIDIsEmpty verifies that a legacy
// service (created without auth_method) has no auth_method_id in the response.
func TestGetService_LegacyService_AuthMethodIDIsEmpty(t *testing.T) {
	srv, _ := newTestServer()

	postJSON(srv, "/api/v1/services", map[string]interface{}{
		"name":       "stripe",
		"type":       "http_proxy",
		"target":     "https://api.stripe.com",
		"inject":     "header",
		"credential": "sk_test_abc",
	})

	w := getPath(srv, "/api/v1/services/stripe")
	body := decodeJSON(t, w)

	// Legacy service: auth_method_id should be absent or empty.
	if val, found := body["auth_method_id"]; found && val != "" && val != nil {
		t.Errorf("expected empty auth_method_id for legacy service, got %v", val)
	}
}

// ---------------------------------------------------------------------------
// PUT /api/v1/services/{name} — multi-field credential update
// ---------------------------------------------------------------------------

// TestUpdateService_WithCredentialsMap_UpdatesMultiFieldCredentials verifies
// that providing "credentials" map in a PUT updates all credential fields.
func TestUpdateService_WithCredentialsMap_UpdatesMultiFieldCredentials(t *testing.T) {
	srv, reg := newTestServer()

	// First create with multi-field credentials.
	postJSON(srv, "/api/v1/services", map[string]interface{}{
		"name":        "myapi",
		"template":    "custom",
		"auth_method": "basic_auth",
		"target":      "https://api.example.com",
		"credentials": map[string]string{
			"username": "olduser",
			"password": "oldpass",
		},
	})

	// Update with new credentials.
	w := putJSON(srv, "/api/v1/services/myapi", map[string]interface{}{
		"type":        "http_proxy",
		"target":      "https://api.example.com",
		"inject":      "header",
		"auth_method": "basic_auth",
		"credentials": map[string]string{
			"username": "newuser",
			"password": "newpass",
		},
	})

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d (body: %s)", w.Code, w.Body.String())
	}

	authMethod, fields, err := reg.ReadCredentials("myapi")
	if err != nil {
		t.Fatalf("ReadCredentials failed: %v", err)
	}
	if authMethod != "basic_auth" {
		t.Errorf("expected auth_method=basic_auth after update, got %q", authMethod)
	}
	if fields["username"] != "newuser" {
		t.Errorf("expected username=newuser after update, got %q", fields["username"])
	}
	if fields["password"] != "newpass" {
		t.Errorf("expected password=newpass after update, got %q", fields["password"])
	}
}

// TestUpdateService_WithLegacyCredential_StillWorks verifies that the legacy
// single-credential PUT still works after the multi-auth changes.
func TestUpdateService_WithLegacyCredential_StillWorks(t *testing.T) {
	srv, reg := newTestServer()

	postJSON(srv, "/api/v1/services", map[string]interface{}{
		"name":       "stripe",
		"type":       "http_proxy",
		"target":     "https://api.stripe.com",
		"inject":     "header",
		"credential": "old-key",
	})

	w := putJSON(srv, "/api/v1/services/stripe", map[string]interface{}{
		"type":       "http_proxy",
		"target":     "https://api.stripe.com",
		"inject":     "header",
		"credential": "new-key",
	})

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d (body: %s)", w.Code, w.Body.String())
	}

	cred, err := reg.GetCredential("stripe")
	if err != nil {
		t.Fatalf("GetCredential failed: %v", err)
	}
	if cred != "new-key" {
		t.Errorf("expected credential=new-key after update, got %q", cred)
	}
}

// TestUpdateService_WithNoCredentialFields_PreservesExistingCredentials verifies
// that a PUT with no credential data preserves the existing credentials.
func TestUpdateService_WithNoCredentialFields_PreservesExistingCredentials(t *testing.T) {
	srv, reg := newTestServer()

	postJSON(srv, "/api/v1/services", map[string]interface{}{
		"name":       "stripe",
		"type":       "http_proxy",
		"target":     "https://api.stripe.com",
		"inject":     "header",
		"credential": "original-key",
	})

	// PUT with no credential data.
	putJSON(srv, "/api/v1/services/stripe", map[string]interface{}{
		"type":   "http_proxy",
		"target": "https://api.stripe.com/v2",
		"inject": "header",
	})

	// Credential should be unchanged.
	cred, err := reg.GetCredential("stripe")
	if err != nil {
		t.Fatalf("GetCredential failed: %v", err)
	}
	if cred != "original-key" {
		t.Errorf("expected credential=original-key preserved, got %q", cred)
	}
}

// ---------------------------------------------------------------------------
// POST /api/v1/services/{name}/rotate — multi-field credential rotation
// ---------------------------------------------------------------------------

// TestRotateCredential_WithCredentialsMap_RotatesAllFields verifies that
// providing "credentials" map in a rotate request replaces all credential fields.
func TestRotateCredential_WithCredentialsMap_RotatesAllFields(t *testing.T) {
	srv, reg := newTestServer()

	// Create with multi-field credentials.
	postJSON(srv, "/api/v1/services", map[string]interface{}{
		"name":        "myapi",
		"template":    "custom",
		"auth_method": "basic_auth",
		"target":      "https://api.example.com",
		"credentials": map[string]string{
			"username": "olduser",
			"password": "oldpass",
		},
	})

	// Rotate with new credentials map.
	w := postJSON(srv, "/api/v1/services/myapi/rotate", map[string]interface{}{
		"credentials": map[string]string{
			"username": "rotateduser",
			"password": "rotatedpass",
		},
	})

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d (body: %s)", w.Code, w.Body.String())
	}

	authMethod, fields, err := reg.ReadCredentials("myapi")
	if err != nil {
		t.Fatalf("ReadCredentials failed: %v", err)
	}
	// Auth method should be preserved during rotation.
	if authMethod != "basic_auth" {
		t.Errorf("expected auth_method=basic_auth preserved after rotate, got %q", authMethod)
	}
	if fields["username"] != "rotateduser" {
		t.Errorf("expected username=rotateduser after rotate, got %q", fields["username"])
	}
	if fields["password"] != "rotatedpass" {
		t.Errorf("expected password=rotatedpass after rotate, got %q", fields["password"])
	}
}

// TestRotateCredential_WithLegacyCredential_StillWorks verifies that the
// legacy single-string rotate still works.
func TestRotateCredential_WithLegacyCredential_StillWorks(t *testing.T) {
	srv, reg := newTestServer()

	postJSON(srv, "/api/v1/services", map[string]interface{}{
		"name":       "stripe",
		"type":       "http_proxy",
		"target":     "https://api.stripe.com",
		"inject":     "header",
		"credential": "old-key",
	})

	w := postJSON(srv, "/api/v1/services/stripe/rotate", map[string]interface{}{
		"credential": "rotated-key",
	})

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d (body: %s)", w.Code, w.Body.String())
	}

	cred, err := reg.GetCredential("stripe")
	if err != nil {
		t.Fatalf("GetCredential failed: %v", err)
	}
	if cred != "rotated-key" {
		t.Errorf("expected credential=rotated-key after rotate, got %q", cred)
	}
}

// TestRotateCredential_WithNoCredentials_Returns400 verifies that a rotate
// request with neither "credential" nor "credentials" returns 400.
func TestRotateCredential_WithNoCredentials_Returns400(t *testing.T) {
	srv, _ := newTestServer()

	postJSON(srv, "/api/v1/services", map[string]interface{}{
		"name":       "stripe",
		"type":       "http_proxy",
		"target":     "https://api.stripe.com",
		"inject":     "header",
		"credential": "old-key",
	})

	w := postJSON(srv, "/api/v1/services/stripe/rotate", map[string]interface{}{})

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing credentials in rotate, got %d (body: %s)", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// GET /api/v1/templates — verify existing WP-MA-1 behavior (already done)
// ---------------------------------------------------------------------------

// TestListTemplates_ReturnsServiceTemplateFormat verifies that the template
// list response uses the new ServiceTemplate format with auth_methods.
// This is a verification that WP-MA-1 work is in place.
func TestListTemplates_ReturnsServiceTemplateFormat(t *testing.T) {
	srv, _ := newTestServer()
	w := getPath(srv, "/api/v1/templates")

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	body := decodeJSON(t, w)
	templates, ok := body["templates"].([]interface{})
	if !ok {
		t.Fatal("expected 'templates' array")
	}

	for _, rawTmpl := range templates {
		tmpl, ok := rawTmpl.(map[string]interface{})
		if !ok {
			continue
		}
		// ServiceTemplate has "id" not "name".
		if _, hasID := tmpl["id"]; !hasID {
			t.Errorf("template missing 'id' field: %v", tmpl)
		}
		// ServiceTemplate has "auth_methods" array.
		if _, hasAuthMethods := tmpl["auth_methods"]; !hasAuthMethods {
			t.Errorf("template %v missing 'auth_methods' field", tmpl["id"])
		}
	}
}

// ---------------------------------------------------------------------------
// GET /api/v1/templates/{name} — new single-template endpoint
// ---------------------------------------------------------------------------

// TestGetTemplate_Returns200WithTemplateData verifies that GET /api/v1/templates/{name}
// returns a single template with all its auth methods.
func TestGetTemplate_Returns200WithTemplateData(t *testing.T) {
	srv, _ := newTestServer()

	w := getPath(srv, "/api/v1/templates/github")

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d (body: %s)", w.Code, w.Body.String())
	}

	body := decodeJSON(t, w)
	if body["id"] != "github" {
		t.Errorf("expected id=github, got %v", body["id"])
	}
	if body["display_name"] != "GitHub" {
		t.Errorf("expected display_name=GitHub, got %v", body["display_name"])
	}
}

// TestGetTemplate_Returns200WithAuthMethods verifies that the single-template
// response includes the auth_methods array.
func TestGetTemplate_Returns200WithAuthMethods(t *testing.T) {
	srv, _ := newTestServer()

	w := getPath(srv, "/api/v1/templates/github")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	body := decodeJSON(t, w)
	methods, ok := body["auth_methods"].([]interface{})
	if !ok {
		t.Fatal("expected auth_methods to be an array")
	}
	if len(methods) < 4 {
		t.Errorf("expected github to have at least 4 auth methods, got %d", len(methods))
	}
}

// TestGetTemplate_Returns404ForUnknownTemplate verifies that requesting a
// template that does not exist returns 404.
func TestGetTemplate_Returns404ForUnknownTemplate(t *testing.T) {
	srv, _ := newTestServer()

	w := getPath(srv, "/api/v1/templates/nonexistent-template")
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 for unknown template, got %d (body: %s)", w.Code, w.Body.String())
	}
}

// TestGetTemplate_ReturnsStripeTemplate verifies that the Stripe template
// can be retrieved by name.
func TestGetTemplate_ReturnsStripeTemplate(t *testing.T) {
	srv, _ := newTestServer()

	w := getPath(srv, "/api/v1/templates/stripe")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for stripe template, got %d (body: %s)", w.Code, w.Body.String())
	}

	body := decodeJSON(t, w)
	if body["id"] != "stripe" {
		t.Errorf("expected id=stripe, got %v", body["id"])
	}
}

// TestGetTemplate_ContentTypeIsJSON verifies Content-Type header.
func TestGetTemplate_ContentTypeIsJSON(t *testing.T) {
	srv, _ := newTestServer()
	w := getPath(srv, "/api/v1/templates/github")
	ct := w.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("expected Content-Type=application/json, got %q", ct)
	}
}

// TestGetTemplate_MethodNotAllowed verifies that POST to /api/v1/templates/{name}
// is rejected with 405.
func TestGetTemplate_MethodNotAllowed(t *testing.T) {
	srv, _ := newTestServer()

	// postJSON helper uses POST; expect 405.
	w := postJSON(srv, "/api/v1/templates/github", map[string]interface{}{})
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for POST /api/v1/templates/{name}, got %d", w.Code)
	}
}

// ---------------------------------------------------------------------------
// Validation error format
// ---------------------------------------------------------------------------

// TestCreateService_ValidationError_HasDescriptiveMessage verifies that
// validation failures return a 400 with a message describing the issue.
func TestCreateService_ValidationError_HasDescriptiveMessage(t *testing.T) {
	srv, _ := newTestServer()

	w := postJSON(srv, "/api/v1/services", map[string]interface{}{
		"name":        "github",
		"template":    "github",
		"auth_method": "github_pat_classic",
		"credentials": map[string]string{
			"token": "not-valid-pattern",
		},
	})

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}

	body := decodeJSON(t, w)
	errMsg, hasErr := body["error"]
	if !hasErr || errMsg == "" {
		t.Error("expected non-empty 'error' field in 400 response")
	}
}
