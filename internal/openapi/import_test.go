package openapi_test

import (
	"testing"

	"github.com/straylight-ai/straylight/internal/openapi"
	"github.com/straylight-ai/straylight/internal/services"
)

func TestFromSpec_BearerHTTP(t *testing.T) {
	spec := []byte(`{
		"openapi": "3.1.0",
		"info": {"title": "Test API", "version": "1.0.0"},
		"servers": [{"url": "https://api.example.com"}],
		"paths": {},
		"components": {
			"securitySchemes": {
				"bearerAuth": {"type": "http", "scheme": "bearer"}
			}
		}
	}`)

	result, err := openapi.FromSpec(spec, "test-source")
	if err != nil {
		t.Fatalf("FromSpec() error = %v", err)
	}
	if result.Source != "test-source" {
		t.Errorf("expected Source='test-source', got %q", result.Source)
	}
	if len(result.Template.AuthMethods) != 1 {
		t.Fatalf("expected 1 auth method, got %d", len(result.Template.AuthMethods))
	}
	auth := result.Template.AuthMethods[0]
	if auth.Injection.Type != services.InjectionBearerHeader {
		t.Errorf("expected bearer_header, got %q", auth.Injection.Type)
	}
	if len(auth.Fields) != 1 || auth.Fields[0].Key != "token" {
		t.Errorf("expected 1 field with key='token', got %v", auth.Fields)
	}
}

func TestFromSpec_BasicHTTP(t *testing.T) {
	spec := []byte(`{
		"openapi": "3.1.0",
		"info": {"title": "Test API", "version": "1.0.0"},
		"servers": [{"url": "https://api.example.com"}],
		"paths": {},
		"components": {
			"securitySchemes": {
				"basicAuth": {"type": "http", "scheme": "basic"}
			}
		}
	}`)

	result, err := openapi.FromSpec(spec, "test-source")
	if err != nil {
		t.Fatalf("FromSpec() error = %v", err)
	}
	if len(result.Template.AuthMethods) != 1 {
		t.Fatalf("expected 1 auth method, got %d", len(result.Template.AuthMethods))
	}
	auth := result.Template.AuthMethods[0]
	if auth.Injection.Type != services.InjectionBasicAuth {
		t.Errorf("expected basic_auth, got %q", auth.Injection.Type)
	}
	if len(auth.Fields) != 2 {
		t.Errorf("expected 2 fields (username, password), got %d", len(auth.Fields))
	}
}

func TestFromSpec_APIKeyHeader(t *testing.T) {
	spec := []byte(`{
		"openapi": "3.1.0",
		"info": {"title": "Test API", "version": "1.0.0"},
		"servers": [{"url": "https://api.example.com"}],
		"paths": {},
		"components": {
			"securitySchemes": {
				"apiKey": {"type": "apiKey", "in": "header", "name": "X-API-Key"}
			}
		}
	}`)

	result, err := openapi.FromSpec(spec, "test-source")
	if err != nil {
		t.Fatalf("FromSpec() error = %v", err)
	}
	if len(result.Template.AuthMethods) != 1 {
		t.Fatalf("expected 1 auth method, got %d", len(result.Template.AuthMethods))
	}
	auth := result.Template.AuthMethods[0]
	if auth.Injection.Type != services.InjectionCustomHeader {
		t.Errorf("expected custom_header, got %q", auth.Injection.Type)
	}
	if auth.Injection.HeaderName != "X-API-Key" {
		t.Errorf("expected HeaderName='X-API-Key', got %q", auth.Injection.HeaderName)
	}
	if len(auth.Fields) != 1 || auth.Fields[0].Key != "token" {
		t.Errorf("expected 1 field with key='token', got %v", auth.Fields)
	}
}

func TestFromSpec_APIKeyQuery(t *testing.T) {
	spec := []byte(`{
		"openapi": "3.1.0",
		"info": {"title": "Test API", "version": "1.0.0"},
		"servers": [{"url": "https://api.example.com"}],
		"paths": {},
		"components": {
			"securitySchemes": {
				"apiKey": {"type": "apiKey", "in": "query", "name": "api_key"}
			}
		}
	}`)

	result, err := openapi.FromSpec(spec, "test-source")
	if err != nil {
		t.Fatalf("FromSpec() error = %v", err)
	}
	if len(result.Template.AuthMethods) != 1 {
		t.Fatalf("expected 1 auth method, got %d", len(result.Template.AuthMethods))
	}
	auth := result.Template.AuthMethods[0]
	if auth.Injection.Type != services.InjectionQueryParam {
		t.Errorf("expected query_param, got %q", auth.Injection.Type)
	}
	if auth.Injection.QueryParam != "api_key" {
		t.Errorf("expected QueryParam='api_key', got %q", auth.Injection.QueryParam)
	}
}

func TestFromSpec_APIKeyCookie(t *testing.T) {
	spec := []byte(`{
		"openapi": "3.1.0",
		"info": {"title": "Test API", "version": "1.0.0"},
		"servers": [{"url": "https://api.example.com"}],
		"paths": {},
		"components": {
			"securitySchemes": {
				"cookieKey": {"type": "apiKey", "in": "cookie", "name": "session"}
			}
		}
	}`)

	result, err := openapi.FromSpec(spec, "test-source")
	if err != nil {
		t.Fatalf("FromSpec() error = %v", err)
	}
	if len(result.Template.AuthMethods) != 1 {
		t.Fatalf("expected 1 auth method, got %d", len(result.Template.AuthMethods))
	}
	auth := result.Template.AuthMethods[0]
	if auth.Injection.Type != services.InjectionCustomAuth {
		t.Errorf("expected custom_auth, got %q", auth.Injection.Type)
	}
	if auth.Injection.Custom == nil {
		t.Fatal("expected Custom to be non-nil")
	}
	cookieVal, ok := auth.Injection.Custom.Headers["Cookie"]
	if !ok {
		t.Fatalf("expected Cookie header in Custom.Headers, got %v", auth.Injection.Custom.Headers)
	}
	if cookieVal != "session={{.token}}" {
		t.Errorf("expected 'session={{.token}}', got %q", cookieVal)
	}
}

func TestFromSpec_OAuth2(t *testing.T) {
	spec := []byte(`{
		"openapi": "3.1.0",
		"info": {"title": "Test API", "version": "1.0.0"},
		"servers": [{"url": "https://api.example.com"}],
		"paths": {},
		"components": {
			"securitySchemes": {
				"oauth2Auth": {"type": "oauth2", "flows": {}}
			}
		}
	}`)

	result, err := openapi.FromSpec(spec, "test-source")
	if err != nil {
		t.Fatalf("FromSpec() error = %v", err)
	}
	if len(result.Template.AuthMethods) != 1 {
		t.Fatalf("expected 1 auth method, got %d", len(result.Template.AuthMethods))
	}
	auth := result.Template.AuthMethods[0]
	if auth.Injection.Type != services.InjectionOAuth {
		t.Errorf("expected oauth, got %q", auth.Injection.Type)
	}
	if len(auth.Fields) != 0 {
		t.Errorf("expected empty fields for OAuth, got %d", len(auth.Fields))
	}
}

func TestFromSpec_MutualTLS(t *testing.T) {
	spec := []byte(`{
		"openapi": "3.1.0",
		"info": {"title": "Test API", "version": "1.0.0"},
		"servers": [{"url": "https://api.example.com"}],
		"paths": {},
		"components": {
			"securitySchemes": {
				"mtls": {"type": "mutualTLS"}
			}
		}
	}`)

	result, err := openapi.FromSpec(spec, "test-source")
	if err != nil {
		t.Fatalf("FromSpec() error = %v", err)
	}
	// mutualTLS is unsupported — no auth methods, warning only.
	if len(result.Template.AuthMethods) != 0 {
		t.Errorf("expected 0 auth methods for mutualTLS, got %d", len(result.Template.AuthMethods))
	}
	if len(result.Warnings) == 0 {
		t.Error("expected at least one warning for mutualTLS")
	}
}

func TestFromSpec_ServersURL(t *testing.T) {
	spec := []byte(`{
		"openapi": "3.1.0",
		"info": {"title": "Test API", "version": "1.0.0"},
		"servers": [{"url": "https://api.example.com/v1"}, {"url": "https://api.example.com/v2"}],
		"paths": {}
	}`)

	result, err := openapi.FromSpec(spec, "test-source")
	if err != nil {
		t.Fatalf("FromSpec() error = %v", err)
	}
	if result.Template.Target != "https://api.example.com/v1" {
		t.Errorf("expected Target='https://api.example.com/v1', got %q", result.Template.Target)
	}
}

func TestFromSpec_IsDraft(t *testing.T) {
	spec := []byte(`{
		"openapi": "3.1.0",
		"info": {"title": "Test API", "version": "1.0.0"},
		"servers": [{"url": "https://api.example.com"}],
		"paths": {}
	}`)

	result, err := openapi.FromSpec(spec, "my-source")
	if err != nil {
		t.Fatalf("FromSpec() error = %v", err)
	}
	// Draft is indicated by Source being set to the source argument.
	if result.Source != "my-source" {
		t.Errorf("expected Source='my-source', got %q", result.Source)
	}
}

func TestFromSpec_InvalidJSON(t *testing.T) {
	spec := []byte(`{ invalid json }`)
	_, err := openapi.FromSpec(spec, "test-source")
	if err == nil {
		t.Error("expected error for invalid JSON, got nil")
	}
}
