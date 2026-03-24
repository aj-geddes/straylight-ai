package proxy_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/straylight-ai/straylight/internal/proxy"
	"github.com/straylight-ai/straylight/internal/services"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newTestRequest(t *testing.T, rawURL string) *http.Request {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse url %q: %v", rawURL, err)
	}
	return &http.Request{
		Header: make(http.Header),
		URL:    u,
	}
}

func testCtx(t *testing.T) context.Context {
	t.Helper()
	return context.Background()
}

func parseEcho(t *testing.T, body string) map[string]interface{} {
	t.Helper()
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatalf("parse echo body: %v", err)
	}
	return m
}

func assertHeader(t *testing.T, echo map[string]interface{}, name, want string) {
	t.Helper()
	headers, _ := echo["headers"].(map[string]interface{})
	slice, _ := headers[http.CanonicalHeaderKey(name)].([]interface{})
	if len(slice) == 0 {
		t.Errorf("header %q not present; headers: %v", name, headers)
		return
	}
	if slice[0] != want {
		t.Errorf("header %q: expected %q, got %q", name, want, slice[0])
	}
}

func containsStr(s, sub string) bool {
	return strings.Contains(s, sub)
}

// ---------------------------------------------------------------------------
// InjectorRegistry
// ---------------------------------------------------------------------------

func TestInjectorRegistry_RegisterAndGet(t *testing.T) {
	r := proxy.NewInjectorRegistry()
	r.Register("test_type", &proxy.BearerHeaderInjector{})

	inj, err := r.Get("test_type")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if inj == nil {
		t.Fatal("expected non-nil injector")
	}
}

func TestInjectorRegistry_GetUnknownReturnsError(t *testing.T) {
	r := proxy.NewInjectorRegistry()

	_, err := r.Get("nonexistent")
	if err == nil {
		t.Fatal("expected error for unknown injection type, got nil")
	}
}

func TestInjectorRegistry_GetUnknownErrorMentionsType(t *testing.T) {
	r := proxy.NewInjectorRegistry()

	_, err := r.Get("my_custom_type")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !containsStr(err.Error(), "my_custom_type") {
		t.Errorf("error should mention the unknown type; got: %v", err)
	}
}

func TestDefaultInjectorRegistry_HasAllBuiltins(t *testing.T) {
	r := proxy.DefaultInjectorRegistry()

	builtins := []string{
		"bearer_header",
		"custom_header",
		"multi_header",
		"query_param",
		"basic_auth",
	}
	for _, name := range builtins {
		inj, err := r.Get(name)
		if err != nil {
			t.Errorf("builtin %q not registered: %v", name, err)
		}
		if inj == nil {
			t.Errorf("builtin %q returned nil injector", name)
		}
	}
}

// ---------------------------------------------------------------------------
// BearerHeaderInjector
// ---------------------------------------------------------------------------

func TestBearerHeaderInjector_TokenKey(t *testing.T) {
	req := newTestRequest(t, "https://api.example.com/v1/resource")
	inj := &proxy.BearerHeaderInjector{}

	cfg := services.InjectionConfig{Type: services.InjectionBearerHeader}
	fields := map[string]string{"token": "tok_abc123"}

	if err := inj.Inject(req, fields, cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got := req.Header.Get("Authorization")
	if got != "Bearer tok_abc123" {
		t.Errorf("expected 'Bearer tok_abc123', got %q", got)
	}
}

func TestBearerHeaderInjector_FallsBackToValueKey(t *testing.T) {
	req := newTestRequest(t, "https://api.example.com/")
	inj := &proxy.BearerHeaderInjector{}

	cfg := services.InjectionConfig{Type: services.InjectionBearerHeader}
	fields := map[string]string{"value": "legacy_secret"}

	if err := inj.Inject(req, fields, cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got := req.Header.Get("Authorization")
	if got != "Bearer legacy_secret" {
		t.Errorf("expected 'Bearer legacy_secret', got %q", got)
	}
}

func TestBearerHeaderInjector_TokenKeyPreferredOverValue(t *testing.T) {
	req := newTestRequest(t, "https://api.example.com/")
	inj := &proxy.BearerHeaderInjector{}

	cfg := services.InjectionConfig{Type: services.InjectionBearerHeader}
	fields := map[string]string{
		"token": "preferred_token",
		"value": "legacy_value",
	}

	if err := inj.Inject(req, fields, cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got := req.Header.Get("Authorization")
	if got != "Bearer preferred_token" {
		t.Errorf("expected 'Bearer preferred_token', got %q", got)
	}
}

func TestBearerHeaderInjector_MissingCredentialReturnsError(t *testing.T) {
	req := newTestRequest(t, "https://api.example.com/")
	inj := &proxy.BearerHeaderInjector{}

	cfg := services.InjectionConfig{Type: services.InjectionBearerHeader}
	fields := map[string]string{"other_key": "value"}

	err := inj.Inject(req, fields, cfg)
	if err == nil {
		t.Fatal("expected error for missing token field, got nil")
	}
}

func TestBearerHeaderInjector_EmptyFieldsReturnsError(t *testing.T) {
	req := newTestRequest(t, "https://api.example.com/")
	inj := &proxy.BearerHeaderInjector{}

	cfg := services.InjectionConfig{Type: services.InjectionBearerHeader}
	fields := map[string]string{}

	err := inj.Inject(req, fields, cfg)
	if err == nil {
		t.Fatal("expected error for empty fields, got nil")
	}
}

// ---------------------------------------------------------------------------
// CustomHeaderInjector
// ---------------------------------------------------------------------------

func TestCustomHeaderInjector_SetsNamedHeader(t *testing.T) {
	req := newTestRequest(t, "https://api.example.com/")
	inj := &proxy.CustomHeaderInjector{}

	cfg := services.InjectionConfig{
		Type:       services.InjectionCustomHeader,
		HeaderName: "x-api-key",
	}
	fields := map[string]string{"token": "sk-ant-abc"}

	if err := inj.Inject(req, fields, cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got := req.Header.Get("x-api-key")
	if got != "sk-ant-abc" {
		t.Errorf("expected 'sk-ant-abc', got %q", got)
	}
}

func TestCustomHeaderInjector_RendersHeaderTemplate(t *testing.T) {
	req := newTestRequest(t, "https://api.example.com/")
	inj := &proxy.CustomHeaderInjector{}

	cfg := services.InjectionConfig{
		Type:           services.InjectionCustomHeader,
		HeaderName:     "Authorization",
		HeaderTemplate: "token {{.Secret}}",
	}
	fields := map[string]string{"token": "ghp_xyz"}

	if err := inj.Inject(req, fields, cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got := req.Header.Get("Authorization")
	if got != "token ghp_xyz" {
		t.Errorf("expected 'token ghp_xyz', got %q", got)
	}
}

func TestCustomHeaderInjector_DefaultsToAuthorizationWhenNoHeaderName(t *testing.T) {
	req := newTestRequest(t, "https://api.example.com/")
	inj := &proxy.CustomHeaderInjector{}

	cfg := services.InjectionConfig{
		Type:           services.InjectionCustomHeader,
		HeaderName:     "",
		HeaderTemplate: "Bearer {{.Secret}}",
	}
	fields := map[string]string{"token": "mytoken"}

	if err := inj.Inject(req, fields, cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got := req.Header.Get("Authorization")
	if got != "Bearer mytoken" {
		t.Errorf("expected 'Bearer mytoken', got %q", got)
	}
}

func TestCustomHeaderInjector_FallsBackToValueKey(t *testing.T) {
	req := newTestRequest(t, "https://api.example.com/")
	inj := &proxy.CustomHeaderInjector{}

	cfg := services.InjectionConfig{
		Type:       services.InjectionCustomHeader,
		HeaderName: "PRIVATE-TOKEN",
	}
	fields := map[string]string{"value": "glpat_legacy"}

	if err := inj.Inject(req, fields, cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got := req.Header.Get("PRIVATE-TOKEN")
	if got != "glpat_legacy" {
		t.Errorf("expected 'glpat_legacy', got %q", got)
	}
}

func TestCustomHeaderInjector_MissingCredentialReturnsError(t *testing.T) {
	req := newTestRequest(t, "https://api.example.com/")
	inj := &proxy.CustomHeaderInjector{}

	cfg := services.InjectionConfig{
		Type:       services.InjectionCustomHeader,
		HeaderName: "x-api-key",
	}
	fields := map[string]string{"unrelated": "val"}

	err := inj.Inject(req, fields, cfg)
	if err == nil {
		t.Fatal("expected error for missing credential, got nil")
	}
}

func TestCustomHeaderInjector_InvalidTemplateReturnsError(t *testing.T) {
	req := newTestRequest(t, "https://api.example.com/")
	inj := &proxy.CustomHeaderInjector{}

	cfg := services.InjectionConfig{
		Type:           services.InjectionCustomHeader,
		HeaderName:     "x-api-key",
		HeaderTemplate: "{{.Invalid broken template",
	}
	fields := map[string]string{"token": "myval"}

	err := inj.Inject(req, fields, cfg)
	if err == nil {
		t.Fatal("expected error for invalid template, got nil")
	}
}

// ---------------------------------------------------------------------------
// MultiHeaderInjector
// ---------------------------------------------------------------------------

func TestMultiHeaderInjector_SetsMultipleHeaders(t *testing.T) {
	req := newTestRequest(t, "https://api.example.com/")
	inj := &proxy.MultiHeaderInjector{}

	cfg := services.InjectionConfig{
		Type: services.InjectionMultiHeader,
		Headers: map[string]string{
			"access_key_id": "X-Access-Key",
			"secret":        "X-Secret",
		},
	}
	fields := map[string]string{
		"access_key_id": "AKID123",
		"secret":        "mysecret456",
	}

	if err := inj.Inject(req, fields, cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := req.Header.Get("X-Access-Key"); got != "AKID123" {
		t.Errorf("X-Access-Key: expected 'AKID123', got %q", got)
	}
	if got := req.Header.Get("X-Secret"); got != "mysecret456" {
		t.Errorf("X-Secret: expected 'mysecret456', got %q", got)
	}
}

func TestMultiHeaderInjector_SingleHeaderMapping(t *testing.T) {
	req := newTestRequest(t, "https://api.example.com/")
	inj := &proxy.MultiHeaderInjector{}

	cfg := services.InjectionConfig{
		Type:    services.InjectionMultiHeader,
		Headers: map[string]string{"token": "Authorization"},
	}
	fields := map[string]string{"token": "mytoken"}

	if err := inj.Inject(req, fields, cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := req.Header.Get("Authorization"); got != "mytoken" {
		t.Errorf("Authorization: expected 'mytoken', got %q", got)
	}
}

func TestMultiHeaderInjector_MissingFieldReturnsError(t *testing.T) {
	req := newTestRequest(t, "https://api.example.com/")
	inj := &proxy.MultiHeaderInjector{}

	cfg := services.InjectionConfig{
		Type: services.InjectionMultiHeader,
		Headers: map[string]string{
			"access_key_id": "X-Access-Key",
			"secret":        "X-Secret",
		},
	}
	// Only one of the two required fields present.
	fields := map[string]string{
		"access_key_id": "AKID123",
		// "secret" is absent
	}

	err := inj.Inject(req, fields, cfg)
	if err == nil {
		t.Fatal("expected error for missing field, got nil")
	}
}

func TestMultiHeaderInjector_EmptyHeadersMappingIsNoop(t *testing.T) {
	req := newTestRequest(t, "https://api.example.com/")
	inj := &proxy.MultiHeaderInjector{}

	cfg := services.InjectionConfig{
		Type:    services.InjectionMultiHeader,
		Headers: map[string]string{},
	}
	fields := map[string]string{"token": "val"}

	if err := inj.Inject(req, fields, cfg); err != nil {
		t.Fatalf("unexpected error for empty headers map: %v", err)
	}
}

// ---------------------------------------------------------------------------
// QueryParamInjector
// ---------------------------------------------------------------------------

func TestQueryParamInjector_AddsParam(t *testing.T) {
	req := newTestRequest(t, "https://api.example.com/v1/data")
	inj := &proxy.QueryParamInjector{}

	cfg := services.InjectionConfig{
		Type:       services.InjectionQueryParam,
		QueryParam: "api_key",
	}
	fields := map[string]string{"token": "my-api-key"}

	if err := inj.Inject(req, fields, cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got := req.URL.Query().Get("api_key")
	if got != "my-api-key" {
		t.Errorf("expected api_key=my-api-key, got %q", got)
	}
}

func TestQueryParamInjector_FallsBackToValueKey(t *testing.T) {
	req := newTestRequest(t, "https://api.example.com/")
	inj := &proxy.QueryParamInjector{}

	cfg := services.InjectionConfig{
		Type:       services.InjectionQueryParam,
		QueryParam: "key",
	}
	fields := map[string]string{"value": "legacy_key"}

	if err := inj.Inject(req, fields, cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got := req.URL.Query().Get("key")
	if got != "legacy_key" {
		t.Errorf("expected key=legacy_key, got %q", got)
	}
}

func TestQueryParamInjector_PreservesExistingQueryParams(t *testing.T) {
	req := newTestRequest(t, "https://api.example.com/search?q=golang")
	inj := &proxy.QueryParamInjector{}

	cfg := services.InjectionConfig{
		Type:       services.InjectionQueryParam,
		QueryParam: "api_key",
	}
	fields := map[string]string{"token": "abc"}

	if err := inj.Inject(req, fields, cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	q := req.URL.Query()
	if got := q.Get("api_key"); got != "abc" {
		t.Errorf("expected api_key=abc, got %q", got)
	}
	if got := q.Get("q"); got != "golang" {
		t.Errorf("expected q=golang still present, got %q", got)
	}
}

func TestQueryParamInjector_MissingCredentialReturnsError(t *testing.T) {
	req := newTestRequest(t, "https://api.example.com/")
	inj := &proxy.QueryParamInjector{}

	cfg := services.InjectionConfig{
		Type:       services.InjectionQueryParam,
		QueryParam: "api_key",
	}
	fields := map[string]string{"unrelated": "val"}

	err := inj.Inject(req, fields, cfg)
	if err == nil {
		t.Fatal("expected error for missing credential, got nil")
	}
}

// ---------------------------------------------------------------------------
// BasicAuthInjector
// ---------------------------------------------------------------------------

func TestBasicAuthInjector_EncodesCorrectly(t *testing.T) {
	req := newTestRequest(t, "https://api.example.com/")
	inj := &proxy.BasicAuthInjector{}

	cfg := services.InjectionConfig{Type: services.InjectionBasicAuth}
	fields := map[string]string{
		"username": "alice",
		"password": "s3cr3t",
	}

	if err := inj.Inject(req, fields, cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got := req.Header.Get("Authorization")
	expected := "Basic " + base64.StdEncoding.EncodeToString([]byte("alice:s3cr3t"))
	if got != expected {
		t.Errorf("expected %q, got %q", expected, got)
	}
}

func TestBasicAuthInjector_MissingUsernameReturnsError(t *testing.T) {
	req := newTestRequest(t, "https://api.example.com/")
	inj := &proxy.BasicAuthInjector{}

	cfg := services.InjectionConfig{Type: services.InjectionBasicAuth}
	fields := map[string]string{
		"password": "s3cr3t",
		// username absent
	}

	err := inj.Inject(req, fields, cfg)
	if err == nil {
		t.Fatal("expected error for missing username, got nil")
	}
}

func TestBasicAuthInjector_MissingPasswordReturnsError(t *testing.T) {
	req := newTestRequest(t, "https://api.example.com/")
	inj := &proxy.BasicAuthInjector{}

	cfg := services.InjectionConfig{Type: services.InjectionBasicAuth}
	fields := map[string]string{
		"username": "alice",
		// password absent
	}

	err := inj.Inject(req, fields, cfg)
	if err == nil {
		t.Fatal("expected error for missing password, got nil")
	}
}

func TestBasicAuthInjector_BothMissingReturnsError(t *testing.T) {
	req := newTestRequest(t, "https://api.example.com/")
	inj := &proxy.BasicAuthInjector{}

	cfg := services.InjectionConfig{Type: services.InjectionBasicAuth}
	fields := map[string]string{}

	err := inj.Inject(req, fields, cfg)
	if err == nil {
		t.Fatal("expected error for missing username and password, got nil")
	}
}

func TestBasicAuthInjector_SpecialCharsInCredentials(t *testing.T) {
	req := newTestRequest(t, "https://api.example.com/")
	inj := &proxy.BasicAuthInjector{}

	cfg := services.InjectionConfig{Type: services.InjectionBasicAuth}
	// Password contains colons — these must be preserved in base64.
	fields := map[string]string{
		"username": "user@example.com",
		"password": "p@ss:w0rd!",
	}

	if err := inj.Inject(req, fields, cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got := req.Header.Get("Authorization")
	expected := "Basic " + base64.StdEncoding.EncodeToString([]byte("user@example.com:p@ss:w0rd!"))
	if got != expected {
		t.Errorf("expected %q, got %q", expected, got)
	}
}

// ---------------------------------------------------------------------------
// Proxy integration: legacy path must still work (backward compat)
// ---------------------------------------------------------------------------

func TestProxy_LegacyHeaderInjection_StillWorks(t *testing.T) {
	upstream := upstreamEchoServer(t)

	r := newFakeResolver()
	r.addService(services.Service{
		Name:           "legacy-svc",
		Type:           "http_proxy",
		Target:         upstream.URL,
		Inject:         "header",
		HeaderName:     "Authorization",
		HeaderTemplate: "Bearer {{.secret}}",
	}, "legacy-token")

	p := proxy.NewProxy(r, nil)
	resp, err := p.HandleAPICall(testCtx(t), proxy.APICallRequest{
		Service: "legacy-svc",
		Method:  "GET",
		Path:    "/",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	echo := parseEcho(t, resp.Body)
	assertHeader(t, echo, "Authorization", "Bearer legacy-token")
}

func TestProxy_LegacyQueryInjection_StillWorks(t *testing.T) {
	upstream := upstreamEchoServer(t)

	r := newFakeResolver()
	r.addService(services.Service{
		Name:       "legacy-query",
		Type:       "http_proxy",
		Target:     upstream.URL,
		Inject:     "query",
		QueryParam: "api_key",
	}, "qparam-val")

	p := proxy.NewProxy(r, nil)
	resp, err := p.HandleAPICall(testCtx(t), proxy.APICallRequest{
		Service: "legacy-query",
		Method:  "GET",
		Path:    "/",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	echo := parseEcho(t, resp.Body)
	rawQuery, _ := echo["query"].(string)
	if !containsStr(rawQuery, "api_key=qparam-val") {
		t.Errorf("expected api_key=qparam-val in query %q", rawQuery)
	}
}

// ---------------------------------------------------------------------------
// Proxy integration: new auth-method path
// ---------------------------------------------------------------------------

// fakeMultiResolver implements ServiceResolver with ReadCredentials support.
type fakeMultiResolver struct {
	svcs        map[string]services.Service
	creds       map[string]string
	multiCreds  map[string]map[string]string
	authMethods map[string]string
}

func newFakeMultiResolver() *fakeMultiResolver {
	return &fakeMultiResolver{
		svcs:        make(map[string]services.Service),
		creds:       make(map[string]string),
		multiCreds:  make(map[string]map[string]string),
		authMethods: make(map[string]string),
	}
}

func (f *fakeMultiResolver) addServiceWithCreds(svc services.Service, authMethod string, fields map[string]string) {
	f.svcs[svc.Name] = svc
	f.authMethods[svc.Name] = authMethod
	f.multiCreds[svc.Name] = fields
	if v, ok := fields["token"]; ok {
		f.creds[svc.Name] = v
	} else if v, ok := fields["value"]; ok {
		f.creds[svc.Name] = v
	}
}

func (f *fakeMultiResolver) Get(name string) (services.Service, error) {
	svc, ok := f.svcs[name]
	if !ok {
		return services.Service{}, fmt.Errorf("services: %q not found", name)
	}
	return svc, nil
}

func (f *fakeMultiResolver) GetCredential(name string) (string, error) {
	cred, ok := f.creds[name]
	if !ok {
		return "", fmt.Errorf("services: %q not found", name)
	}
	return cred, nil
}

func (f *fakeMultiResolver) ReadCredentials(name string) (string, map[string]string, error) {
	am, ok := f.authMethods[name]
	if !ok {
		return "", nil, fmt.Errorf("services: %q not found", name)
	}
	fields, ok := f.multiCreds[name]
	if !ok {
		return "", nil, fmt.Errorf("services: no credentials for %q", name)
	}
	return am, fields, nil
}

func TestProxy_NewAuthMethod_BearerHeader(t *testing.T) {
	upstream := upstreamEchoServer(t)

	r := newFakeMultiResolver()
	r.addServiceWithCreds(
		services.Service{
			Name:         "new-bearer",
			Type:         "http_proxy",
			Target:       upstream.URL,
			Inject:       "header",
			AuthMethodID: "github_pat_classic",
		},
		"github_pat_classic",
		map[string]string{"token": "ghp_abcdef"},
	)

	p := proxy.NewProxy(r, nil)
	resp, err := p.HandleAPICall(testCtx(t), proxy.APICallRequest{
		Service: "new-bearer",
		Method:  "GET",
		Path:    "/",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	echo := parseEcho(t, resp.Body)
	assertHeader(t, echo, "Authorization", "Bearer ghp_abcdef")
}

func TestProxy_NewAuthMethod_BasicAuth(t *testing.T) {
	upstream := upstreamEchoServer(t)

	r := newFakeMultiResolver()
	r.addServiceWithCreds(
		services.Service{
			Name:         "new-basic",
			Type:         "http_proxy",
			Target:       upstream.URL,
			Inject:       "header",
			AuthMethodID: "basic_auth",
		},
		"basic_auth",
		map[string]string{"username": "alice", "password": "s3cr3t"},
	)

	p := proxy.NewProxy(r, nil)
	resp, err := p.HandleAPICall(testCtx(t), proxy.APICallRequest{
		Service: "new-basic",
		Method:  "GET",
		Path:    "/",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	echo := parseEcho(t, resp.Body)
	expected := "Basic " + base64.StdEncoding.EncodeToString([]byte("alice:s3cr3t"))
	assertHeader(t, echo, "Authorization", expected)
}

func TestProxy_NewAuthMethod_QueryParam(t *testing.T) {
	upstream := upstreamEchoServer(t)

	r := newFakeMultiResolver()
	r.addServiceWithCreds(
		services.Service{
			Name:         "new-query",
			Type:         "http_proxy",
			Target:       upstream.URL,
			Inject:       "query",
			QueryParam:   "key",
			AuthMethodID: "google_api_key",
		},
		"google_api_key",
		map[string]string{"token": "AIzaSyXXXX"},
	)

	p := proxy.NewProxy(r, nil)
	resp, err := p.HandleAPICall(testCtx(t), proxy.APICallRequest{
		Service: "new-query",
		Method:  "GET",
		Path:    "/",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	echo := parseEcho(t, resp.Body)
	rawQuery, _ := echo["query"].(string)
	if !containsStr(rawQuery, "AIzaSyXXXX") {
		t.Errorf("expected token in query %q", rawQuery)
	}
}

func TestProxy_NewAuthMethod_CustomHeader_Anthropic(t *testing.T) {
	// anthropic_api_key uses custom_header with HeaderName "x-api-key".
	upstream := upstreamEchoServer(t)

	r := newFakeMultiResolver()
	r.addServiceWithCreds(
		services.Service{
			Name:         "custom-hdr",
			Type:         "http_proxy",
			Target:       upstream.URL,
			Inject:       "header",
			AuthMethodID: "anthropic_api_key",
		},
		"anthropic_api_key",
		map[string]string{"token": "sk-ant-abc123"},
	)

	p := proxy.NewProxy(r, nil)
	resp, err := p.HandleAPICall(testCtx(t), proxy.APICallRequest{
		Service: "custom-hdr",
		Method:  "GET",
		Path:    "/",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	echo := parseEcho(t, resp.Body)
	assertHeader(t, echo, "X-Api-Key", "sk-ant-abc123")
}

func TestProxy_NewAuthMethod_CustomHeader_GitLab(t *testing.T) {
	// gitlab_pat uses custom_header with HeaderName "PRIVATE-TOKEN".
	upstream := upstreamEchoServer(t)

	r := newFakeMultiResolver()
	r.addServiceWithCreds(
		services.Service{
			Name:         "gitlab-svc",
			Type:         "http_proxy",
			Target:       upstream.URL,
			Inject:       "header",
			AuthMethodID: "gitlab_pat",
		},
		"gitlab_pat",
		map[string]string{"token": "glpat-abc"},
	)

	p := proxy.NewProxy(r, nil)
	resp, err := p.HandleAPICall(testCtx(t), proxy.APICallRequest{
		Service: "gitlab-svc",
		Method:  "GET",
		Path:    "/",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	echo := parseEcho(t, resp.Body)
	assertHeader(t, echo, "Private-Token", "glpat-abc")
}

func TestProxy_UnknownInjectionType_ReturnsError(t *testing.T) {
	upstream := upstreamEchoServer(t)

	r := newFakeMultiResolver()
	r.addServiceWithCreds(
		services.Service{
			Name:         "bad-method",
			Type:         "http_proxy",
			Target:       upstream.URL,
			Inject:       "header",
			AuthMethodID: "unknown_type_method",
		},
		"unknown_type_method",
		map[string]string{"token": "val"},
	)

	p := proxy.NewProxy(r, nil)
	_, err := p.HandleAPICall(testCtx(t), proxy.APICallRequest{
		Service: "bad-method",
		Method:  "GET",
		Path:    "/",
	})
	if err == nil {
		t.Fatal("expected error for unknown injection type, got nil")
	}
}

// TestProxy_NewAuthMethod_LegacyVaultFormat tests a service with AuthMethodID
// whose vault credential is stored in the legacy "value" format (auth_method="legacy").
// resolveInjectionConfig should fall back to the service's flat inject fields.
func TestProxy_NewAuthMethod_LegacyVaultFormat_HeaderFallback(t *testing.T) {
	upstream := upstreamEchoServer(t)

	// fakeMultiResolver that returns "legacy" as the auth method to simulate
	// a vault entry in the pre-multi-field format.
	r := newFakeMultiResolver()
	svc := services.Service{
		Name:           "legacy-vault-svc",
		Type:           "http_proxy",
		Target:         upstream.URL,
		Inject:         "header",
		HeaderName:     "Authorization",
		HeaderTemplate: "Bearer {{.Secret}}",
		AuthMethodID:   "some_method_id", // non-empty triggers new path
	}
	r.svcs[svc.Name] = svc
	// Manually set auth method to "legacy" to simulate old vault format.
	r.authMethods[svc.Name] = "legacy"
	r.multiCreds[svc.Name] = map[string]string{"value": "legacy-tok"}
	r.creds[svc.Name] = "legacy-tok"

	p := proxy.NewProxy(r, nil)
	resp, err := p.HandleAPICall(testCtx(t), proxy.APICallRequest{
		Service: "legacy-vault-svc",
		Method:  "GET",
		Path:    "/",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	echo := parseEcho(t, resp.Body)
	// The legacy injection config uses custom_header with the service's HeaderName/Template.
	assertHeader(t, echo, "Authorization", "Bearer legacy-tok")
}

func TestProxy_NewAuthMethod_LegacyVaultFormat_QueryFallback(t *testing.T) {
	upstream := upstreamEchoServer(t)

	r := newFakeMultiResolver()
	svc := services.Service{
		Name:         "legacy-query-svc",
		Type:         "http_proxy",
		Target:       upstream.URL,
		Inject:       "query",
		QueryParam:   "apikey",
		AuthMethodID: "some_method_id",
	}
	r.svcs[svc.Name] = svc
	r.authMethods[svc.Name] = "legacy"
	r.multiCreds[svc.Name] = map[string]string{"value": "qval"}
	r.creds[svc.Name] = "qval"

	p := proxy.NewProxy(r, nil)
	resp, err := p.HandleAPICall(testCtx(t), proxy.APICallRequest{
		Service: "legacy-query-svc",
		Method:  "GET",
		Path:    "/",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	echo := parseEcho(t, resp.Body)
	rawQuery, _ := echo["query"].(string)
	if !containsStr(rawQuery, "apikey=qval") {
		t.Errorf("expected apikey=qval in query %q", rawQuery)
	}
}

func TestProxy_NewAuthMethod_LegacyVaultFormat_DefaultBearerFallback(t *testing.T) {
	upstream := upstreamEchoServer(t)

	r := newFakeMultiResolver()
	svc := services.Service{
		Name:         "legacy-default-svc",
		Type:         "http_proxy",
		Target:       upstream.URL,
		Inject:       "unknown_mode", // triggers default bearer fallback
		AuthMethodID: "some_method_id",
	}
	r.svcs[svc.Name] = svc
	r.authMethods[svc.Name] = "legacy"
	r.multiCreds[svc.Name] = map[string]string{"value": "bear-tok"}
	r.creds[svc.Name] = "bear-tok"

	p := proxy.NewProxy(r, nil)
	resp, err := p.HandleAPICall(testCtx(t), proxy.APICallRequest{
		Service: "legacy-default-svc",
		Method:  "GET",
		Path:    "/",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	echo := parseEcho(t, resp.Body)
	// Default fallback injects as bearer_header using "value" field.
	assertHeader(t, echo, "Authorization", "Bearer bear-tok")
}

// TestProxy_CredentialsCache_MultiField verifies multi-field credentials are
// cached and not fetched again on the second request.
func TestProxy_CredentialsCache_MultiField(t *testing.T) {
	upstream := upstreamEchoServer(t)

	callCount := 0
	r := &countingMultiResolver{
		delegate:  newFakeMultiResolver(),
		callCount: &callCount,
	}
	r.delegate.addServiceWithCreds(
		services.Service{
			Name:         "cache-test",
			Type:         "http_proxy",
			Target:       upstream.URL,
			Inject:       "header",
			AuthMethodID: "github_pat_classic",
		},
		"github_pat_classic",
		map[string]string{"token": "tok"},
	)

	p := proxy.NewProxy(r, nil)
	ctx := testCtx(t)

	for i := 0; i < 3; i++ {
		if _, err := p.HandleAPICall(ctx, proxy.APICallRequest{
			Service: "cache-test",
			Method:  "GET",
			Path:    "/",
		}); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}

	if callCount != 1 {
		t.Errorf("expected ReadCredentials called 1 time, got %d", callCount)
	}
}

// countingMultiResolver wraps fakeMultiResolver and counts ReadCredentials calls.
type countingMultiResolver struct {
	delegate  *fakeMultiResolver
	callCount *int
}

func (c *countingMultiResolver) Get(name string) (services.Service, error) {
	return c.delegate.Get(name)
}

func (c *countingMultiResolver) GetCredential(name string) (string, error) {
	return c.delegate.GetCredential(name)
}

func (c *countingMultiResolver) ReadCredentials(name string) (string, map[string]string, error) {
	*c.callCount++
	return c.delegate.ReadCredentials(name)
}
