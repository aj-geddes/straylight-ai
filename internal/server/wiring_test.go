package server_test

// Tests for issue #11 wiring: community template registry + EgressGuard passthrough.
//
// RED phase: these tests fail until server.Config.Templates is wired into
// handleListTemplates/findTemplate and serve() passes the configured EgressGuard.

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/straylight-ai/straylight/internal/egress"
	"github.com/straylight-ai/straylight/internal/server"
	"github.com/straylight-ai/straylight/internal/services"
)

// minimalTemplate returns a minimal valid ServiceTemplate for injection tests.
// Uses bearer_header injection so it passes FilterTemplatesForPersonalTier.
func minimalTemplate(id, displayName string) services.ServiceTemplate {
	return services.ServiceTemplate{
		ID:          id,
		DisplayName: displayName,
		Target:      "https://example.com",
		AuthMethods: []services.AuthMethod{
			{
				ID:   "bearer",
				Name: "Bearer Token",
				Fields: []services.CredentialField{
					{Key: "token", Label: "Token", Type: services.FieldPassword, Required: true},
				},
				Injection: services.InjectionConfig{
					Type: services.InjectionBearerHeader,
				},
			},
		},
	}
}

// newTestServerWithTemplates creates a server with a real Registry and an
// explicit Templates slice injected via Config. EgressGuard is left nil.
func newTestServerWithTemplates(templates []services.ServiceTemplate) *server.Server {
	vault := newMockVaultForRoutes()
	registry := services.NewRegistry(vault)
	return server.New(server.Config{
		ListenAddress: "127.0.0.1:0",
		Version:       "test",
		Registry:      registry,
		Templates:     templates,
	})
}

// newTestServerWithEgressGuard creates a server with an explicit EgressGuard.
func newTestServerWithEgressGuard(templates []services.ServiceTemplate, guard egress.Guard) *server.Server {
	vault := newMockVaultForRoutes()
	registry := services.NewRegistry(vault)
	return server.New(server.Config{
		ListenAddress: "127.0.0.1:0",
		Version:       "test",
		Registry:      registry,
		Templates:     templates,
		EgressGuard:   guard,
	})
}

// ---------------------------------------------------------------------------
// trackingGuard implements egress.Guard and records whether CheckHost was called.
// ---------------------------------------------------------------------------

type trackingGuard struct {
	checked bool
	inner   egress.Guard
}

func (tg *trackingGuard) CheckIP(ip net.IP, policy egress.Policy) egress.Decision {
	return tg.inner.CheckIP(ip, policy)
}

func (tg *trackingGuard) CheckHost(ctx context.Context, host string, policy egress.Policy) egress.Decision {
	tg.checked = true
	return tg.inner.CheckHost(ctx, host, policy)
}

// Compile-time assertion: trackingGuard satisfies egress.Guard.
var _ egress.Guard = (*trackingGuard)(nil)

// ---------------------------------------------------------------------------
// Community template wiring tests (fail until handleListTemplates uses cfg.Templates)
// ---------------------------------------------------------------------------

// TestCommunityTemplate_AppearsInTemplatesList verifies that a template injected
// via Config.Templates appears in GET /api/v1/templates.
func TestCommunityTemplate_AppearsInTemplatesList(t *testing.T) {
	srv := newTestServerWithTemplates([]services.ServiceTemplate{
		minimalTemplate("community-svc", "Community Svc"),
	})

	w := getPath(srv, "/api/v1/templates")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var result map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to decode JSON: %v", err)
	}

	templatesList, ok := result["templates"].([]interface{})
	if !ok {
		t.Fatalf("expected 'templates' array, got %T", result["templates"])
	}

	found := false
	for _, raw := range templatesList {
		tmpl, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		if id, _ := tmpl["id"].(string); id == "community-svc" {
			found = true
			if dn, _ := tmpl["display_name"].(string); dn != "Community Svc" {
				t.Errorf("expected display_name='Community Svc', got %q", dn)
			}
		}
	}
	if !found {
		t.Errorf("community-svc not found in templates response; got %d templates", len(templatesList))
	}
}

// TestInjectedTemplates_ExcludeBuiltins verifies that when Config.Templates is
// non-nil the handler serves exactly those templates, not the global ServiceTemplates.
func TestInjectedTemplates_ExcludeBuiltins(t *testing.T) {
	srv := newTestServerWithTemplates([]services.ServiceTemplate{
		minimalTemplate("custom-a", "Custom A"),
		minimalTemplate("custom-b", "Custom B"),
	})

	w := getPath(srv, "/api/v1/templates")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var result map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to decode JSON: %v", err)
	}

	templatesList, ok := result["templates"].([]interface{})
	if !ok {
		t.Fatalf("expected 'templates' array, got %T", result["templates"])
	}

	// Builtin templates must NOT appear.
	builtinIDs := map[string]bool{"github": true, "stripe": true, "openai": true}
	for _, raw := range templatesList {
		tmpl, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		if id, _ := tmpl["id"].(string); builtinIDs[id] {
			t.Errorf("builtin template %q must not appear when Config.Templates is set", id)
		}
	}

	// Both injected templates must appear.
	ids := map[string]bool{}
	for _, raw := range templatesList {
		tmpl, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		if id, _ := tmpl["id"].(string); id != "" {
			ids[id] = true
		}
	}
	for _, want := range []string{"custom-a", "custom-b"} {
		if !ids[want] {
			t.Errorf("injected template %q not found in response", want)
		}
	}
}

// TestGetTemplateByID_UsesInjectedCatalog verifies GET /api/v1/templates/{id}
// finds a template from Config.Templates.
func TestGetTemplateByID_UsesInjectedCatalog(t *testing.T) {
	srv := newTestServerWithTemplates([]services.ServiceTemplate{
		minimalTemplate("my-api", "My API"),
	})

	w := getPath(srv, "/api/v1/templates/my-api")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var result map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to decode JSON: %v", err)
	}
	if id, _ := result["id"].(string); id != "my-api" {
		t.Errorf("expected id='my-api', got %q", id)
	}
}

// TestGetTemplateByID_NotFoundWhenNotInjected verifies that a template in
// services.ServiceTemplates but not in Config.Templates returns 404 when
// Config.Templates is set (Config.Templates is fully authoritative).
func TestGetTemplateByID_NotFoundWhenNotInjected(t *testing.T) {
	srv := newTestServerWithTemplates([]services.ServiceTemplate{
		minimalTemplate("community-only", "Community Only"),
	})

	w := getPath(srv, "/api/v1/templates/github")
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 for 'github' not in injected catalog, got %d", w.Code)
	}
}

// ---------------------------------------------------------------------------
// EgressGuard wiring tests
// ---------------------------------------------------------------------------

// TestImportEndpoint_UsesConfiguredEgressGuard verifies that the import handler
// uses Config.EgressGuard when set (via AllowAll, the loopback httptest server
// is allowed and we get 200, proving the configured guard was used).
func TestImportEndpoint_UsesConfiguredEgressGuard(t *testing.T) {
	specContent := `{"openapi":"3.1.0","info":{"title":"Test","version":"1.0.0"},"servers":[{"url":"https://api.example.com"}],"paths":{},"components":{"securitySchemes":{"bearerAuth":{"type":"http","scheme":"bearer"}}}}`
	specServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(specContent))
	}))
	defer specServer.Close()

	tg := &trackingGuard{inner: egress.AllowAll()}
	srv := newTestServerWithEgressGuard(nil, tg)

	body, _ := json.Marshal(map[string]string{"url": specServer.URL})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/templates/import", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 with allow-all guard, got %d: %s", w.Code, w.Body.String())
	}
	if !tg.checked {
		t.Error("expected trackingGuard.CheckHost to be called, but it was not")
	}
}

// TestImportEndpoint_NilEgressGuardFallsBackToDefault verifies that when
// Config.EgressGuard is nil the import handler falls back to egress.New(),
// which blocks loopback addresses → 400 Bad Request.
func TestImportEndpoint_NilEgressGuardFallsBackToDefault(t *testing.T) {
	specServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"openapi":"3.1.0","info":{"title":"Local","version":"1.0.0"},"servers":[{"url":"http://localhost:8080"}],"paths":{}}`))
	}))
	defer specServer.Close()

	srv := server.New(server.Config{})

	body, _ := json.Marshal(map[string]string{"url": specServer.URL})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/templates/import", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 (loopback blocked by default guard), got %d: %s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// Finding 3: EgressSSRFGuard adapter must satisfy mcpauth.SSRFGuard.
// RED: fails until NewEgressSSRFGuard is added to internal/server.
// ---------------------------------------------------------------------------

// TestNewEgressSSRFGuard_AllowsPublicHost verifies the adapter allows a resolvable
// public host (as decided by egress.Guard.CheckHost with default-deny policy).
func TestNewEgressSSRFGuard_AllowsPublicHost(t *testing.T) {
	g := egress.AllowAll()
	ssrfGuard := server.NewEgressSSRFGuard(g)
	if !ssrfGuard.IsHostAllowed(context.Background(), "example.com") {
		t.Error("AllowAll egress guard: expected IsHostAllowed(example.com) == true")
	}
}

// TestNewEgressSSRFGuard_BlocksPrivateHost verifies the adapter blocks a private-IP host
// as denied by the default denylist via egress.Guard.CheckHost.
func TestNewEgressSSRFGuard_BlocksPrivateHost(t *testing.T) {
	g := egress.New()
	ssrfGuard := server.NewEgressSSRFGuard(g)
	// 169.254.169.254 is in the SSRF denylist — must be blocked.
	if ssrfGuard.IsHostAllowed(context.Background(), "169.254.169.254") {
		t.Error("default egress guard: expected IsHostAllowed(169.254.169.254) == false")
	}
}
