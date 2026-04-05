package server_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/straylight-ai/straylight/internal/oauth"
	"github.com/straylight-ai/straylight/internal/server"
	"github.com/straylight-ai/straylight/internal/services"
)

// ---------------------------------------------------------------------------
// Fake vault for route-level OAuth config tests
// ---------------------------------------------------------------------------

type routesFakeVault struct {
	mu      sync.RWMutex
	secrets map[string]map[string]interface{}
}

func newRoutesFakeVault() *routesFakeVault {
	return &routesFakeVault{secrets: make(map[string]map[string]interface{})}
}

func (f *routesFakeVault) WriteSecret(path string, data map[string]interface{}) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := make(map[string]interface{}, len(data))
	for k, v := range data {
		cp[k] = v
	}
	f.secrets[path] = cp
	return nil
}

func (f *routesFakeVault) ReadSecret(path string) (map[string]interface{}, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	data, ok := f.secrets[path]
	if !ok {
		return nil, fmt.Errorf("not found: %s", path)
	}
	cp := make(map[string]interface{}, len(data))
	for k, v := range data {
		cp[k] = v
	}
	return cp, nil
}

func (f *routesFakeVault) DeleteSecret(path string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.secrets, path)
	return nil
}

type routesFakeServiceUpdater struct{}

func (f *routesFakeServiceUpdater) Update(_ string, _ services.Service, _ *string) error {
	return nil
}

func (f *routesFakeServiceUpdater) Create(_ services.Service, _ string) error {
	return nil
}

func (f *routesFakeServiceUpdater) Get(name string) (services.Service, error) {
	return services.Service{}, fmt.Errorf("service %q not found", name)
}

func newTestServerWithOAuth(t *testing.T) (*server.Server, *routesFakeVault) {
	t.Helper()
	v := newRoutesFakeVault()
	h := oauth.NewHandler(v, &routesFakeServiceUpdater{}, "http://localhost:9470")
	srv := server.New(server.Config{
		ListenAddress: "127.0.0.1:0",
		Version:       "1.0.3",
		OAuthHandler:  h,
	})
	return srv, v
}

// ---------------------------------------------------------------------------
// GET /api/v1/oauth/{provider}/config
// ---------------------------------------------------------------------------

func TestOAuthConfigRoutes_GetConfig_Returns200WhenConfigured(t *testing.T) {
	srv, v := newTestServerWithOAuth(t)
	_ = v.WriteSecret("services/github/oauth_client_secret", map[string]interface{}{
		"client_id":     "my-cid",
		"client_secret": "my-cs",
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/oauth/github/config", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (body: %s)", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["configured"] != true {
		t.Errorf("expected configured=true, got %v", resp["configured"])
	}
	if resp["client_id"] != "my-cid" {
		t.Errorf("expected client_id=my-cid, got %v", resp["client_id"])
	}
	if _, hasSecret := resp["client_secret"]; hasSecret {
		t.Error("client_secret must not appear in response")
	}
}

func TestOAuthConfigRoutes_GetConfig_Returns200WhenNotConfigured(t *testing.T) {
	srv, _ := newTestServerWithOAuth(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/oauth/github/config", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["configured"] != false {
		t.Errorf("expected configured=false, got %v", resp["configured"])
	}
}

func TestOAuthConfigRoutes_GetConfig_UnknownProviderReturns400(t *testing.T) {
	srv, _ := newTestServerWithOAuth(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/oauth/badprovider/config", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

// ---------------------------------------------------------------------------
// POST /api/v1/oauth/{provider}/config
// ---------------------------------------------------------------------------

func TestOAuthConfigRoutes_SaveConfig_Returns200AndStoresCredentials(t *testing.T) {
	srv, v := newTestServerWithOAuth(t)

	body, _ := json.Marshal(map[string]string{
		"client_id":     "new-cid",
		"client_secret": "new-cs",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/github/config", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (body: %s)", w.Code, w.Body.String())
	}

	// Verify stored in vault.
	stored, err := v.ReadSecret("services/github/oauth_client_secret")
	if err != nil {
		t.Fatalf("expected vault secret: %v", err)
	}
	if stored["client_id"] != "new-cid" {
		t.Errorf("expected client_id stored, got %v", stored["client_id"])
	}
}

func TestOAuthConfigRoutes_SaveConfig_MissingClientIDReturns400(t *testing.T) {
	srv, _ := newTestServerWithOAuth(t)

	body, _ := json.Marshal(map[string]string{"client_secret": "cs"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/github/config", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

// ---------------------------------------------------------------------------
// DELETE /api/v1/oauth/{provider}/config
// ---------------------------------------------------------------------------

func TestOAuthConfigRoutes_DeleteConfig_Returns204(t *testing.T) {
	srv, v := newTestServerWithOAuth(t)
	_ = v.WriteSecret("services/github/oauth_client_secret", map[string]interface{}{
		"client_id":     "cid",
		"client_secret": "cs",
	})

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/oauth/github/config", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d", w.Code)
	}
}

func TestOAuthConfigRoutes_DeleteConfig_UnknownProviderReturns400(t *testing.T) {
	srv, _ := newTestServerWithOAuth(t)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/oauth/badprovider/config", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}
