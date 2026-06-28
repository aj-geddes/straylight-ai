// Package oauth_test tests the RefreshGuard wiring in Handler.RefreshToken.
//
// Phase 4, ADR-012: wire tokenexchange.RefreshGuard so concurrent refreshes
// for the same service single-flight, and the rotated refresh token is written
// back to OpenBao atomically — protecting Slack and Atlassian rotating RTs.
package oauth_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/straylight-ai/straylight/internal/oauth"
	"github.com/straylight-ai/straylight/internal/services"
	"github.com/straylight-ai/straylight/internal/tokenexchange"
)

// ---------------------------------------------------------------------------
// Mock VaultClient (thread-safe) — satisfies oauth.VaultClient
// ---------------------------------------------------------------------------

type rgMockVault struct {
	mu         sync.RWMutex
	store      map[string]map[string]interface{}
	writeCalls int32
}

func newRGMockVault() *rgMockVault {
	return &rgMockVault{store: make(map[string]map[string]interface{})}
}

func (v *rgMockVault) WriteSecret(path string, data map[string]interface{}) error {
	atomic.AddInt32(&v.writeCalls, 1)
	v.mu.Lock()
	defer v.mu.Unlock()
	cp := make(map[string]interface{}, len(data))
	for k, val := range data {
		cp[k] = val
	}
	v.store[path] = cp
	return nil
}

func (v *rgMockVault) ReadSecret(path string) (map[string]interface{}, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	d, ok := v.store[path]
	if !ok {
		return nil, fmt.Errorf("secret not found: %s", path)
	}
	cp := make(map[string]interface{}, len(d))
	for k, val := range d {
		cp[k] = val
	}
	return cp, nil
}

func (v *rgMockVault) DeleteSecret(_ string) error { return nil }

// ---------------------------------------------------------------------------
// Mock ServiceManager — satisfies oauth.ServiceManager
// ---------------------------------------------------------------------------

type rgMockSvcMgr struct{}

func (m *rgMockSvcMgr) Create(_ services.Service, _ string) error            { return nil }
func (m *rgMockSvcMgr) Update(_ string, _ services.Service, _ *string) error { return nil }
func (m *rgMockSvcMgr) Get(name string) (services.Service, error) {
	return services.Service{}, fmt.Errorf("service not found: %s", name)
}

// ---------------------------------------------------------------------------
// fakeTokenServer — a mock provider token endpoint
// ---------------------------------------------------------------------------

type rgFakeTokenServer struct {
	srv        *httptest.Server
	callCount  int32
	returnErr  bool
	newAccess  string
	newRefresh string
}

func newRGFakeTokenServer(newAccess, newRefresh string) *rgFakeTokenServer {
	f := &rgFakeTokenServer{
		newAccess:  newAccess,
		newRefresh: newRefresh,
	}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&f.callCount, 1)
		if f.returnErr {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"Token has been expired or revoked."}`))
			return
		}
		// Simulate latency so concurrent goroutines arrive while first is in-flight.
		time.Sleep(10 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token":  f.newAccess,
			"refresh_token": f.newRefresh,
			"token_type":    "bearer",
			"expires_in":    3600,
		})
	}))
	return f
}

func (f *rgFakeTokenServer) close() { f.srv.Close() }

// injectProvider replaces the named provider's TokenURL with the given URL.
// Returns a restore function that should be deferred.
func injectProvider(name, tokenURL string) func() {
	original, ok := oauth.Providers[name]
	oauth.Providers[name] = oauth.Provider{
		Name:          original.Name,
		AuthURL:       original.AuthURL,
		TokenURL:      tokenURL,
		DefaultScopes: original.DefaultScopes,
	}
	if !ok {
		return func() { delete(oauth.Providers, name) }
	}
	return func() { oauth.Providers[name] = original }
}

// seedVaultTokens writes initial oauth token data for a service into the mock vault.
func seedVaultTokens(v *rgMockVault, serviceName, providerName string) {
	_ = v.WriteSecret("services/"+serviceName+"/oauth_tokens", map[string]interface{}{
		"access_token":  "old_access_token",
		"refresh_token": "old_refresh_token",
		"token_type":    "bearer",
		"scope":         "repo",
		"expires_at":    time.Now().Add(5 * time.Minute).Format(time.RFC3339),
		"provider":      providerName,
	})
	// Seed client credential path so readClientID/readClientSecret work.
	_ = v.WriteSecret("services/"+providerName+"/oauth_client_secret", map[string]interface{}{
		"client_id":     "test-client-id",
		"client_secret": "test-client-secret",
	})
	// Reset write counter after seeding.
	atomic.StoreInt32(&v.writeCalls, 0)
}

// ---------------------------------------------------------------------------
// TestRefreshToken_WithGuard_ConcurrentSameService_SingleFlight
// ---------------------------------------------------------------------------
//
// N goroutines call RefreshToken for the same service simultaneously.
// The upstream token endpoint must be called exactly once.
// All callers receive the same new access token.
// The vault is written exactly once with the new tokens.

func TestRefreshToken_WithGuard_ConcurrentSameService_SingleFlight(t *testing.T) {
	const serviceName = "slack-svc"
	const providerName = "github"

	fake := newRGFakeTokenServer("new_access_token_abc", "new_refresh_token_xyz")
	defer fake.close()

	restore := injectProvider(providerName, fake.srv.URL)
	defer restore()

	v := newRGMockVault()
	seedVaultTokens(v, serviceName, providerName)

	guard := tokenexchange.NewRefreshGuard()
	h := oauth.NewHandlerWithGuard(v, &rgMockSvcMgr{}, "http://localhost:9470", guard)

	const n = 20
	var wg sync.WaitGroup
	var mu sync.Mutex
	var accessTokens []string

	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			tok, err := h.RefreshToken(serviceName)
			if err != nil {
				t.Errorf("RefreshToken: %v", err)
				return
			}
			mu.Lock()
			accessTokens = append(accessTokens, tok)
			mu.Unlock()
		}()
	}
	wg.Wait()

	// Token endpoint called exactly once (single-flight).
	if c := atomic.LoadInt32(&fake.callCount); c != 1 {
		t.Errorf("token endpoint called %d times, want 1", c)
	}

	// All callers received the same new access token.
	if len(accessTokens) != n {
		t.Fatalf("collected %d tokens, want %d", len(accessTokens), n)
	}
	for i, tok := range accessTokens {
		if tok != "new_access_token_abc" {
			t.Errorf("accessTokens[%d] = %q, want %q", i, tok, "new_access_token_abc")
		}
	}

	// Vault was written exactly once with the new tokens (atomic write-back).
	if c := atomic.LoadInt32(&v.writeCalls); c != 1 {
		t.Errorf("vault.WriteSecret called %d times, want 1", c)
	}
}

// ---------------------------------------------------------------------------
// TestRefreshToken_WithGuard_AtomicWriteBack
// ---------------------------------------------------------------------------
//
// After a single RefreshToken call, the vault must contain the new access_token
// AND new refresh_token at the oauth token path.

func TestRefreshToken_WithGuard_AtomicWriteBack(t *testing.T) {
	const serviceName = "atlassian-svc"
	const providerName = "github"

	fake := newRGFakeTokenServer("fresh_access_tok", "fresh_refresh_tok")
	defer fake.close()

	restore := injectProvider(providerName, fake.srv.URL)
	defer restore()

	v := newRGMockVault()
	seedVaultTokens(v, serviceName, providerName)

	guard := tokenexchange.NewRefreshGuard()
	h := oauth.NewHandlerWithGuard(v, &rgMockSvcMgr{}, "http://localhost:9470", guard)

	tok, err := h.RefreshToken(serviceName)
	if err != nil {
		t.Fatalf("RefreshToken: %v", err)
	}
	if tok != "fresh_access_tok" {
		t.Errorf("returned token = %q, want %q", tok, "fresh_access_tok")
	}

	// Verify vault contents.
	data, _ := v.ReadSecret("services/" + serviceName + "/oauth_tokens")
	if data == nil {
		t.Fatal("vault token path is empty after refresh")
	}
	if at, _ := data["access_token"].(string); at != "fresh_access_tok" {
		t.Errorf("vault access_token = %q, want %q", at, "fresh_access_tok")
	}
	if rt, _ := data["refresh_token"].(string); rt != "fresh_refresh_tok" {
		t.Errorf("vault refresh_token = %q, want %q", rt, "fresh_refresh_tok")
	}
}

// ---------------------------------------------------------------------------
// TestRefreshToken_WithGuard_ErrorDoesNotPoisonNextCall
// ---------------------------------------------------------------------------
//
// When the first RefreshToken call fails, write-back is NOT performed.
// A subsequent call retries and succeeds.

func TestRefreshToken_WithGuard_ErrorDoesNotPoisonNextCall(t *testing.T) {
	const serviceName = "slack-rt-svc"
	const providerName = "github"

	fake := newRGFakeTokenServer("recovered_access", "recovered_refresh")
	fake.returnErr = true // first call returns 400
	defer fake.close()

	restore := injectProvider(providerName, fake.srv.URL)
	defer restore()

	v := newRGMockVault()
	seedVaultTokens(v, serviceName, providerName)

	guard := tokenexchange.NewRefreshGuard()
	h := oauth.NewHandlerWithGuard(v, &rgMockSvcMgr{}, "http://localhost:9470", guard)

	// First call — must fail.
	_, err := h.RefreshToken(serviceName)
	if err == nil {
		t.Fatal("expected error on first RefreshToken (token endpoint returns 400), got nil")
	}

	// No vault write-back on failure.
	if c := atomic.LoadInt32(&v.writeCalls); c != 0 {
		t.Errorf("vault written %d times after failed refresh, want 0", c)
	}

	// Second call — should succeed now.
	fake.returnErr = false
	tok, err := h.RefreshToken(serviceName)
	if err != nil {
		t.Fatalf("second RefreshToken failed: %v", err)
	}
	if tok != "recovered_access" {
		t.Errorf("second call returned %q, want %q", tok, "recovered_access")
	}
}
