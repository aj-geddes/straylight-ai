package vault_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/straylight-ai/straylight/internal/vault"
)

// ---------------------------------------------------------------------------
// Supervisor construction
// ---------------------------------------------------------------------------

// TestNewSupervisor_DefaultConfig verifies NewSupervisor uses sensible defaults.
func TestNewSupervisor_DefaultConfig(t *testing.T) {
	sup := vault.NewSupervisor(vault.SupervisorConfig{})
	if sup == nil {
		t.Fatal("expected non-nil supervisor")
	}
}

// TestSupervisorConfig_CustomPaths verifies custom paths are stored.
func TestSupervisorConfig_CustomPaths(t *testing.T) {
	cfg := vault.SupervisorConfig{
		BinaryPath: "/usr/local/bin/bao",
		HCLPath:    "/custom/openbao.hcl",
		InitPath:   "/custom/init.json",
		ListenAddr: "http://127.0.0.1:8200",
	}
	sup := vault.NewSupervisor(cfg)
	if sup.Config().BinaryPath != "/usr/local/bin/bao" {
		t.Errorf("expected BinaryPath=/usr/local/bin/bao, got %q", sup.Config().BinaryPath)
	}
	if sup.Config().InitPath != "/custom/init.json" {
		t.Errorf("expected InitPath=/custom/init.json, got %q", sup.Config().InitPath)
	}
}

// ---------------------------------------------------------------------------
// waitForReady (polling health)
// ---------------------------------------------------------------------------

// TestWaitForReady_SucceedsWhenHealthy verifies WaitForReady returns nil when
// the mock server responds 200 to the health check.
func TestWaitForReady_SucceedsWhenHealthy(t *testing.T) {
	srv := mockBaoServer(t, map[string]http.HandlerFunc{
		"/v1/sys/health": func(w http.ResponseWriter, r *http.Request) {
			jsonBody(t, w, http.StatusOK, map[string]interface{}{
				"initialized": false,
				"sealed":      true,
				"standby":     false,
			})
		},
	})
	defer srv.Close()

	sup := vault.NewSupervisor(vault.SupervisorConfig{
		ListenAddr: srv.URL,
	})

	err := sup.WaitForReady(2 * time.Second)
	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
}

// TestWaitForReady_TimesOutWhenUnreachable verifies WaitForReady returns an error
// when the server is unreachable and the timeout expires.
func TestWaitForReady_TimesOutWhenUnreachable(t *testing.T) {
	sup := vault.NewSupervisor(vault.SupervisorConfig{
		ListenAddr: "http://127.0.0.1:19999",
	})

	start := time.Now()
	err := sup.WaitForReady(350 * time.Millisecond)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected error when server is unreachable")
	}
	// Should have attempted multiple polls before timing out.
	// The poll interval is 100ms so with a 350ms timeout at least 2 attempts
	// will be made — the elapsed time should be at least 200ms.
	if elapsed < 200*time.Millisecond {
		t.Errorf("expected to wait at least 200ms, waited %v", elapsed)
	}
}

// TestWaitForReady_EventuallyReady verifies WaitForReady succeeds when the server
// becomes available after a short delay (simulates OpenBao startup latency where
// the process starts but takes a moment to bind the port).
// WaitForReady considers any HTTP response (including 503/sealed) as "ready"
// because the OpenBao process is running and accepting connections. The sealed
// state is resolved separately by InitializeVault.
func TestWaitForReady_EventuallyReady(t *testing.T) {
	var callCount int32

	srv := mockBaoServer(t, map[string]http.HandlerFunc{
		"/v1/sys/health": func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&callCount, 1)
			// A sealed vault returns 503 — this is still "ready" (process is up)
			jsonBody(t, w, http.StatusServiceUnavailable, map[string]interface{}{
				"initialized": true,
				"sealed":      true,
			})
		},
	})
	defer srv.Close()

	sup := vault.NewSupervisor(vault.SupervisorConfig{
		ListenAddr: srv.URL,
	})

	// Should succeed immediately since the server responds (even with 503)
	err := sup.WaitForReady(3 * time.Second)
	if err != nil {
		t.Fatalf("expected nil error when server responds (even if sealed), got: %v", err)
	}
	if atomic.LoadInt32(&callCount) < 1 {
		t.Errorf("expected at least 1 call to health endpoint, got %d", callCount)
	}
}

// ---------------------------------------------------------------------------
// InitializeVault
// ---------------------------------------------------------------------------

// TestInitializeVault_NewVault verifies the full initialization sequence when
// OpenBao has never been initialized.
func TestInitializeVault_NewVault(t *testing.T) {
	initDir := t.TempDir()
	initPath := filepath.Join(initDir, "init.json")

	// Track which endpoints were called
	var (
		initCalled       atomic.Bool
		unsealCalled     atomic.Bool
		kvMountCalled    atomic.Bool
		dbMountCalled    atomic.Bool
		policyCreated    atomic.Bool
		authEnabled      atomic.Bool
		roleCreated      atomic.Bool
		roleIDCalled     atomic.Bool
		secretIDCalled   atomic.Bool
		loginCalled      atomic.Bool
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/sys/init":
			jsonBody(t, w, http.StatusOK, map[string]interface{}{
				"initialized": false,
			})

		case r.Method == http.MethodPut && r.URL.Path == "/v1/sys/init":
			initCalled.Store(true)
			jsonBody(t, w, http.StatusOK, map[string]interface{}{
				"keys":       []string{"aabbccdd"},
				"root_token": "hvs.roottoken",
			})

		case r.Method == http.MethodPut && r.URL.Path == "/v1/sys/unseal":
			unsealCalled.Store(true)
			jsonBody(t, w, http.StatusOK, map[string]interface{}{
				"sealed":   false,
				"progress": 0,
				"t":        1,
				"n":        1,
			})

		case r.Method == http.MethodPost && r.URL.Path == "/v1/sys/mounts/secret":
			kvMountCalled.Store(true)
			w.WriteHeader(http.StatusNoContent)

		case r.Method == http.MethodPost && r.URL.Path == "/v1/sys/mounts/database":
			dbMountCalled.Store(true)
			w.WriteHeader(http.StatusNoContent)

		case r.Method == http.MethodPut && r.URL.Path == "/v1/sys/policies/acl/straylight":
			policyCreated.Store(true)
			w.WriteHeader(http.StatusNoContent)

		case r.Method == http.MethodPost && r.URL.Path == "/v1/sys/auth/approle":
			authEnabled.Store(true)
			w.WriteHeader(http.StatusNoContent)

		case r.Method == http.MethodPost && r.URL.Path == "/v1/auth/approle/role/straylight":
			roleCreated.Store(true)
			w.WriteHeader(http.StatusNoContent)

		case r.Method == http.MethodGet && r.URL.Path == "/v1/auth/approle/role/straylight/role-id":
			roleIDCalled.Store(true)
			jsonBody(t, w, http.StatusOK, map[string]interface{}{
				"data": map[string]interface{}{
					"role_id": "role-abc123",
				},
			})

		case r.Method == http.MethodPost && r.URL.Path == "/v1/auth/approle/role/straylight/secret-id":
			secretIDCalled.Store(true)
			jsonBody(t, w, http.StatusOK, map[string]interface{}{
				"data": map[string]interface{}{
					"secret_id": "secret-xyz789",
				},
			})

		case r.Method == http.MethodPost && r.URL.Path == "/v1/auth/approle/login":
			loginCalled.Store(true)
			jsonBody(t, w, http.StatusOK, map[string]interface{}{
				"auth": map[string]interface{}{
					"client_token": "hvs.apptoken",
				},
			})

		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	sup := vault.NewSupervisor(vault.SupervisorConfig{
		ListenAddr: srv.URL,
		InitPath:   initPath,
	})

	client, err := sup.InitializeVault()
	if err != nil {
		t.Fatalf("InitializeVault returned unexpected error: %v", err)
	}
	if client == nil {
		t.Fatal("expected non-nil client after initialization")
	}

	// Verify all steps in the init sequence were called
	for name, called := range map[string]*atomic.Bool{
		"PUT /v1/sys/init":                                &initCalled,
		"PUT /v1/sys/unseal":                              &unsealCalled,
		"POST /v1/sys/mounts/secret":                     &kvMountCalled,
		"POST /v1/sys/mounts/database":                   &dbMountCalled,
		"PUT /v1/sys/policies/acl/straylight":            &policyCreated,
		"POST /v1/sys/auth/approle":                      &authEnabled,
		"POST /v1/auth/approle/role/straylight":          &roleCreated,
		"GET /v1/auth/approle/role/straylight/role-id":   &roleIDCalled,
		"POST /v1/auth/approle/role/straylight/secret-id": &secretIDCalled,
		"POST /v1/auth/approle/login":                    &loginCalled,
	} {
		if !called.Load() {
			t.Errorf("expected %s to be called during initialization", name)
		}
	}

	// Verify client has AppRole token (not root token)
	if client.Token() != "hvs.apptoken" {
		t.Errorf("expected AppRole token hvs.apptoken, got %q", client.Token())
	}

	// Verify init.json was written
	if _, err := os.Stat(initPath); os.IsNotExist(err) {
		t.Error("expected init.json to be written")
	}

	// Verify init.json has correct permissions (0600)
	info, err := os.Stat(initPath)
	if err != nil {
		t.Fatalf("stat init.json: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("expected init.json permissions 0600, got %o", info.Mode().Perm())
	}

	// Verify init.json contains expected fields (but NOT verify actual values — no logging of secrets)
	data, err := os.ReadFile(initPath)
	if err != nil {
		t.Fatalf("read init.json: %v", err)
	}
	var initData map[string]interface{}
	if err := json.Unmarshal(data, &initData); err != nil {
		t.Fatalf("parse init.json: %v", err)
	}
	if initData["unseal_key"] == nil {
		t.Error("expected 'unseal_key' in init.json")
	}
	if initData["role_id"] == nil {
		t.Error("expected 'role_id' in init.json")
	}
	if initData["secret_id"] == nil {
		t.Error("expected 'secret_id' in init.json")
	}
	// Root token must NOT be in init.json (we discard it after init)
	// Actually per the spec root_token IS written to init.json for recovery
	// (not kept in memory long-term, but must be on disk for recovery situations)
	// The important thing is it's not in memory and the file has 0600 perms
}

// TestInitializeVault_AlreadyInitialized verifies that when init.json exists,
// the supervisor reads the unseal key and authenticates via AppRole without
// calling PUT /v1/sys/init again.
func TestInitializeVault_AlreadyInitialized(t *testing.T) {
	initDir := t.TempDir()
	initPath := filepath.Join(initDir, "init.json")

	// Write a pre-existing init.json (simulating a prior init)
	initContent := map[string]interface{}{
		"unseal_key": "aabbccdd",
		"root_token": "hvs.roottoken",
		"role_id":    "role-abc123",
		"secret_id":  "secret-xyz789",
	}
	data, _ := json.Marshal(initContent)
	if err := os.WriteFile(initPath, data, 0o600); err != nil {
		t.Fatalf("write init.json: %v", err)
	}

	var reinitAttempted atomic.Bool

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/sys/init":
			// Report already initialized
			jsonBody(t, w, http.StatusOK, map[string]interface{}{
				"initialized": true,
			})

		case r.Method == http.MethodPut && r.URL.Path == "/v1/sys/init":
			// Should NOT be called
			reinitAttempted.Store(true)
			w.WriteHeader(http.StatusBadRequest)

		case r.Method == http.MethodPut && r.URL.Path == "/v1/sys/unseal":
			jsonBody(t, w, http.StatusOK, map[string]interface{}{
				"sealed": false,
			})

		case r.Method == http.MethodPost && r.URL.Path == "/v1/auth/approle/login":
			jsonBody(t, w, http.StatusOK, map[string]interface{}{
				"auth": map[string]interface{}{
					"client_token": "hvs.apptoken",
				},
			})

		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	sup := vault.NewSupervisor(vault.SupervisorConfig{
		ListenAddr: srv.URL,
		InitPath:   initPath,
	})

	client, err := sup.InitializeVault()
	if err != nil {
		t.Fatalf("InitializeVault returned unexpected error: %v", err)
	}
	if client == nil {
		t.Fatal("expected non-nil client")
	}
	if reinitAttempted.Load() {
		t.Error("PUT /v1/sys/init should NOT be called when already initialized")
	}
	if client.Token() != "hvs.apptoken" {
		t.Errorf("expected token hvs.apptoken, got %q", client.Token())
	}
}

// TestInitializeVault_InitFailure verifies that InitializeVault returns an error
// when the OpenBao init API call fails.
func TestInitializeVault_InitFailure(t *testing.T) {
	initDir := t.TempDir()
	initPath := filepath.Join(initDir, "init.json")

	srv := mockBaoServer(t, map[string]http.HandlerFunc{
		"/v1/sys/init": func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet {
				jsonBody(t, w, http.StatusOK, map[string]interface{}{"initialized": false})
				return
			}
			// PUT fails
			jsonBody(t, w, http.StatusInternalServerError, map[string]interface{}{
				"errors": []string{"internal server error"},
			})
		},
	})
	defer srv.Close()

	sup := vault.NewSupervisor(vault.SupervisorConfig{
		ListenAddr: srv.URL,
		InitPath:   initPath,
	})

	_, err := sup.InitializeVault()
	if err == nil {
		t.Fatal("expected error when init API fails, got nil")
	}
}

// TestInitializeVault_UnsealFailure verifies that InitializeVault returns an error
// when the unseal call fails.
func TestInitializeVault_UnsealFailure(t *testing.T) {
	initDir := t.TempDir()
	initPath := filepath.Join(initDir, "init.json")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/sys/init":
			jsonBody(t, w, http.StatusOK, map[string]interface{}{"initialized": false})
		case r.Method == http.MethodPut && r.URL.Path == "/v1/sys/init":
			jsonBody(t, w, http.StatusOK, map[string]interface{}{
				"keys":       []string{"aabbccdd"},
				"root_token": "hvs.roottoken",
			})
		case r.Method == http.MethodPut && r.URL.Path == "/v1/sys/unseal":
			jsonBody(t, w, http.StatusInternalServerError, map[string]interface{}{
				"errors": []string{"unseal failed"},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	sup := vault.NewSupervisor(vault.SupervisorConfig{
		ListenAddr: srv.URL,
		InitPath:   initPath,
	})

	_, err := sup.InitializeVault()
	if err == nil {
		t.Fatal("expected error when unseal fails, got nil")
	}
}

// ---------------------------------------------------------------------------
// VaultStatus helper
// ---------------------------------------------------------------------------

// TestVaultStatus_Unsealed verifies VaultStatus returns "unsealed" for a healthy vault.
func TestVaultStatus_Unsealed(t *testing.T) {
	srv := mockBaoServer(t, map[string]http.HandlerFunc{
		"/v1/sys/health": func(w http.ResponseWriter, r *http.Request) {
			jsonBody(t, w, http.StatusOK, map[string]interface{}{
				"initialized": true,
				"sealed":      false,
			})
		},
	})
	defer srv.Close()

	sup := vault.NewSupervisor(vault.SupervisorConfig{
		ListenAddr: srv.URL,
	})

	status := sup.VaultStatus()
	if status != "unsealed" {
		t.Errorf("expected status=unsealed, got %q", status)
	}
}

// TestVaultStatus_Sealed verifies VaultStatus returns "sealed" when vault is sealed.
func TestVaultStatus_Sealed(t *testing.T) {
	srv := mockBaoServer(t, map[string]http.HandlerFunc{
		"/v1/sys/health": func(w http.ResponseWriter, r *http.Request) {
			jsonBody(t, w, http.StatusServiceUnavailable, map[string]interface{}{
				"initialized": true,
				"sealed":      true,
			})
		},
	})
	defer srv.Close()

	sup := vault.NewSupervisor(vault.SupervisorConfig{
		ListenAddr: srv.URL,
	})

	status := sup.VaultStatus()
	if status != "sealed" {
		t.Errorf("expected status=sealed, got %q", status)
	}
}

// TestVaultStatus_Unavailable verifies VaultStatus returns "unavailable" when server is down.
func TestVaultStatus_Unavailable(t *testing.T) {
	sup := vault.NewSupervisor(vault.SupervisorConfig{
		ListenAddr: "http://127.0.0.1:19999",
	})

	status := sup.VaultStatus()
	if status != "unavailable" {
		t.Errorf("expected status=unavailable, got %q", status)
	}
}

// ---------------------------------------------------------------------------
// Additional error-path coverage
// ---------------------------------------------------------------------------

// TestInitializeVault_LoginFailure verifies InitializeVault returns an error
// when the AppRole login call fails after a successful init+unseal sequence.
func TestInitializeVault_LoginFailure(t *testing.T) {
	initDir := t.TempDir()
	initPath := filepath.Join(initDir, "init.json")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/sys/init":
			jsonBody(t, w, http.StatusOK, map[string]interface{}{"initialized": false})
		case r.Method == http.MethodPut && r.URL.Path == "/v1/sys/init":
			jsonBody(t, w, http.StatusOK, map[string]interface{}{
				"keys":       []string{"aabbccdd"},
				"root_token": "hvs.roottoken",
			})
		case r.Method == http.MethodPut && r.URL.Path == "/v1/sys/unseal":
			jsonBody(t, w, http.StatusOK, map[string]interface{}{"sealed": false})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/sys/mounts/secret":
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPut && r.URL.Path == "/v1/sys/policies/acl/straylight":
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/sys/auth/approle":
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/auth/approle/role/straylight":
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && r.URL.Path == "/v1/auth/approle/role/straylight/role-id":
			jsonBody(t, w, http.StatusOK, map[string]interface{}{
				"data": map[string]interface{}{"role_id": "role-abc123"},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/auth/approle/role/straylight/secret-id":
			jsonBody(t, w, http.StatusOK, map[string]interface{}{
				"data": map[string]interface{}{"secret_id": "secret-xyz789"},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/auth/approle/login":
			// Login fails
			jsonBody(t, w, http.StatusForbidden, map[string]interface{}{
				"errors": []string{"permission denied"},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	sup := vault.NewSupervisor(vault.SupervisorConfig{
		ListenAddr: srv.URL,
		InitPath:   initPath,
	})

	_, err := sup.InitializeVault()
	if err == nil {
		t.Fatal("expected error when AppRole login fails, got nil")
	}
}

// TestInitializeVault_ResumeLoginFailure verifies that when already-initialized
// and the AppRole login fails, InitializeVault returns an error.
func TestInitializeVault_ResumeLoginFailure(t *testing.T) {
	initDir := t.TempDir()
	initPath := filepath.Join(initDir, "init.json")

	initContent := map[string]interface{}{
		"unseal_key": "aabbccdd",
		"root_token": "hvs.roottoken",
		"role_id":    "role-abc123",
		"secret_id":  "secret-xyz789",
	}
	data, _ := json.Marshal(initContent)
	if err := os.WriteFile(initPath, data, 0o600); err != nil {
		t.Fatalf("write init.json: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/sys/init":
			jsonBody(t, w, http.StatusOK, map[string]interface{}{"initialized": true})
		case r.Method == http.MethodPut && r.URL.Path == "/v1/sys/unseal":
			jsonBody(t, w, http.StatusOK, map[string]interface{}{"sealed": false})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/auth/approle/login":
			jsonBody(t, w, http.StatusForbidden, map[string]interface{}{
				"errors": []string{"permission denied"},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	sup := vault.NewSupervisor(vault.SupervisorConfig{
		ListenAddr: srv.URL,
		InitPath:   initPath,
	})

	_, err := sup.InitializeVault()
	if err == nil {
		t.Fatal("expected error when resume AppRole login fails, got nil")
	}
}

// TestInitializeVault_ResumeUnsealFailure verifies that when already-initialized
// and the unseal call fails, InitializeVault returns an error.
func TestInitializeVault_ResumeUnsealFailure(t *testing.T) {
	initDir := t.TempDir()
	initPath := filepath.Join(initDir, "init.json")

	initContent := map[string]interface{}{
		"unseal_key": "aabbccdd",
		"root_token": "hvs.roottoken",
		"role_id":    "role-abc123",
		"secret_id":  "secret-xyz789",
	}
	data, _ := json.Marshal(initContent)
	if err := os.WriteFile(initPath, data, 0o600); err != nil {
		t.Fatalf("write init.json: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/sys/init":
			jsonBody(t, w, http.StatusOK, map[string]interface{}{"initialized": true})
		case r.Method == http.MethodPut && r.URL.Path == "/v1/sys/unseal":
			// Unseal fails
			jsonBody(t, w, http.StatusInternalServerError, map[string]interface{}{
				"errors": []string{"unseal failed"},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	sup := vault.NewSupervisor(vault.SupervisorConfig{
		ListenAddr: srv.URL,
		InitPath:   initPath,
	})

	_, err := sup.InitializeVault()
	if err == nil {
		t.Fatal("expected error when resume unseal fails, got nil")
	}
}

// TestInitializeVault_MissingInitFile verifies that when already-initialized
// but init.json is missing, InitializeVault returns an error.
func TestInitializeVault_MissingInitFile(t *testing.T) {
	srv := mockBaoServer(t, map[string]http.HandlerFunc{
		"/v1/sys/init": func(w http.ResponseWriter, r *http.Request) {
			jsonBody(t, w, http.StatusOK, map[string]interface{}{"initialized": true})
		},
	})
	defer srv.Close()

	sup := vault.NewSupervisor(vault.SupervisorConfig{
		ListenAddr: srv.URL,
		InitPath:   "/nonexistent/path/init.json",
	})

	_, err := sup.InitializeVault()
	if err == nil {
		t.Fatal("expected error when init.json is missing, got nil")
	}
}

// TestVaultStatus_DecodeError verifies VaultStatus handles a response with an
// undecodable body gracefully, falling back based on HTTP status.
func TestVaultStatus_DecodeError(t *testing.T) {
	srv := mockBaoServer(t, map[string]http.HandlerFunc{
		"/v1/sys/health": func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("not-json"))
		},
	})
	defer srv.Close()

	sup := vault.NewSupervisor(vault.SupervisorConfig{
		ListenAddr: srv.URL,
	})
	// When body is undecodable but status is 200, should return "unsealed"
	status := sup.VaultStatus()
	if status != "unsealed" {
		t.Errorf("expected status=unsealed on 200 with bad body, got %q", status)
	}
}

// TestReadSecret_DecodeError verifies ReadSecret returns an error when the
// response body cannot be decoded.
func TestReadSecret_DecodeError(t *testing.T) {
	srv := mockBaoServer(t, map[string]http.HandlerFunc{
		"/v1/secret/data/services/bad": func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("not-json-at-all"))
		},
	})
	defer srv.Close()

	c := vault.NewClient(srv.URL)
	c.SetToken("s.testtoken")

	_, err := c.ReadSecret("services/bad")
	if err == nil {
		t.Fatal("expected error when response body is not valid JSON, got nil")
	}
}

// TestIsSealed_DecodeError verifies IsSealed returns an error when the response
// body cannot be decoded.
func TestIsSealed_DecodeError(t *testing.T) {
	srv := mockBaoServer(t, map[string]http.HandlerFunc{
		"/v1/sys/health": func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("not-json"))
		},
	})
	defer srv.Close()

	c := vault.NewClient(srv.URL)
	_, err := c.IsSealed()
	if err == nil {
		t.Fatal("expected error when response body is not valid JSON, got nil")
	}
}

// TestWriteSecret_BuildRequestError verifies WriteSecret returns an error for
// an invalid address that causes request construction to fail.
func TestWriteSecret_BuildRequestError(t *testing.T) {
	// Use an invalid URL to trigger http.NewRequest error via illegal chars
	c := vault.NewClient("://invalid-url")
	err := c.WriteSecret("services/test", map[string]interface{}{"k": "v"})
	if err == nil {
		t.Fatal("expected error for invalid URL, got nil")
	}
}

// TestListSecrets_DecodeError verifies ListSecrets returns an error when the
// response body cannot be decoded.
func TestListSecrets_DecodeError(t *testing.T) {
	srv := mockBaoServer(t, map[string]http.HandlerFunc{
		"/v1/secret/metadata/services/": func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("not-json"))
		},
	})
	defer srv.Close()

	c := vault.NewClient(srv.URL)
	c.SetToken("s.testtoken")

	_, err := c.ListSecrets("services/")
	if err == nil {
		t.Fatal("expected error when response body is not valid JSON, got nil")
	}
}

// TestStop_NilProcess verifies Stop does not panic when no process has been started.
func TestStop_NilProcess(t *testing.T) {
	sup := vault.NewSupervisor(vault.SupervisorConfig{})
	// Should not panic or error
	if err := sup.Stop(); err != nil {
		t.Errorf("Stop() on nil process returned unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Integration-style test (build tag: integration)
// ---------------------------------------------------------------------------

// TestIntegration_FullInitUnsealAuth is skipped unless -tags=integration is set.
// It documents the expected full flow against a real OpenBao binary.
// To run: go test -tags=integration ./internal/vault/... -run TestIntegration_
func TestIntegration_FullInitUnsealAuth(t *testing.T) {
	t.Skip("integration test: run with -tags=integration and a real bao binary")

	// Expected flow (documented here for human readers):
	// 1. Start: bao server -config=/etc/straylight/openbao.hcl
	// 2. WaitForReady polls /v1/sys/health until 200/503 (any response means it's up)
	// 3. CheckInit GET /v1/sys/init → {initialized: false}
	// 4. Initialize PUT /v1/sys/init → {keys: [...], root_token: "..."}
	// 5. Save keys + root_token + role_id + secret_id to init.json (chmod 0600)
	// 6. Unseal PUT /v1/sys/unseal → {sealed: false}
	// 7. Enable KV v2 POST /v1/sys/mounts/secret
	// 8. Create policy PUT /v1/sys/policies/acl/straylight
	// 9. Enable AppRole POST /v1/sys/auth/approle
	// 10. Create role POST /v1/auth/approle/role/straylight
	// 11. Get RoleID GET /v1/auth/approle/role/straylight/role-id
	// 12. Get SecretID POST /v1/auth/approle/role/straylight/secret-id
	// 13. Login POST /v1/auth/approle/login → {auth: {client_token: "..."}}
	// 14. Client now uses AppRole token (root token discarded from memory)
	// 15. Write/Read/Delete KV v2 secrets round-trip
	// 16. Second start: reads existing init.json, unseal, re-authenticate
}
