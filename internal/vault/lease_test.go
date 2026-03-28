// Package vault_test — tests for vault client lease management methods.
package vault_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/straylight-ai/straylight/internal/vault"
)

// ---------------------------------------------------------------------------
// TestRenewLease_SuccessfulRenewal verifies RenewLease returns updated LeaseInfo.
// ---------------------------------------------------------------------------

func TestRenewLease_SuccessfulRenewal(t *testing.T) {
	srv := mockBaoServer(t, map[string]http.HandlerFunc{
		"/v1/sys/leases/renew": func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPut {
				t.Errorf("method = %q, want PUT", r.Method)
			}
			jsonBody(t, w, http.StatusOK, map[string]interface{}{
				"lease_id":       "database/creds/pg-ro/abc123",
				"lease_duration": 300,
				"renewable":      true,
			})
		},
	})
	defer srv.Close()

	c := vault.NewClient(srv.URL)
	c.SetToken("test-token")

	info, err := c.RenewLease("database/creds/pg-ro/abc123", 300)
	if err != nil {
		t.Fatalf("RenewLease: %v", err)
	}
	if info.LeaseID != "database/creds/pg-ro/abc123" {
		t.Errorf("LeaseID = %q, want %q", info.LeaseID, "database/creds/pg-ro/abc123")
	}
	if info.LeaseDuration != 300 {
		t.Errorf("LeaseDuration = %d, want 300", info.LeaseDuration)
	}
	if !info.Renewable {
		t.Error("expected Renewable = true")
	}
}

// ---------------------------------------------------------------------------
// TestRenewLease_VaultError verifies RenewLease returns an error on non-2xx.
// ---------------------------------------------------------------------------

func TestRenewLease_VaultError(t *testing.T) {
	srv := mockBaoServer(t, map[string]http.HandlerFunc{
		"/v1/sys/leases/renew": func(w http.ResponseWriter, r *http.Request) {
			jsonBody(t, w, http.StatusBadRequest, map[string]interface{}{
				"errors": []string{"lease not found"},
			})
		},
	})
	defer srv.Close()

	c := vault.NewClient(srv.URL)
	c.SetToken("test-token")

	_, err := c.RenewLease("database/creds/pg-ro/missing", 300)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// TestRevokeLease_Success verifies RevokeLease calls the correct endpoint.
// ---------------------------------------------------------------------------

func TestRevokeLease_Success(t *testing.T) {
	called := false
	srv := mockBaoServer(t, map[string]http.HandlerFunc{
		"/v1/sys/leases/revoke": func(w http.ResponseWriter, r *http.Request) {
			called = true
			if r.Method != http.MethodPut {
				t.Errorf("method = %q, want PUT", r.Method)
			}
			w.WriteHeader(http.StatusNoContent)
		},
	})
	defer srv.Close()

	c := vault.NewClient(srv.URL)
	c.SetToken("test-token")

	if err := c.RevokeLease("database/creds/pg-ro/abc123"); err != nil {
		t.Fatalf("RevokeLease: %v", err)
	}
	if !called {
		t.Error("expected /v1/sys/leases/revoke to be called")
	}
}

// ---------------------------------------------------------------------------
// TestRevokeLease_VaultError verifies RevokeLease returns an error on failure.
// ---------------------------------------------------------------------------

func TestRevokeLease_VaultError(t *testing.T) {
	srv := mockBaoServer(t, map[string]http.HandlerFunc{
		"/v1/sys/leases/revoke": func(w http.ResponseWriter, r *http.Request) {
			jsonBody(t, w, http.StatusInternalServerError, map[string]interface{}{
				"errors": []string{"vault unavailable"},
			})
		},
	})
	defer srv.Close()

	c := vault.NewClient(srv.URL)
	c.SetToken("test-token")

	err := c.RevokeLease("database/creds/pg-ro/abc123")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// TestRevokeLeasePrefix_Success verifies RevokeLeasePrefix uses the correct path.
// ---------------------------------------------------------------------------

func TestRevokeLeasePrefix_Success(t *testing.T) {
	called := false
	capturedPath := ""
	srv := mockBaoServer(t, map[string]http.HandlerFunc{
		"/v1/sys/leases/revoke-prefix/": func(w http.ResponseWriter, r *http.Request) {
			called = true
			capturedPath = r.URL.Path
			w.WriteHeader(http.StatusNoContent)
		},
	})
	defer srv.Close()

	c := vault.NewClient(srv.URL)
	c.SetToken("test-token")

	if err := c.RevokeLeasePrefix("database/"); err != nil {
		t.Fatalf("RevokeLeasePrefix: %v", err)
	}
	if !called {
		t.Error("expected /v1/sys/leases/revoke-prefix/ to be called")
	}
	if !strings.HasSuffix(capturedPath, "database/") {
		t.Errorf("path = %q, want suffix 'database/'", capturedPath)
	}
}

// ---------------------------------------------------------------------------
// TestReadWithLease_ReturnsDataAndLease verifies ReadWithLease extracts all fields.
// ---------------------------------------------------------------------------

func TestReadWithLease_ReturnsDataAndLease(t *testing.T) {
	srv := mockBaoServer(t, map[string]http.HandlerFunc{
		"/v1/database/creds/pg-ro": func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				t.Errorf("method = %q, want GET", r.Method)
			}
			jsonBody(t, w, http.StatusOK, map[string]interface{}{
				"lease_id":       "database/creds/pg-ro/xyz789",
				"lease_duration": 900,
				"renewable":      true,
				"data": map[string]interface{}{
					"username": "v-pg-abc",
					"password": "s3cr3t-pass",
				},
			})
		},
	})
	defer srv.Close()

	c := vault.NewClient(srv.URL)
	c.SetToken("test-token")

	data, leaseID, leaseTTL, err := c.ReadWithLease("database/creds/pg-ro")
	if err != nil {
		t.Fatalf("ReadWithLease: %v", err)
	}
	if leaseID != "database/creds/pg-ro/xyz789" {
		t.Errorf("leaseID = %q, want %q", leaseID, "database/creds/pg-ro/xyz789")
	}
	if leaseTTL != 900 {
		t.Errorf("leaseTTL = %d, want 900", leaseTTL)
	}
	if data["username"] != "v-pg-abc" {
		t.Errorf("username = %q, want %q", data["username"], "v-pg-abc")
	}
}

// ---------------------------------------------------------------------------
// TestReadWithLease_NotFound verifies a 404 returns an error.
// ---------------------------------------------------------------------------

func TestReadWithLease_NotFound(t *testing.T) {
	srv := mockBaoServer(t, map[string]http.HandlerFunc{
		"/v1/database/creds/missing": func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		},
	})
	defer srv.Close()

	c := vault.NewClient(srv.URL)
	c.SetToken("test-token")

	_, _, _, err := c.ReadWithLease("database/creds/missing")
	if err == nil {
		t.Fatal("expected error for 404, got nil")
	}
}

// ---------------------------------------------------------------------------
// TestEnableSecretsEngine_Success verifies EnableSecretsEngine calls the mount API.
// ---------------------------------------------------------------------------

func TestEnableSecretsEngine_Success(t *testing.T) {
	called := false
	srv := mockBaoServer(t, map[string]http.HandlerFunc{
		"/v1/sys/mounts/database": func(w http.ResponseWriter, r *http.Request) {
			called = true
			if r.Method != http.MethodPost {
				t.Errorf("method = %q, want POST", r.Method)
			}
			w.WriteHeader(http.StatusNoContent)
		},
	})
	defer srv.Close()

	c := vault.NewClient(srv.URL)
	c.SetToken("test-token")

	err := c.EnableSecretsEngine("database", "database", map[string]interface{}{
		"description": "Straylight dynamic database credentials",
	})
	if err != nil {
		t.Fatalf("EnableSecretsEngine: %v", err)
	}
	if !called {
		t.Error("expected /v1/sys/mounts/database to be called")
	}
}

// ---------------------------------------------------------------------------
// TestConfigureDatabaseConnection_Success verifies database config write.
// ---------------------------------------------------------------------------

func TestConfigureDatabaseConnection_Success(t *testing.T) {
	called := false
	srv := mockBaoServer(t, map[string]http.HandlerFunc{
		"/v1/database/config/my-pg": func(w http.ResponseWriter, r *http.Request) {
			called = true
			if r.Method != http.MethodPost {
				t.Errorf("method = %q, want POST", r.Method)
			}
			w.WriteHeader(http.StatusNoContent)
		},
	})
	defer srv.Close()

	c := vault.NewClient(srv.URL)
	c.SetToken("test-token")

	err := c.ConfigureDatabaseConnection(
		"my-pg",
		"postgresql-database-plugin",
		"postgresql://admin:pass@db:5432/mydb",
		[]string{"my-pg-ro", "my-pg-rw"},
		map[string]interface{}{
			"username": "admin",
			"password": "pass",
		},
	)
	if err != nil {
		t.Fatalf("ConfigureDatabaseConnection: %v", err)
	}
	if !called {
		t.Error("expected /v1/database/config/my-pg to be called")
	}
}

// ---------------------------------------------------------------------------
// TestCreateDatabaseRole_Success verifies database role creation.
// ---------------------------------------------------------------------------

func TestCreateDatabaseRole_Success(t *testing.T) {
	called := false
	srv := mockBaoServer(t, map[string]http.HandlerFunc{
		"/v1/database/roles/my-pg-ro": func(w http.ResponseWriter, r *http.Request) {
			called = true
			if r.Method != http.MethodPost {
				t.Errorf("method = %q, want POST", r.Method)
			}
			w.WriteHeader(http.StatusNoContent)
		},
	})
	defer srv.Close()

	c := vault.NewClient(srv.URL)
	c.SetToken("test-token")

	err := c.CreateDatabaseRole(
		"my-pg-ro",
		"my-pg",
		[]string{
			`CREATE ROLE "{{name}}" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';`,
			`GRANT SELECT ON ALL TABLES IN SCHEMA public TO "{{name}}";`,
		},
		"15m",
		"1h",
	)
	if err != nil {
		t.Fatalf("CreateDatabaseRole: %v", err)
	}
	if !called {
		t.Error("expected /v1/database/roles/my-pg-ro to be called")
	}
}

// ---------------------------------------------------------------------------
// TestGetDynamicCredential_Success verifies dynamic credential retrieval.
// ---------------------------------------------------------------------------

func TestGetDynamicCredential_Success(t *testing.T) {
	srv := mockBaoServer(t, map[string]http.HandlerFunc{
		"/v1/database/creds/my-pg-ro": func(w http.ResponseWriter, r *http.Request) {
			jsonBody(t, w, http.StatusOK, map[string]interface{}{
				"lease_id":       "database/creds/my-pg-ro/gen123",
				"lease_duration": 900,
				"renewable":      true,
				"data": map[string]interface{}{
					"username": "v-my-pg-abc",
					"password": "dynamic-pass",
				},
			})
		},
	})
	defer srv.Close()

	c := vault.NewClient(srv.URL)
	c.SetToken("test-token")

	creds, leaseID, leaseDuration, err := c.GetDynamicCredential("database", "my-pg-ro")
	if err != nil {
		t.Fatalf("GetDynamicCredential: %v", err)
	}
	if leaseID != "database/creds/my-pg-ro/gen123" {
		t.Errorf("leaseID = %q, want %q", leaseID, "database/creds/my-pg-ro/gen123")
	}
	if leaseDuration != 900 {
		t.Errorf("leaseDuration = %d, want 900", leaseDuration)
	}
	if creds["username"] != "v-my-pg-abc" {
		t.Errorf("username = %q, want %q", creds["username"], "v-my-pg-abc")
	}
}
