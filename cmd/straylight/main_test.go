// Package main tests for the straylight serve() component wiring (ADR-013 Phases 1+2).
package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/straylight-ai/straylight/internal/database"
	"github.com/straylight-ai/straylight/internal/firewall"
	"github.com/straylight-ai/straylight/internal/lease"
	"github.com/straylight-ai/straylight/internal/scanner"
)

// ---------------------------------------------------------------------------
// Mock VaultClient — satisfies database.VaultClient (see internal/database/database.go)
// ---------------------------------------------------------------------------

type mockVaultClient struct {
	dynamicCreds    map[string]interface{}
	dynamicLeaseID  string
	dynamicLeaseTTL int
	dynamicErr      error
	callCount       int
}

func (m *mockVaultClient) GetDynamicCredential(enginePath, roleName string) (map[string]interface{}, string, int, error) {
	m.callCount++
	return m.dynamicCreds, m.dynamicLeaseID, m.dynamicLeaseTTL, m.dynamicErr
}

func (m *mockVaultClient) ConfigureDatabaseConnection(name, plugin, connURL string, allowedRoles []string, extra map[string]interface{}) error {
	return nil
}

func (m *mockVaultClient) CreateDatabaseRole(name, dbName string, creationStatements []string, defaultTTL, maxTTL string) error {
	return nil
}

func (m *mockVaultClient) RenewLease(leaseID string, increment int) (*lease.LeaseInfo, error) {
	return &lease.LeaseInfo{LeaseID: leaseID, LeaseDuration: increment}, nil
}

func (m *mockVaultClient) RevokeLease(leaseID string) error { return nil }

func (m *mockVaultClient) RevokeLeasePrefix(prefix string) error { return nil }

// Compile-time check that the mock satisfies the interface.
var _ database.VaultClient = (*mockVaultClient)(nil)

// ---------------------------------------------------------------------------
// TestVersionCmdUsesRuntimeVersion
//
// RED: version subcommand currently hardcodes "go": "go1.24".
// GREEN: after fix, it must emit runtime.Version().
// ---------------------------------------------------------------------------

func TestVersionCmdUsesRuntimeVersion(t *testing.T) {
	t.Parallel()

	// Redirect os.Stdout to a pipe so we can capture the JSON the command writes.
	origStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w

	cmd := newVersionCmd()
	cmd.Run(cmd, nil)

	w.Close()
	os.Stdout = origStdout

	var buf [4096]byte
	n, _ := r.Read(buf[:])
	r.Close()
	output := buf[:n]

	var result map[string]string
	if err := json.Unmarshal(output, &result); err != nil {
		t.Fatalf("failed to parse version JSON: %v\noutput: %s", err, output)
	}

	want := runtime.Version()
	got := result["go"]
	if got != want {
		t.Errorf("version cmd 'go' field = %q, want %q (runtime.Version())", got, want)
	}
}

// ---------------------------------------------------------------------------
// TestFirewallBlocksOpenbaoDirViaBlockedDirs
//
// RED: serve() does not yet call SetFileReader; this test verifies that the
// Firewall constructed with BlockedDirs=[<dataDir>/openbao] blocks reads from
// that subtree — exactly the guard serve() must wire for read_file (Phase 1).
// ---------------------------------------------------------------------------

func TestFirewallBlocksOpenbaoDirViaBlockedDirs(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	openbaoDir := filepath.Join(tmpDir, "openbao")
	if err := os.MkdirAll(openbaoDir, 0o700); err != nil {
		t.Fatalf("mkdir openbao: %v", err)
	}
	initJSON := filepath.Join(openbaoDir, "init.json")
	if err := os.WriteFile(initJSON, []byte(`{"unseal_key":"secret"}`), 0o600); err != nil {
		t.Fatalf("write init.json: %v", err)
	}

	// Construct the firewall exactly as serve() will (Phase 1 wiring).
	fw := firewall.NewFirewall(firewall.FirewallConfig{
		BlockedDirs: []string{filepath.Join(tmpDir, "openbao")},
		// BlockedPatterns and StructuredKeyPatterns use defaults (filled by NewFirewall).
	})

	// Attempt to read the openbao init.json — must be blocked.
	_, readErr := fw.ReadFileRedacted(initJSON)
	if readErr == nil {
		t.Fatal("expected error reading <dataDir>/openbao/init.json, got nil")
	}
	if !strings.Contains(strings.ToLower(readErr.Error()), "blocked") {
		t.Errorf("expected error to contain 'blocked', got: %v", readErr)
	}
}

// ---------------------------------------------------------------------------
// TestFirewallAllowsNormalFileOutsideBlockedDir
//
// Verifies that the firewall with BlockedDirs set allows reads of legitimate
// project files that are NOT inside the blocked subtree.
// ---------------------------------------------------------------------------

func TestFirewallAllowsNormalFileOutsideBlockedDir(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	openbaoDir := filepath.Join(tmpDir, "openbao")
	if err := os.MkdirAll(openbaoDir, 0o700); err != nil {
		t.Fatalf("mkdir openbao: %v", err)
	}

	normalFile := filepath.Join(tmpDir, "config.txt")
	if err := os.WriteFile(normalFile, []byte("database_url=ignored\nhello=world\n"), 0o644); err != nil {
		t.Fatalf("write normal file: %v", err)
	}

	fw := firewall.NewFirewall(firewall.FirewallConfig{
		BlockedDirs: []string{openbaoDir},
		// No ProjectRoot set — the test file is in tmpDir, no root restriction.
	})

	result, err := fw.ReadFileRedacted(normalFile)
	if err != nil {
		t.Fatalf("unexpected error reading normal file: %v", err)
	}
	if result == nil {
		t.Fatal("ReadFileRedacted returned nil result for normal file")
	}
	// The word "hello" should survive (it is not a sensitive key).
	if !strings.Contains(result.Content, "hello") {
		t.Errorf("expected 'hello' to survive redaction, content: %q", result.Content)
	}
}

// ---------------------------------------------------------------------------
// TestFirewallDefaultConfigBlocksInitJSONByName
//
// DefaultConfig already lists "init.json" in BlockedPatterns.
// This is defense-in-depth: name-based block is the second layer after dir-based.
// ---------------------------------------------------------------------------

func TestFirewallDefaultConfigBlocksInitJSONByName(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	initFile := filepath.Join(tmpDir, "init.json")
	if err := os.WriteFile(initFile, []byte(`{"unseal_key":"s3cr3t"}`), 0o644); err != nil {
		t.Fatalf("write init.json: %v", err)
	}

	// NewFirewall with zero config populates defaults (including "init.json" pattern).
	fw := firewall.NewFirewall(firewall.FirewallConfig{})

	_, err := fw.ReadFileRedacted(initFile)
	if err == nil {
		t.Fatal("expected init.json to be blocked by default pattern, got nil error")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "blocked") {
		t.Errorf("expected 'blocked' in error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// TestScannerNew
//
// Phase 1: serve() will call scanner.New() and SetScanner(sc).
// Verify scanner.New() works and ScanDirectory runs without error on a temp dir.
// ---------------------------------------------------------------------------

func TestScannerNew(t *testing.T) {
	t.Parallel()

	sc := scanner.New()
	if sc == nil {
		t.Fatal("scanner.New() returned nil")
	}

	tmpDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmpDir, "hello.go"), []byte("package main\n"), 0o644); err != nil {
		t.Fatalf("write test file: %v", err)
	}

	result, err := sc.ScanDirectory(tmpDir)
	if err != nil {
		t.Fatalf("ScanDirectory: %v", err)
	}
	if result == nil {
		t.Fatal("ScanDirectory returned nil result")
	}
}

// ---------------------------------------------------------------------------
// TestDBManagerCreationWithMock
//
// Phase 2: serve() will call database.NewManager(vaultClient).
// Verify the Manager can be constructed with a mock and is non-nil.
// ---------------------------------------------------------------------------

func TestDBManagerCreationWithMock(t *testing.T) {
	t.Parallel()

	vc := &mockVaultClient{}
	mgr := database.NewManager(vc)
	if mgr == nil {
		t.Fatal("database.NewManager returned nil")
	}

	dbs := mgr.ListDatabases()
	if len(dbs) != 0 {
		t.Errorf("expected empty database list, got %v", dbs)
	}

	// Close must not panic.
	mgr.Close()
}

// ---------------------------------------------------------------------------
// TestDBManagerGetCredentialsUsesReadOnlyLease
//
// Phase 2: GetCredentials must request a "readonly" vault role and cache the
// lease so the mock is only called once on repeated calls.
// ---------------------------------------------------------------------------

func TestDBManagerGetCredentialsUsesReadOnlyLease(t *testing.T) {
	t.Parallel()

	vc := &mockVaultClient{
		dynamicCreds: map[string]interface{}{
			"username": "testuser",
			"password": "testpass",
		},
		dynamicLeaseID:  "lease-1",
		dynamicLeaseTTL: 900,
	}
	mgr := database.NewManager(vc)
	defer mgr.Close()

	// First call — must reach the vault mock.
	user, pass, leaseID, err := mgr.GetCredentials("mydb", "readonly")
	if err != nil {
		t.Fatalf("GetCredentials (first): %v", err)
	}
	if user != "testuser" {
		t.Errorf("username = %q, want %q", user, "testuser")
	}
	if pass != "testpass" {
		t.Errorf("password = %q, want %q", pass, "testpass")
	}
	if leaseID != "lease-1" {
		t.Errorf("leaseID = %q, want %q", leaseID, "lease-1")
	}
	if vc.callCount != 1 {
		t.Errorf("vault called %d time(s) on first GetCredentials, want 1", vc.callCount)
	}

	// Second call — must return cached values; vault NOT called again.
	user2, pass2, leaseID2, err := mgr.GetCredentials("mydb", "readonly")
	if err != nil {
		t.Fatalf("GetCredentials (second): %v", err)
	}
	if user2 != user || pass2 != pass || leaseID2 != leaseID {
		t.Errorf("cached values differ: got (%q,%q,%q), want (%q,%q,%q)", user2, pass2, leaseID2, user, pass, leaseID)
	}
	if vc.callCount != 1 {
		t.Errorf("vault called %d time(s) after second GetCredentials, want still 1 (cached)", vc.callCount)
	}
}

// ---------------------------------------------------------------------------
// TestDBManagerRevokeAllAndClose
//
// Phase 2 shutdown path: serve() must call mgr.RevokeAll() then mgr.Close()
// to invalidate temporary DB users on shutdown.
// ---------------------------------------------------------------------------

func TestDBManagerRevokeAllAndClose(t *testing.T) {
	t.Parallel()

	vc := &mockVaultClient{}
	mgr := database.NewManager(vc)

	// RevokeAll and Close must not panic.
	mgr.RevokeAll()
	mgr.Close()
}
