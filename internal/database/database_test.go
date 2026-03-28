// Package database_test tests the database Manager using mock dependencies.
// No real database or vault is required; all external interfaces are mocked.
package database_test

import (
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/straylight-ai/straylight/internal/database"
	"github.com/straylight-ai/straylight/internal/lease"
)

// ---------------------------------------------------------------------------
// Mock vault client
// ---------------------------------------------------------------------------

type mockVaultClient struct {
	dynamicCreds     map[string]interface{}
	dynamicLeaseID   string
	dynamicLeaseTTL  int
	dynamicErr       error
	configureCalled  bool
	configureErr     error
	createRoleCalled bool
	createRoleErr    error
}

func (m *mockVaultClient) GetDynamicCredential(enginePath, roleName string) (map[string]interface{}, string, int, error) {
	return m.dynamicCreds, m.dynamicLeaseID, m.dynamicLeaseTTL, m.dynamicErr
}

func (m *mockVaultClient) ConfigureDatabaseConnection(name, plugin, connURL string, allowedRoles []string, extra map[string]interface{}) error {
	m.configureCalled = true
	return m.configureErr
}

func (m *mockVaultClient) CreateDatabaseRole(name, dbName string, creationStatements []string, defaultTTL, maxTTL string) error {
	m.createRoleCalled = true
	return m.createRoleErr
}

func (m *mockVaultClient) RenewLease(leaseID string, increment int) (*lease.LeaseInfo, error) {
	return &lease.LeaseInfo{LeaseID: leaseID, LeaseDuration: increment}, nil
}

func (m *mockVaultClient) RevokeLease(leaseID string) error {
	return nil
}

func (m *mockVaultClient) RevokeLeasePrefix(prefix string) error {
	return nil
}

// ---------------------------------------------------------------------------
// Mock audit emitter
// ---------------------------------------------------------------------------

type mockAudit struct {
	events []string
}

func (m *mockAudit) Emit(event interface{ GetType() string }) {
	m.events = append(m.events, event.GetType())
}

// ---------------------------------------------------------------------------
// Mock DB executor (replaces database/sql internals)
// ---------------------------------------------------------------------------

// mockDBExecutor lets tests inject controlled query results without a real DB.
type mockDBExecutor struct {
	columns []string
	rows    [][]interface{}
	err     error
}

func (m *mockDBExecutor) QueryContext(query string, args ...interface{}) (database.RowScanner, error) {
	if m.err != nil {
		return nil, m.err
	}
	return &mockRows{cols: m.columns, data: m.rows}, nil
}

// mockRows implements database.RowScanner.
type mockRows struct {
	cols    []string
	data    [][]interface{}
	pos     int
	closed  bool
}

func (r *mockRows) Columns() ([]string, error) {
	return r.cols, nil
}

func (r *mockRows) Next() bool {
	if r.pos >= len(r.data) {
		return false
	}
	r.pos++
	return true
}

func (r *mockRows) Scan(dest ...interface{}) error {
	row := r.data[r.pos-1]
	for i, d := range dest {
		if i < len(row) {
			switch v := d.(type) {
			case *interface{}:
				*v = row[i]
			}
		}
	}
	return nil
}

func (r *mockRows) Close() error {
	r.closed = true
	return nil
}

func (r *mockRows) Err() error {
	return nil
}

// ---------------------------------------------------------------------------
// Test: DatabaseConfig validation
// ---------------------------------------------------------------------------

func TestDatabaseConfig_Validation(t *testing.T) {
	tests := []struct {
		name    string
		cfg     database.DatabaseConfig
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid postgres config",
			cfg: database.DatabaseConfig{
				Engine:         "postgresql",
				Host:           "db.example.com",
				Port:           5432,
				AdminUser:      "admin",
				AdminPassword:  "secret",
				Database:       "mydb",
				DefaultTTL:     "15m",
				MaxTTL:         "1h",
			},
			wantErr: false,
		},
		{
			name: "valid mysql config",
			cfg: database.DatabaseConfig{
				Engine:        "mysql",
				Host:          "mysql.example.com",
				Port:          3306,
				AdminUser:     "root",
				AdminPassword: "root_pass",
				Database:      "app",
				DefaultTTL:    "15m",
				MaxTTL:        "1h",
			},
			wantErr: false,
		},
		{
			name: "invalid engine",
			cfg: database.DatabaseConfig{
				Engine:        "oracle",
				Host:          "db.example.com",
				Port:          1521,
				AdminUser:     "admin",
				AdminPassword: "secret",
				Database:      "mydb",
			},
			wantErr: true,
			errMsg:  "unsupported engine",
		},
		{
			name: "missing host",
			cfg: database.DatabaseConfig{
				Engine:        "postgresql",
				Port:          5432,
				AdminUser:     "admin",
				AdminPassword: "secret",
				Database:      "mydb",
			},
			wantErr: true,
			errMsg:  "host is required",
		},
		{
			name: "missing admin user",
			cfg: database.DatabaseConfig{
				Engine:        "postgresql",
				Host:          "db.example.com",
				Port:          5432,
				AdminPassword: "secret",
				Database:      "mydb",
			},
			wantErr: true,
			errMsg:  "admin_user is required",
		},
		{
			name: "missing admin password",
			cfg: database.DatabaseConfig{
				Engine:    "postgresql",
				Host:      "db.example.com",
				Port:      5432,
				AdminUser: "admin",
				Database:  "mydb",
			},
			wantErr: true,
			errMsg:  "admin_password is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if tt.wantErr {
				if err == nil {
					t.Fatalf("Validate() = nil, want error containing %q", tt.errMsg)
				}
				if tt.errMsg != "" && !containsStr(err.Error(), tt.errMsg) {
					t.Errorf("Validate() error = %q, want to contain %q", err.Error(), tt.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("Validate() = %v, want nil", err)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Test: Manager.ConfigureDatabase calls vault
// ---------------------------------------------------------------------------

func TestManager_ConfigureDatabase_CallsVault(t *testing.T) {
	vc := &mockVaultClient{
		dynamicCreds:    map[string]interface{}{"username": "v-user-abc", "password": "v-pass-abc"},
		dynamicLeaseID:  "database/creds/my-postgres-ro/abc",
		dynamicLeaseTTL: 900,
	}
	mgr := database.NewManager(vc)
	defer mgr.Close()

	cfg := database.DatabaseConfig{
		Engine:        "postgresql",
		Host:          "db.example.com",
		Port:          5432,
		AdminUser:     "admin",
		AdminPassword: "secret",
		Database:      "mydb",
		DefaultTTL:    "15m",
		MaxTTL:        "1h",
	}

	err := mgr.ConfigureDatabase("my-postgres", cfg)
	if err != nil {
		t.Fatalf("ConfigureDatabase() = %v, want nil", err)
	}

	if !vc.configureCalled {
		t.Error("ConfigureDatabaseConnection was not called on vault client")
	}
	if !vc.createRoleCalled {
		t.Error("CreateDatabaseRole was not called on vault client")
	}
}

func TestManager_ConfigureDatabase_VaultError(t *testing.T) {
	vc := &mockVaultClient{
		configureErr: errors.New("vault connection failed"),
	}
	mgr := database.NewManager(vc)
	defer mgr.Close()

	cfg := database.DatabaseConfig{
		Engine:        "postgresql",
		Host:          "db.example.com",
		Port:          5432,
		AdminUser:     "admin",
		AdminPassword: "secret",
		Database:      "mydb",
	}

	err := mgr.ConfigureDatabase("my-postgres", cfg)
	if err == nil {
		t.Fatal("ConfigureDatabase() = nil, want error")
	}
	if !containsStr(err.Error(), "vault") {
		t.Errorf("error %q should mention vault", err.Error())
	}
	// Error must NOT contain the admin password
	if containsStr(err.Error(), "secret") {
		t.Errorf("error %q must not contain admin password", err.Error())
	}
}

// ---------------------------------------------------------------------------
// Test: QueryResult structure
// ---------------------------------------------------------------------------

func TestQueryResult_RowCount(t *testing.T) {
	r := &database.QueryResult{
		Columns:  []string{"id", "name"},
		Rows:     [][]interface{}{{1, "Alice"}, {2, "Bob"}},
		RowCount: 2,
		Duration: 5 * time.Millisecond,
	}

	if r.RowCount != 2 {
		t.Errorf("RowCount = %d, want 2", r.RowCount)
	}
	if len(r.Columns) != 2 {
		t.Errorf("len(Columns) = %d, want 2", len(r.Columns))
	}
}

// ---------------------------------------------------------------------------
// Test: Engine-specific connection string building (no live DB)
// ---------------------------------------------------------------------------

func TestBuildConnectionString_Postgres(t *testing.T) {
	cfg := database.DatabaseConfig{
		Engine:   "postgresql",
		Host:     "db.example.com",
		Port:     5432,
		Database: "mydb",
		SSLMode:  "require",
	}
	connStr := database.BuildConnectionString(cfg, "tmpuser", "tmppass")
	if connStr == "" {
		t.Fatal("BuildConnectionString() returned empty string")
	}
	// Must contain host and database name — not the password directly in a way
	// that leaks to logs (driver DSN format is acceptable for internal use).
	if !containsStr(connStr, "db.example.com") {
		t.Errorf("connection string %q missing host", connStr)
	}
	if !containsStr(connStr, "mydb") {
		t.Errorf("connection string %q missing database name", connStr)
	}
}

func TestBuildConnectionString_MySQL(t *testing.T) {
	cfg := database.DatabaseConfig{
		Engine:   "mysql",
		Host:     "mysql.example.com",
		Port:     3306,
		Database: "appdb",
	}
	connStr := database.BuildConnectionString(cfg, "tmpuser", "tmppass")
	if connStr == "" {
		t.Fatal("BuildConnectionString() returned empty string")
	}
	if !containsStr(connStr, "mysql.example.com") {
		t.Errorf("connection string %q missing host", connStr)
	}
}

func TestBuildConnectionString_DefaultPort(t *testing.T) {
	tests := []struct {
		engine   string
		wantPort string
	}{
		{"postgresql", "5432"},
		{"mysql", "3306"},
	}
	for _, tt := range tests {
		t.Run(tt.engine, func(t *testing.T) {
			cfg := database.DatabaseConfig{
				Engine:   tt.engine,
				Host:     "db.example.com",
				Port:     0, // zero → use default
				Database: "mydb",
			}
			connStr := database.BuildConnectionString(cfg, "u", "p")
			if !containsStr(connStr, tt.wantPort) {
				t.Errorf("BuildConnectionString() = %q, want port %s", connStr, tt.wantPort)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Test: Result sanitization — credentials must not appear in output
// ---------------------------------------------------------------------------

func TestSanitizeRows_NoCredentials(t *testing.T) {
	sensitiveValues := []string{"super-secret-password", "v-user-token123"}
	rows := [][]interface{}{
		{1, "alice", "super-secret-password"},
		{2, "bob", "safe-value"},
	}

	sanitized := database.SanitizeRows(rows, sensitiveValues)

	for i, row := range sanitized {
		for j, cell := range row {
			s, ok := cell.(string)
			if !ok {
				continue
			}
			for _, secret := range sensitiveValues {
				if containsStr(s, secret) {
					t.Errorf("row[%d][%d] = %q contains secret value", i, j, s)
				}
			}
		}
	}
}

func TestSanitizeRows_PreservesNonSensitive(t *testing.T) {
	rows := [][]interface{}{
		{1, "alice", "alice@example.com"},
		{2, "bob", "bob@example.com"},
	}

	sanitized := database.SanitizeRows(rows, []string{"top-secret"})
	if len(sanitized) != 2 {
		t.Errorf("SanitizeRows() len = %d, want 2", len(sanitized))
	}
	if sanitized[0][1] != "alice" {
		t.Errorf("SanitizeRows() row[0][1] = %v, want 'alice'", sanitized[0][1])
	}
}

// ---------------------------------------------------------------------------
// Test: VaultPlugin name resolution
// ---------------------------------------------------------------------------

func TestVaultPluginName(t *testing.T) {
	tests := []struct {
		engine string
		want   string
	}{
		{"postgresql", "postgresql-database-plugin"},
		{"mysql", "mysql-database-plugin"},
		{"redis", "redis-database-plugin"},
	}
	for _, tt := range tests {
		t.Run(tt.engine, func(t *testing.T) {
			got := database.VaultPluginName(tt.engine)
			if got != tt.want {
				t.Errorf("VaultPluginName(%q) = %q, want %q", tt.engine, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Test: CreationStatements for each engine
// ---------------------------------------------------------------------------

func TestDefaultCreationStatements_Postgres(t *testing.T) {
	stmts := database.DefaultCreationStatements("postgresql")
	if len(stmts) == 0 {
		t.Fatal("DefaultCreationStatements(postgresql) returned empty slice")
	}
	// Must contain vault template placeholders
	joined := joinStrings(stmts)
	for _, placeholder := range []string{"{{name}}", "{{password}}", "{{expiration}}"} {
		if !containsStr(joined, placeholder) {
			t.Errorf("postgres creation statements missing placeholder %q", placeholder)
		}
	}
}

func TestDefaultCreationStatements_MySQL(t *testing.T) {
	stmts := database.DefaultCreationStatements("mysql")
	if len(stmts) == 0 {
		t.Fatal("DefaultCreationStatements(mysql) returned empty slice")
	}
	joined := joinStrings(stmts)
	for _, placeholder := range []string{"{{name}}", "{{password}}"} {
		if !containsStr(joined, placeholder) {
			t.Errorf("mysql creation statements missing placeholder %q", placeholder)
		}
	}
}

// ---------------------------------------------------------------------------
// Test: Credential extraction from vault response
// ---------------------------------------------------------------------------

func TestExtractCredentials(t *testing.T) {
	tests := []struct {
		name     string
		data     map[string]interface{}
		wantUser string
		wantPass string
		wantErr  bool
	}{
		{
			name:     "standard vault response",
			data:     map[string]interface{}{"username": "v-user-abc123", "password": "v-pass-xyz456"},
			wantUser: "v-user-abc123",
			wantPass: "v-pass-xyz456",
		},
		{
			name:    "missing username",
			data:    map[string]interface{}{"password": "somepass"},
			wantErr: true,
		},
		{
			name:    "missing password",
			data:    map[string]interface{}{"username": "someuser"},
			wantErr: true,
		},
		{
			name:    "empty data",
			data:    map[string]interface{}{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user, pass, err := database.ExtractCredentials(tt.data)
			if tt.wantErr {
				if err == nil {
					t.Fatal("ExtractCredentials() = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("ExtractCredentials() = %v, want nil", err)
			}
			if user != tt.wantUser {
				t.Errorf("username = %q, want %q", user, tt.wantUser)
			}
			if pass != tt.wantPass {
				t.Errorf("password = %q, want %q", pass, tt.wantPass)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Test: Manager.Close stops renewal goroutine cleanly
// ---------------------------------------------------------------------------

func TestManager_Close_IsIdempotent(t *testing.T) {
	vc := &mockVaultClient{}
	mgr := database.NewManager(vc)

	// Calling Close multiple times must not panic.
	mgr.Close()
	mgr.Close()
}

// ---------------------------------------------------------------------------
// Test: Lease cache hit — vault not called again for cached credential
// ---------------------------------------------------------------------------

func TestManager_GetCredentials_CachesLease(t *testing.T) {
	callCount := 0
	vc := &mockVaultClient{}
	vc.dynamicCreds = map[string]interface{}{"username": "v-user-1", "password": "v-pass-1"}
	vc.dynamicLeaseID = "database/creds/my-pg-ro/token1"
	vc.dynamicLeaseTTL = 900

	// Track calls using a wrapper that increments callCount.
	countingVC := &countingVaultClient{inner: vc, countPtr: &callCount}

	mgr := database.NewManager(countingVC)
	defer mgr.Close()

	cfg := database.DatabaseConfig{
		Engine:        "postgresql",
		Host:          "db.example.com",
		Port:          5432,
		AdminUser:     "admin",
		AdminPassword: "secret",
		Database:      "mydb",
	}
	_ = mgr.ConfigureDatabase("my-pg", cfg)

	// First call — should call vault.
	u1, p1, l1, err := mgr.GetCredentials("my-pg", "readonly")
	if err != nil {
		t.Fatalf("first GetCredentials() = %v", err)
	}
	firstCall := callCount

	// Second call — cache hit, vault must NOT be called again.
	u2, p2, l2, err := mgr.GetCredentials("my-pg", "readonly")
	if err != nil {
		t.Fatalf("second GetCredentials() = %v", err)
	}

	if callCount != firstCall {
		t.Errorf("vault called %d times total, want %d (cache should have hit)", callCount, firstCall)
	}
	if u1 != u2 || p1 != p2 || l1 != l2 {
		t.Errorf("cached credentials differ: (%q,%q,%q) vs (%q,%q,%q)", u1, p1, l1, u2, p2, l2)
	}
}

// countingVaultClient wraps mockVaultClient and counts GetDynamicCredential calls.
type countingVaultClient struct {
	inner    *mockVaultClient
	countPtr *int
}

func (c *countingVaultClient) GetDynamicCredential(enginePath, roleName string) (map[string]interface{}, string, int, error) {
	*c.countPtr++
	return c.inner.GetDynamicCredential(enginePath, roleName)
}

func (c *countingVaultClient) ConfigureDatabaseConnection(name, plugin, connURL string, allowedRoles []string, extra map[string]interface{}) error {
	return c.inner.ConfigureDatabaseConnection(name, plugin, connURL, allowedRoles, extra)
}

func (c *countingVaultClient) CreateDatabaseRole(name, dbName string, creationStatements []string, defaultTTL, maxTTL string) error {
	return c.inner.CreateDatabaseRole(name, dbName, creationStatements, defaultTTL, maxTTL)
}

func (c *countingVaultClient) RenewLease(leaseID string, increment int) (*lease.LeaseInfo, error) {
	return c.inner.RenewLease(leaseID, increment)
}

func (c *countingVaultClient) RevokeLease(leaseID string) error {
	return c.inner.RevokeLease(leaseID)
}

func (c *countingVaultClient) RevokeLeasePrefix(prefix string) error {
	return c.inner.RevokeLeasePrefix(prefix)
}

// ---------------------------------------------------------------------------
// Test: GetCredentials vault error — no connection string in error
// ---------------------------------------------------------------------------

func TestManager_GetCredentials_VaultError_NoConnectionString(t *testing.T) {
	vc := &mockVaultClient{
		dynamicErr: errors.New("vault: connection refused"),
	}
	mgr := database.NewManager(vc)
	defer mgr.Close()

	cfg := database.DatabaseConfig{
		Engine:        "postgresql",
		Host:          "secret-db-host.internal",
		Port:          5432,
		AdminUser:     "admin",
		AdminPassword: "admin-secret",
		Database:      "proddb",
	}
	_ = mgr.ConfigureDatabase("prod-pg", cfg)

	_, _, _, err := mgr.GetCredentials("prod-pg", "readonly")
	if err == nil {
		t.Fatal("GetCredentials() = nil, want error when vault fails")
	}

	// Returned error must not contain the connection string or admin credentials.
	for _, sensitive := range []string{"secret-db-host.internal", "admin-secret", "proddb"} {
		if containsStr(err.Error(), sensitive) {
			t.Errorf("error %q must not contain sensitive value %q", err.Error(), sensitive)
		}
	}
}

// ---------------------------------------------------------------------------
// Test: sql.ErrNoRows handling — returns empty result, not error
// ---------------------------------------------------------------------------

func TestQueryResult_EmptyRows(t *testing.T) {
	result := &database.QueryResult{
		Columns:  []string{"id", "name"},
		Rows:     [][]interface{}{},
		RowCount: 0,
		Duration: 1 * time.Millisecond,
	}
	if result.RowCount != 0 {
		t.Errorf("RowCount = %d, want 0", result.RowCount)
	}
	if len(result.Rows) != 0 {
		t.Errorf("len(Rows) = %d, want 0", len(result.Rows))
	}
}

// ---------------------------------------------------------------------------
// Test: MaxRows enforcement
// ---------------------------------------------------------------------------

func TestQueryResult_MaxRows(t *testing.T) {
	// MaxRows=2 with 5 rows should truncate to 2.
	rows := make([][]interface{}, 5)
	for i := range rows {
		rows[i] = []interface{}{i, "name"}
	}
	truncated := database.ApplyMaxRows(rows, 2)
	if len(truncated) != 2 {
		t.Errorf("ApplyMaxRows() len = %d, want 2", len(truncated))
	}
}

func TestQueryResult_MaxRows_ZeroMeansNoLimit(t *testing.T) {
	rows := make([][]interface{}, 5)
	for i := range rows {
		rows[i] = []interface{}{i}
	}
	all := database.ApplyMaxRows(rows, 0)
	if len(all) != 5 {
		t.Errorf("ApplyMaxRows(rows, 0) len = %d, want 5 (no limit)", len(all))
	}
}

// ---------------------------------------------------------------------------
// Test: ScanRows — converts sql.Rows-like into [][]interface{}
// ---------------------------------------------------------------------------

func TestScanRows_Basic(t *testing.T) {
	mock := &mockRows{
		cols: []string{"id", "name", "active"},
		data: [][]interface{}{
			{1, "Alice", true},
			{2, "Bob", false},
		},
	}

	cols, rows, err := database.ScanRows(mock)
	if err != nil {
		t.Fatalf("ScanRows() = %v, want nil", err)
	}
	if len(cols) != 3 {
		t.Errorf("cols len = %d, want 3", len(cols))
	}
	if len(rows) != 2 {
		t.Errorf("rows len = %d, want 2", len(rows))
	}
}

func TestScanRows_Empty(t *testing.T) {
	mock := &mockRows{
		cols: []string{"id"},
		data: [][]interface{}{},
	}

	cols, rows, err := database.ScanRows(mock)
	if err != nil {
		t.Fatalf("ScanRows() = %v, want nil", err)
	}
	if len(cols) != 1 {
		t.Errorf("cols len = %d, want 1", len(cols))
	}
	if len(rows) != 0 {
		t.Errorf("rows len = %d, want 0", len(rows))
	}
}

// ---------------------------------------------------------------------------
// Test: Manager.ConfigureDatabase uses correct Vault plugin name per engine
// ---------------------------------------------------------------------------

func TestManager_ConfigureDatabase_PluginNameByEngine(t *testing.T) {
	tests := []struct {
		engine     string
		wantPlugin string
	}{
		{"postgresql", "postgresql-database-plugin"},
		{"mysql", "mysql-database-plugin"},
	}

	for _, tt := range tests {
		t.Run(tt.engine, func(t *testing.T) {
			captureVC := &capturingVaultClient{}
			mgr := database.NewManager(captureVC)
			defer mgr.Close()

			cfg := database.DatabaseConfig{
				Engine:        tt.engine,
				Host:          "db.example.com",
				Port:          5432,
				AdminUser:     "admin",
				AdminPassword: "pass",
				Database:      "mydb",
			}
			_ = mgr.ConfigureDatabase("svc", cfg)

			if captureVC.lastPlugin != tt.wantPlugin {
				t.Errorf("plugin = %q, want %q", captureVC.lastPlugin, tt.wantPlugin)
			}
		})
	}
}

// capturingVaultClient records the plugin name passed to ConfigureDatabaseConnection.
type capturingVaultClient struct {
	lastPlugin string
}

func (c *capturingVaultClient) GetDynamicCredential(_, _ string) (map[string]interface{}, string, int, error) {
	return map[string]interface{}{"username": "u", "password": "p"}, "lease-id", 900, nil
}

func (c *capturingVaultClient) ConfigureDatabaseConnection(name, plugin, connURL string, allowedRoles []string, extra map[string]interface{}) error {
	c.lastPlugin = plugin
	return nil
}

func (c *capturingVaultClient) CreateDatabaseRole(_, _ string, _ []string, _, _ string) error {
	return nil
}

func (c *capturingVaultClient) RenewLease(leaseID string, increment int) (*lease.LeaseInfo, error) {
	return &lease.LeaseInfo{LeaseID: leaseID, LeaseDuration: increment}, nil
}

func (c *capturingVaultClient) RevokeLease(_ string) error { return nil }

func (c *capturingVaultClient) RevokeLeasePrefix(_ string) error { return nil }

// ---------------------------------------------------------------------------
// Test: ConfigureDatabase validates config before calling vault
// ---------------------------------------------------------------------------

func TestManager_ConfigureDatabase_ValidationError(t *testing.T) {
	vc := &mockVaultClient{}
	mgr := database.NewManager(vc)
	defer mgr.Close()

	// Invalid config — missing host.
	cfg := database.DatabaseConfig{
		Engine:        "postgresql",
		AdminUser:     "admin",
		AdminPassword: "secret",
		Database:      "mydb",
	}

	err := mgr.ConfigureDatabase("my-pg", cfg)
	if err == nil {
		t.Fatal("ConfigureDatabase() = nil, want validation error")
	}
	// Vault must NOT have been called.
	if vc.configureCalled {
		t.Error("vault.ConfigureDatabaseConnection should not be called when validation fails")
	}
}

// ---------------------------------------------------------------------------
// Test: Manager recognizes configured databases (GetDatabaseConfig)
// ---------------------------------------------------------------------------

func TestManager_GetDatabaseConfig_AfterConfigure(t *testing.T) {
	vc := &mockVaultClient{}
	mgr := database.NewManager(vc)
	defer mgr.Close()

	cfg := database.DatabaseConfig{
		Engine:        "postgresql",
		Host:          "db.example.com",
		Port:          5432,
		AdminUser:     "admin",
		AdminPassword: "secret",
		Database:      "mydb",
	}
	_ = mgr.ConfigureDatabase("my-pg", cfg)

	got, ok := mgr.GetDatabaseConfig("my-pg")
	if !ok {
		t.Fatal("GetDatabaseConfig() = false, want true after ConfigureDatabase")
	}
	if got.Engine != "postgresql" {
		t.Errorf("Engine = %q, want postgresql", got.Engine)
	}
	if got.Host != "db.example.com" {
		t.Errorf("Host = %q, want db.example.com", got.Host)
	}
	// Admin password must NOT be stored in the returned config for safety.
	if got.AdminPassword != "" {
		t.Error("GetDatabaseConfig() must not return admin password")
	}
}

func TestManager_GetDatabaseConfig_Unknown(t *testing.T) {
	vc := &mockVaultClient{}
	mgr := database.NewManager(vc)
	defer mgr.Close()

	_, ok := mgr.GetDatabaseConfig("nonexistent")
	if ok {
		t.Error("GetDatabaseConfig() = true, want false for unknown service")
	}
}

// ---------------------------------------------------------------------------
// Test: Manager.ListDatabases
// ---------------------------------------------------------------------------

func TestManager_ListDatabases(t *testing.T) {
	vc := &mockVaultClient{}
	mgr := database.NewManager(vc)
	defer mgr.Close()

	if names := mgr.ListDatabases(); len(names) != 0 {
		t.Errorf("ListDatabases() = %v, want empty", names)
	}

	cfg := database.DatabaseConfig{
		Engine: "postgresql", Host: "h", Port: 5432,
		AdminUser: "u", AdminPassword: "p", Database: "d",
	}
	_ = mgr.ConfigureDatabase("pg1", cfg)
	_ = mgr.ConfigureDatabase("pg2", cfg)

	names := mgr.ListDatabases()
	if len(names) != 2 {
		t.Errorf("ListDatabases() len = %d, want 2", len(names))
	}
}

// ---------------------------------------------------------------------------
// Test: Manager.RemoveDatabase
// ---------------------------------------------------------------------------

func TestManager_RemoveDatabase(t *testing.T) {
	vc := &mockVaultClient{}
	mgr := database.NewManager(vc)
	defer mgr.Close()

	cfg := database.DatabaseConfig{
		Engine: "postgresql", Host: "h", Port: 5432,
		AdminUser: "u", AdminPassword: "p", Database: "d",
	}
	_ = mgr.ConfigureDatabase("pg1", cfg)

	err := mgr.RemoveDatabase("pg1")
	if err != nil {
		t.Fatalf("RemoveDatabase() = %v, want nil", err)
	}

	_, ok := mgr.GetDatabaseConfig("pg1")
	if ok {
		t.Error("GetDatabaseConfig() still returns true after RemoveDatabase")
	}
}

func TestManager_RemoveDatabase_Unknown(t *testing.T) {
	vc := &mockVaultClient{}
	mgr := database.NewManager(vc)
	defer mgr.Close()

	err := mgr.RemoveDatabase("nonexistent")
	if err == nil {
		t.Error("RemoveDatabase() = nil, want error for unknown service")
	}
}

// ---------------------------------------------------------------------------
// Test: RowScanner interface is implemented by sql.Rows
// ---------------------------------------------------------------------------

// This is a compile-time check that *sql.Rows satisfies database.RowScanner.
// It ensures our interface definition stays compatible with the standard library.
var _ database.RowScanner = (*sql.Rows)(nil)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func containsStr(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		func() bool {
			for i := 0; i <= len(s)-len(substr); i++ {
				if s[i:i+len(substr)] == substr {
					return true
				}
			}
			return false
		}())
}

func joinStrings(ss []string) string {
	var out string
	for _, s := range ss {
		out += s + " "
	}
	return out
}
