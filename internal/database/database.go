// Package database provides dynamic database credential management and query execution.
//
// The Manager coordinates:
//   - Vault dynamic credentials via the database secrets engine
//   - Lease lifecycle management (caching, renewal, revocation)
//   - Database connections using Go's database/sql
//   - Query execution with parameterized queries
//   - Result sanitization before returning to callers
//
// AI callers (via straylight_db_query) never see database passwords or connection strings.
// Credentials exist only inside the Manager and are sourced from OpenBao leases.
package database

import (
	"database/sql"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/straylight-ai/straylight/internal/lease"
)

// supportedEngines is the set of valid database engine values.
var supportedEngines = map[string]bool{
	"postgresql": true,
	"mysql":      true,
	"redis":      true,
}

// defaultPorts maps an engine name to its well-known port.
var defaultPorts = map[string]int{
	"postgresql": 5432,
	"mysql":      3306,
	"redis":      6379,
}

// vaultPluginNames maps an engine name to the OpenBao database plugin name.
var vaultPluginNames = map[string]string{
	"postgresql": "postgresql-database-plugin",
	"mysql":      "mysql-database-plugin",
	"redis":      "redis-database-plugin",
}

// DatabaseConfig holds the configuration required to register a database with
// OpenBao's database secrets engine and generate temporary credentials.
type DatabaseConfig struct {
	// Engine is the database engine type: postgresql, mysql, or redis.
	Engine string
	// Host is the database server hostname.
	Host string
	// Port is the database server port (0 = use default for engine).
	Port int
	// AdminUser is the admin username OpenBao uses to create temporary users.
	AdminUser string
	// AdminPassword is the admin password (never returned by GetDatabaseConfig).
	AdminPassword string
	// Database is the database/schema name (not used for redis).
	Database string
	// SSLMode is the TLS/SSL mode: disable, require, verify-ca, verify-full.
	SSLMode string
	// DefaultTTL is the default lease TTL for temporary credentials (e.g., "15m").
	DefaultTTL string
	// MaxTTL is the maximum lease TTL (e.g., "1h").
	MaxTTL string
	// AllowedStatements is the SQL whitelist for the role's creation statements.
	// When nil or empty, DefaultCreationStatements is used.
	AllowedStatements []string
}

// Validate checks that all required fields are present and the engine is supported.
func (c DatabaseConfig) Validate() error {
	if !supportedEngines[c.Engine] {
		return fmt.Errorf("database: unsupported engine %q: must be postgresql, mysql, or redis", c.Engine)
	}
	if c.Host == "" {
		return fmt.Errorf("database: host is required")
	}
	if c.AdminUser == "" {
		return fmt.Errorf("database: admin_user is required")
	}
	if c.AdminPassword == "" {
		return fmt.Errorf("database: admin_password is required")
	}
	return nil
}

// resolvedPort returns Port if set, otherwise the default port for Engine.
func (c DatabaseConfig) resolvedPort() int {
	if c.Port > 0 {
		return c.Port
	}
	return defaultPorts[c.Engine]
}

// QueryResult holds the output of a successful database query.
type QueryResult struct {
	// Columns is the ordered list of column names.
	Columns []string
	// Rows contains the row data; each row is a slice of column values.
	Rows [][]interface{}
	// RowCount is the number of rows returned.
	RowCount int
	// Duration is the time taken to execute the query.
	Duration time.Duration
	// LeaseID is the vault lease ID of the credentials used.
	LeaseID string
	// LeaseTTLSeconds is the remaining TTL of the lease.
	LeaseTTLSeconds int
	// Engine is the database engine that executed the query.
	Engine string
}

// RowScanner is the interface satisfied by *sql.Rows. It enables injection of
// mock row scanners in tests without requiring a real database connection.
type RowScanner interface {
	Columns() ([]string, error)
	Next() bool
	Scan(dest ...interface{}) error
	Close() error
	Err() error
}

// VaultClient is the interface the Manager uses for dynamic credential operations.
// Implemented by *vault.Client; use a mock in tests.
type VaultClient interface {
	GetDynamicCredential(enginePath, roleName string) (creds map[string]interface{}, leaseID string, leaseDuration int, err error)
	ConfigureDatabaseConnection(name, plugin, connURL string, allowedRoles []string, extra map[string]interface{}) error
	CreateDatabaseRole(name, dbName string, creationStatements []string, defaultTTL, maxTTL string) error
	RenewLease(leaseID string, increment int) (*lease.LeaseInfo, error)
	RevokeLease(leaseID string) error
	RevokeLeasePrefix(prefix string) error
}

// dbEntry stores a registered database configuration (without admin password)
// and its associated lease manager entry.
type dbEntry struct {
	config    DatabaseConfig // AdminPassword is zeroed on store for safety
	engine    string
	roleSuffix string // e.g., "ro" or "rw"
}

// Manager coordinates database configuration, dynamic credential management,
// and connection pooling for the straylight_db_query MCP tool.
//
// The AI never sees passwords or connection strings — they exist only inside
// Manager and are sourced from OpenBao lease data.
type Manager struct {
	mu       sync.RWMutex
	vault    VaultClient
	leases   *lease.Manager
	dbs      map[string]dbEntry // key: service name
	logger   *slog.Logger
}

// NewManager creates a Manager backed by the given VaultClient.
// The lease manager is started automatically.
func NewManager(vc VaultClient) *Manager {
	return &Manager{
		vault:  vc,
		leases: lease.NewManager(vc),
		dbs:    make(map[string]dbEntry),
		logger: slog.Default(),
	}
}

// Close stops the internal renewal goroutine. Call RevokeAll before Close for
// a clean shutdown that invalidates all temporary database users.
func (m *Manager) Close() {
	m.leases.Close()
}

// RevokeAll revokes all active lease credentials. Call during server shutdown.
func (m *Manager) RevokeAll() {
	m.leases.RevokeAll()
}

// ConfigureDatabase registers a database with OpenBao's database secrets engine.
// It validates the config, builds the plugin connection URL, and creates a
// read-only vault role for temporary credential generation.
//
// The admin password is NOT stored in the Manager after setup — it is passed
// to vault once and then discarded from memory.
func (m *Manager) ConfigureDatabase(name string, cfg DatabaseConfig) error {
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("database: configure %q: %w", name, err)
	}

	plugin := VaultPluginName(cfg.Engine)
	connURL := buildVaultConnectionURL(cfg)
	roRoleName := name + "-ro"
	rwRoleName := name + "-rw"
	allowedRoles := []string{roRoleName, rwRoleName}

	extra := map[string]interface{}{
		"username": cfg.AdminUser,
		"password": cfg.AdminPassword,
	}

	// Configure the database connection in vault (admin creds used by vault only).
	if err := m.vault.ConfigureDatabaseConnection(name, plugin, connURL, allowedRoles, extra); err != nil {
		// Sanitize: do not include connection string or admin password in error.
		return fmt.Errorf("database: configure connection %q: vault call failed", name)
	}

	// Create the read-only role.
	creationStmts := cfg.AllowedStatements
	if len(creationStmts) == 0 {
		creationStmts = DefaultCreationStatements(cfg.Engine)
	}
	defaultTTL := cfg.DefaultTTL
	if defaultTTL == "" {
		defaultTTL = "15m"
	}
	maxTTL := cfg.MaxTTL
	if maxTTL == "" {
		maxTTL = "1h"
	}

	if err := m.vault.CreateDatabaseRole(roRoleName, name, creationStmts, defaultTTL, maxTTL); err != nil {
		return fmt.Errorf("database: create role %q: vault call failed", roRoleName)
	}

	// Store sanitized config (no admin password).
	sanitizedCfg := cfg
	sanitizedCfg.AdminPassword = "" // scrub from stored config

	m.mu.Lock()
	m.dbs[name] = dbEntry{
		config:     sanitizedCfg,
		engine:     cfg.Engine,
		roleSuffix: "ro",
	}
	m.mu.Unlock()

	m.logger.Info("database: configured", "name", name, "engine", cfg.Engine)
	return nil
}

// GetDatabaseConfig returns a sanitized (no admin password) copy of the config
// for the named database. Returns (zero, false) if not found.
func (m *Manager) GetDatabaseConfig(name string) (DatabaseConfig, bool) {
	m.mu.RLock()
	entry, ok := m.dbs[name]
	m.mu.RUnlock()
	if !ok {
		return DatabaseConfig{}, false
	}
	return entry.config, true
}

// ListDatabases returns the names of all configured databases.
func (m *Manager) ListDatabases() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	names := make([]string, 0, len(m.dbs))
	for name := range m.dbs {
		names = append(names, name)
	}
	return names
}

// RemoveDatabase removes a database configuration from the Manager.
// Returns an error if the name is not registered.
func (m *Manager) RemoveDatabase(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.dbs[name]; !ok {
		return fmt.Errorf("database: %q not found", name)
	}
	delete(m.dbs, name)
	m.logger.Info("database: removed", "name", name)
	return nil
}

// GetCredentials returns temporary database credentials for the named service
// and role (e.g., "readonly" or "readwrite"). It checks the lease cache first;
// on a miss it provisions new credentials from vault.
//
// Returns username, password, leaseID, error. The password is used only for
// database connections inside the Manager and never returned to the AI caller.
func (m *Manager) GetCredentials(serviceName, role string) (username, password, leaseID string, err error) {
	// Check lease cache.
	if l, ok := m.leases.Get(serviceName, role); ok {
		return l.Credentials["username"], l.Credentials["password"], l.ID, nil
	}

	// Determine the vault role name suffix.
	roleSuffix := "ro"
	if role == "readwrite" || role == "rw" {
		roleSuffix = "rw"
	}
	vaultRoleName := serviceName + "-" + roleSuffix

	// Provision new credentials from vault.
	creds, lID, ttl, vaultErr := m.vault.GetDynamicCredential("database", vaultRoleName)
	if vaultErr != nil {
		// Never include connection details in error message.
		return "", "", "", fmt.Errorf("database: credentials unavailable for service %q (role=%s)", serviceName, role)
	}

	username, password, extractErr := ExtractCredentials(creds)
	if extractErr != nil {
		return "", "", "", fmt.Errorf("database: invalid credential response for service %q", serviceName)
	}

	// Cache the lease.
	leaseInfo := &lease.LeaseInfo{
		LeaseID:       lID,
		LeaseDuration: ttl,
		Renewable:     true,
	}
	m.leases.Store(serviceName, role, leaseInfo, map[string]string{
		"username": username,
		"password": password,
	})

	return username, password, lID, nil
}

// ---------------------------------------------------------------------------
// Public pure functions (exported for testing and reuse)
// ---------------------------------------------------------------------------

// VaultPluginName returns the OpenBao database plugin name for the given engine.
func VaultPluginName(engine string) string {
	if p, ok := vaultPluginNames[engine]; ok {
		return p
	}
	return engine + "-database-plugin"
}

// DefaultCreationStatements returns the OpenBao creation SQL statements for a
// new temporary database user for the given engine. These statements use
// OpenBao template placeholders: {{name}}, {{password}}, {{expiration}}.
func DefaultCreationStatements(engine string) []string {
	switch engine {
	case "postgresql":
		return []string{
			`CREATE ROLE "{{name}}" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';`,
			`GRANT SELECT ON ALL TABLES IN SCHEMA public TO "{{name}}";`,
		}
	case "mysql":
		return []string{
			`CREATE USER '{{name}}'@'%' IDENTIFIED BY '{{password}}';`,
			`GRANT SELECT ON *.* TO '{{name}}'@'%';`,
		}
	default:
		return []string{}
	}
}

// BuildConnectionString returns a driver-appropriate connection string for
// use with database/sql. The admin password is passed in as arguments so it
// can be used at connection time without being stored in the Manager.
//
// This function is exported so tests can inspect the format without needing
// a live database. The connection string is never returned to the AI caller.
func BuildConnectionString(cfg DatabaseConfig, username, password string) string {
	port := cfg.resolvedPort()

	switch cfg.Engine {
	case "postgresql":
		sslMode := cfg.SSLMode
		if sslMode == "" {
			sslMode = "disable"
		}
		return fmt.Sprintf("host=%s port=%d dbname=%s user=%s password=%s sslmode=%s",
			cfg.Host, port, cfg.Database, username, password, sslMode)

	case "mysql":
		return fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?parseTime=true",
			username, password, cfg.Host, port, cfg.Database)

	default:
		return fmt.Sprintf("%s:%s@%s:%d", username, password, cfg.Host, port)
	}
}

// ExtractCredentials pulls the username and password from a vault dynamic
// credential response. Returns an error if either field is missing.
func ExtractCredentials(data map[string]interface{}) (username, password string, err error) {
	u, ok := data["username"].(string)
	if !ok || u == "" {
		return "", "", fmt.Errorf("database: credential response missing username")
	}
	p, ok := data["password"].(string)
	if !ok || p == "" {
		return "", "", fmt.Errorf("database: credential response missing password")
	}
	return u, p, nil
}

// SanitizeRows replaces any cell value in rows that matches a sensitive value
// with a redaction placeholder. This prevents credentials from appearing in
// query results returned to the AI via straylight_db_query.
func SanitizeRows(rows [][]interface{}, sensitiveValues []string) [][]interface{} {
	if len(sensitiveValues) == 0 {
		return rows
	}
	out := make([][]interface{}, len(rows))
	for i, row := range rows {
		outRow := make([]interface{}, len(row))
		for j, cell := range row {
			outRow[j] = sanitizeCell(cell, sensitiveValues)
		}
		out[i] = outRow
	}
	return out
}

// sanitizeCell replaces a cell value if it matches any sensitive value.
func sanitizeCell(cell interface{}, sensitiveValues []string) interface{} {
	s, ok := cell.(string)
	if !ok {
		return cell
	}
	for _, secret := range sensitiveValues {
		if secret != "" && strings.Contains(s, secret) {
			return "[REDACTED]"
		}
	}
	return cell
}

// ApplyMaxRows truncates rows to at most maxRows entries.
// maxRows=0 means no limit (returns rows unchanged).
func ApplyMaxRows(rows [][]interface{}, maxRows int) [][]interface{} {
	if maxRows <= 0 || len(rows) <= maxRows {
		return rows
	}
	return rows[:maxRows]
}

// ScanRows reads all rows from a RowScanner into a columns slice and a
// [][]interface{} matrix. The RowScanner is closed before returning.
func ScanRows(rows RowScanner) (columns []string, data [][]interface{}, err error) {
	defer rows.Close()

	columns, err = rows.Columns()
	if err != nil {
		return nil, nil, fmt.Errorf("database: get columns: %w", err)
	}

	n := len(columns)
	for rows.Next() {
		dest := make([]interface{}, n)
		ptrs := make([]interface{}, n)
		for i := range dest {
			ptrs[i] = &dest[i]
		}
		if scanErr := rows.Scan(ptrs...); scanErr != nil {
			return nil, nil, fmt.Errorf("database: scan row: %w", scanErr)
		}
		// Dereference the interface pointers.
		row := make([]interface{}, n)
		for i := range dest {
			row[i] = dest[i]
		}
		data = append(data, row)
	}

	if rowErr := rows.Err(); rowErr != nil {
		return nil, nil, fmt.Errorf("database: row iteration: %w", rowErr)
	}

	return columns, data, nil
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// buildVaultConnectionURL builds the OpenBao-style connection URL for the
// database secrets engine. The URL uses {{username}} and {{password}}
// placeholders so OpenBao substitutes the admin credentials at rotation time.
func buildVaultConnectionURL(cfg DatabaseConfig) string {
	port := cfg.resolvedPort()

	switch cfg.Engine {
	case "postgresql":
		sslMode := cfg.SSLMode
		if sslMode == "" {
			sslMode = "require"
		}
		return fmt.Sprintf("postgresql://{{username}}:{{password}}@%s:%d/%s?sslmode=%s",
			cfg.Host, port, cfg.Database, sslMode)
	case "mysql":
		return fmt.Sprintf("{{username}}:{{password}}@tcp(%s:%d)/%s",
			cfg.Host, port, cfg.Database)
	case "redis":
		return fmt.Sprintf("rediss://{{username}}:{{password}}@%s:%d",
			cfg.Host, port)
	default:
		return fmt.Sprintf("%s:%d", cfg.Host, port)
	}
}

// Ensure *sql.Rows satisfies RowScanner at compile time.
var _ RowScanner = (*sql.Rows)(nil)
