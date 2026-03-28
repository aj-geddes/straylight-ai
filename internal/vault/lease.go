// Package vault — lease management and dynamic credential methods for the vault Client.
package vault

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// LeaseInfo holds the metadata returned by vault for a dynamic secret lease.
type LeaseInfo struct {
	// LeaseID is the vault lease ID for this credential grant.
	LeaseID string
	// LeaseDuration is the TTL in seconds for this lease.
	LeaseDuration int
	// Renewable indicates whether the lease can be renewed.
	Renewable bool
}

// leaseResponse is the JSON structure returned by vault lease endpoints.
type leaseResponse struct {
	LeaseID       string `json:"lease_id"`
	LeaseDuration int    `json:"lease_duration"`
	Renewable     bool   `json:"renewable"`
}

// RenewLease extends the TTL of an existing vault lease.
// increment is the requested new TTL in seconds.
// Returns the updated LeaseInfo or an error if the renewal fails.
func (c *Client) RenewLease(leaseID string, increment int) (*LeaseInfo, error) {
	payload := map[string]interface{}{
		"lease_id":  leaseID,
		"increment": increment,
	}

	var result leaseResponse
	if err := c.apiCall(http.MethodPut, "/v1/sys/leases/renew", payload, &result); err != nil {
		return nil, fmt.Errorf("vault: renew lease %q: %w", leaseID, err)
	}

	return &LeaseInfo{
		LeaseID:       result.LeaseID,
		LeaseDuration: result.LeaseDuration,
		Renewable:     result.Renewable,
	}, nil
}

// RevokeLease immediately revokes a vault lease, invalidating the associated
// dynamic credentials.
func (c *Client) RevokeLease(leaseID string) error {
	payload := map[string]interface{}{"lease_id": leaseID}
	err := c.apiCall(http.MethodPut, "/v1/sys/leases/revoke", payload, nil)
	if err != nil {
		return fmt.Errorf("vault: revoke lease %q: %w", leaseID, err)
	}
	return nil
}

// RevokeLeasePrefix revokes all leases that begin with the given prefix.
// Use this during shutdown to revoke all database leases at once with
// prefix "database/".
func (c *Client) RevokeLeasePrefix(prefix string) error {
	prefix = strings.TrimPrefix(prefix, "/")
	path := "/v1/sys/leases/revoke-prefix/" + prefix
	err := c.apiCall(http.MethodPut, path, map[string]interface{}{}, nil)
	if err != nil {
		return fmt.Errorf("vault: revoke lease prefix %q: %w", prefix, err)
	}
	return nil
}

// leaseWithDataResponse is the top-level response from a dynamic secret read.
type leaseWithDataResponse struct {
	LeaseID       string                 `json:"lease_id"`
	LeaseDuration int                    `json:"lease_duration"`
	Renewable     bool                   `json:"renewable"`
	Data          map[string]interface{} `json:"data"`
}

// ReadWithLease reads a vault path that returns a lease alongside data.
// This is used for dynamic secrets engines (database, cloud) where the
// response includes both credential data and a lease for renewal/revocation.
//
// Returns the data map, the lease ID, the TTL in seconds, and any error.
func (c *Client) ReadWithLease(path string) (data map[string]interface{}, leaseID string, leaseTTL int, err error) {
	path = strings.TrimPrefix(path, "/")

	req, reqErr := c.buildGetRequest("/v1/" + path)
	if reqErr != nil {
		return nil, "", 0, fmt.Errorf("vault: build read-with-lease request: %w", reqErr)
	}

	resp, respErr := c.http.Do(req)
	if respErr != nil {
		return nil, "", 0, fmt.Errorf("vault: read-with-lease %q: %w", path, respErr)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, "", 0, fmt.Errorf("vault: path %q not found", path)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		msg := readErrorBody(resp.Body)
		return nil, "", 0, fmt.Errorf("vault: read-with-lease %q: status %d: %s", path, resp.StatusCode, msg)
	}

	var result leaseWithDataResponse
	if decErr := json.NewDecoder(resp.Body).Decode(&result); decErr != nil {
		return nil, "", 0, fmt.Errorf("vault: decode read-with-lease response: %w", decErr)
	}

	return result.Data, result.LeaseID, result.LeaseDuration, nil
}

// EnableSecretsEngine mounts a new secrets engine at the given path.
// engineType is the vault engine type (e.g., "database", "aws").
// config is optional additional mount configuration.
func (c *Client) EnableSecretsEngine(path, engineType string, config map[string]interface{}) error {
	payload := map[string]interface{}{
		"type": engineType,
	}
	for k, v := range config {
		payload[k] = v
	}
	path = strings.TrimPrefix(path, "/")
	if err := c.apiCall(http.MethodPost, "/v1/sys/mounts/"+path, payload, nil); err != nil {
		return fmt.Errorf("vault: enable secrets engine %q (type=%s): %w", path, engineType, err)
	}
	return nil
}

// ConfigureDatabaseConnection writes a database connection configuration to
// the vault database secrets engine.
//
// name is the connection name (e.g., "my-postgres").
// plugin is the vault database plugin name (e.g., "postgresql-database-plugin").
// connURL is the connection URL with {{username}} and {{password}} placeholders.
// allowedRoles lists the role names that may generate credentials from this connection.
// extra holds additional plugin-specific fields (e.g., username, password).
func (c *Client) ConfigureDatabaseConnection(name, plugin, connURL string, allowedRoles []string, extra map[string]interface{}) error {
	payload := map[string]interface{}{
		"plugin_name":    plugin,
		"connection_url": connURL,
		"allowed_roles":  allowedRoles,
	}
	for k, v := range extra {
		payload[k] = v
	}
	if err := c.apiCall(http.MethodPost, "/v1/database/config/"+name, payload, nil); err != nil {
		return fmt.Errorf("vault: database: configure %q: %w", name, err)
	}
	return nil
}

// CreateDatabaseRole creates a vault database role that defines how temporary
// database users are created.
//
// name is the role name (e.g., "my-postgres-ro").
// dbName is the connection name this role is associated with.
// creationStatements are SQL statements to create the temporary user.
// defaultTTL is the default lease duration (e.g., "15m").
// maxTTL is the maximum lease duration (e.g., "1h").
func (c *Client) CreateDatabaseRole(name, dbName string, creationStatements []string, defaultTTL, maxTTL string) error {
	payload := map[string]interface{}{
		"db_name":             dbName,
		"creation_statements": creationStatements,
		"default_ttl":         defaultTTL,
		"max_ttl":             maxTTL,
	}
	if err := c.apiCall(http.MethodPost, "/v1/database/roles/"+name, payload, nil); err != nil {
		return fmt.Errorf("vault: database: create role %q: %w", name, err)
	}
	return nil
}

// GetDynamicCredential generates a new set of temporary credentials from the
// given secrets engine at the given role.
//
// enginePath is the mount path of the engine (e.g., "database").
// roleName is the role to generate credentials for (e.g., "my-postgres-ro").
//
// Returns the credential map, the lease ID, the TTL in seconds, and any error.
func (c *Client) GetDynamicCredential(enginePath, roleName string) (creds map[string]interface{}, leaseID string, leaseDuration int, err error) {
	path := strings.TrimPrefix(enginePath, "/") + "/creds/" + roleName
	data, lID, ttl, readErr := c.ReadWithLease(path)
	if readErr != nil {
		return nil, "", 0, fmt.Errorf("vault: get dynamic credential %s/%s: %w", enginePath, roleName, readErr)
	}
	return data, lID, ttl, nil
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// buildGetRequest constructs an authenticated GET request for the given path.
// path must start with "/".
func (c *Client) buildGetRequest(path string) (*http.Request, error) {
	req, err := http.NewRequest(http.MethodGet, c.address+path, nil)
	if err != nil {
		return nil, err
	}
	c.setAuthHeader(req)
	return req, nil
}
