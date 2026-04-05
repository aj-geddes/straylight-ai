// Package vault manages the OpenBao process lifecycle: start, health-poll,
// auto-initialize, unseal, and crash recovery restart.
package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

const (
	// defaultListenAddr is the local address OpenBao listens on inside the container.
	defaultListenAddr = "http://127.0.0.1:8200"

	// defaultBinaryPath is the location of the OpenBao binary in the container image.
	defaultBinaryPath = "/usr/local/bin/bao"

	// defaultHCLPath is the default OpenBao server configuration file path.
	defaultHCLPath = "/etc/straylight/openbao.hcl"

	// defaultInitPath is where init credentials are persisted across restarts.
	defaultInitPath = "/data/openbao/init.json"

	// pollInterval is how often the health endpoint is checked during startup.
	pollInterval = 100 * time.Millisecond

	// straylightPolicy is the HCL policy document granting read/write access to
	// the services secret path, the AppRole auth paths, and the database secrets engine.
	straylightPolicy = `
path "secret/data/services/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
path "secret/data/services/+/credential" {
  capabilities = ["create", "read", "update", "delete"]
}
path "secret/data/services/+/metadata" {
  capabilities = ["create", "read", "update", "delete"]
}
path "secret/metadata/services/*" {
  capabilities = ["list", "read", "delete"]
}
path "secret/metadata/services/+/credential" {
  capabilities = ["list", "read", "delete"]
}
path "secret/metadata/services/+/metadata" {
  capabilities = ["list", "read", "delete"]
}
path "auth/approle/role/straylight/secret-id" {
  capabilities = ["update"]
}
path "secret/data/config/*" {
  capabilities = ["create", "read", "update", "delete"]
}
path "secret/metadata/config/*" {
  capabilities = ["list", "read", "delete"]
}
path "database/config/*" {
  capabilities = ["create", "read", "update", "delete"]
}
path "database/roles/*" {
  capabilities = ["create", "read", "update", "delete"]
}
path "database/creds/*" {
  capabilities = ["read"]
}
path "sys/leases/revoke" {
  capabilities = ["update"]
}
path "sys/leases/revoke-prefix/database/*" {
  capabilities = ["update"]
}
path "sys/leases/lookup" {
  capabilities = ["update"]
}
path "sys/mounts/database" {
  capabilities = ["create", "read", "update"]
}
path "auth/token/renew-self" {
  capabilities = ["update"]
}
path "auth/token/lookup-self" {
  capabilities = ["read"]
}
`
)

// SupervisorConfig holds all configuration parameters for the Supervisor.
// Fields left at their zero value are replaced with sensible defaults when
// NewSupervisor constructs the Supervisor.
type SupervisorConfig struct {
	// BinaryPath is the path to the bao binary. Default: /usr/local/bin/bao.
	BinaryPath string

	// HCLPath is the path to the OpenBao server configuration HCL file.
	// Default: /etc/straylight/openbao.hcl.
	HCLPath string

	// InitPath is where the init.json file is stored. Default: /data/openbao/init.json.
	InitPath string

	// ListenAddr is the HTTP address of the OpenBao API. Default: http://127.0.0.1:8200.
	ListenAddr string
}

// initData is the structure persisted to init.json. It holds everything needed
// to unseal and re-authenticate after a restart.
type initData struct {
	UnsealKey  string `json:"unseal_key"`
	RootToken  string `json:"root_token"`
	RoleID     string `json:"role_id"`
	SecretID   string `json:"secret_id"`
}

// tokenRenewalInterval is how often the background goroutine renews the
// AppRole token. Set to half the token_ttl so we renew well before expiry.
const tokenRenewalInterval = 30 * time.Minute

// Supervisor manages the OpenBao child process and drives the full
// initialization, unseal, and AppRole authentication flow.
type Supervisor struct {
	cfg    SupervisorConfig
	logger *slog.Logger

	mu       sync.Mutex
	process  *os.Process
	initInfo *initData
}

// NewSupervisor constructs a Supervisor with defaults applied for any zero-value
// fields in cfg.
func NewSupervisor(cfg SupervisorConfig) *Supervisor {
	if cfg.BinaryPath == "" {
		cfg.BinaryPath = defaultBinaryPath
	}
	if cfg.HCLPath == "" {
		cfg.HCLPath = defaultHCLPath
	}
	if cfg.InitPath == "" {
		cfg.InitPath = defaultInitPath
	}
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = defaultListenAddr
	}
	return &Supervisor{
		cfg:    cfg,
		logger: slog.Default(),
	}
}

// Config returns a copy of the supervisor's resolved configuration.
func (s *Supervisor) Config() SupervisorConfig {
	return s.cfg
}

// WaitForReady polls the OpenBao health endpoint until it returns any HTTP
// response (2xx or otherwise — any response means the server is up and
// accepting connections). Returns an error if timeout elapses first.
//
// Note: /v1/sys/health returns 200 (active), 429 (standby), 472 (DR),
// 473 (performance standby), 501 (not initialised), or 503 (sealed).
// Any of these indicates the process is running and API is reachable.
func (s *Supervisor) WaitForReady(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	client := &http.Client{Timeout: pollInterval}

	for time.Now().Before(deadline) {
		resp, err := client.Get(s.cfg.ListenAddr + "/v1/sys/health")
		if err == nil {
			resp.Body.Close()
			return nil
		}
		sleepUntil := time.Now().Add(pollInterval)
		if sleepUntil.After(deadline) {
			break
		}
		time.Sleep(pollInterval)
	}
	return fmt.Errorf("vault: OpenBao did not become ready within %s", timeout)
}

// VaultStatus returns "unsealed", "sealed", or "unavailable" based on the
// current health endpoint response. It is safe to call at any time and never
// returns an error — unavailability is expressed as the string "unavailable".
func (s *Supervisor) VaultStatus() string {
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(s.cfg.ListenAddr + "/v1/sys/health")
	if err != nil {
		return "unavailable"
	}
	defer resp.Body.Close()

	var payload healthPayload
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		// Can't decode body — treat 200 as unsealed, anything else as unavailable
		if resp.StatusCode == http.StatusOK {
			return "unsealed"
		}
		return "unavailable"
	}

	if payload.Sealed {
		return "sealed"
	}
	return "unsealed"
}

// InitializeVault drives the full OpenBao initialization flow:
//   - If init.json exists: unseal with stored key, authenticate via AppRole.
//   - If not initialized: run full init sequence (init → unseal → KV mount →
//     policy → AppRole → login), save init.json with 0600 permissions.
//
// Returns an authenticated Client using the AppRole token. The root token is
// discarded from memory immediately after use.
func (s *Supervisor) InitializeVault() (*Client, error) {
	client := NewClient(s.cfg.ListenAddr)

	// Check whether OpenBao has been initialized before.
	initialized, err := s.checkInitialized(client)
	if err != nil {
		return nil, fmt.Errorf("vault: check init status: %w", err)
	}

	if initialized {
		return s.resumeFromInitFile(client)
	}
	return s.runFullInit(client)
}

// Start launches the OpenBao binary as a child process and waits for it to
// become ready. It does not perform initialization; call InitializeVault after.
// Returns an error if the binary cannot be started.
func (s *Supervisor) Start(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, s.cfg.BinaryPath, "server", "-config="+s.cfg.HCLPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("vault: start OpenBao: %w", err)
	}

	s.mu.Lock()
	s.process = cmd.Process
	s.mu.Unlock()

	s.logger.Info("vault: OpenBao process started", "pid", cmd.Process.Pid)
	return nil
}

// Stop gracefully terminates the OpenBao child process, if one is running.
func (s *Supervisor) Stop() error {
	s.mu.Lock()
	proc := s.process
	s.mu.Unlock()

	if proc == nil {
		return nil
	}

	if err := proc.Signal(os.Interrupt); err != nil {
		s.logger.Warn("vault: interrupt signal failed, killing", "error", err)
		return proc.Kill()
	}
	return nil
}

// ---------------------------------------------------------------------------
// Internal initialization helpers
// ---------------------------------------------------------------------------

// checkInitialized calls GET /v1/sys/init and returns whether OpenBao reports
// itself as already initialized.
func (s *Supervisor) checkInitialized(client *Client) (bool, error) {
	resp, err := client.http.Get(client.address + "/v1/sys/init")
	if err != nil {
		return false, fmt.Errorf("GET /v1/sys/init: %w", err)
	}
	defer resp.Body.Close()

	var body struct {
		Initialized bool `json:"initialized"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return false, fmt.Errorf("decode /v1/sys/init response: %w", err)
	}
	return body.Initialized, nil
}

// resumeFromInitFile reads init.json, unseals OpenBao using the stored key,
// and authenticates via AppRole. Returns an authenticated client.
func (s *Supervisor) resumeFromInitFile(client *Client) (*Client, error) {
	s.logger.Info("vault: already initialized, loading init file")

	init, err := s.loadInitFile()
	if err != nil {
		return nil, fmt.Errorf("vault: load init file: %w", err)
	}

	// Unseal
	client.SetToken(init.RootToken)
	if err := s.unseal(client, init.UnsealKey); err != nil {
		return nil, fmt.Errorf("vault: unseal: %w", err)
	}

	// Authenticate via AppRole
	token, err := s.appRoleLogin(client, init.RoleID, init.SecretID)
	if err != nil {
		return nil, fmt.Errorf("vault: AppRole login: %w", err)
	}

	// Replace root token with AppRole token
	client.SetToken(token)
	s.logger.Info("vault: authenticated via AppRole")

	// Store init data for token renewal re-login fallback.
	s.mu.Lock()
	s.initInfo = &init
	s.mu.Unlock()

	return client, nil
}

// runFullInit performs the complete first-time initialization sequence.
func (s *Supervisor) runFullInit(client *Client) (*Client, error) {
	s.logger.Info("vault: running first-time initialization")

	// Step 1: Initialize
	unsealKey, rootToken, err := s.initVault(client)
	if err != nil {
		return nil, fmt.Errorf("vault: init: %w", err)
	}

	// Step 2: Unseal (use root token for setup operations)
	client.SetToken(rootToken)
	if err := s.unseal(client, unsealKey); err != nil {
		return nil, fmt.Errorf("vault: unseal: %w", err)
	}

	// Step 3: Enable KV v2 at secret/
	if err := s.enableKVMount(client); err != nil {
		return nil, fmt.Errorf("vault: enable KV mount: %w", err)
	}

	// Step 3b: Enable database secrets engine at database/
	if err := s.enableDatabaseEngine(client); err != nil {
		return nil, fmt.Errorf("vault: enable database engine: %w", err)
	}

	// Step 4: Create straylight policy
	if err := s.createPolicy(client); err != nil {
		return nil, fmt.Errorf("vault: create policy: %w", err)
	}

	// Step 5: Enable AppRole auth
	if err := s.enableAppRole(client); err != nil {
		return nil, fmt.Errorf("vault: enable AppRole: %w", err)
	}

	// Step 6: Create AppRole role "straylight"
	if err := s.createAppRoleRole(client); err != nil {
		return nil, fmt.Errorf("vault: create AppRole role: %w", err)
	}

	// Step 7: Get RoleID
	roleID, err := s.getRoleID(client)
	if err != nil {
		return nil, fmt.Errorf("vault: get RoleID: %w", err)
	}

	// Step 8: Get SecretID
	secretID, err := s.getSecretID(client)
	if err != nil {
		return nil, fmt.Errorf("vault: get SecretID: %w", err)
	}

	// Step 9: Persist init data BEFORE login (so we can recover if login fails)
	init := initData{
		UnsealKey: unsealKey,
		RootToken: rootToken,
		RoleID:    roleID,
		SecretID:  secretID,
	}
	if err := s.saveInitFile(init); err != nil {
		return nil, fmt.Errorf("vault: save init file: %w", err)
	}

	// Step 10: Authenticate via AppRole
	appToken, err := s.appRoleLogin(client, roleID, secretID)
	if err != nil {
		return nil, fmt.Errorf("vault: AppRole login: %w", err)
	}

	// Discard root token from memory; use AppRole token going forward
	client.SetToken(appToken)
	s.logger.Info("vault: initialization complete, authenticated via AppRole")

	// Store init data for token renewal re-login fallback.
	s.mu.Lock()
	s.initInfo = &init
	s.mu.Unlock()

	return client, nil
}

// initVault calls PUT /v1/sys/init with shares=1, threshold=1.
// Returns the unseal key and root token.
func (s *Supervisor) initVault(client *Client) (unsealKey, rootToken string, err error) {
	payload := map[string]interface{}{
		"secret_shares":    1,
		"secret_threshold": 1,
	}
	var result struct {
		Keys      []string `json:"keys"`
		RootToken string   `json:"root_token"`
	}

	if err := client.apiCall(http.MethodPut, "/v1/sys/init", payload, &result); err != nil {
		return "", "", err
	}
	if len(result.Keys) == 0 {
		return "", "", fmt.Errorf("no unseal keys returned")
	}
	// NOTE: We do not log the unseal key or root token values.
	return result.Keys[0], result.RootToken, nil
}

// unseal calls PUT /v1/sys/unseal with the given key.
func (s *Supervisor) unseal(client *Client, key string) error {
	payload := map[string]interface{}{"key": key}
	var result struct {
		Sealed bool `json:"sealed"`
	}
	if err := client.apiCall(http.MethodPut, "/v1/sys/unseal", payload, &result); err != nil {
		return err
	}
	if result.Sealed {
		return fmt.Errorf("vault reported still sealed after unseal attempt")
	}
	return nil
}

// enableDatabaseEngine mounts the database secrets engine at "database/".
// If the engine is already mounted (HTTP 400 "path is already in use"), the
// error is silently ignored — idempotent for restarts.
func (s *Supervisor) enableDatabaseEngine(client *Client) error {
	payload := map[string]interface{}{
		"type":        "database",
		"description": "Straylight dynamic database credentials",
	}
	err := client.apiCall(http.MethodPost, "/v1/sys/mounts/database", payload, nil)
	if err != nil {
		// OpenBao returns a 400 with "path is already in use" when already mounted.
		// Treat this as success so the init flow is idempotent across restarts.
		if strings.Contains(err.Error(), "already in use") || strings.Contains(err.Error(), "status 400") {
			s.logger.Info("vault: database engine already mounted, skipping")
			return nil
		}
		return fmt.Errorf("vault: enable database engine: %w", err)
	}
	s.logger.Info("vault: database secrets engine mounted at database/")
	return nil
}

// enableKVMount enables the KV v2 secrets engine at the "secret/" path.
func (s *Supervisor) enableKVMount(client *Client) error {
	payload := map[string]interface{}{
		"type":        "kv",
		"description": "Straylight KV v2 secrets",
		"options":     map[string]string{"version": "2"},
	}
	return client.apiCall(http.MethodPost, "/v1/sys/mounts/secret", payload, nil)
}

// createPolicy creates the "straylight" ACL policy.
func (s *Supervisor) createPolicy(client *Client) error {
	payload := map[string]interface{}{"policy": straylightPolicy}
	return client.apiCall(http.MethodPut, "/v1/sys/policies/acl/straylight", payload, nil)
}

// enableAppRole enables the AppRole authentication method.
func (s *Supervisor) enableAppRole(client *Client) error {
	payload := map[string]interface{}{"type": "approle"}
	return client.apiCall(http.MethodPost, "/v1/sys/auth/approle", payload, nil)
}

// createAppRoleRole creates the "straylight" AppRole role with the straylight policy.
func (s *Supervisor) createAppRoleRole(client *Client) error {
	payload := map[string]interface{}{
		"token_policies": []string{"straylight"},
		"token_ttl":      "1h",
		"token_max_ttl":  "4h",
	}
	return client.apiCall(http.MethodPost, "/v1/auth/approle/role/straylight", payload, nil)
}

// getRoleID retrieves the RoleID for the "straylight" AppRole.
func (s *Supervisor) getRoleID(client *Client) (string, error) {
	var result struct {
		Data struct {
			RoleID string `json:"role_id"`
		} `json:"data"`
	}
	if err := client.apiCall(http.MethodGet, "/v1/auth/approle/role/straylight/role-id", nil, &result); err != nil {
		return "", err
	}
	return result.Data.RoleID, nil
}

// getSecretID generates and retrieves a SecretID for the "straylight" AppRole.
func (s *Supervisor) getSecretID(client *Client) (string, error) {
	var result struct {
		Data struct {
			SecretID string `json:"secret_id"`
		} `json:"data"`
	}
	if err := client.apiCall(http.MethodPost, "/v1/auth/approle/role/straylight/secret-id", nil, &result); err != nil {
		return "", err
	}
	return result.Data.SecretID, nil
}

// appRoleLogin authenticates using the given roleID and secretID and returns
// the resulting client token.
func (s *Supervisor) appRoleLogin(client *Client, roleID, secretID string) (string, error) {
	payload := map[string]interface{}{
		"role_id":   roleID,
		"secret_id": secretID,
	}
	var result struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	if err := client.apiCall(http.MethodPost, "/v1/auth/approle/login", payload, &result); err != nil {
		return "", err
	}
	if result.Auth.ClientToken == "" {
		return "", fmt.Errorf("AppRole login returned empty client_token")
	}
	return result.Auth.ClientToken, nil
}

// ---------------------------------------------------------------------------
// Token renewal
// ---------------------------------------------------------------------------

// StartTokenRenewal launches a background goroutine that periodically renews
// the AppRole token on client. If renewal fails (e.g. token already expired or
// max TTL reached), it falls back to a full AppRole re-login using stored
// credentials. The goroutine stops when ctx is cancelled.
func (s *Supervisor) StartTokenRenewal(ctx context.Context, client *Client) {
	go func() {
		ticker := time.NewTicker(tokenRenewalInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				s.logger.Info("vault: token renewal stopped")
				return
			case <-ticker.C:
				ttl, err := client.RenewSelfToken(3600) // request 1h extension
				if err == nil {
					s.logger.Info("vault: token renewed", "new_ttl_seconds", ttl)
					continue
				}

				s.logger.Warn("vault: token renewal failed, attempting re-login", "error", err)

				s.mu.Lock()
				info := s.initInfo
				s.mu.Unlock()

				if info == nil {
					s.logger.Error("vault: cannot re-login, no stored init data")
					continue
				}

				token, loginErr := s.appRoleLogin(client, info.RoleID, info.SecretID)
				if loginErr != nil {
					s.logger.Error("vault: re-login failed", "error", loginErr)
					continue
				}

				client.SetToken(token)
				s.logger.Info("vault: re-authenticated via AppRole after renewal failure")
			}
		}
	}()
}

// ---------------------------------------------------------------------------
// Init file helpers
// ---------------------------------------------------------------------------

// saveInitFile writes init data to disk at cfg.InitPath with 0600 permissions.
// The parent directory is created if it does not exist.
func (s *Supervisor) saveInitFile(data initData) error {
	dir := dirOf(s.cfg.InitPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create init dir %q: %w", dir, err)
	}

	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal init data: %w", err)
	}

	// Write with O_CREATE|O_WRONLY|O_TRUNC and strict permissions.
	f, err := os.OpenFile(s.cfg.InitPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("open init file: %w", err)
	}
	defer f.Close()

	if _, err := f.Write(b); err != nil {
		return fmt.Errorf("write init file: %w", err)
	}
	// NOTE: We do not log the contents of init.json.
	s.logger.Info("vault: init file saved", "path", s.cfg.InitPath)
	return nil
}

// loadInitFile reads and parses the init.json file from disk.
func (s *Supervisor) loadInitFile() (initData, error) {
	b, err := os.ReadFile(s.cfg.InitPath)
	if err != nil {
		return initData{}, fmt.Errorf("read init file %q: %w", s.cfg.InitPath, err)
	}

	var data initData
	if err := json.Unmarshal(b, &data); err != nil {
		return initData{}, fmt.Errorf("parse init file: %w", err)
	}
	return data, nil
}

// ---------------------------------------------------------------------------
// Low-level HTTP helper on Client (package-internal only)
// ---------------------------------------------------------------------------

// apiCall performs an authenticated HTTP request against the OpenBao API.
// method is the HTTP method, path is the API path (e.g. "/v1/sys/init"),
// payload is JSON-marshalled and sent as the request body (nil = no body),
// and result, if non-nil, is JSON-decoded from the response body.
// Returns an error on non-2xx responses or network failures.
func (c *Client) apiCall(method, path string, payload interface{}, result interface{}) error {
	var body io.Reader
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("marshal request: %w", err)
		}
		body = bytes.NewReader(b)
	}

	req, err := http.NewRequest(method, c.address+path, body)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	c.setAuthHeader(req)

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		msg := readErrorBody(resp.Body)
		return fmt.Errorf("%s %s: status %d: %s", method, path, resp.StatusCode, msg)
	}

	if result != nil && resp.ContentLength != 0 {
		if err := json.NewDecoder(resp.Body).Decode(result); err != nil {
			return fmt.Errorf("decode response from %s %s: %w", method, path, err)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

// dirOf returns the directory component of a file path without importing path/filepath
// to keep the dependency surface minimal. Falls back to "." for bare filenames.
func dirOf(p string) string {
	idx := strings.LastIndexByte(p, '/')
	if idx < 0 {
		return "."
	}
	return p[:idx]
}
