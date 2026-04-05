// Package vault provides an OpenBao client wrapper for credential storage and retrieval.
// It handles initialization, unsealing, AppRole authentication, and KV v2 operations.
package vault

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	// defaultHTTPTimeout is the timeout for individual API calls to OpenBao.
	defaultHTTPTimeout = 10 * time.Second
)

// Client is an OpenBao API client that communicates over HTTP using an AppRole token.
// All KV operations target the KV v2 engine mounted at "secret/".
type Client struct {
	address string
	mu      sync.RWMutex
	token   string
	http    *http.Client
	logger  *slog.Logger
}

// NewClient constructs a Client pointed at the given OpenBao address
// (e.g., "http://127.0.0.1:8200"). No token is set; call SetToken after
// AppRole authentication.
func NewClient(address string) *Client {
	return &Client{
		address: address,
		http:    &http.Client{Timeout: defaultHTTPTimeout},
		logger:  slog.Default(),
	}
}

// Address returns the OpenBao server address this client targets.
func (c *Client) Address() string {
	return c.address
}

// Token returns the current AppRole (or root) token stored in the client.
// Returns an empty string if no token has been set.
func (c *Client) Token() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.token
}

// SetToken stores a new token for use in subsequent API calls.
// Call this after AppRole authentication to replace the root token.
func (c *Client) SetToken(token string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.token = token
}

// IsHealthy returns true when the OpenBao health endpoint responds with HTTP 200,
// indicating the node is initialized, unsealed, and active.
func (c *Client) IsHealthy() bool {
	resp, err := c.http.Get(c.address + "/v1/sys/health")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// healthPayload is the JSON body returned by GET /v1/sys/health.
type healthPayload struct {
	Initialized bool `json:"initialized"`
	Sealed      bool `json:"sealed"`
}

// IsSealed reports whether the OpenBao node is sealed.
// Returns an error if the health endpoint is unreachable.
func (c *Client) IsSealed() (bool, error) {
	resp, err := c.http.Get(c.address + "/v1/sys/health")
	if err != nil {
		return false, fmt.Errorf("vault: health check failed: %w", err)
	}
	defer resp.Body.Close()

	var payload healthPayload
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return false, fmt.Errorf("vault: decode health response: %w", err)
	}
	return payload.Sealed, nil
}

// WriteSecret stores data at the given KV v2 path under the "secret/" mount.
// path is relative to the mount, e.g. "services/github".
// The data is wrapped in the KV v2 {"data": {...}} envelope automatically.
func (c *Client) WriteSecret(path string, data map[string]interface{}) error {
	payload := map[string]interface{}{"data": data}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("vault: marshal secret: %w", err)
	}

	url := c.address + "/v1/secret/data/" + strings.TrimPrefix(path, "/")
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("vault: build write request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	c.setAuthHeader(req)

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("vault: write secret: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		msg := readErrorBody(resp.Body)
		return fmt.Errorf("vault: write secret %q: status %d: %s", path, resp.StatusCode, msg)
	}
	return nil
}

// kvReadResponse is the top-level response structure from GET /v1/secret/data/<path>.
type kvReadResponse struct {
	Data struct {
		Data     map[string]interface{} `json:"data"`
		Metadata map[string]interface{} `json:"metadata"`
	} `json:"data"`
}

// ReadSecret retrieves the secret data at the given KV v2 path.
// Returns the inner data map (unwrapped from the KV v2 envelope).
func (c *Client) ReadSecret(path string) (map[string]interface{}, error) {
	url := c.address + "/v1/secret/data/" + strings.TrimPrefix(path, "/")
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("vault: build read request: %w", err)
	}
	c.setAuthHeader(req)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("vault: read secret: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("vault: secret %q not found", path)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		msg := readErrorBody(resp.Body)
		return nil, fmt.Errorf("vault: read secret %q: status %d: %s", path, resp.StatusCode, msg)
	}

	var result kvReadResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("vault: decode read response: %w", err)
	}
	return result.Data.Data, nil
}

// DeleteSecret deletes the latest version of the secret at the given KV v2 path.
func (c *Client) DeleteSecret(path string) error {
	url := c.address + "/v1/secret/data/" + strings.TrimPrefix(path, "/")
	req, err := http.NewRequest(http.MethodDelete, url, nil)
	if err != nil {
		return fmt.Errorf("vault: build delete request: %w", err)
	}
	c.setAuthHeader(req)

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("vault: delete secret: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusOK {
		return nil
	}
	msg := readErrorBody(resp.Body)
	return fmt.Errorf("vault: delete secret %q: status %d: %s", path, resp.StatusCode, msg)
}

// kvListResponse is the response structure from GET /v1/secret/metadata/<prefix>?list=true.
type kvListResponse struct {
	Data struct {
		Keys []string `json:"keys"`
	} `json:"data"`
}

// ListSecrets returns the list of keys at the given KV v2 path prefix.
// An empty or missing prefix returns an empty slice (not an error).
func (c *Client) ListSecrets(path string) ([]string, error) {
	metaPath := strings.TrimPrefix(path, "/")
	url := c.address + "/v1/secret/metadata/" + metaPath + "?list=true"

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("vault: build list request: %w", err)
	}
	c.setAuthHeader(req)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("vault: list secrets: %w", err)
	}
	defer resp.Body.Close()

	// 404 means the path is empty (no keys yet) — treat as empty list, not an error.
	if resp.StatusCode == http.StatusNotFound {
		return []string{}, nil
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		msg := readErrorBody(resp.Body)
		return nil, fmt.Errorf("vault: list secrets %q: status %d: %s", path, resp.StatusCode, msg)
	}

	var result kvListResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("vault: decode list response: %w", err)
	}
	return result.Data.Keys, nil
}

// renewSelfToken extends the TTL of the current token by calling
// POST /v1/auth/token/renew-self. Returns the new TTL in seconds.
func (c *Client) RenewSelfToken(increment int) (int, error) {
	payload := map[string]interface{}{"increment": fmt.Sprintf("%ds", increment)}
	body, err := json.Marshal(payload)
	if err != nil {
		return 0, fmt.Errorf("vault: marshal renew request: %w", err)
	}

	url := c.address + "/v1/auth/token/renew-self"
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return 0, fmt.Errorf("vault: build renew request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	c.setAuthHeader(req)

	resp, err := c.http.Do(req)
	if err != nil {
		return 0, fmt.Errorf("vault: renew self token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		msg := readErrorBody(resp.Body)
		return 0, fmt.Errorf("vault: renew self token: status %d: %s", resp.StatusCode, msg)
	}

	var result struct {
		Auth struct {
			LeaseDuration int `json:"lease_duration"`
		} `json:"auth"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0, fmt.Errorf("vault: decode renew response: %w", err)
	}
	return result.Auth.LeaseDuration, nil
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// setAuthHeader adds the X-Vault-Token header to the request.
func (c *Client) setAuthHeader(req *http.Request) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.token != "" {
		req.Header.Set("X-Vault-Token", c.token)
	}
}

// readErrorBody reads at most 512 bytes from r and returns them as a string for
// inclusion in error messages. Ignores read errors — this is best-effort.
func readErrorBody(r io.Reader) string {
	buf := make([]byte, 512)
	n, _ := r.Read(buf)
	return strings.TrimSpace(string(buf[:n]))
}
