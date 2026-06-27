package vault

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// JWKKey is a single JSON Web Key (public key fields only).
type JWKKey struct {
	Kty string `json:"kty,omitempty"`
	Kid string `json:"kid,omitempty"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
}

// JWKSet is a JSON Web Key Set.
type JWKSet struct {
	Keys []JWKKey `json:"keys"`
}

// ConfigureIdentityIssuer sets the issuer URL in OpenBao's identity OIDC config.
func (c *Client) ConfigureIdentityIssuer(issuerURL string) error {
	if issuerURL == "" {
		return fmt.Errorf("issuer URL must not be empty")
	}

	body := map[string]string{"issuer": issuerURL}
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("failed to marshal request body: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, c.address+"/v1/identity/oidc/config", bytes.NewReader(jsonBody))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	c.setAuthHeader(req)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		bodyStr := readErrorBody(resp.Body)
		return fmt.Errorf("vault: configure identity issuer: status %d: %s", resp.StatusCode, bodyStr)
	}

	return nil
}

// CreateIdentityRole creates/updates a named identity-token role in OpenBao.
func (c *Client) CreateIdentityRole(name string, audiences []string, ttl string, claims map[string]any) error {
	if name == "" {
		return fmt.Errorf("role name must not be empty")
	}

	body := map[string]any{
		"allowed_client_ids": audiences,
		"ttl":                ttl,
		"template":           claims,
	}
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("failed to marshal request body: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, c.address+"/v1/identity/oidc/role/"+name, bytes.NewReader(jsonBody))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	c.setAuthHeader(req)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		bodyStr := readErrorBody(resp.Body)
		return fmt.Errorf("vault: create identity role: status %d: %s", resp.StatusCode, bodyStr)
	}

	return nil
}

// GenerateIdentityToken mints a signed identity token for the given role and audience.
func (c *Client) GenerateIdentityToken(role, audience string) (string, time.Time, error) {
	if role == "" {
		return "", time.Time{}, fmt.Errorf("role must not be empty")
	}

	body := map[string]string{"audience": audience}
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to marshal request body: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, c.address+"/v1/identity/oidc/token/"+role, bytes.NewReader(jsonBody))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to create request: %w", err)
	}

	c.setAuthHeader(req)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		bodyStr := readErrorBody(resp.Body)
		return "", time.Time{}, fmt.Errorf("vault: generate identity token: status %d: %s", resp.StatusCode, bodyStr)
	}

	var result struct {
		Data struct {
			Token      string `json:"token"`
			ExpireTime string `json:"expire_time"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", time.Time{}, fmt.Errorf("failed to decode response: %w", err)
	}

	expiresAt, err := time.Parse(time.RFC3339, result.Data.ExpireTime)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to parse expire_time: %w", err)
	}

	return result.Data.Token, expiresAt, nil
}

// FetchPublicJWKS fetches the public JWKS from OpenBao's identity OIDC endpoint.
func (c *Client) FetchPublicJWKS() (JWKSet, error) {
	req, err := http.NewRequest(http.MethodGet, c.address+"/v1/identity/oidc/.well-known/keys", nil)
	if err != nil {
		return JWKSet{}, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return JWKSet{}, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		bodyStr := readErrorBody(resp.Body)
		return JWKSet{}, fmt.Errorf("vault: fetch public jwks: status %d: %s", resp.StatusCode, bodyStr)
	}

	var jwks JWKSet
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return JWKSet{}, fmt.Errorf("failed to decode response: %w", err)
	}

	return jwks, nil
}
