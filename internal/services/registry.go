// Package services manages the service registry — the set of configured external
// services and their metadata. Credential values are stored in the vault, never here.
package services

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// serviceNamePattern matches valid service names: starts with lowercase letter,
// followed by up to 62 lowercase alphanumeric, hyphen, or underscore characters.
var serviceNamePattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,62}$`)

// validTypes is the set of accepted service types.
var validTypes = map[string]bool{
	"http_proxy": true,
	"oauth":      true,
}

// validInject is the set of accepted inject modes for WP-1.1.
// The config schema also supports "body" but the service API spec limits to header/query.
var validInject = map[string]bool{
	"header": true,
	"query":  true,
}

// AccountInfo holds identity information retrieved from a service's API after
// credential storage. It is stored in memory only — never persisted to vault.
type AccountInfo struct {
	DisplayName string            `json:"display_name,omitempty"`
	Username    string            `json:"username,omitempty"`
	Email       string            `json:"email,omitempty"`
	AvatarURL   string            `json:"avatar_url,omitempty"`
	URL         string            `json:"url,omitempty"`
	Plan        string            `json:"plan,omitempty"`
	Extra       map[string]string `json:"extra,omitempty"`
}

// Service represents a configured external service integration.
// Credential values are never stored here — they live in OpenBao only.
type Service struct {
	Name           string            `json:"name"                      yaml:"name"`
	Type           string            `json:"type"                      yaml:"type"`
	Target         string            `json:"target"                    yaml:"target"`
	// AuthMethodID identifies which auth method from the service's template was
	// selected at creation time. When empty, the service uses legacy injection
	// behavior (flat Inject/HeaderName/HeaderTemplate fields).
	AuthMethodID   string            `json:"auth_method_id,omitempty"  yaml:"auth_method_id,omitempty"`
	Inject         string            `json:"inject"                    yaml:"inject"`
	HeaderName     string            `json:"header_name,omitempty"     yaml:"header_name,omitempty"`
	HeaderTemplate string            `json:"header_template,omitempty" yaml:"header_template,omitempty"`
	QueryParam     string            `json:"query_param,omitempty"     yaml:"query_param,omitempty"`
	DefaultHeaders map[string]string `json:"default_headers,omitempty" yaml:"default_headers,omitempty"`
	// ExecEnabled indicates whether this service supports credential-injected
	// command execution via straylight_exec. Set by WP-2.1 (command wrapper).
	ExecEnabled bool `json:"exec_enabled,omitempty" yaml:"exec_enabled,omitempty"`
	// Status is computed at runtime and never persisted to config.
	Status    string    `json:"status"     yaml:"-"`
	CreatedAt time.Time `json:"created_at" yaml:"-"`
	UpdatedAt time.Time `json:"updated_at" yaml:"-"`
	// AccountInfo holds identity information fetched from the service API after
	// credential storage. Stored in memory only — never persisted to vault.
	AccountInfo *AccountInfo `json:"account_info,omitempty" yaml:"-"`
}

// VaultClient is the interface the Registry uses for credential storage.
// Implemented by *vault.Client; use a mock in tests.
type VaultClient interface {
	WriteSecret(path string, data map[string]interface{}) error
	ReadSecret(path string) (map[string]interface{}, error)
	DeleteSecret(path string) error
	ListSecrets(path string) ([]string, error)
}

// Registry is a thread-safe in-memory store of Service records.
// Credentials are stored in OpenBao; the Registry holds only metadata.
type Registry struct {
	mu       sync.RWMutex
	services map[string]Service
	vault    VaultClient
}

// NewRegistry creates an empty Registry backed by the given VaultClient.
func NewRegistry(vault VaultClient) *Registry {
	return &Registry{
		services: make(map[string]Service),
		vault:    vault,
	}
}

// Create adds a new service to the registry and stores its credential in OpenBao.
// Returns an error if the name already exists, validation fails, or vault write fails.
// On vault write failure the service is NOT added to the in-memory registry.
func (r *Registry) Create(svc Service, credential string) error {
	if err := validateService(svc); err != nil {
		return err
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.services[svc.Name]; exists {
		return fmt.Errorf("services: %q already exists", svc.Name)
	}

	if err := r.writeCredential(svc.Name, credential); err != nil {
		return err
	}

	now := time.Now().UTC()
	svc.CreatedAt = now
	svc.UpdatedAt = now
	svc.Status = "available"
	r.services[svc.Name] = svc

	// Persist metadata best-effort — do not fail service creation on metadata write error.
	_ = r.saveMetadata(svc)
	return nil
}

// Get returns the Service metadata for the given name.
// Returns an error if the service does not exist.
// The returned Service never contains credential values.
func (r *Registry) Get(name string) (Service, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	svc, ok := r.services[name]
	if !ok {
		return Service{}, fmt.Errorf("services: %q not found", name)
	}
	return svc, nil
}

// List returns all services in the registry.
// The returned slice is never nil. Credential values are never included.
func (r *Registry) List() []Service {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]Service, 0, len(r.services))
	for _, svc := range r.services {
		result = append(result, svc)
	}
	return result
}

// Update replaces the service configuration for an existing service.
// If credential is non-nil, the credential stored in OpenBao is also replaced.
// CreatedAt is preserved; UpdatedAt is set to now.
// Returns an error if the service does not exist, or if vault write fails.
func (r *Registry) Update(name string, svc Service, credential *string) error {
	if err := validateService(svc); err != nil {
		return err
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	existing, ok := r.services[name]
	if !ok {
		return fmt.Errorf("services: %q not found", name)
	}

	if credential != nil {
		if err := r.writeCredential(name, *credential); err != nil {
			return err
		}
	}

	svc.Name = name
	svc.CreatedAt = existing.CreatedAt
	svc.UpdatedAt = time.Now().UTC()
	svc.Status = existing.Status
	r.services[name] = svc

	// Persist updated metadata best-effort.
	_ = r.saveMetadata(svc)
	return nil
}

// Delete removes a service from the registry and deletes its credential from OpenBao.
// Returns an error if the service does not exist.
// Always attempts vault deletion even if the service entry is removed first, to avoid orphaned secrets.
func (r *Registry) Delete(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, ok := r.services[name]; !ok {
		return fmt.Errorf("services: %q not found", name)
	}

	delete(r.services, name)

	// Best-effort: delete the metadata from vault (ignore errors).
	_ = r.vault.DeleteSecret(metadataPath(name))

	// Best-effort: delete the credential from vault.
	// Errors are returned but the in-memory entry is already gone.
	if err := r.vault.DeleteSecret(credentialPath(name)); err != nil {
		return fmt.Errorf("services: delete credential for %q: %w", name, err)
	}
	return nil
}

// CheckCredential reports whether the credential for the named service is
// "available" (present in vault) or "not_configured" (absent from vault).
// Returns an error if the service does not exist.
func (r *Registry) CheckCredential(name string) (string, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if _, ok := r.services[name]; !ok {
		return "", fmt.Errorf("services: %q not found", name)
	}

	data, err := r.vault.ReadSecret(credentialPath(name))
	if err != nil || data == nil {
		return "not_configured", nil
	}
	return "available", nil
}

// RotateCredential updates the credential for an existing service without
// changing any service configuration. This supports seamless rotation with
// no service downtime: callers should also call proxy.InvalidateCache(name)
// to ensure the next request picks up the new credential immediately.
func (r *Registry) RotateCredential(name string, newCredential string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, ok := r.services[name]; !ok {
		return fmt.Errorf("services: %q not found", name)
	}

	if err := r.writeCredential(name, newCredential); err != nil {
		return err
	}
	return nil
}

// GetCredential returns the raw credential value stored in OpenBao for the named service.
// This is intended for internal use by the proxy only — never expose via HTTP.
//
// Backward compatibility: handles both legacy format (value key only) and new
// multi-field format (auth_method + field keys). For new format, returns the
// "token" field if present, otherwise "value", otherwise the first non-auth_method field.
func (r *Registry) GetCredential(name string) (string, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if _, ok := r.services[name]; !ok {
		return "", fmt.Errorf("services: %q not found", name)
	}

	data, err := r.vault.ReadSecret(credentialPath(name))
	if err != nil {
		return "", fmt.Errorf("services: read credential for %q: %w", name, err)
	}

	// New format: has "auth_method" key — look for "token" then "value" then first field.
	if _, hasAuthMethod := data["auth_method"]; hasAuthMethod {
		for _, preferredKey := range []string{"token", "value"} {
			if v, ok := data[preferredKey]; ok {
				if s, ok := v.(string); ok {
					return s, nil
				}
			}
		}
		// Fall back to first non-auth_method string field.
		for k, v := range data {
			if k == "auth_method" {
				continue
			}
			if s, ok := v.(string); ok {
				return s, nil
			}
		}
		return "", fmt.Errorf("services: no credential value found for %q", name)
	}

	// Legacy format: "value" key only.
	val, ok := data["value"]
	if !ok {
		return "", fmt.Errorf("services: credential for %q missing 'value' field", name)
	}
	cred, ok := val.(string)
	if !ok {
		return "", fmt.Errorf("services: credential for %q has unexpected type", name)
	}
	return cred, nil
}

// ReadCredentials returns the auth method ID and credential fields stored in
// OpenBao for the named service. This is the multi-field counterpart to GetCredential.
//
// Handles both new format (with auth_method key) and legacy format (with value key).
// Legacy format returns ("legacy", {"value": val}).
func (r *Registry) ReadCredentials(name string) (authMethod string, fields map[string]string, err error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if _, ok := r.services[name]; !ok {
		return "", nil, fmt.Errorf("services: %q not found", name)
	}

	data, err := r.vault.ReadSecret(credentialPath(name))
	if err != nil {
		return "", nil, fmt.Errorf("services: read credentials for %q: %w", name, err)
	}

	// New format: has "auth_method" key.
	if am, ok := data["auth_method"].(string); ok {
		result := make(map[string]string, len(data)-1)
		for k, v := range data {
			if k == "auth_method" {
				continue
			}
			if s, ok := v.(string); ok {
				result[k] = s
			}
		}
		return am, result, nil
	}

	// Legacy format: has "value" key but no "auth_method".
	if val, ok := data["value"].(string); ok {
		return "legacy", map[string]string{"value": val}, nil
	}

	return "", nil, fmt.Errorf("services: unrecognized credential format for %q", name)
}

// CreateWithAuth adds a new service to the registry and stores multi-field
// credentials in OpenBao along with the auth method ID.
// Returns an error if the name already exists, validation fails, or vault write fails.
func (r *Registry) CreateWithAuth(svc Service, authMethod string, credentials map[string]string) error {
	if err := validateService(svc); err != nil {
		return err
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.services[svc.Name]; exists {
		return fmt.Errorf("services: %q already exists", svc.Name)
	}

	if err := r.writeCredentials(svc.Name, authMethod, credentials); err != nil {
		return err
	}

	now := time.Now().UTC()
	svc.AuthMethodID = authMethod
	svc.CreatedAt = now
	svc.UpdatedAt = now
	svc.Status = "available"
	r.services[svc.Name] = svc

	// Persist metadata best-effort — do not fail service creation on metadata write error.
	_ = r.saveMetadata(svc)
	return nil
}

// UpdateCredentials replaces all credential fields for an existing service.
// The authMethod is stored alongside the new credential fields.
// Returns an error if the service does not exist or if vault write fails.
func (r *Registry) UpdateCredentials(name, authMethod string, credentials map[string]string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, ok := r.services[name]; !ok {
		return fmt.Errorf("services: %q not found", name)
	}

	if err := r.writeCredentials(name, authMethod, credentials); err != nil {
		return err
	}
	return nil
}

// SetAccountInfo stores account identity information on an existing service.
// The info is kept in memory only and is never written to vault.
// Pass nil to clear previously set account info.
// Returns an error if the service does not exist.
func (r *Registry) SetAccountInfo(name string, info *AccountInfo) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	svc, ok := r.services[name]
	if !ok {
		return fmt.Errorf("services: %q not found", name)
	}

	svc.AccountInfo = info
	r.services[name] = svc
	return nil
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// credentialPath returns the OpenBao KV path for a service's credential.
func credentialPath(name string) string {
	return "services/" + name + "/credential"
}

// metadataPath returns the OpenBao KV path for a service's metadata.
func metadataPath(name string) string {
	return "services/" + name + "/metadata"
}

// writeCredential stores a single credential in OpenBao in the new format.
// The credential is stored with auth_method="api_key" and key "value" for
// backward compatibility with legacy Create callers.
func (r *Registry) writeCredential(name, credential string) error {
	return r.writeCredentials(name, "api_key", map[string]string{"value": credential})
}

// writeCredentials stores multi-field credentials in OpenBao.
// The auth_method discriminator is stored alongside the credential fields.
func (r *Registry) writeCredentials(name, authMethod string, fields map[string]string) error {
	data := make(map[string]interface{}, len(fields)+1)
	data["auth_method"] = authMethod
	for k, v := range fields {
		data[k] = v
	}
	if err := r.vault.WriteSecret(credentialPath(name), data); err != nil {
		return fmt.Errorf("services: store credentials for %q: %w", name, err)
	}
	return nil
}

// saveMetadata writes service configuration fields to vault at
// services/{name}/metadata. The vault KV store uses a flat map, so
// DefaultHeaders are serialized as a JSON string. saveMetadata is
// best-effort: callers must not treat failure as a hard error.
func (r *Registry) saveMetadata(svc Service) error {
	data := map[string]interface{}{
		"name":            svc.Name,
		"type":            svc.Type,
		"target":          svc.Target,
		"inject":          svc.Inject,
		"auth_method_id":  svc.AuthMethodID,
		"header_name":     svc.HeaderName,
		"header_template": svc.HeaderTemplate,
		"query_param":     svc.QueryParam,
	}
	if svc.DefaultHeaders != nil {
		headerJSON, err := json.Marshal(svc.DefaultHeaders)
		if err == nil {
			data["default_headers"] = string(headerJSON)
		}
	}
	return r.vault.WriteSecret(metadataPath(svc.Name), data)
}

// LoadFromVault reads service metadata persisted at services/*/metadata and
// populates the in-memory registry. Existing entries are never overwritten so
// it is safe to call multiple times. Services with credentials but without
// metadata (legacy) are silently skipped.
//
// LoadFromVault is intended to be called once on startup after the vault is
// ready and before any request handling begins.
func (r *Registry) LoadFromVault() error {
	names, err := r.vault.ListSecrets("services/")
	if err != nil {
		// No services yet — treat as empty, not an error.
		return nil
	}

	for _, name := range names {
		// Vault list returns directory names with a trailing slash.
		name = strings.TrimSuffix(name, "/")
		if name == "" {
			continue
		}

		data, err := r.vault.ReadSecret(metadataPath(name))
		if err != nil {
			// Service has credentials but no metadata (legacy) — skip silently.
			continue
		}

		svc := Service{
			Name:           getString(data, "name"),
			Type:           getString(data, "type"),
			Target:         getString(data, "target"),
			Inject:         getString(data, "inject"),
			AuthMethodID:   getString(data, "auth_method_id"),
			HeaderName:     getString(data, "header_name"),
			HeaderTemplate: getString(data, "header_template"),
			QueryParam:     getString(data, "query_param"),
			Status:         "available",
			CreatedAt:      time.Now().UTC(),
			UpdatedAt:      time.Now().UTC(),
		}

		if headerJSON := getString(data, "default_headers"); headerJSON != "" {
			var headers map[string]string
			if json.Unmarshal([]byte(headerJSON), &headers) == nil {
				svc.DefaultHeaders = headers
			}
		}

		r.mu.Lock()
		if _, exists := r.services[name]; !exists {
			r.services[name] = svc
		}
		r.mu.Unlock()
	}
	return nil
}

// getString extracts a string value from a map[string]interface{} by key.
// Returns an empty string if the key is absent or the value is not a string.
func getString(data map[string]interface{}, key string) string {
	v, _ := data[key].(string)
	return v
}

// validateService checks that the required fields of svc are valid.
func validateService(svc Service) error {
	// Validate name format.
	if !serviceNamePattern.MatchString(svc.Name) {
		return fmt.Errorf("services: invalid name %q: must match ^[a-z][a-z0-9_-]{0,62}$", svc.Name)
	}

	// Validate type.
	if !validTypes[svc.Type] {
		return fmt.Errorf("services: invalid type %q: must be http_proxy or oauth", svc.Type)
	}

	// Validate target: must be a valid URL with https scheme.
	if svc.Target == "" {
		return fmt.Errorf("services: target is required")
	}
	u, err := url.ParseRequestURI(svc.Target)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("services: target %q must be a valid URL with https:// scheme", svc.Target)
	}

	// Validate inject.
	if !validInject[svc.Inject] {
		return fmt.Errorf("services: invalid inject %q: must be header or query", svc.Inject)
	}

	return nil
}
