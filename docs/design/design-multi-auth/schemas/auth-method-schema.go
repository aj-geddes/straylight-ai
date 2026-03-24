// Package services — proposed type additions for multi-auth-method support.
// This file is a design artifact, not compilable code.
// It shows the exact struct definitions to add to internal/services/.

package services

// =============================================================================
// NEW TYPES — add to internal/services/auth_methods.go
// =============================================================================

// InjectionType enumerates the supported credential injection strategies.
type InjectionType string

const (
	InjectionBearerHeader  InjectionType = "bearer_header"
	InjectionCustomHeader  InjectionType = "custom_header"
	InjectionMultiHeader   InjectionType = "multi_header"
	InjectionQueryParam    InjectionType = "query_param"
	InjectionBasicAuth     InjectionType = "basic_auth"
	InjectionOAuth         InjectionType = "oauth"
	InjectionNamedStrategy InjectionType = "named_strategy"
)

// FieldType enumerates the UI input types for credential fields.
type FieldType string

const (
	FieldPassword FieldType = "password"
	FieldText     FieldType = "text"
	FieldTextarea FieldType = "textarea"
)

// AuthMethod describes one way to authenticate with a service.
// Templates define a slice of these; the user chooses one when creating a service.
type AuthMethod struct {
	ID          string            `json:"id"           yaml:"id"`
	Name        string            `json:"name"         yaml:"name"`
	Description string            `json:"description"  yaml:"description"`
	Fields      []CredentialField `json:"fields"       yaml:"fields"`
	Injection   InjectionConfig   `json:"injection"    yaml:"injection"`
	AutoRefresh bool              `json:"auto_refresh"  yaml:"auto_refresh"`
	TokenPrefix string            `json:"token_prefix,omitempty" yaml:"token_prefix,omitempty"`
}

// CredentialField describes one input the user must provide for an auth method.
type CredentialField struct {
	Key         string   `json:"key"                    yaml:"key"`
	Label       string   `json:"label"                  yaml:"label"`
	Type        FieldType `json:"type"                  yaml:"type"`
	Placeholder string   `json:"placeholder,omitempty"  yaml:"placeholder,omitempty"`
	Required    bool     `json:"required"               yaml:"required"`
	Pattern     string   `json:"pattern,omitempty"      yaml:"pattern,omitempty"`
	HelpText    string   `json:"help_text,omitempty"    yaml:"help_text,omitempty"`
}

// InjectionConfig describes how credentials are injected into HTTP requests.
type InjectionConfig struct {
	Type           InjectionType     `json:"type"                       yaml:"type"`
	HeaderName     string            `json:"header_name,omitempty"      yaml:"header_name,omitempty"`
	HeaderTemplate string            `json:"header_template,omitempty"  yaml:"header_template,omitempty"`
	QueryParam     string            `json:"query_param,omitempty"      yaml:"query_param,omitempty"`
	Headers        map[string]string `json:"headers,omitempty"          yaml:"headers,omitempty"`
	Strategy       string            `json:"strategy,omitempty"         yaml:"strategy,omitempty"`
}

// =============================================================================
// UPDATED TYPE — ServiceTemplate replaces the current map[string]Service usage
// Add to internal/services/templates.go
// =============================================================================

// ServiceTemplate is a pre-configured template for a common service.
// Templates are read-only and define the available auth methods.
type ServiceTemplate struct {
	ID             string            `json:"id"              yaml:"id"`
	DisplayName    string            `json:"display_name"    yaml:"display_name"`
	Description    string            `json:"description"     yaml:"description"`
	Icon           string            `json:"icon"            yaml:"icon"`
	Target         string            `json:"target"          yaml:"target"`
	DefaultHeaders map[string]string `json:"default_headers,omitempty" yaml:"default_headers,omitempty"`
	AuthMethods    []AuthMethod      `json:"auth_methods"    yaml:"auth_methods"`
	ExecConfig     *ExecConfig       `json:"exec_config,omitempty" yaml:"exec_config,omitempty"`
}

// ExecConfig holds configuration for credential injection into command execution.
type ExecConfig struct {
	EnvVar string `json:"env_var" yaml:"env_var"`
}

// =============================================================================
// UPDATED TYPE — Service gains AuthMethodID field
// Modify in internal/services/registry.go
// =============================================================================

// Service represents a configured external service integration.
// Add this field to the existing Service struct:
//
//   AuthMethodID string `json:"auth_method,omitempty" yaml:"auth_method,omitempty"`
//
// When AuthMethodID is empty, the service uses legacy injection behavior
// (flat Inject/HeaderName/HeaderTemplate fields).

// =============================================================================
// UPDATED FUNCTION — writeCredential becomes writeCredentials
// Modify in internal/services/registry.go
// =============================================================================

// writeCredentials stores multi-field credentials in OpenBao.
// The auth_method discriminator is stored alongside the credential fields.
//
// func (r *Registry) writeCredentials(name string, authMethod string, fields map[string]string) error {
//     data := make(map[string]interface{}, len(fields)+1)
//     data["auth_method"] = authMethod
//     for k, v := range fields {
//         data[k] = v
//     }
//     return r.vault.WriteSecret(credentialPath(name), data)
// }

// =============================================================================
// UPDATED FUNCTION — GetCredential becomes GetCredentials (returns map)
// Modify in internal/services/registry.go
// =============================================================================

// GetCredentials returns the auth method ID and credential fields from OpenBao.
// Handles both new format (with auth_method key) and legacy format (with value key).
//
// func (r *Registry) GetCredentials(name string) (authMethod string, fields map[string]string, err error) {
//     data, err := r.vault.ReadSecret(credentialPath(name))
//     if err != nil {
//         return "", nil, fmt.Errorf("services: read credentials for %q: %w", name, err)
//     }
//
//     // New format: has "auth_method" key
//     if am, ok := data["auth_method"].(string); ok {
//         fields := make(map[string]string)
//         for k, v := range data {
//             if k == "auth_method" {
//                 continue
//             }
//             if s, ok := v.(string); ok {
//                 fields[k] = s
//             }
//         }
//         return am, fields, nil
//     }
//
//     // Legacy format: has "value" key
//     if val, ok := data["value"].(string); ok {
//         return "api_key", map[string]string{"value": val}, nil
//     }
//
//     return "", nil, fmt.Errorf("services: unrecognized credential format for %q", name)
// }

// =============================================================================
// NEW FUNCTION — Create overload accepting multi-field credentials
// Add to internal/services/registry.go
// =============================================================================

// CreateWithAuth creates a service with a specific auth method and multi-field credentials.
//
// func (r *Registry) CreateWithAuth(svc Service, authMethod string, credentials map[string]string) error {
//     if err := validateService(svc); err != nil {
//         return err
//     }
//     r.mu.Lock()
//     defer r.mu.Unlock()
//     if _, exists := r.services[svc.Name]; exists {
//         return fmt.Errorf("services: %q already exists", svc.Name)
//     }
//     if err := r.writeCredentials(svc.Name, authMethod, credentials); err != nil {
//         return err
//     }
//     now := time.Now().UTC()
//     svc.AuthMethodID = authMethod
//     svc.CreatedAt = now
//     svc.UpdatedAt = now
//     svc.Status = "available"
//     r.services[svc.Name] = svc
//     return nil
// }

// =============================================================================
// BACKWARD COMPATIBILITY — existing Create(svc, credential string) still works
// The existing Create method wraps the single credential as:
//   credentials = map[string]string{"value": credential}
//   authMethod = "api_key"
// =============================================================================
