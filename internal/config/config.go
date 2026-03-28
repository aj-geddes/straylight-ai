// Package config handles loading and validation of the Straylight-AI configuration file.
package config

import (
	"fmt"
	"net"
	"os"
	"strconv"

	"gopkg.in/yaml.v3"
)

const (
	DefaultVaultAddress         = "http://127.0.0.1:8200"
	DefaultListenAddress        = "0.0.0.0:9470"
	DefaultLogLevel             = "info"
	DefaultLogFormat            = "text"
	DefaultReplacementTemplate  = "[REDACTED:{{.service}}]"
	DefaultTimeoutSeconds       = 30
	DefaultConfigPath           = "/data/config.yaml"
)

// Config is the root configuration structure for Straylight-AI.
type Config struct {
	Version   string                    `yaml:"version"`
	Vault     VaultConfig               `yaml:"vault"`
	Server    ServerConfig              `yaml:"server"`
	Sanitizer SanitizerConfig           `yaml:"sanitizer"`
	Services  map[string]ServiceConfig  `yaml:"services"`
	Databases map[string]DatabaseConfig `yaml:"databases"`
	Cloud     CloudConfig               `yaml:"cloud"`
}

// CloudConfig holds global defaults for cloud provider temporary credentials.
type CloudConfig struct {
	// AWS holds global AWS defaults.
	AWS CloudAWSDefaults `yaml:"aws"`
	// GCP holds global GCP defaults.
	GCP CloudGCPDefaults `yaml:"gcp"`
	// Azure holds global Azure defaults.
	Azure CloudAzureDefaults `yaml:"azure"`
}

// CloudAWSDefaults holds global AWS defaults applied when a service config
// does not specify these fields.
type CloudAWSDefaults struct {
	// DefaultRegion is the AWS region if not specified per-service.
	DefaultRegion string `yaml:"default_region"`
	// DefaultSessionDurationSecs is the STS session TTL. Range: 900-43200.
	// Defaults to 900 (15 minutes, the AWS minimum).
	DefaultSessionDurationSecs int `yaml:"default_session_duration_seconds"`
}

// CloudGCPDefaults holds global GCP defaults.
type CloudGCPDefaults struct {
	// DefaultTokenLifetimeSecs is the access token TTL. Defaults to 3600 (1 hour).
	DefaultTokenLifetimeSecs int `yaml:"default_token_lifetime_seconds"`
}

// CloudAzureDefaults holds global Azure defaults.
type CloudAzureDefaults struct {
	// DefaultScope is the token scope. Defaults to "https://management.azure.com/.default".
	DefaultScope string `yaml:"default_scope"`
}

// DatabaseConfig holds configuration for a database service (type=database).
// Admin credentials are stored in vault; this struct captures connection metadata.
type DatabaseConfig struct {
	Engine        string `yaml:"engine"`
	Host          string `yaml:"host"`
	Port          int    `yaml:"port"`
	Database      string `yaml:"database"`
	SSLMode       string `yaml:"ssl_mode"`
	AdminUser     string `yaml:"admin_user"`
	AdminPassword string `yaml:"admin_password"`
	DefaultRole   string `yaml:"default_role"`
	DefaultTTL    string `yaml:"default_ttl"`
	MaxTTL        string `yaml:"max_ttl"`
}

// VaultConfig holds OpenBao connection settings.
type VaultConfig struct {
	Address string `yaml:"address"`
}

// ServerConfig holds HTTP server settings.
type ServerConfig struct {
	ListenAddress string `yaml:"listen_address"`
	LogLevel      string `yaml:"log_level"`
	LogFormat     string `yaml:"log_format"`
}

// SanitizerConfig holds output sanitizer settings.
type SanitizerConfig struct {
	Enabled             bool             `yaml:"enabled"`
	ReplacementTemplate string           `yaml:"replacement_template"`
	CustomPatterns      []CustomPattern  `yaml:"custom_patterns"`
}

// CustomPattern is a user-defined regex pattern for credential detection.
type CustomPattern struct {
	Name    string `yaml:"name"`
	Pattern string `yaml:"pattern"`
	Service string `yaml:"service"`
}

// ServiceConfig defines a single external service integration.
type ServiceConfig struct {
	Type               string            `yaml:"type"`
	Target             string            `yaml:"target"`
	Inject             string            `yaml:"inject"`
	HeaderTemplate     string            `yaml:"header_template"`
	HeaderName         string            `yaml:"header_name"`
	QueryParam         string            `yaml:"query_param"`
	DefaultHeaders     map[string]string `yaml:"default_headers"`
	TimeoutSeconds     int               `yaml:"timeout_seconds"`
	ExecConfig         *ExecConfig       `yaml:"exec_config"`
	OAuthConfig        *OAuthConfig      `yaml:"oauth_config"`
	CloudConfig        *CloudServiceConfig `yaml:"cloud_config"`
	CredentialPatterns []string          `yaml:"credential_patterns"`
}

// CloudServiceConfig holds cloud-provider-specific configuration for a service
// with type=cloud. The Engine field determines which sub-config is used.
type CloudServiceConfig struct {
	// Engine identifies the cloud provider: "aws", "gcp", or "azure".
	Engine string `yaml:"engine"`

	// AWS holds AWS-specific configuration. Used when Engine is "aws".
	AWS *CloudServiceAWSConfig `yaml:"aws"`
	// GCP holds GCP-specific configuration. Used when Engine is "gcp".
	GCP *CloudServiceGCPConfig `yaml:"gcp"`
	// Azure holds Azure-specific configuration. Used when Engine is "azure".
	Azure *CloudServiceAzureConfig `yaml:"azure"`
}

// CloudServiceAWSConfig holds AWS-specific fields for a cloud service.
type CloudServiceAWSConfig struct {
	// RoleARN is the IAM role ARN for STS AssumeRole.
	RoleARN string `yaml:"role_arn"`
	// Region sets AWS_DEFAULT_REGION. Defaults to the global CloudAWSDefaults.DefaultRegion.
	Region string `yaml:"region"`
	// SessionDurationSecs is the STS session TTL. Zero uses the global default (900s).
	SessionDurationSecs int `yaml:"session_duration_seconds"`
	// SessionPolicy is an optional inline IAM policy JSON for further scope restriction.
	SessionPolicy string `yaml:"session_policy"`
}

// CloudServiceGCPConfig holds GCP-specific fields for a cloud service.
type CloudServiceGCPConfig struct {
	// ProjectID sets CLOUDSDK_CORE_PROJECT.
	ProjectID string `yaml:"project_id"`
	// Scopes are the OAuth2 scopes for the access token.
	Scopes []string `yaml:"scopes"`
	// TokenLifetimeSecs is the requested token TTL. Zero uses the global default (3600s).
	TokenLifetimeSecs int `yaml:"token_lifetime_seconds"`
}

// CloudServiceAzureConfig holds Azure-specific fields for a cloud service.
type CloudServiceAzureConfig struct {
	// TenantID is the Azure AD tenant ID (stored in vault, not here).
	TenantID string `yaml:"tenant_id"`
	// SubscriptionID sets AZURE_SUBSCRIPTION_ID.
	SubscriptionID string `yaml:"subscription_id"`
	// Scope is the token audience. Defaults to the global CloudAzureDefaults.DefaultScope.
	Scope string `yaml:"scope"`
}

// ExecConfig holds configuration for command execution credential injection.
type ExecConfig struct {
	EnvVar          string            `yaml:"env_var"`
	AllowedCommands []string          `yaml:"allowed_commands"`
	EnvExtras       map[string]string `yaml:"env_extras"`
}

// OAuthConfig holds OAuth 2.0 flow configuration.
type OAuthConfig struct {
	Provider    string   `yaml:"provider"`
	ClientID    string   `yaml:"client_id"`
	AuthURL     string   `yaml:"auth_url"`
	TokenURL    string   `yaml:"token_url"`
	Scopes      []string `yaml:"scopes"`
	AutoRefresh bool     `yaml:"auto_refresh"`
	RedirectURI string   `yaml:"redirect_uri"`
}

// Load reads the YAML config file at path, applies defaults, and validates it.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: cannot read file %q: %w", path, err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("config: failed to parse YAML: %w", err)
	}

	applyDefaults(&cfg)

	if err := validate(&cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// applyDefaults fills in zero-value fields with their default values.
func applyDefaults(cfg *Config) {
	if cfg.Vault.Address == "" {
		cfg.Vault.Address = DefaultVaultAddress
	}
	if cfg.Server.ListenAddress == "" {
		cfg.Server.ListenAddress = DefaultListenAddress
	}
	if cfg.Server.LogLevel == "" {
		cfg.Server.LogLevel = DefaultLogLevel
	}
	if cfg.Server.LogFormat == "" {
		cfg.Server.LogFormat = DefaultLogFormat
	}
	// Sanitizer is enabled by default; only override if the whole block was absent.
	// We detect absence by checking whether both Enabled is false and template is empty.
	if !cfg.Sanitizer.Enabled && cfg.Sanitizer.ReplacementTemplate == "" {
		cfg.Sanitizer.Enabled = true
		cfg.Sanitizer.ReplacementTemplate = DefaultReplacementTemplate
	} else if cfg.Sanitizer.ReplacementTemplate == "" {
		cfg.Sanitizer.ReplacementTemplate = DefaultReplacementTemplate
	}

	for name, svc := range cfg.Services {
		if svc.Inject == "" {
			svc.Inject = "header"
		}
		if svc.HeaderTemplate == "" {
			svc.HeaderTemplate = "Bearer {{.secret}}"
		}
		if svc.HeaderName == "" {
			svc.HeaderName = "Authorization"
		}
		if svc.TimeoutSeconds == 0 {
			svc.TimeoutSeconds = DefaultTimeoutSeconds
		}
		cfg.Services[name] = svc
	}
}

var validLogLevels = map[string]bool{
	"debug": true,
	"info":  true,
	"warn":  true,
	"error": true,
}

var validLogFormats = map[string]bool{
	"text": true,
	"json": true,
}

// validate checks that required fields are present and values are within allowed ranges.
func validate(cfg *Config) error {
	if cfg.Server.ListenAddress == "" {
		return fmt.Errorf("config: server.listen_address is required")
	}

	if !validLogLevels[cfg.Server.LogLevel] {
		return fmt.Errorf("config: server.log_level %q is invalid; must be one of: debug, info, warn, error", cfg.Server.LogLevel)
	}

	if !validLogFormats[cfg.Server.LogFormat] {
		return fmt.Errorf("config: server.log_format %q is invalid; must be one of: text, json", cfg.Server.LogFormat)
	}

	validServiceTypes := map[string]bool{
		"http_proxy": true,
		"oauth":      true,
		"database":   true,
		"cloud":      true,
	}
	for name, svc := range cfg.Services {
		if !validServiceTypes[svc.Type] {
			return fmt.Errorf("config: services.%s.type %q is invalid; must be http_proxy, oauth, database, or cloud", name, svc.Type)
		}
		// Database and cloud services do not require a target URL.
		if svc.Type != "database" && svc.Type != "cloud" && svc.Target == "" {
			return fmt.Errorf("config: services.%s.target is required", name)
		}
	}

	return nil
}

// PortFromListenAddress parses "host:port" and returns the numeric port.
func PortFromListenAddress(addr string) (int, error) {
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return 0, fmt.Errorf("config: invalid listen address %q: %w", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return 0, fmt.Errorf("config: invalid port in address %q: %w", addr, err)
	}
	return port, nil
}
