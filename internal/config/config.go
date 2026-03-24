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
	CredentialPatterns []string          `yaml:"credential_patterns"`
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

	for name, svc := range cfg.Services {
		if svc.Type != "http_proxy" && svc.Type != "oauth" {
			return fmt.Errorf("config: services.%s.type %q is invalid; must be http_proxy or oauth", name, svc.Type)
		}
		if svc.Target == "" {
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
