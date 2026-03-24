package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/straylight-ai/straylight/internal/config"
)

// TestLoadConfig_ValidYAML verifies that a valid YAML config file is parsed correctly.
func TestLoadConfig_ValidYAML(t *testing.T) {
	yaml := `
version: "1"
vault:
  address: "http://127.0.0.1:9443"
server:
  listen_address: "0.0.0.0:9470"
  log_level: info
  log_format: text
sanitizer:
  enabled: true
  replacement_template: "[REDACTED:{{.service}}]"
`
	path := writeTempConfig(t, yaml)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load() returned unexpected error: %v", err)
	}

	if cfg.Version != "1" {
		t.Errorf("expected version=1, got %q", cfg.Version)
	}
	if cfg.Vault.Address != "http://127.0.0.1:9443" {
		t.Errorf("expected vault address=http://127.0.0.1:9443, got %q", cfg.Vault.Address)
	}
	if cfg.Server.ListenAddress != "0.0.0.0:9470" {
		t.Errorf("expected server listen_address=0.0.0.0:9470, got %q", cfg.Server.ListenAddress)
	}
	if cfg.Server.LogLevel != "info" {
		t.Errorf("expected log_level=info, got %q", cfg.Server.LogLevel)
	}
	if !cfg.Sanitizer.Enabled {
		t.Error("expected sanitizer.enabled=true")
	}
}

// TestLoadConfig_DefaultValues verifies that default values are applied when optional fields are omitted.
func TestLoadConfig_DefaultValues(t *testing.T) {
	yaml := `
version: "1"
server:
  listen_address: "0.0.0.0:9470"
`
	path := writeTempConfig(t, yaml)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load() returned unexpected error: %v", err)
	}

	if cfg.Vault.Address != "http://127.0.0.1:8200" {
		t.Errorf("expected default vault address=http://127.0.0.1:8200, got %q", cfg.Vault.Address)
	}
	if cfg.Server.LogLevel != "info" {
		t.Errorf("expected default log_level=info, got %q", cfg.Server.LogLevel)
	}
	if cfg.Server.LogFormat != "text" {
		t.Errorf("expected default log_format=text, got %q", cfg.Server.LogFormat)
	}
	if !cfg.Sanitizer.Enabled {
		t.Error("expected default sanitizer.enabled=true")
	}
	if cfg.Sanitizer.ReplacementTemplate != "[REDACTED:{{.service}}]" {
		t.Errorf("expected default replacement_template, got %q", cfg.Sanitizer.ReplacementTemplate)
	}
}

// TestLoadConfig_MissingFile verifies that a missing config file returns an error.
func TestLoadConfig_MissingFile(t *testing.T) {
	_, err := config.Load("/nonexistent/path/config.yaml")
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

// TestLoadConfig_InvalidYAML verifies that malformed YAML returns a parse error.
func TestLoadConfig_InvalidYAML(t *testing.T) {
	path := writeTempConfig(t, "server:\n  listen_address: [unclosed")
	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected parse error for invalid YAML, got nil")
	}
}

// TestLoadConfig_MissingListenAddress verifies that missing listen_address gets a default.
func TestLoadConfig_MissingListenAddress(t *testing.T) {
	yaml := `
version: "1"
server:
  log_level: debug
`
	path := writeTempConfig(t, yaml)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load() returned unexpected error: %v", err)
	}
	if cfg.Server.ListenAddress != "0.0.0.0:9470" {
		t.Errorf("expected default listen_address=0.0.0.0:9470, got %q", cfg.Server.ListenAddress)
	}
}

// TestLoadConfig_InvalidLogLevel verifies that an invalid log level returns a validation error.
func TestLoadConfig_InvalidLogLevel(t *testing.T) {
	yaml := `
version: "1"
server:
  listen_address: "0.0.0.0:9470"
  log_level: verbose
`
	path := writeTempConfig(t, yaml)
	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected validation error for invalid log_level=verbose, got nil")
	}
}

// TestLoadConfig_ServiceEntries verifies that service configurations are parsed.
func TestLoadConfig_ServiceEntries(t *testing.T) {
	yaml := `
version: "1"
server:
  listen_address: "0.0.0.0:9470"
services:
  stripe:
    type: http_proxy
    target: "https://api.stripe.com"
    inject: header
    header_template: "Bearer {{.secret}}"
`
	path := writeTempConfig(t, yaml)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load() returned unexpected error: %v", err)
	}

	svc, ok := cfg.Services["stripe"]
	if !ok {
		t.Fatal("expected services.stripe to exist")
	}
	if svc.Type != "http_proxy" {
		t.Errorf("expected stripe.type=http_proxy, got %q", svc.Type)
	}
	if svc.Target != "https://api.stripe.com" {
		t.Errorf("expected stripe.target=https://api.stripe.com, got %q", svc.Target)
	}
}

// TestPortFromListenAddress verifies extraction of port from listen address.
func TestPortFromListenAddress(t *testing.T) {
	cases := []struct {
		address string
		port    int
		wantErr bool
	}{
		{"0.0.0.0:9470", 9470, false},
		{"localhost:8080", 8080, false},
		{":9000", 9000, false},
		{"invalid", 0, true},
		{"host:notaport", 0, true},
	}

	for _, tc := range cases {
		port, err := config.PortFromListenAddress(tc.address)
		if tc.wantErr {
			if err == nil {
				t.Errorf("PortFromListenAddress(%q): expected error, got nil", tc.address)
			}
			continue
		}
		if err != nil {
			t.Errorf("PortFromListenAddress(%q): unexpected error: %v", tc.address, err)
			continue
		}
		if port != tc.port {
			t.Errorf("PortFromListenAddress(%q): expected %d, got %d", tc.address, tc.port, port)
		}
	}
}

// writeTempConfig writes content to a temp file and returns its path.
func writeTempConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("writeTempConfig: %v", err)
	}
	return path
}
