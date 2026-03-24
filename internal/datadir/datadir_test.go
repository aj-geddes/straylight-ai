// Package datadir_test tests the data directory initialization logic.
package datadir_test

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/straylight-ai/straylight/internal/datadir"
)

// TestInitialize_FirstStart verifies that calling Initialize on an empty
// directory creates the expected subdirectory structure.
func TestInitialize_FirstStart(t *testing.T) {
	base := t.TempDir()

	if err := datadir.Initialize(base); err != nil {
		t.Fatalf("Initialize returned unexpected error: %v", err)
	}

	dirs := []string{
		filepath.Join(base, "openbao"),
		filepath.Join(base, "openbao", "storage"),
	}
	for _, d := range dirs {
		info, err := os.Stat(d)
		if err != nil {
			t.Errorf("expected directory %q to exist, got error: %v", d, err)
			continue
		}
		if !info.IsDir() {
			t.Errorf("expected %q to be a directory", d)
		}
	}
}

// TestInitialize_DirectoryPermissions verifies that created directories have
// mode 0700.
func TestInitialize_DirectoryPermissions(t *testing.T) {
	base := t.TempDir()

	if err := datadir.Initialize(base); err != nil {
		t.Fatalf("Initialize returned unexpected error: %v", err)
	}

	dirs := []string{
		filepath.Join(base, "openbao"),
		filepath.Join(base, "openbao", "storage"),
	}
	for _, d := range dirs {
		info, err := os.Stat(d)
		if err != nil {
			t.Fatalf("cannot stat %q: %v", d, err)
		}
		perm := info.Mode().Perm()
		if perm != 0700 {
			t.Errorf("directory %q has permissions %04o, want 0700", d, perm)
		}
	}
}

// TestInitialize_CreatesDefaultConfig verifies that config.yaml is written
// on first start and contains the required top-level keys.
func TestInitialize_CreatesDefaultConfig(t *testing.T) {
	base := t.TempDir()

	if err := datadir.Initialize(base); err != nil {
		t.Fatalf("Initialize returned unexpected error: %v", err)
	}

	configPath := filepath.Join(base, "config.yaml")
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("config.yaml not created: %v", err)
	}

	var parsed map[string]interface{}
	if err := yaml.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("config.yaml is not valid YAML: %v", err)
	}

	requiredKeys := []string{"vault", "server", "sanitizer", "services"}
	for _, key := range requiredKeys {
		if _, ok := parsed[key]; !ok {
			t.Errorf("config.yaml missing required key %q", key)
		}
	}
}

// TestInitialize_ConfigPermissions verifies that config.yaml is created with
// mode 0644.
func TestInitialize_ConfigPermissions(t *testing.T) {
	base := t.TempDir()

	if err := datadir.Initialize(base); err != nil {
		t.Fatalf("Initialize returned unexpected error: %v", err)
	}

	configPath := filepath.Join(base, "config.yaml")
	info, err := os.Stat(configPath)
	if err != nil {
		t.Fatalf("cannot stat config.yaml: %v", err)
	}
	perm := info.Mode().Perm()
	if perm != 0644 {
		t.Errorf("config.yaml has permissions %04o, want 0644", perm)
	}
}

// TestInitialize_Restart_PreservesConfig verifies that calling Initialize a
// second time (simulating a restart) does NOT overwrite an existing config.yaml.
func TestInitialize_Restart_PreservesConfig(t *testing.T) {
	base := t.TempDir()

	// First start: creates the config.
	if err := datadir.Initialize(base); err != nil {
		t.Fatalf("first Initialize failed: %v", err)
	}

	configPath := filepath.Join(base, "config.yaml")
	sentinel := "# sentinel-marker-do-not-overwrite\n"
	original, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("cannot read config after first init: %v", err)
	}
	modified := append([]byte(sentinel), original...)
	if err := os.WriteFile(configPath, modified, 0644); err != nil {
		t.Fatalf("cannot write modified config: %v", err)
	}

	// Second start (restart): must NOT overwrite the sentinel.
	if err := datadir.Initialize(base); err != nil {
		t.Fatalf("second Initialize failed: %v", err)
	}

	after, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("cannot read config after second init: %v", err)
	}
	if string(after) != string(modified) {
		t.Errorf("config.yaml was overwritten on restart\ngot:\n%s\nwant:\n%s", after, modified)
	}
}

// TestInitialize_MissingBaseDirectory verifies that passing a non-existent
// base path returns a clear, descriptive error.
func TestInitialize_MissingBaseDirectory(t *testing.T) {
	err := datadir.Initialize("/this/path/does/not/exist/at/all")
	if err == nil {
		t.Fatal("expected error for non-existent base directory, got nil")
	}
}

// TestInitialize_NonWritableBaseDirectory verifies that a base directory that
// exists but is not writable produces a clear error.
func TestInitialize_NonWritableBaseDirectory(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root: permission checks do not apply")
	}
	base := t.TempDir()
	// Remove write permission so mkdir inside it fails.
	if err := os.Chmod(base, 0500); err != nil {
		t.Fatalf("cannot chmod temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(base, 0700) })

	err := datadir.Initialize(base)
	if err == nil {
		t.Fatal("expected error for non-writable base directory, got nil")
	}
}

// TestInitialize_BaseIsFile verifies that passing a file path (not a directory)
// as basePath returns a clear error.
func TestInitialize_BaseIsFile(t *testing.T) {
	base := t.TempDir()
	filePath := filepath.Join(base, "not-a-dir")
	if err := os.WriteFile(filePath, []byte("x"), 0644); err != nil {
		t.Fatalf("cannot create test file: %v", err)
	}

	err := datadir.Initialize(filePath)
	if err == nil {
		t.Fatal("expected error when base path is a file, got nil")
	}
}

// TestInitialize_DefaultConfigValues verifies the specific default values
// written to config.yaml match the expected schema.
func TestInitialize_DefaultConfigValues(t *testing.T) {
	base := t.TempDir()

	if err := datadir.Initialize(base); err != nil {
		t.Fatalf("Initialize returned unexpected error: %v", err)
	}

	configPath := filepath.Join(base, "config.yaml")
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("cannot read config.yaml: %v", err)
	}

	type vaultSection struct {
		Address string `yaml:"address"`
	}
	type serverSection struct {
		ListenAddress string `yaml:"listen_address"`
	}
	type sanitizerSection struct {
		Enabled bool `yaml:"enabled"`
	}
	type defaultCfg struct {
		Vault     vaultSection     `yaml:"vault"`
		Server    serverSection    `yaml:"server"`
		Sanitizer sanitizerSection `yaml:"sanitizer"`
		Services  map[string]interface{} `yaml:"services"`
	}

	var cfg defaultCfg
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("config.yaml parse error: %v", err)
	}

	if cfg.Vault.Address != "http://127.0.0.1:8200" {
		t.Errorf("vault.address = %q, want %q", cfg.Vault.Address, "http://127.0.0.1:8200")
	}
	if cfg.Server.ListenAddress != "0.0.0.0:9470" {
		t.Errorf("server.listen_address = %q, want %q", cfg.Server.ListenAddress, "0.0.0.0:9470")
	}
	if !cfg.Sanitizer.Enabled {
		t.Errorf("sanitizer.enabled = false, want true")
	}
	if cfg.Services == nil {
		t.Errorf("services must be present (may be empty map)")
	}
}
