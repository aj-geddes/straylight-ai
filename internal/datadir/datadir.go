// Package datadir handles initialization of the Straylight-AI data directory.
//
// On first start it creates the required subdirectory structure and a default
// config.yaml. On subsequent starts (restarts) it is idempotent: existing files
// are never overwritten.
package datadir

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const (
	// DirPermission is the mode applied to all directories created under basePath.
	DirPermission os.FileMode = 0700

	// ConfigPermission is the mode applied to the generated config.yaml.
	ConfigPermission os.FileMode = 0644
)

// defaultConfigYAML is the minimal config written on first start.
const defaultConfigYAML = `vault:
  address: http://127.0.0.1:8200

server:
  listen_address: "0.0.0.0:9470"

sanitizer:
  enabled: true

services: {}
`

// Initialize ensures the data directory hierarchy exists and that a default
// config.yaml is present. It is safe to call on every startup: existing files
// are never modified.
//
// Expected layout after a successful call:
//
//	basePath/
//	  openbao/
//	    storage/     — OpenBao file storage backend
//	  config.yaml    — default configuration (created only if absent)
func Initialize(basePath string) error {
	if err := validateBase(basePath); err != nil {
		return err
	}

	subdirs := []string{
		filepath.Join(basePath, "openbao", "storage"),
	}
	for _, d := range subdirs {
		if err := os.MkdirAll(d, DirPermission); err != nil {
			return fmt.Errorf("datadir: cannot create directory %q: %w", d, err)
		}
	}

	if err := writeDefaultConfigIfAbsent(filepath.Join(basePath, "config.yaml")); err != nil {
		return err
	}

	return nil
}

// validateBase checks that basePath exists and that we can write to it.
func validateBase(basePath string) error {
	info, err := os.Stat(basePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("datadir: base path %q does not exist; ensure the volume is mounted", basePath)
		}
		return fmt.Errorf("datadir: cannot access base path %q: %w", basePath, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("datadir: base path %q is not a directory", basePath)
	}

	// Probe writability by attempting to create (and immediately remove) a temp file.
	probe := filepath.Join(basePath, ".datadir_write_probe")
	f, err := os.OpenFile(probe, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("datadir: base path %q is not writable: %w", basePath, err)
	}
	f.Close()
	_ = os.Remove(probe)

	return nil
}

// writeDefaultConfigIfAbsent writes the default config.yaml only when the
// target file does not already exist.
func writeDefaultConfigIfAbsent(path string) error {
	_, err := os.Stat(path)
	if err == nil {
		// File already exists — do not overwrite.
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("datadir: cannot stat config file %q: %w", path, err)
	}

	if err := os.WriteFile(path, []byte(defaultConfigYAML), ConfigPermission); err != nil {
		return fmt.Errorf("datadir: cannot write default config to %q: %w", path, err)
	}
	return nil
}
