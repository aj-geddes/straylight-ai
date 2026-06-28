package services_test

import (
	"strings"
	"testing"

	"github.com/straylight-ai/straylight/internal/services"
)

// ---------------------------------------------------------------------------
// ADR-013 Phase 3: ExecEnabled + AllowedCommands validation tests
// ---------------------------------------------------------------------------

// TestValidateServiceExecEnabledRequiresAllowedCommands verifies that a service
// with ExecEnabled=true but an empty AllowedCommands list is rejected.
// An empty allowlist for an exec-enabled service means every command is permitted,
// which defeats the mandatory-allowlist requirement (ADR-013 Part C.1).
func TestValidateServiceExecEnabledRequiresAllowedCommands(t *testing.T) {
	vault := newMockVault()
	reg := services.NewRegistry(vault)

	svc := services.Service{
		Name:            "deploy-svc",
		Type:            "cloud",
		ExecEnabled:     true,
		AllowedCommands: nil, // must be rejected
	}

	err := reg.Create(svc, "cred")
	if err == nil {
		t.Fatal("expected error when ExecEnabled=true but AllowedCommands is empty")
	}
	for _, want := range []string{"allowed_commands", "exec_enabled"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("expected error to mention %q; got: %q", want, err.Error())
		}
	}
}

// TestValidateServiceExecEnabledEmptySliceRequiresAllowedCommands verifies that
// an explicit empty slice (not nil) is also rejected for exec-enabled services.
func TestValidateServiceExecEnabledEmptySliceRequiresAllowedCommands(t *testing.T) {
	vault := newMockVault()
	reg := services.NewRegistry(vault)

	svc := services.Service{
		Name:            "deploy-svc",
		Type:            "cloud",
		ExecEnabled:     true,
		AllowedCommands: []string{}, // explicit empty — also invalid
	}

	err := reg.Create(svc, "cred")
	if err == nil {
		t.Fatal("expected error when ExecEnabled=true but AllowedCommands is empty slice")
	}
}

// TestValidateServiceExecDisabledAllowedCommandsOptional verifies that when
// ExecEnabled=false (the default), AllowedCommands is not required.
func TestValidateServiceExecDisabledAllowedCommandsOptional(t *testing.T) {
	vault := newMockVault()
	reg := services.NewRegistry(vault)

	svc := services.Service{
		Name:        "regular-cloud",
		Type:        "cloud",
		ExecEnabled: false,
		// AllowedCommands intentionally absent.
	}

	err := reg.Create(svc, "cred")
	if err != nil {
		t.Errorf("unexpected error for ExecEnabled=false service: %v", err)
	}
}

// TestValidateServiceExecEnabledWithAllowedCommandsAccepted verifies that a
// properly configured exec-enabled service (non-empty AllowedCommands) passes validation.
func TestValidateServiceExecEnabledWithAllowedCommandsAccepted(t *testing.T) {
	vault := newMockVault()
	reg := services.NewRegistry(vault)

	svc := services.Service{
		Name:            "aws-deploy",
		Type:            "cloud",
		ExecEnabled:     true,
		AllowedCommands: []string{"aws"},
	}

	err := reg.Create(svc, "cred")
	if err != nil {
		t.Errorf("unexpected error for valid exec-enabled service: %v", err)
	}
}

// ---------------------------------------------------------------------------
// ExecEnvVar validation tests
// ---------------------------------------------------------------------------

// TestValidateServiceExecEnvVar_RequiredForNonCloudExecEnabled verifies that
// a non-cloud service with ExecEnabled=true must have a non-empty ExecEnvVar.
func TestValidateServiceExecEnvVar_RequiredForNonCloudExecEnabled(t *testing.T) {
	vault := newMockVault()
	reg := services.NewRegistry(vault)

	svc := services.Service{
		Name:            "github-deploy",
		Type:            "http_proxy",
		Target:          "https://api.github.com",
		Inject:          "header",
		ExecEnabled:     true,
		AllowedCommands: []string{"git"},
		// ExecEnvVar intentionally absent -- must be rejected
	}

	err := reg.Create(svc, "cred")
	if err == nil {
		t.Fatal("expected error when ExecEnabled=true but ExecEnvVar is empty for non-cloud service")
	}
	if !strings.Contains(err.Error(), "exec_env_var") {
		t.Errorf("expected error to mention exec_env_var; got: %q", err.Error())
	}
}

// TestValidateServiceExecEnvVar_CloudServiceNotRequired verifies that cloud
// services (which use multi-var EnvVars) do not require ExecEnvVar.
func TestValidateServiceExecEnvVar_CloudServiceNotRequired(t *testing.T) {
	vault := newMockVault()
	reg := services.NewRegistry(vault)

	svc := services.Service{
		Name:            "aws-deploy",
		Type:            "cloud",
		ExecEnabled:     true,
		AllowedCommands: []string{"aws"},
		// ExecEnvVar omitted for cloud service -- allowed
	}

	err := reg.Create(svc, "cred")
	if err != nil {
		t.Errorf("unexpected error for cloud service without ExecEnvVar: %v", err)
	}
}

// TestValidateServiceExecEnvVar_WithEnvVarAccepted verifies that a non-cloud
// exec-enabled service with ExecEnvVar set is accepted.
func TestValidateServiceExecEnvVar_WithEnvVarAccepted(t *testing.T) {
	vault := newMockVault()
	reg := services.NewRegistry(vault)

	svc := services.Service{
		Name:            "github-deploy",
		Type:            "http_proxy",
		Target:          "https://api.github.com",
		Inject:          "header",
		ExecEnabled:     true,
		AllowedCommands: []string{"git", "gh"},
		ExecEnvVar:      "GH_TOKEN",
	}

	err := reg.Create(svc, "cred")
	if err != nil {
		t.Errorf("unexpected error for valid exec-enabled service with ExecEnvVar: %v", err)
	}
}

// TestValidateServiceExecEnvVar_PersistsToVaultAndLoads verifies that ExecEnvVar
// is stored in vault metadata and reloaded into the registry on LoadFromVault.
func TestValidateServiceExecEnvVar_PersistsToVaultAndLoads(t *testing.T) {
	vault := newMockVault()
	reg := services.NewRegistry(vault)

	svc := services.Service{
		Name:            "github-exec",
		Type:            "http_proxy",
		Target:          "https://api.github.com",
		Inject:          "header",
		ExecEnabled:     true,
		AllowedCommands: []string{"gh"},
		ExecEnvVar:      "GH_TOKEN",
	}

	if err := reg.Create(svc, "cred"); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Create a new registry backed by the same vault and reload.
	reg2 := services.NewRegistry(vault)
	if err := reg2.LoadFromVault(); err != nil {
		t.Fatalf("LoadFromVault: %v", err)
	}

	loaded, err := reg2.Get("github-exec")
	if err != nil {
		t.Fatalf("Get after reload: %v", err)
	}
	if loaded.ExecEnvVar != "GH_TOKEN" {
		t.Errorf("ExecEnvVar after reload = %q, want %q", loaded.ExecEnvVar, "GH_TOKEN")
	}
}
