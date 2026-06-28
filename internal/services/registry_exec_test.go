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
