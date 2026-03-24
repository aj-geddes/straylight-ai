// Package cmdwrap_test — EnvVar validation tests (FIX 2).
package cmdwrap_test

import (
	"context"
	"strings"
	"testing"

	"github.com/straylight-ai/straylight/internal/cmdwrap"
	"github.com/straylight-ai/straylight/internal/services"
)

// newValidWrapper returns a Wrapper with a valid github service and credential.
func newValidWrapper() *cmdwrap.Wrapper {
	svc := services.Service{Name: "github", Type: "http_proxy"}
	resolver := &fakeResolver{
		credentials: map[string]string{"github": "secrettoken"},
		svcs:        map[string]services.Service{"github": svc},
	}
	return cmdwrap.NewWrapper(resolver, &noopSanitizer{})
}

// TestExecute_EmptyEnvVar_ReturnsError verifies that an empty EnvVar is rejected.
func TestExecute_EmptyEnvVar_ReturnsError(t *testing.T) {
	w := newValidWrapper()

	req := cmdwrap.ExecRequest{
		Service:        "github",
		Command:        "echo hi",
		EnvVar:         "", // empty — must be rejected
		TimeoutSeconds: 5,
	}

	_, err := w.Execute(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for empty EnvVar, got nil")
	}
	if !strings.Contains(err.Error(), "env_var") {
		t.Errorf("expected error to mention env_var, got: %q", err.Error())
	}
}

// TestExecute_LowercaseEnvVar_ReturnsError verifies that a lowercase env var is rejected.
func TestExecute_LowercaseEnvVar_ReturnsError(t *testing.T) {
	w := newValidWrapper()

	req := cmdwrap.ExecRequest{
		Service:        "github",
		Command:        "echo hi",
		EnvVar:         "gh_token", // lowercase — must be rejected
		TimeoutSeconds: 5,
	}

	_, err := w.Execute(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for lowercase EnvVar, got nil")
	}
}

// TestExecute_PATH_ReturnsError verifies that PATH is a reserved env var.
func TestExecute_PATH_ReturnsError(t *testing.T) {
	w := newValidWrapper()

	req := cmdwrap.ExecRequest{
		Service:        "github",
		Command:        "echo hi",
		EnvVar:         "PATH", // reserved — must be rejected
		TimeoutSeconds: 5,
	}

	_, err := w.Execute(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for PATH env var, got nil")
	}
	if !strings.Contains(err.Error(), "reserved") {
		t.Errorf("expected 'reserved' in error, got: %q", err.Error())
	}
}

// TestExecute_LD_PRELOAD_ReturnsError verifies that LD_PRELOAD is a reserved env var.
func TestExecute_LD_PRELOAD_ReturnsError(t *testing.T) {
	w := newValidWrapper()

	req := cmdwrap.ExecRequest{
		Service:        "github",
		Command:        "echo hi",
		EnvVar:         "LD_PRELOAD", // reserved — must be rejected
		TimeoutSeconds: 5,
	}

	_, err := w.Execute(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for LD_PRELOAD env var, got nil")
	}
	if !strings.Contains(err.Error(), "reserved") {
		t.Errorf("expected 'reserved' in error, got: %q", err.Error())
	}
}

// TestExecute_LD_LIBRARY_PATH_ReturnsError verifies that LD_LIBRARY_PATH is reserved.
func TestExecute_LD_LIBRARY_PATH_ReturnsError(t *testing.T) {
	w := newValidWrapper()

	req := cmdwrap.ExecRequest{
		Service:        "github",
		Command:        "echo hi",
		EnvVar:         "LD_LIBRARY_PATH",
		TimeoutSeconds: 5,
	}

	_, err := w.Execute(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for LD_LIBRARY_PATH, got nil")
	}
}

// TestExecute_HOME_ReturnsError verifies that HOME is a reserved env var.
func TestExecute_HOME_ReturnsError(t *testing.T) {
	w := newValidWrapper()

	req := cmdwrap.ExecRequest{
		Service:        "github",
		Command:        "echo hi",
		EnvVar:         "HOME",
		TimeoutSeconds: 5,
	}

	_, err := w.Execute(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for HOME env var, got nil")
	}
}

// TestExecute_ValidEnvVar_Succeeds verifies that a valid env var like GH_TOKEN is accepted.
func TestExecute_ValidEnvVar_Succeeds(t *testing.T) {
	w := newValidWrapper()

	req := cmdwrap.ExecRequest{
		Service:        "github",
		Command:        "echo ok",
		EnvVar:         "GH_TOKEN", // valid — must succeed
		TimeoutSeconds: 5,
	}

	_, err := w.Execute(context.Background(), req)
	if err != nil {
		t.Fatalf("expected no error for valid EnvVar GH_TOKEN, got: %v", err)
	}
}

// TestExecute_ValidEnvVarWithDigits_Succeeds verifies env vars with digits are accepted.
func TestExecute_ValidEnvVarWithDigits_Succeeds(t *testing.T) {
	w := newValidWrapper()

	validVars := []string{
		"GH_TOKEN",
		"MY_API_KEY_2",
		"TOKEN123",
		"A",
		"A0",
	}

	for _, envVar := range validVars {
		t.Run(envVar, func(t *testing.T) {
			req := cmdwrap.ExecRequest{
				Service:        "github",
				Command:        "echo ok",
				EnvVar:         envVar,
				TimeoutSeconds: 5,
			}
			_, err := w.Execute(context.Background(), req)
			if err != nil {
				t.Errorf("expected no error for valid EnvVar %q, got: %v", envVar, err)
			}
		})
	}
}

// TestExecute_InvalidEnvVarPatterns_ReturnError verifies various invalid patterns.
func TestExecute_InvalidEnvVarPatterns_ReturnError(t *testing.T) {
	w := newValidWrapper()

	invalidVars := []string{
		"",            // empty
		"lowercase",   // lowercase start
		"_START",      // starts with underscore
		"1NUMBER",     // starts with digit
		"HAS SPACE",   // contains space
		"HAS-DASH",    // contains dash
		"HAS.DOT",     // contains dot
	}

	for _, envVar := range invalidVars {
		t.Run("envvar="+envVar, func(t *testing.T) {
			req := cmdwrap.ExecRequest{
				Service:        "github",
				Command:        "echo hi",
				EnvVar:         envVar,
				TimeoutSeconds: 5,
			}
			_, err := w.Execute(context.Background(), req)
			if err == nil {
				t.Errorf("expected error for invalid EnvVar %q, got nil", envVar)
			}
		})
	}
}
