// Package cmdwrap_test: tests for the EnvVars map extension for cloud credentials.
package cmdwrap_test

import (
	"context"
	"strings"
	"testing"

	"github.com/straylight-ai/straylight/internal/cmdwrap"
	"github.com/straylight-ai/straylight/internal/services"
)

// newCloudTestWrapper builds a Wrapper wired to a cloud service "aws-prod".
// The service has no single credential value — it relies on EnvVars injection.
func newCloudTestWrapper() *cmdwrap.Wrapper {
	svc := services.Service{
		Name: "aws-prod",
		Type: "cloud",
	}
	resolver := &fakeResolver{
		credentials: map[string]string{},
		svcs:        map[string]services.Service{"aws-prod": svc},
	}
	return cmdwrap.NewWrapper(resolver, &noopSanitizer{})
}

// TestExecuteEnvVarsMultipleInjected verifies that when EnvVars is set on the
// request, all key-value pairs are injected into the subprocess environment.
func TestExecuteEnvVarsMultipleInjected(t *testing.T) {
	w := newCloudTestWrapper()

	req := cmdwrap.ExecRequest{
		Service: "aws-prod",
		Command: "printenv AWS_ACCESS_KEY_ID",
		EnvVars: map[string]string{
			"AWS_ACCESS_KEY_ID":     "ASIA1234TEST",
			"AWS_SECRET_ACCESS_KEY": "secretval",
			"AWS_SESSION_TOKEN":     "tokenval",
			"AWS_DEFAULT_REGION":    "us-west-2",
		},
		TimeoutSeconds: 5,
	}

	resp, err := w.Execute(context.Background(), req)
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	if resp.ExitCode != 0 {
		t.Fatalf("expected exit code 0, got %d; stderr: %s", resp.ExitCode, resp.Stderr)
	}

	if !strings.Contains(resp.Stdout, "ASIA1234TEST") {
		t.Errorf("expected AWS_ACCESS_KEY_ID in stdout; got: %q", resp.Stdout)
	}
}

// TestExecuteEnvVarsTakesPrecedenceOverEnvVar verifies that when both EnvVar
// and EnvVars are set, EnvVars takes precedence.
func TestExecuteEnvVarsTakesPrecedenceOverEnvVar(t *testing.T) {
	// Use a service with a real credential to test the precedence.
	svc := services.Service{Name: "github", Type: "http_proxy"}
	resolver := &fakeResolver{
		credentials: map[string]string{"github": "legacy-token-value"},
		svcs:        map[string]services.Service{"github": svc},
	}
	w := cmdwrap.NewWrapper(resolver, &noopSanitizer{})

	req := cmdwrap.ExecRequest{
		Service: "github",
		Command: "printenv GH_TOKEN",
		// Both fields set — EnvVars should win.
		EnvVar: "GH_TOKEN",
		EnvVars: map[string]string{
			"GH_TOKEN": "from-envvars-map",
		},
		TimeoutSeconds: 5,
	}

	resp, err := w.Execute(context.Background(), req)
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	if !strings.Contains(resp.Stdout, "from-envvars-map") {
		t.Errorf("expected 'from-envvars-map' (from EnvVars map) in stdout; got: %q", resp.Stdout)
	}
}

// TestExecuteCloudServiceNoEnvVarRequired verifies that a cloud service with
// EnvVars set does not require the EnvVar single-value field.
func TestExecuteCloudServiceNoEnvVarRequired(t *testing.T) {
	w := newCloudTestWrapper()

	req := cmdwrap.ExecRequest{
		Service: "aws-prod",
		Command: "echo ok",
		// No EnvVar field — relies entirely on EnvVars map
		EnvVars: map[string]string{
			"AWS_ACCESS_KEY_ID": "ASIA_TEST",
		},
		TimeoutSeconds: 5,
	}

	resp, err := w.Execute(context.Background(), req)
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	if resp.ExitCode != 0 {
		t.Errorf("expected exit code 0, got %d", resp.ExitCode)
	}
}

// TestExecuteEnvVarsReservedKeyRejected verifies that injecting a reserved env
// var via the EnvVars map returns an error.
func TestExecuteEnvVarsReservedKeyRejected(t *testing.T) {
	w := newCloudTestWrapper()

	req := cmdwrap.ExecRequest{
		Service: "aws-prod",
		Command: "echo test",
		EnvVars: map[string]string{
			"LD_PRELOAD": "/evil.so", // reserved
		},
		TimeoutSeconds: 5,
	}

	_, err := w.Execute(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for reserved env var in EnvVars map, got nil")
	}
}

// TestExecuteEnvVarsInvalidKeyRejected verifies that injecting an invalid env
// var name via the EnvVars map returns an error.
func TestExecuteEnvVarsInvalidKeyRejected(t *testing.T) {
	w := newCloudTestWrapper()

	req := cmdwrap.ExecRequest{
		Service: "aws-prod",
		Command: "echo test",
		EnvVars: map[string]string{
			"invalid-key": "value", // must be uppercase
		},
		TimeoutSeconds: 5,
	}

	_, err := w.Execute(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for invalid env var name in EnvVars map, got nil")
	}
}
