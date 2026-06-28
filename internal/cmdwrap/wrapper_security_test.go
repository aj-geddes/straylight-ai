// Package cmdwrap_test: security regression tests for QA findings on exec activation.
//
// RED tests (will fail before the fixes):
//   - CRITICAL: Allowlist must use svc.AllowedCommands, not req.AllowedCommands
//   - CRITICAL: Empty svc.AllowedCommands for exec-enabled service = fail-closed deny
//   - HIGH: Path-normalized allowlist (absolute path and ./relative match "name")
//   - CRITICAL: Credential env var populated from svc.ExecEnvVar
package cmdwrap_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/straylight-ai/straylight/internal/cmdwrap"
	"github.com/straylight-ai/straylight/internal/egress"
	"github.com/straylight-ai/straylight/internal/services"
)

// ---------------------------------------------------------------------------
// Resolver for security tests
// ---------------------------------------------------------------------------

// securityTestResolver provides configurable services and credentials.
type securityTestResolver struct {
	svcs        map[string]services.Service
	credentials map[string]string
}

func (r *securityTestResolver) GetCredential(name string) (string, error) {
	if v, ok := r.credentials[name]; ok {
		return v, nil
	}
	return "", nil
}

func (r *securityTestResolver) Get(name string) (services.Service, error) {
	svc, ok := r.svcs[name]
	if !ok {
		return services.Service{}, nil
	}
	return svc, nil
}

// newSecurityWrapper builds a Wrapper with the given service, using egress.AllowAll
// and the current process uid/gid (no real uid-drop in unit tests).
func newSecurityWrapper(svc services.Service, credential string) *cmdwrap.Wrapper {
	resolver := &securityTestResolver{
		svcs:        map[string]services.Service{svc.Name: svc},
		credentials: map[string]string{svc.Name: credential},
	}
	w := cmdwrap.NewWrapperWithGuard(resolver, &noopSanitizer{}, egress.AllowAll())
	w.SetChildCredential(uint32(os.Getuid()), uint32(os.Getgid()))
	w.SetApprover(&autoApprover{})
	return w
}

// ---------------------------------------------------------------------------
// CRITICAL Finding 1: checkAllowlist must use svc.AllowedCommands
// ---------------------------------------------------------------------------

// TestWrapperServiceAllowlist_UnlistedBinaryRejected is a RED test.
//
// Before fix: checkAllowlist(argv[0], service, req.AllowedCommands) — req.AllowedCommands
// is empty, so the function returns nil (allow-all). "ls" runs unguarded.
//
// After fix: checkAllowlist uses svc.AllowedCommands=["echo"], so "ls" is rejected.
func TestWrapperServiceAllowlist_UnlistedBinaryRejected(t *testing.T) {
	svc := services.Service{
		Name:            "github",
		Type:            "http_proxy",
		Target:          "https://api.github.com",
		Inject:          "header",
		ExecEnabled:     true,
		AllowedCommands: []string{"echo"},
	}
	w := newSecurityWrapper(svc, "mytoken")

	req := cmdwrap.ExecRequest{
		Service:        "github",
		Command:        "ls -la",
		EnvVar:         "GH_TOKEN",
		TimeoutSeconds: 5,
		// AllowedCommands intentionally absent — must be sourced from svc
	}

	_, err := w.Execute(context.Background(), req)
	if err == nil {
		t.Fatal("SECURITY BUG: unlisted binary 'ls' ran; expected rejection via svc.AllowedCommands")
	}
	if !strings.Contains(err.Error(), "not allowed") {
		t.Errorf("expected 'not allowed' in error; got: %q", err.Error())
	}
}

// TestWrapperServiceAllowlist_ListedBinaryAllowed verifies the positive case:
// a binary in svc.AllowedCommands passes even when req.AllowedCommands is empty.
func TestWrapperServiceAllowlist_ListedBinaryAllowed(t *testing.T) {
	svc := services.Service{
		Name:            "github",
		Type:            "http_proxy",
		Target:          "https://api.github.com",
		Inject:          "header",
		ExecEnabled:     true,
		AllowedCommands: []string{"echo"},
	}
	w := newSecurityWrapper(svc, "mytoken")

	req := cmdwrap.ExecRequest{
		Service:        "github",
		Command:        "echo security-test",
		EnvVar:         "GH_TOKEN",
		TimeoutSeconds: 5,
		// AllowedCommands intentionally absent — must be sourced from svc
	}

	resp, err := w.Execute(context.Background(), req)
	if err != nil {
		t.Fatalf("expected 'echo' to be allowed by svc.AllowedCommands; got: %v", err)
	}
	if !strings.Contains(resp.Stdout, "security-test") {
		t.Errorf("expected 'security-test' in stdout; got: %q", resp.Stdout)
	}
}

// TestWrapperEmptyServiceAllowlist_DeniesAll is a RED test.
//
// An exec-enabled service with an empty AllowedCommands slice must be treated
// as deny-all (fail-closed). The wrapper must not rely solely on validateService
// for this — it must enforce it at runtime too (defense-in-depth).
//
// Before fix: empty req.AllowedCommands = allow-all (permit everything).
// After fix: empty svc.AllowedCommands for exec path = deny with "not allowed".
func TestWrapperEmptyServiceAllowlist_DeniesAll(t *testing.T) {
	// Directly inject a service with empty AllowedCommands into the resolver,
	// bypassing validateService (which would normally reject this config).
	svc := services.Service{
		Name:            "misconfigured",
		Type:            "http_proxy",
		Target:          "https://example.com",
		Inject:          "header",
		ExecEnabled:     true,
		AllowedCommands: []string{}, // explicitly empty — must still deny-all
	}
	w := newSecurityWrapper(svc, "token")

	req := cmdwrap.ExecRequest{
		Service:        "misconfigured",
		Command:        "echo anything",
		EnvVar:         "TOKEN",
		TimeoutSeconds: 5,
	}

	_, err := w.Execute(context.Background(), req)
	if err == nil {
		t.Fatal("SECURITY BUG: empty svc.AllowedCommands allowed command execution; must fail closed")
	}
	// Accept either form: "not allowed" or "no allowed commands" — both signal fail-closed deny.
	if !strings.Contains(err.Error(), "not allowed") && !strings.Contains(err.Error(), "no allowed commands") {
		t.Errorf("expected deny error for empty allowlist; got: %q", err.Error())
	}
}

// ---------------------------------------------------------------------------
// HIGH Finding 3: Path-normalized allowlist check
// ---------------------------------------------------------------------------

// TestAllowlistPathNormalization_AbsolutePath is a RED test.
//
// Before fix: checkAllowlist compares argv[0] ("/usr/bin/echo") against "echo" —
// they don't match, so the command is rejected even though it's the same binary.
//
// After fix: exec.LookPath + filepath.Base normalizes to "echo", which matches.
func TestAllowlistPathNormalization_AbsolutePath(t *testing.T) {
	echoPath, err := exec.LookPath("echo")
	if err != nil {
		t.Skip("echo not found in PATH: " + err.Error())
	}
	echoBase := filepath.Base(echoPath)

	svc := services.Service{
		Name:            "github",
		Type:            "http_proxy",
		Target:          "https://api.github.com",
		Inject:          "header",
		ExecEnabled:     true,
		AllowedCommands: []string{echoBase}, // just "echo"
	}
	w := newSecurityWrapper(svc, "tok")

	req := cmdwrap.ExecRequest{
		Service:        "github",
		Command:        echoPath + " path-norm-test", // absolute path like /bin/echo
		EnvVar:         "GH_TOKEN",
		TimeoutSeconds: 5,
	}

	_, err = w.Execute(context.Background(), req)
	if err != nil && strings.Contains(err.Error(), "not allowed") {
		t.Errorf("absolute path %q should match allowlist entry %q via path normalization; got: %v",
			echoPath, echoBase, err)
	}
}

// TestAllowlistPathNormalization_RelativePath is a RED test.
//
// Before fix: "./aws" != "aws" — string comparison rejects the relative form.
// After fix: exec.LookPath("./aws") resolves to an abs path, filepath.Base gives "aws".
func TestAllowlistPathNormalization_RelativePath(t *testing.T) {
	// Create a temp dir with a dummy "aws" shell script.
	tmpDir := t.TempDir()
	scriptPath := filepath.Join(tmpDir, "aws")
	if err := os.WriteFile(scriptPath, []byte("#!/bin/sh\necho aws-mock-output"), 0755); err != nil {
		t.Fatalf("create test script: %v", err)
	}

	// Change working directory so "./aws" resolves.
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(origDir) })

	svc := services.Service{
		Name:            "aws-svc",
		Type:            "cloud",
		ExecEnabled:     true,
		AllowedCommands: []string{"aws"}, // just "aws"
	}
	w := newSecurityWrapper(svc, "token")

	req := cmdwrap.ExecRequest{
		Service:        "aws-svc",
		Command:        "./aws", // relative form
		EnvVar:         "AWS_TOKEN",
		TimeoutSeconds: 5,
	}

	_, err = w.Execute(context.Background(), req)
	if err != nil && strings.Contains(err.Error(), "not allowed") {
		t.Errorf("relative path './aws' should match allowlist entry 'aws' via path normalization; got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// CRITICAL Finding 2: EnvVar populated from svc.ExecEnvVar
// ---------------------------------------------------------------------------

// TestWrapperEnvVarFromService is a RED test.
//
// Before fix: handleExec builds ExecRequest with no EnvVar, Execute fails with
// "env_var is invalid" because req.EnvVar="" doesn't match the pattern.
//
// After fix: wrapper reads svc.ExecEnvVar and uses it as req.EnvVar when EnvVars is empty.
func TestWrapperEnvVarFromService(t *testing.T) {
	svc := services.Service{
		Name:            "github",
		Type:            "http_proxy",
		Target:          "https://api.github.com",
		Inject:          "header",
		ExecEnabled:     true,
		AllowedCommands: []string{"printenv"},
		ExecEnvVar:      "GH_TOKEN",
	}
	// Use noopSanitizer so the raw credential value appears in output.
	resolver := &securityTestResolver{
		svcs:        map[string]services.Service{"github": svc},
		credentials: map[string]string{"github": "secret-cred-value"},
	}
	w := cmdwrap.NewWrapperWithGuard(resolver, &noopSanitizer{}, egress.AllowAll())
	w.SetChildCredential(uint32(os.Getuid()), uint32(os.Getgid()))
	w.SetApprover(&autoApprover{})

	// No EnvVar in the request — must come from svc.ExecEnvVar.
	req := cmdwrap.ExecRequest{
		Service:        "github",
		Command:        "printenv GH_TOKEN",
		TimeoutSeconds: 5,
		// EnvVar intentionally absent
	}

	resp, err := w.Execute(context.Background(), req)
	if err != nil {
		t.Fatalf("expected success (EnvVar from svc.ExecEnvVar='GH_TOKEN'); got: %v", err)
	}
	if !strings.Contains(resp.Stdout, "secret-cred-value") {
		t.Errorf("expected credential value in stdout via GH_TOKEN env var; got: %q", resp.Stdout)
	}
}
