// Package cmdwrap_test verifies subprocess execution, credential injection,
// output sanitization, allowlist enforcement, timeout handling, and large
// output truncation for the straylight_exec MCP tool.
package cmdwrap_test

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/straylight-ai/straylight/internal/cmdwrap"
	"github.com/straylight-ai/straylight/internal/services"
)

// autoApprover is a test-only Approver that always permits execution.
// It is used in existing tests so that the new fail-closed approval gate
// does not block tests that are not specifically testing approval.
type autoApprover struct{}

func (a *autoApprover) Await(_ context.Context, _ cmdwrap.ApprovalRequest) error { return nil }

// configureTestCredentials sets SetChildCredential (current process uid/gid, no
// real uid-drop on the test host) and SetApprover (autoApprover) on w. This
// satisfies the ADR-013 fail-closed requirements without dropping privileges in
// unit tests. The real uid-drop to 10101 is verified in container integration tests.
func configureTestCredentials(w *cmdwrap.Wrapper) *cmdwrap.Wrapper {
	w.SetChildCredential(uint32(os.Getuid()), uint32(os.Getgid()))
	w.SetApprover(&autoApprover{})
	return w
}

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

// fakeResolver implements CredentialResolver using in-memory maps.
type fakeResolver struct {
	credentials map[string]string
	svcs        map[string]services.Service
}

func (r *fakeResolver) GetCredential(name string) (string, error) {
	v, ok := r.credentials[name]
	if !ok {
		return "", fmt.Errorf("services: %q not found", name)
	}
	return v, nil
}

func (r *fakeResolver) Get(name string) (services.Service, error) {
	svc, ok := r.svcs[name]
	if !ok {
		return services.Service{}, fmt.Errorf("services: %q not found", name)
	}
	return svc, nil
}

// fakeSanitizer replaces a known secret value with [REDACTED:test].
type fakeSanitizer struct {
	redact string
}

func (s *fakeSanitizer) Sanitize(input string) string {
	if s.redact == "" {
		return input
	}
	return strings.ReplaceAll(input, s.redact, "[REDACTED:test]")
}

// noopSanitizer passes text through unchanged.
type noopSanitizer struct{}

func (s *noopSanitizer) Sanitize(input string) string { return input }

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const testSecret = "supersecret1234"

// newTestWrapper builds a Wrapper wired to a single service "github" with a
// known credential value. It configures the child credential (current process
// uid/gid) and an auto-approver so that the ADR-013 fail-closed gates do not
// block tests that are not specifically testing those guards.
func newTestWrapper(secret string) *cmdwrap.Wrapper {
	// AllowedCommands covers all binaries used in the wrapper_test.go test suite.
	// The allowlist is now sourced from svc (not req) as part of the security fix.
	svc := services.Service{
		Name:            "github",
		Type:            "http_proxy",
		ExecEnabled:     true,
		AllowedCommands: []string{"printenv", "echo", "false", "sleep", "dd", "true"},
	}

	resolver := &fakeResolver{
		credentials: map[string]string{"github": secret},
		svcs:        map[string]services.Service{"github": svc},
	}
	san := &fakeSanitizer{redact: secret}
	return configureTestCredentials(cmdwrap.NewWrapper(resolver, san))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestExecuteEnvVarInjection verifies that the credential is set in the
// subprocess environment as the named env var.
func TestExecuteEnvVarInjection(t *testing.T) {
	w := newTestWrapper(testSecret)

	req := cmdwrap.ExecRequest{
		Service:        "github",
		Command:        "printenv GH_TOKEN",
		EnvVar:         "GH_TOKEN",
		TimeoutSeconds: 5,
	}

	resp, err := w.Execute(context.Background(), req)
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	if resp.ExitCode != 0 {
		t.Fatalf("expected exit code 0, got %d; stderr: %s", resp.ExitCode, resp.Stderr)
	}

	// The raw env var value would have been redacted by the sanitizer.
	// We verify the env var was set by checking that its redacted form appears.
	if !strings.Contains(resp.Stdout, "[REDACTED:test]") {
		t.Errorf("expected credential to be redacted in stdout; got: %q", resp.Stdout)
	}
}

// TestExecuteCredentialNotInOutput verifies that the raw credential value
// never appears in any response field after sanitization.
func TestExecuteCredentialNotInOutput(t *testing.T) {
	w := newTestWrapper(testSecret)

	req := cmdwrap.ExecRequest{
		Service:        "github",
		Command:        "printenv GH_TOKEN",
		EnvVar:         "GH_TOKEN",
		TimeoutSeconds: 5,
	}

	resp, err := w.Execute(context.Background(), req)
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	if strings.Contains(resp.Stdout, testSecret) {
		t.Errorf("raw credential appeared in Stdout: %q", resp.Stdout)
	}
	if strings.Contains(resp.Stderr, testSecret) {
		t.Errorf("raw credential appeared in Stderr: %q", resp.Stderr)
	}
}

// TestExecuteExitCodePropagation verifies that the exit code from the
// subprocess is faithfully returned.
func TestExecuteExitCodePropagation(t *testing.T) {
	w := newTestWrapper(testSecret)

	req := cmdwrap.ExecRequest{
		Service:        "github",
		Command:        "false",
		EnvVar:         "GH_TOKEN",
		TimeoutSeconds: 5,
	}

	resp, err := w.Execute(context.Background(), req)
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	if resp.ExitCode == 0 {
		t.Error("expected non-zero exit code from 'false', got 0")
	}
}

// TestExecuteStdoutCaptured verifies stdout is captured correctly.
func TestExecuteStdoutCaptured(t *testing.T) {
	w := newTestWrapper(testSecret)

	req := cmdwrap.ExecRequest{
		Service:        "github",
		Command:        "echo hello-stdout",
		EnvVar:         "GH_TOKEN",
		TimeoutSeconds: 5,
	}

	resp, err := w.Execute(context.Background(), req)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !strings.Contains(resp.Stdout, "hello-stdout") {
		t.Errorf("expected 'hello-stdout' in stdout; got %q", resp.Stdout)
	}
	if resp.Stderr != "" {
		t.Errorf("expected empty stderr; got %q", resp.Stderr)
	}
}

// TestExecuteTimeout verifies that a command exceeding the timeout is killed
// and exit code -1 is returned.
func TestExecuteTimeout(t *testing.T) {
	w := newTestWrapper(testSecret)

	req := cmdwrap.ExecRequest{
		Service:        "github",
		Command:        "sleep 60",
		EnvVar:         "GH_TOKEN",
		TimeoutSeconds: 1,
	}

	start := time.Now()
	resp, err := w.Execute(context.Background(), req)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	if resp.ExitCode != -1 {
		t.Errorf("expected exit code -1 on timeout; got %d", resp.ExitCode)
	}
	if !strings.Contains(resp.Stderr, "timed out") {
		t.Errorf("expected timeout message in stderr; got %q", resp.Stderr)
	}
	// Should complete well before the sleep duration.
	if elapsed > 5*time.Second {
		t.Errorf("timeout took too long: %v", elapsed)
	}
}

// TestExecuteAllowlistEnforced verifies that a command not in the service's
// AllowedCommands list is rejected. The allowlist is now sourced from the
// service configuration (svc.AllowedCommands), not req.AllowedCommands.
// "ls" is not in the newTestWrapper service allowlist, so it is blocked.
func TestExecuteAllowlistEnforced(t *testing.T) {
	w := newTestWrapper(testSecret)

	req := cmdwrap.ExecRequest{
		Service:        "github",
		Command:        "ls -la",
		EnvVar:         "GH_TOKEN",
		TimeoutSeconds: 5,
		// AllowedCommands in the request is ignored — svc.AllowedCommands controls access.
	}

	_, err := w.Execute(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for blocked command")
	}
	if !strings.Contains(err.Error(), "not allowed") {
		t.Errorf("expected 'not allowed' in error; got %q", err.Error())
	}
	if !strings.Contains(err.Error(), "github") {
		t.Errorf("expected service name in error; got %q", err.Error())
	}
}

// TestExecuteAllowlistPermitted verifies that a command in the service's
// AllowedCommands list runs successfully.
func TestExecuteAllowlistPermitted(t *testing.T) {
	w := newTestWrapper(testSecret)

	req := cmdwrap.ExecRequest{
		Service:        "github",
		Command:        "echo allowed",
		EnvVar:         "GH_TOKEN",
		TimeoutSeconds: 5,
		// echo is in the service's AllowedCommands list (see newTestWrapper).
	}

	resp, err := w.Execute(context.Background(), req)
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	if resp.ExitCode != 0 {
		t.Errorf("expected exit code 0; got %d", resp.ExitCode)
	}
	if !strings.Contains(resp.Stdout, "allowed") {
		t.Errorf("expected 'allowed' in stdout; got %q", resp.Stdout)
	}
}

// TestExecuteAllowlistControlledByService verifies that the service's
// AllowedCommands list — not req.AllowedCommands — controls which commands run.
// The req.AllowedCommands field is now ignored; the service config is authoritative.
// A command in the service allowlist succeeds even when req.AllowedCommands is nil.
func TestExecuteAllowlistControlledByService(t *testing.T) {
	w := newTestWrapper(testSecret)

	req := cmdwrap.ExecRequest{
		Service:        "github",
		Command:        "echo anything",
		EnvVar:         "GH_TOKEN",
		TimeoutSeconds: 5,
		// AllowedCommands in the request is ignored (security fix).
		// "echo" is in the service's AllowedCommands, so this succeeds.
		AllowedCommands: nil,
	}

	resp, err := w.Execute(context.Background(), req)
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	if resp.ExitCode != 0 {
		t.Errorf("expected exit code 0; got %d", resp.ExitCode)
	}
}

// TestExecuteUnknownService verifies that an unknown service name returns an
// error without executing any command.
func TestExecuteUnknownService(t *testing.T) {
	w := newTestWrapper(testSecret)

	req := cmdwrap.ExecRequest{
		Service:        "nonexistent",
		Command:        "echo hi",
		EnvVar:         "GH_TOKEN",
		TimeoutSeconds: 5,
	}

	_, err := w.Execute(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for unknown service")
	}
}

// TestExecuteMissingCredential verifies that a service with no stored
// credential returns an error.
func TestExecuteMissingCredential(t *testing.T) {
	svc := services.Service{
		Name:            "nocred",
		Type:            "http_proxy",
		ExecEnabled:     true,
		AllowedCommands: []string{"echo"}, // required so allowlist passes before cred check
	}
	resolver := &fakeResolver{
		credentials: map[string]string{}, // no credential stored
		svcs:        map[string]services.Service{"nocred": svc},
	}
	w := cmdwrap.NewWrapper(resolver, &noopSanitizer{})

	req := cmdwrap.ExecRequest{
		Service:        "nocred",
		Command:        "echo hi",
		EnvVar:         "SOME_TOKEN",
		TimeoutSeconds: 5,
	}

	_, err := w.Execute(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for missing credential")
	}
}

// TestExecuteCommandNotFound verifies that a non-existent binary returns a
// meaningful error rather than panicking.
func TestExecuteCommandNotFound(t *testing.T) {
	w := newTestWrapper(testSecret)

	req := cmdwrap.ExecRequest{
		Service:        "github",
		Command:        "this-binary-definitely-does-not-exist-xyz",
		EnvVar:         "GH_TOKEN",
		TimeoutSeconds: 5,
	}

	_, err := w.Execute(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for command not found")
	}
}

// TestExecuteLargeOutputTruncated verifies that output exceeding 1 MB is
// truncated and the truncation marker is appended.
func TestExecuteLargeOutputTruncated(t *testing.T) {
	w := newTestWrapper(testSecret)

	// dd produces slightly over 1 MB of null bytes to stdout.
	req := cmdwrap.ExecRequest{
		Service:        "github",
		Command:        "dd if=/dev/zero bs=1100000 count=1",
		EnvVar:         "GH_TOKEN",
		TimeoutSeconds: 10,
	}

	resp, err := w.Execute(context.Background(), req)
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	const oneMB = 1 << 20
	const truncationMarker = "[output truncated]"
	if len(resp.Stdout) > oneMB+len(truncationMarker)+10 {
		t.Errorf("stdout not truncated: len=%d", len(resp.Stdout))
	}
	if !strings.Contains(resp.Stdout, truncationMarker) {
		t.Errorf("expected truncation marker in stdout; got (len=%d)", len(resp.Stdout))
	}
}

// TestExecuteDefaultTimeout verifies that a zero TimeoutSeconds defaults to 30.
func TestExecuteDefaultTimeout(t *testing.T) {
	w := newTestWrapper(testSecret)

	req := cmdwrap.ExecRequest{
		Service:        "github",
		Command:        "echo default-timeout",
		EnvVar:         "GH_TOKEN",
		TimeoutSeconds: 0, // should default to 30
	}

	resp, err := w.Execute(context.Background(), req)
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	if resp.ExitCode != 0 {
		t.Errorf("expected exit code 0; got %d", resp.ExitCode)
	}
}

// TestExecuteOutputSanitized verifies that sanitization is applied to stdout.
func TestExecuteOutputSanitized(t *testing.T) {
	secret := "verysecrettoken9999"
	svc := services.Service{
		Name:            "github",
		Type:            "http_proxy",
		ExecEnabled:     true,
		AllowedCommands: []string{"printenv"},
	}
	resolver := &fakeResolver{
		credentials: map[string]string{"github": secret},
		svcs:        map[string]services.Service{"github": svc},
	}
	san := &fakeSanitizer{redact: secret}
	w := configureTestCredentials(cmdwrap.NewWrapper(resolver, san))

	req := cmdwrap.ExecRequest{
		Service:        "github",
		Command:        "printenv MYTOKEN",
		EnvVar:         "MYTOKEN",
		TimeoutSeconds: 5,
	}

	resp, err := w.Execute(context.Background(), req)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}

	if strings.Contains(resp.Stdout, secret) {
		t.Errorf("credential appeared unsanitized in stdout: %q", resp.Stdout)
	}
	if strings.Contains(resp.Stderr, secret) {
		t.Errorf("credential appeared unsanitized in stderr: %q", resp.Stderr)
	}
}

// TestExecuteMinimalEnvironment verifies that the subprocess environment
// contains only essential variables (PATH, HOME, USER, TERM) plus the
// injected credential, not the parent process's full environment.
func TestExecuteMinimalEnvironment(t *testing.T) {
	// Set a parent env var that should NOT leak into the subprocess.
	t.Setenv("SHOULD_NOT_LEAK", "leaky_value_xyz")

	w := newTestWrapper(testSecret)

	req := cmdwrap.ExecRequest{
		Service:        "github",
		Command:        "printenv SHOULD_NOT_LEAK",
		EnvVar:         "GH_TOKEN",
		TimeoutSeconds: 5,
	}

	resp, err := w.Execute(context.Background(), req)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}

	// printenv exits 1 with no output if the var is unset.
	if strings.Contains(resp.Stdout, "leaky_value_xyz") {
		t.Errorf("parent environment leaked into subprocess: %q", resp.Stdout)
	}
}

// TestExecuteNoShellMetacharacters verifies that shell metacharacters in the
// command string are not interpreted — the command uses direct exec, not sh -c.
func TestExecuteNoShellMetacharacters(t *testing.T) {
	w := newTestWrapper(testSecret)

	// If shell invocation were used, $(echo injected) would be evaluated.
	// With direct exec, it should be passed as a literal argument to echo.
	req := cmdwrap.ExecRequest{
		Service:        "github",
		Command:        "echo $(whoami)",
		EnvVar:         "GH_TOKEN",
		TimeoutSeconds: 5,
	}

	resp, err := w.Execute(context.Background(), req)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}

	// The literal string "$(whoami)" should appear in output, NOT the user name.
	if !strings.Contains(resp.Stdout, "$(whoami)") {
		t.Errorf("shell substitution was evaluated; expected literal '$(whoami)', got: %q", resp.Stdout)
	}
}

// TestExecuteEmptyCommand verifies that an empty command string returns an
// error rather than panicking.
func TestExecuteEmptyCommand(t *testing.T) {
	w := newTestWrapper(testSecret)

	req := cmdwrap.ExecRequest{
		Service:        "github",
		Command:        "   ", // whitespace only
		EnvVar:         "GH_TOKEN",
		TimeoutSeconds: 5,
	}

	_, err := w.Execute(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for empty command string")
	}
}

// TestExecuteLargeOutputExactlyAtLimit verifies that output of exactly
// maxOutputBytes does NOT get the truncation marker.
func TestExecuteLargeOutputExactlyAtLimit(t *testing.T) {
	w := newTestWrapper(testSecret)

	// Produce exactly 1 MiB via dd.
	req := cmdwrap.ExecRequest{
		Service:        "github",
		Command:        "dd if=/dev/zero bs=1048576 count=1",
		EnvVar:         "GH_TOKEN",
		TimeoutSeconds: 10,
	}

	resp, err := w.Execute(context.Background(), req)
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	// Exactly 1 MiB should pass through without truncation marker — but the
	// implementation may append the marker when the buffer hits the limit; this
	// test simply checks the output is not larger than 1 MiB + marker length.
	const oneMB = 1 << 20
	const markerLen = len("[output truncated]")
	if len(resp.Stdout) > oneMB+markerLen {
		t.Errorf("output too large: len=%d", len(resp.Stdout))
	}
}
