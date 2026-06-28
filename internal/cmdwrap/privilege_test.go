//go:build linux

// Package cmdwrap_test covers the privilege-separation seams added in ADR-013 Phase 3.
// These tests run on Linux only (where SysProcAttr.Credential is supported).
// The actual uid-drop (kernel enforcement of init.json unreadability) is an
// integration test that requires the container setup; these unit tests verify
// the Go data structures and fail-closed logic without requiring CAP_SETUID.
package cmdwrap_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"syscall"
	"testing"

	"github.com/straylight-ai/straylight/internal/cmdwrap"
	"github.com/straylight-ai/straylight/internal/egress"
	"github.com/straylight-ai/straylight/internal/services"
)

// ---------------------------------------------------------------------------
// Test doubles for privilege tests
// ---------------------------------------------------------------------------

// execPrivResolver provides a service with ExecEnabled=true and AllowedCommands
// so the privilege gate is reached during Execute.
type execPrivResolver struct {
	allowedCmds []string
}

func (r *execPrivResolver) GetCredential(name string) (string, error) {
	if name == "testsvc" {
		return "testcred", nil
	}
	return "", fmt.Errorf("services: %q not found", name)
}

func (r *execPrivResolver) Get(name string) (services.Service, error) {
	if name == "testsvc" {
		return services.Service{
			Name:            "testsvc",
			Type:            "cloud",
			ExecEnabled:     true,
			AllowedCommands: r.allowedCmds,
		}, nil
	}
	return services.Service{}, fmt.Errorf("services: %q not found", name)
}

// passApprover is an Approver that always permits.
type passApprover struct{}

func (a *passApprover) Await(_ context.Context, _ cmdwrap.ApprovalRequest) error { return nil }

// denyApprover is an Approver that always denies.
type denyApprover struct {
	reason string
}

func (a *denyApprover) Await(_ context.Context, _ cmdwrap.ApprovalRequest) error {
	return errors.New(a.reason)
}

// ---------------------------------------------------------------------------
// TestBuildSysProcAttrForTest: pure function correctness
// ---------------------------------------------------------------------------

// TestBuildSysProcAttrForTest verifies that BuildSysProcAttrForTest constructs a
// SysProcAttr with the expected Credential fields. This is a pure unit test:
// it verifies the Go struct is built correctly without any real uid-drop.
func TestBuildSysProcAttrForTest(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("SysProcAttr.Credential is Linux-specific")
	}

	tests := []struct {
		name string
		uid  uint32
		gid  uint32
	}{
		{name: "exec_uid_10101", uid: 10101, gid: 10101},
		{name: "arbitrary", uid: 1000, gid: 1001},
		{name: "current", uid: uint32(os.Getuid()), gid: uint32(os.Getgid())},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Act
			attr := cmdwrap.BuildSysProcAttrForTest(tt.uid, tt.gid)

			// Assert: must be non-nil with correct fields.
			if attr == nil {
				t.Fatal("BuildSysProcAttrForTest returned nil")
			}
			if attr.Credential == nil {
				t.Fatal("SysProcAttr.Credential is nil")
			}
			if attr.Credential.Uid != tt.uid {
				t.Errorf("Credential.Uid = %d, want %d", attr.Credential.Uid, tt.uid)
			}
			if attr.Credential.Gid != tt.gid {
				t.Errorf("Credential.Gid = %d, want %d", attr.Credential.Gid, tt.gid)
			}
			if !attr.Credential.NoSetGroups {
				t.Error("Credential.NoSetGroups must be true to suppress setgroups(2) call")
			}
			// Compile-time assertion that the return type is actually *syscall.SysProcAttr.
			var _ *syscall.SysProcAttr = attr
		})
	}
}

// ---------------------------------------------------------------------------
// TestExecuteFailsClosedWithoutChildCredential
// ---------------------------------------------------------------------------

// TestExecuteFailsClosedWithoutChildCredential verifies that Execute refuses to
// run any command when no child credential has been configured. This is the
// primary fail-closed guarantee: a Wrapper without SetChildCredential MUST NOT
// execute commands (it must not fall back to the parent uid).
func TestExecuteFailsClosedWithoutChildCredential(t *testing.T) {
	resolver := &execPrivResolver{allowedCmds: []string{"echo"}}
	san := &noopSanitizer{}
	w := cmdwrap.NewWrapperWithGuard(resolver, san, egress.AllowAll())
	// Deliberately NOT calling SetChildCredential or SetApprover.

	req := cmdwrap.ExecRequest{
		Service:        "testsvc",
		Command:        "echo hello",
		EnvVar:         "TEST_TOKEN",
		TimeoutSeconds: 5,
	}

	_, err := w.Execute(context.Background(), req)
	if err == nil {
		t.Fatal("Execute must return an error when no child credential is configured")
	}
	if !strings.Contains(err.Error(), "child credential") {
		t.Errorf("expected error to mention 'child credential', got: %q", err.Error())
	}
}

// ---------------------------------------------------------------------------
// TestExecuteWithChildCredentialAndApprover
// ---------------------------------------------------------------------------

// TestExecuteWithChildCredentialAndApprover verifies that a Wrapper with
// SetChildCredential (same uid as the test process, so no actual drop) and a
// permissive SetApprover executes the command successfully.
// The real uid-drop to 10101 is verified in container integration tests.
func TestExecuteWithChildCredentialAndApprover(t *testing.T) {
	uid := uint32(os.Getuid())
	gid := uint32(os.Getgid())

	resolver := &execPrivResolver{allowedCmds: []string{"echo"}}
	san := &noopSanitizer{}
	w := cmdwrap.NewWrapperWithGuard(resolver, san, egress.AllowAll())
	w.SetChildCredential(uid, gid)
	w.SetApprover(&passApprover{})

	req := cmdwrap.ExecRequest{
		Service:        "testsvc",
		Command:        "echo hello",
		EnvVar:         "TEST_TOKEN",
		TimeoutSeconds: 5,
	}

	resp, err := w.Execute(context.Background(), req)
	if err != nil {
		t.Fatalf("Execute returned unexpected error: %v", err)
	}
	if resp.ExitCode != 0 {
		t.Errorf("expected exit code 0, got %d; stderr: %s", resp.ExitCode, resp.Stderr)
	}
	if !strings.Contains(resp.Stdout, "hello") {
		t.Errorf("expected 'hello' in stdout; got: %q", resp.Stdout)
	}
}

// ---------------------------------------------------------------------------
// TestApproverDenyBlocksExecution
// ---------------------------------------------------------------------------

// TestApproverDenyBlocksExecution verifies that when the Approver returns a
// non-nil error, Execute returns an error and does NOT run the command.
func TestApproverDenyBlocksExecution(t *testing.T) {
	uid := uint32(os.Getuid())
	gid := uint32(os.Getgid())

	resolver := &execPrivResolver{allowedCmds: []string{"echo"}}
	san := &noopSanitizer{}
	w := cmdwrap.NewWrapperWithGuard(resolver, san, egress.AllowAll())
	w.SetChildCredential(uid, gid)
	w.SetApprover(&denyApprover{reason: "exec approval denied by operator"})

	req := cmdwrap.ExecRequest{
		Service:        "testsvc",
		Command:        "echo hello",
		EnvVar:         "TEST_TOKEN",
		TimeoutSeconds: 5,
	}

	_, err := w.Execute(context.Background(), req)
	if err == nil {
		t.Fatal("Execute must return an error when the Approver denies")
	}
	if !strings.Contains(err.Error(), "approval") {
		t.Errorf("expected error to mention 'approval', got: %q", err.Error())
	}
}

// ---------------------------------------------------------------------------
// TestMissingApproverFailsClosedForExec
// ---------------------------------------------------------------------------

// TestMissingApproverFailsClosedForExec verifies that when SetChildCredential
// is set but NO approver is configured, Execute fails closed. This prevents
// accidental exec without human-in-the-loop approval for high-impact commands.
func TestMissingApproverFailsClosedForExec(t *testing.T) {
	uid := uint32(os.Getuid())
	gid := uint32(os.Getgid())

	resolver := &execPrivResolver{allowedCmds: []string{"echo"}}
	san := &noopSanitizer{}
	w := cmdwrap.NewWrapperWithGuard(resolver, san, egress.AllowAll())
	w.SetChildCredential(uid, gid)
	// Deliberately NOT calling SetApprover.

	req := cmdwrap.ExecRequest{
		Service:        "testsvc",
		Command:        "echo hello",
		EnvVar:         "TEST_TOKEN",
		TimeoutSeconds: 5,
	}

	_, err := w.Execute(context.Background(), req)
	if err == nil {
		t.Fatal("Execute must fail closed when no approver is configured")
	}
	if !strings.Contains(err.Error(), "approval") {
		t.Errorf("expected error to mention 'approval', got: %q", err.Error())
	}
}

// ---------------------------------------------------------------------------
// TestApprovalRequestContainsExpectedFields
// ---------------------------------------------------------------------------

// TestApprovalRequestContainsExpectedFields verifies that the ApprovalRequest
// passed to Await contains the service name, tool name, and the parsed argv.
// Credential values must never appear in the ApprovalRequest.
func TestApprovalRequestContainsExpectedFields(t *testing.T) {
	uid := uint32(os.Getuid())
	gid := uint32(os.Getgid())

	var capturedReq cmdwrap.ApprovalRequest
	captureApprover := &captureAndAllowApprover{capture: &capturedReq}

	resolver := &execPrivResolver{allowedCmds: []string{"echo"}}
	san := &noopSanitizer{}
	w := cmdwrap.NewWrapperWithGuard(resolver, san, egress.AllowAll())
	w.SetChildCredential(uid, gid)
	w.SetApprover(captureApprover)

	req := cmdwrap.ExecRequest{
		Service:        "testsvc",
		Command:        "echo world",
		EnvVar:         "TEST_TOKEN",
		TimeoutSeconds: 5,
	}

	_, err := w.Execute(context.Background(), req)
	if err != nil {
		t.Fatalf("Execute returned unexpected error: %v", err)
	}

	if capturedReq.Service != "testsvc" {
		t.Errorf("ApprovalRequest.Service = %q, want %q", capturedReq.Service, "testsvc")
	}
	if capturedReq.Tool != "straylight_exec" {
		t.Errorf("ApprovalRequest.Tool = %q, want %q", capturedReq.Tool, "straylight_exec")
	}
	if len(capturedReq.Argv) == 0 || capturedReq.Argv[0] != "echo" {
		t.Errorf("ApprovalRequest.Argv = %v, want first element to be %q", capturedReq.Argv, "echo")
	}
}

// captureAndAllowApprover records the last ApprovalRequest and permits it.
type captureAndAllowApprover struct {
	capture *cmdwrap.ApprovalRequest
}

func (a *captureAndAllowApprover) Await(_ context.Context, req cmdwrap.ApprovalRequest) error {
	*a.capture = req
	return nil
}
