// Package cmdwrap_test verifies that Execute with a child credential matching the
// current process uid/gid does not require CAP_SETUID/CAP_SETGID and succeeds
// in unprivileged environments (mirrors the Linux CI scenario).
//
// RED phase: this test exercises the behaviour introduced by the same-uid no-op
// skip in Execute. On Linux CI without CAP_SETUID, the test currently fails with
// "fork/exec ...: operation not permitted" because buildSysProcAttr always sets
// Credential (causing setgroups(0) which needs CAP_SETGID). The fix removes
// Credential from cmd.SysProcAttr when child uid/gid == current process uid/gid.
package cmdwrap_test

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/straylight-ai/straylight/internal/cmdwrap"
	"github.com/straylight-ai/straylight/internal/egress"
	"github.com/straylight-ai/straylight/internal/services"
)

// sameUIDResolver provides a minimal service suitable for the same-uid tests.
type sameUIDResolver struct{}

func (r *sameUIDResolver) GetCredential(name string) (string, error) {
	return "testcred", nil
}

func (r *sameUIDResolver) Get(name string) (services.Service, error) {
	return services.Service{
		Name:            name,
		Type:            "http_proxy",
		ExecEnabled:     true,
		AllowedCommands: []string{"echo", "true"},
		ExecEnvVar:      "TEST_TOKEN",
	}, nil
}

// TestExecute_SameUID_SucceedsWithoutPrivilege verifies that Execute with a child
// credential equal to the current process uid/gid does NOT trigger a real
// setuid/setgroups syscall and succeeds without CAP_SETUID/CAP_SETGID.
//
// This directly mirrors the Linux CI failure: the tests configure same-uid
// credentials to avoid a real drop, but on Linux the Credential field in
// SysProcAttr still causes setgroups(0) to be called, requiring CAP_SETGID.
// The fix: when child uid == os.Getuid() AND child gid == os.Getgid(), do NOT
// set cmd.SysProcAttr at all so no privileged syscalls are issued.
func TestExecute_SameUID_SucceedsWithoutPrivilege(t *testing.T) {
	uid := uint32(os.Getuid())
	gid := uint32(os.Getgid())

	w := cmdwrap.NewWrapperWithGuard(&sameUIDResolver{}, &noopSanitizer{}, egress.AllowAll())
	w.SetChildCredential(uid, gid) // same as current process — no-op drop
	w.SetApprover(&autoApprover{})

	req := cmdwrap.ExecRequest{
		Service:        "testsvc",
		Command:        "echo same-uid-noop",
		EnvVar:         "TEST_TOKEN",
		TimeoutSeconds: 5,
	}

	resp, err := w.Execute(context.Background(), req)
	if err != nil {
		// On Linux without CAP_SETUID this used to fail with:
		// "cmdwrap: fork/exec /usr/bin/echo: operation not permitted"
		t.Fatalf("Execute with same-uid credential returned error (should succeed without privileges): %v", err)
	}
	if resp.ExitCode != 0 {
		t.Errorf("expected exit code 0; got %d; stderr: %s", resp.ExitCode, resp.Stderr)
	}
	if !strings.Contains(resp.Stdout, "same-uid-noop") {
		t.Errorf("expected 'same-uid-noop' in stdout; got: %q", resp.Stdout)
	}
}

// TestExecute_SameUID_FailClosedWithoutCredential verifies that the fail-closed
// guarantee (no credential configured → Execute refuses) is NOT weakened by the
// same-uid skip. A Wrapper with NO SetChildCredential call must still deny.
func TestExecute_SameUID_FailClosedWithoutCredential(t *testing.T) {
	w := cmdwrap.NewWrapperWithGuard(&sameUIDResolver{}, &noopSanitizer{}, egress.AllowAll())
	// Deliberately do NOT call SetChildCredential.
	w.SetApprover(&autoApprover{})

	req := cmdwrap.ExecRequest{
		Service:        "testsvc",
		Command:        "echo should-not-run",
		EnvVar:         "TEST_TOKEN",
		TimeoutSeconds: 5,
	}

	_, err := w.Execute(context.Background(), req)
	if err == nil {
		t.Fatal("Execute must fail closed when no child credential is configured")
	}
	if !strings.Contains(err.Error(), "child credential") {
		t.Errorf("expected error to mention 'child credential'; got: %q", err.Error())
	}
}
