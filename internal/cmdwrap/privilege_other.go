//go:build !linux

package cmdwrap

import "syscall"

// buildSysProcAttr constructs a SysProcAttr that drops the child process to the
// given uid/gid via setuid(2)/setgid(2). On non-Linux platforms (macOS, etc.),
// NoSetGroups=true suppresses setgroups(2) which is not supported for non-root
// callers on macOS. Supplementary group clearing is Linux-only (see privilege_linux.go).
//
// Production deployments run on Linux containers where the full group-clearing
// behavior applies. This file supports local development and testing on macOS.
//
// The function is intentionally pure (no side effects) to enable unit testing
// without actually dropping privileges.
func buildSysProcAttr(uid, gid uint32) *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid: uid,
			Gid: gid,
			// NoSetGroups=true suppresses setgroups(2) call on platforms where
			// it is not permitted for non-root callers (macOS).
			NoSetGroups: true,
		},
	}
}

// BuildSysProcAttrForTest is the exported thin wrapper around buildSysProcAttr
// for white-box unit testing.
func BuildSysProcAttrForTest(uid, gid uint32) *syscall.SysProcAttr {
	return buildSysProcAttr(uid, gid)
}
