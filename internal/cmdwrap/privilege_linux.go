//go:build linux

package cmdwrap

import "syscall"

// buildSysProcAttr constructs a SysProcAttr that drops the child process to the
// given uid/gid via setuid(2)/setgid(2). On Linux, an explicit empty Groups
// slice (with NoSetGroups=false) causes setgroups(0) to run, clearing all
// supplementary groups inherited from the parent process. This prevents the child
// from using supplementary group membership (e.g., docker, sudo) to access
// restricted files.
//
// This is the structural control (ADR-013 Part A, Option A2): the child runs as
// uid 10101 while init.json is 0600 owned by uid 10001, so the kernel returns
// EACCES on open(2) for every binary the agent might invoke.
//
// The function is intentionally pure (no side effects) to enable unit testing
// without actually dropping privileges.
func buildSysProcAttr(uid, gid uint32) *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid: uid,
			Gid: gid,
			// Groups: explicit empty slice so that setgroups(0) is called,
			// clearing all supplementary groups inherited from the parent process.
			// This is defense-in-depth: the child cannot use supplementary group
			// membership to access files owned by those groups.
			Groups: []uint32{},
			// NoSetGroups: false ensures setgroups(2) is called with the empty
			// list above. The kernel then enforces group isolation.
			NoSetGroups: false,
		},
	}
}

// BuildSysProcAttrForTest is the exported thin wrapper around buildSysProcAttr
// for white-box unit testing. It verifies the SysProcAttr struct is built
// correctly without any real privilege drop (no CAP_SETUID required in tests).
func BuildSysProcAttrForTest(uid, gid uint32) *syscall.SysProcAttr {
	return buildSysProcAttr(uid, gid)
}
