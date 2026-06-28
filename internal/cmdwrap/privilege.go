package cmdwrap

import "syscall"

// buildSysProcAttr constructs a SysProcAttr that drops the child process to the
// given uid/gid via setuid(2)/setgid(2). NoSetGroups suppresses the supplementary
// group list reset so the parent process does not need CAP_SETGID for the
// getgroups/setgroups pair — only CAP_SETUID/CAP_SETGID for the uid/gid drop.
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
			Uid:         uid,
			Gid:         gid,
			NoSetGroups: true,
		},
	}
}

// BuildSysProcAttrForTest is the exported thin wrapper around buildSysProcAttr
// for white-box unit testing. It verifies the SysProcAttr struct is built
// correctly without any real privilege drop (no CAP_SETUID required in tests).
func BuildSysProcAttrForTest(uid, gid uint32) *syscall.SysProcAttr {
	return buildSysProcAttr(uid, gid)
}
