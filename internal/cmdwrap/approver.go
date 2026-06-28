package cmdwrap

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
)

// LoggingAutoApprover is a v1 Approver implementation that logs every exec
// request and auto-approves it. It satisfies the fail-closed requirement by
// being an explicitly configured, non-nil Approver — the wrapper will not run
// without one.
//
// Operators can replace this with a blocking implementation that requires a
// human to approve/deny via a side-channel (e.g. Slack bot, signed JWT, or
// a local terminal prompt). The Approver interface is intentionally minimal
// to allow diverse approval backends.
//
// This implementation is suitable for single-operator deployments where the
// operator trusts the allowed_commands list and service ExecEnabled opt-in
// as sufficient controls, and wants a log trail without a blocking prompt.
type LoggingAutoApprover struct {
	logger *slog.Logger
}

// NewAutoApprover creates a LoggingAutoApprover that logs every exec approval
// decision at INFO level and auto-approves. Use it as the production default
// for deployments that do not yet have a blocking approval mechanism.
//
// WARNING (v1 limitation): This approver auto-approves every exec request.
// All commands that pass the allowlist and ExecEnabled gate are executed
// without a human approval step. Replace with a blocking Approver implementation
// for environments requiring explicit per-command operator sign-off.
func NewAutoApprover() *LoggingAutoApprover {
	a := NewAutoApproverWithLogger(slog.Default())
	slog.Warn("straylight_exec: LoggingAutoApprover active — exec requests are auto-approved; replace with a blocking Approver for human-in-the-loop enforcement (v1 limitation)")
	return a
}

// NewAutoApproverWithLogger creates a LoggingAutoApprover with a custom logger.
// Useful for tests that want to suppress or capture log output.
func NewAutoApproverWithLogger(logger *slog.Logger) *LoggingAutoApprover {
	return &LoggingAutoApprover{logger: logger}
}

// Await logs the approval request and returns nil (auto-approve). The log line
// is the audit trail for every exec invocation. Credential values are never
// included — only the service name, tool, and argv are logged.
func (a *LoggingAutoApprover) Await(_ context.Context, req ApprovalRequest) error {
	// Log the argv as a space-joined string for readability.
	// Never log req from the env (credentials are env-injected, not in argv).
	argv := strings.Join(req.Argv, " ")
	a.logger.Info("exec approval: auto-approved",
		"tool", req.Tool,
		"service", req.Service,
		"argv", fmt.Sprintf("[%s]", argv),
	)
	return nil
}
