// Package cmdwrap implements command wrapping for the straylight_exec MCP tool.
// It executes commands with credentials injected as environment variables,
// enforces command allowlists, captures and sanitizes output, and enforces
// execution timeouts.
//
// Security properties:
//   - Credentials are injected via env var only, never via command-line arguments.
//   - The subprocess inherits a minimal environment (PATH, HOME, USER, TERM plus
//     the named credential env var) — the parent process environment is NOT inherited.
//   - Commands are executed directly via exec.Command (not via sh -c), so shell
//     metacharacters are treated as literal characters.
//   - Both stdout and stderr are run through the sanitizer before being returned.
//   - Output exceeding maxOutputBytes is truncated.
//   - A best-effort egress pre-flight check (ADR-010) denies commands whose
//     parseable URL arguments resolve to denied SSRF destinations.
//
// Residual risk (ADR-010 v1): the child process's own socket-level egress is
// NOT mediated by this wrapper. Hosts not parseable from the command args (env-
// driven endpoints, config files, follow-on connections) are not checked.
// Container-level egress (nft/eBPF) is the tracked paydown for issue #9.
//
// Implemented in WP-2.1.
package cmdwrap

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/straylight-ai/straylight/internal/egress"
	"github.com/straylight-ai/straylight/internal/services"
)

// envVarPattern matches valid environment variable names: starts with an
// uppercase letter, followed by up to 63 uppercase alphanumeric or underscore
// characters.
var envVarPattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)

// reservedEnvVars are environment variable names that must not be overridden
// by credential injection to prevent privilege escalation or library hijacking.
var reservedEnvVars = map[string]bool{
	"PATH":            true,
	"LD_PRELOAD":      true,
	"LD_LIBRARY_PATH": true,
	"HOME":            true,
	"USER":            true,
	"SHELL":           true,
}

// maxOutputBytes is the maximum number of bytes captured from a single stream
// (stdout or stderr) before truncation.
const maxOutputBytes = 1 << 20 // 1 MiB

// defaultTimeoutSeconds is used when ExecRequest.TimeoutSeconds is zero.
const defaultTimeoutSeconds = 30

// truncationMarker is appended to output that has been truncated.
const truncationMarker = "[output truncated]"

// essentialEnvKeys are the environment variable names copied from the parent
// process into the subprocess's minimal environment.
var essentialEnvKeys = []string{"PATH", "HOME", "USER", "TERM"}

// CredentialResolver provides access to service metadata and credentials.
type CredentialResolver interface {
	// GetCredential returns the raw credential value for the named service.
	GetCredential(name string) (string, error)
	// Get returns the Service metadata for the named service.
	Get(name string) (services.Service, error)
}

// Sanitizer redacts credentials and other sensitive values from text.
type Sanitizer interface {
	Sanitize(input string) string
}

// Approver gates straylight_exec commands behind a human-in-the-loop decision
// (ADR-013 Part A, Option A5). Await blocks until the operator approves or
// denies the request, or until ctx is cancelled.
//
// A nil Approver causes Execute to fail closed (deny) for exec requests.
// Always configure an explicit Approver; use a permissive implementation only
// in controlled environments.
type Approver interface {
	// Await blocks until the operator approves (nil) or denies (non-nil error)
	// the execution request. The argv is provided for display; it must NOT
	// contain credential values (credentials are env-injected, never in argv).
	Await(ctx context.Context, req ApprovalRequest) error
}

// ApprovalRequest carries the minimal set of fields needed for a human to make
// an informed exec approval decision. Credential values are never included.
type ApprovalRequest struct {
	// Service is the name of the configured service whose credential will be injected.
	Service string
	// Argv is the parsed command (binary + args). No env vars, no credentials.
	Argv []string
	// Tool identifies the MCP tool that triggered the request ("straylight_exec").
	Tool string
}

// execChildCredential holds the uid/gid for the exec child process.
// A zero value means "not configured" (fail-closed: Execute will refuse).
type execChildCredential struct {
	set bool
	uid uint32
	gid uint32
}

// Wrapper executes subprocesses with credentials injected as environment
// variables and sanitizes their output.
type Wrapper struct {
	resolver  CredentialResolver
	sanitizer Sanitizer
	guard     egress.Guard
	childCred execChildCredential
	approver  Approver
}

// NewWrapper creates a Wrapper using the given resolver and sanitizer with the
// default egress guard (built-in SSRF denylist).
func NewWrapper(resolver CredentialResolver, sanitizer Sanitizer) *Wrapper {
	return NewWrapperWithGuard(resolver, sanitizer, egress.New())
}

// NewWrapperWithGuard creates a Wrapper with an explicit egress guard.
// Use egress.AllowAll() in tests that do not need SSRF blocking.
func NewWrapperWithGuard(resolver CredentialResolver, sanitizer Sanitizer, guard egress.Guard) *Wrapper {
	return &Wrapper{
		resolver:  resolver,
		sanitizer: sanitizer,
		guard:     guard,
	}
}

// SetChildCredential configures the uid/gid that exec child processes are
// dropped to via SysProcAttr.Credential before the child executes (ADR-013
// Part A, Option A2). Without this call, Execute fails closed.
//
// In the production container, uid/gid 10101 ("straylight-exec") is used. In
// unit tests, the current process uid/gid can be passed to avoid real uid-drop
// (which requires CAP_SETUID). The actual kernel-enforced init.json protection
// is verified in container integration tests, not unit tests.
func (w *Wrapper) SetChildCredential(uid, gid uint32) {
	w.childCred = execChildCredential{set: true, uid: uid, gid: gid}
}

// SetApprover wires the human-in-the-loop approval gate (ADR-013 Part A,
// Option A5). When set and Execute is called, the Approver.Await is invoked
// after allowlist + egress checks and BEFORE the child process is spawned.
// When unset (nil), Execute fails closed for exec requests.
func (w *Wrapper) SetApprover(a Approver) {
	w.approver = a
}

// ExecRequest describes a command execution request.
type ExecRequest struct {
	// Service is the name of the configured service whose credential is injected.
	Service string `json:"service"`

	// Command is the command string to execute, e.g. "git push origin main".
	// It is split into argv using simple whitespace tokenisation (no shell
	// metacharacter evaluation).
	Command string `json:"command"`

	// EnvVar is the environment variable name to inject with the credential value,
	// e.g. "GH_TOKEN". Used for single-credential (http_proxy / oauth) services.
	// Ignored when EnvVars is non-empty.
	EnvVar string `json:"env_var"`

	// EnvVars is a map of environment variable names to values for services that
	// require multiple credentials (e.g., cloud services with AWS_ACCESS_KEY_ID,
	// AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN). When non-empty, EnvVars takes
	// precedence over EnvVar. All keys must satisfy the same format constraints
	// as EnvVar: uppercase, not reserved.
	EnvVars map[string]string `json:"env_vars,omitempty"`

	// TimeoutSeconds is the maximum execution time in seconds. Zero defaults to
	// defaultTimeoutSeconds (30).
	TimeoutSeconds int `json:"timeout_seconds"`

	// AllowedCommands, if non-empty, restricts execution to commands whose
	// binary name (first token) matches one of the listed values. An empty
	// slice means no restriction.
	AllowedCommands []string `json:"allowed_commands,omitempty"`
}

// ExecResponse holds the outcome of a command execution.
type ExecResponse struct {
	// ExitCode is the process exit code. -1 indicates a timeout or signal kill.
	ExitCode int `json:"exit_code"`

	// Stdout is the sanitized standard output of the command, truncated to
	// maxOutputBytes if necessary.
	Stdout string `json:"stdout"`

	// Stderr is the sanitized standard error of the command, truncated to
	// maxOutputBytes if necessary.
	Stderr string `json:"stderr"`
}

// Execute runs the command described by req inside a subprocess.
//
// When req.EnvVars is non-empty (cloud services), all key-value pairs are
// injected as environment variables and req.EnvVar is ignored.
// When req.EnvVars is empty, the credential for req.Service is fetched from
// the resolver and injected as a single environment variable named req.EnvVar.
//
// The subprocess runs in a minimal environment (PATH, HOME, USER, TERM plus
// the injected credential variable(s)). Both stdout and stderr are captured,
// sanitized, and returned in ExecResponse.
//
// Execute returns a non-nil error only for setup failures (unknown service,
// missing credential, command not found, allowlist violation, egress denial).
// Timeout and non-zero exit codes are reported via ExecResponse.ExitCode
// without returning an error.
func (w *Wrapper) Execute(ctx context.Context, req ExecRequest) (*ExecResponse, error) {
	// Fail-closed: a child credential MUST be configured (ADR-013 Part A, Option A2).
	// Executing as the parent uid would give the child process access to the
	// OpenBao init.json (owned by the same uid), which violates the THREAT-MODEL §4
	// invariant. Never fall back to same-uid exec silently.
	if !w.childCred.set {
		return nil, errors.New("cmdwrap: child credential not configured: refusing to execute as parent uid (ADR-013 fail-closed)")
	}

	// Resolve service metadata — ensures the service exists.
	svc, err := w.resolver.Get(req.Service)
	if err != nil {
		return nil, fmt.Errorf("cmdwrap: %w", err)
	}

	var envPairs []string

	if len(req.EnvVars) > 0 {
		// Multi-var path: validate and collect all entries.
		pairs, err := buildEnvVarsMap(req.EnvVars)
		if err != nil {
			return nil, err
		}
		envPairs = pairs
	} else {
		// Single-var path: validate env_var and resolve credential.
		// Populate from svc.ExecEnvVar when the request omits the field.
		// This allows the service configuration to supply the env var name so
		// handleExec does not need to know it (ADR-013 security seam fix).
		envVar := req.EnvVar
		if envVar == "" && svc.ExecEnvVar != "" {
			envVar = svc.ExecEnvVar
		}
		if !envVarPattern.MatchString(envVar) {
			return nil, fmt.Errorf("cmdwrap: env_var %q is invalid: must match ^[A-Z][A-Z0-9_]{0,63}$", envVar)
		}
		if reservedEnvVars[envVar] {
			return nil, fmt.Errorf("cmdwrap: env_var %q is a reserved system variable", envVar)
		}

		credential, err := w.resolver.GetCredential(req.Service)
		if err != nil {
			return nil, fmt.Errorf("cmdwrap: %w", err)
		}
		envPairs = buildEnv(envVar, credential)
	}

	// Parse the command string into argv.
	argv, err := splitCommand(req.Command)
	if err != nil {
		return nil, fmt.Errorf("cmdwrap: %w", err)
	}

	// Path-normalize argv[0] before allowlist check so that "aws", "./aws", and
	// "/usr/bin/aws" all match an allowlist entry of "aws" (Finding 3 fix).
	// exec.LookPath resolves the binary path; filepath.Base extracts the name.
	// On failure (binary not found) we use argv[0] as-is — the command will
	// fail at exec time with a clear "not found" error.
	resolvedBin, lookErr := exec.LookPath(argv[0])
	if lookErr != nil {
		resolvedBin = argv[0]
	}
	normalizedBin := filepath.Base(resolvedBin)

	// Enforce command allowlist using svc.AllowedCommands (not req.AllowedCommands).
	// The allowlist is the service-level control — callers must not be able to
	// bypass it by omitting or clearing req.AllowedCommands (Finding 1 fix).
	if err := checkAllowlist(normalizedBin, req.Service, svc.AllowedCommands); err != nil {
		return nil, err
	}

	// Egress pre-flight: extract URL-shaped args and deny if any resolve to a
	// blocked destination. This is best-effort (ADR-010 v1): only args that look
	// like URLs are parsed; env-driven or config-driven targets are not checked.
	if err := w.checkEgressPreflight(ctx, argv, svc); err != nil {
		return nil, err
	}

	// Human-in-the-loop approval gate (ADR-013 Part A, Option A5).
	// Fail-closed: a nil approver is treated as a permanent deny so that exec
	// cannot be wired without explicitly configuring an approval strategy.
	// The ApprovalRequest carries argv (never env vars / credential values).
	if w.approver == nil {
		return nil, errors.New("cmdwrap: exec approval gate not configured: refusing to run without an Approver (ADR-013 fail-closed)")
	}
	approvalReq := ApprovalRequest{
		Service: req.Service,
		Argv:    argv,
		Tool:    "straylight_exec",
	}
	if err := w.approver.Await(ctx, approvalReq); err != nil {
		return nil, fmt.Errorf("cmdwrap: exec approval denied: %w", err)
	}

	// Apply timeout.
	timeout := req.TimeoutSeconds
	if timeout <= 0 {
		timeout = defaultTimeoutSeconds
	}
	timeoutCtx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
	defer cancel()

	// Build the command. exec.LookPath is called implicitly by exec.CommandContext.
	cmd := exec.CommandContext(timeoutCtx, argv[0], argv[1:]...)

	// Drop the child process to the configured exec uid/gid (ADR-013 Part A,
	// Option A2). This makes init.json (owned by the parent uid, mode 0600 inside
	// a 0700 dir) unreadable by the child via any binary the agent might choose.
	// The actual kernel enforcement is verified in container integration tests.
	cmd.SysProcAttr = buildSysProcAttr(w.childCred.uid, w.childCred.gid)

	// Set the minimal environment (essential keys + injected credentials).
	cmd.Env = appendEssentialEnv(envPairs)

	// Attach stdout and stderr pipes for separate capture.
	var stdoutBuf, stderrBuf limitedBuffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	// Run the command.
	runErr := cmd.Run()

	// Determine exit code.
	exitCode := 0
	if runErr != nil {
		var exitErr *exec.ExitError
		switch {
		case errors.Is(timeoutCtx.Err(), context.DeadlineExceeded):
			// Timeout: kill was triggered by context cancellation.
			exitCode = -1
		case errors.As(runErr, &exitErr):
			exitCode = exitErr.ExitCode()
		default:
			// Command not found or other launch failure.
			return nil, fmt.Errorf("cmdwrap: %w", runErr)
		}
	}

	// Build stderr; prepend timeout message when timed out.
	stderrStr := stderrBuf.String()
	if exitCode == -1 {
		timeoutMsg := fmt.Sprintf("command timed out after %d seconds", timeout)
		if stderrStr == "" {
			stderrStr = timeoutMsg
		} else {
			stderrStr = timeoutMsg + "\n" + stderrStr
		}
	}

	// Sanitize both streams.
	sanitizedStdout := w.sanitizer.Sanitize(stdoutBuf.String())
	sanitizedStderr := w.sanitizer.Sanitize(stderrStr)

	return &ExecResponse{
		ExitCode: exitCode,
		Stdout:   sanitizedStdout,
		Stderr:   sanitizedStderr,
	}, nil
}

// checkEgressPreflight extracts URL-shaped arguments from argv and applies the
// egress guard's CheckHost to each. Returns an error if any destination is denied.
// This is best-effort: only http/https URL args are parsed; other destinations
// (flags like --host, config files, env vars) are not checked.
func (w *Wrapper) checkEgressPreflight(ctx context.Context, argv []string, svc services.Service) error {
	policy := egressPolicyFrom(svc.Egress)

	for _, arg := range argv[1:] { // skip argv[0] (binary name)
		host := extractHost(arg)
		if host == "" {
			continue
		}
		if d := w.guard.CheckHost(ctx, host, policy); !d.Allowed {
			return fmt.Errorf("cmdwrap: egress denied for host %q: %s", host, d.Reason)
		}
	}
	return nil
}

// extractHost parses an argument that looks like an http/https URL and returns
// its hostname. Returns empty string if the arg is not a parseable URL.
func extractHost(arg string) string {
	lower := strings.ToLower(arg)
	if !strings.HasPrefix(lower, "http://") && !strings.HasPrefix(lower, "https://") {
		return ""
	}
	u, err := url.Parse(arg)
	if err != nil || u.Hostname() == "" {
		return ""
	}
	return u.Hostname()
}

// egressPolicyFrom converts a *services.EgressPolicy to an egress.Policy.
// Returns a zero Policy (default deny SSRF ranges, allow public) when nil.
func egressPolicyFrom(ep *services.EgressPolicy) egress.Policy {
	if ep == nil {
		return egress.Policy{}
	}
	return egress.Policy{
		AllowHosts:    ep.AllowHosts,
		AllowCIDRs:    ep.AllowCIDRs,
		AllowLoopback: ep.AllowLoopback,
	}
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// splitCommand splits a command string into argv using shell-like whitespace
// tokenisation. It does NOT evaluate shell metacharacters; each token is
// passed as-is to the subprocess. Quoted strings are not supported — arguments
// with spaces must be passed via environment variables.
//
// Returns an error if the command string is empty or contains only whitespace.
func splitCommand(command string) ([]string, error) {
	tokens := strings.FieldsFunc(command, unicode.IsSpace)
	if len(tokens) == 0 {
		return nil, errors.New("command must not be empty")
	}
	return tokens, nil
}

// checkAllowlist returns nil when binary is in the allowed list.
// Fails closed when allowed is empty: an exec-enabled service must have a
// non-empty allowlist — empty means "deny all" (ADR-013 Finding 1 fix).
// The old allow-all-when-empty behavior applied to req.AllowedCommands which is
// now unused; svc.AllowedCommands must always be validated explicitly.
func checkAllowlist(binary, service string, allowed []string) error {
	if len(allowed) == 0 {
		return fmt.Errorf("cmdwrap: no allowed commands configured for service %q (exec requires a non-empty allowlist)", service)
	}
	for _, a := range allowed {
		if binary == a {
			return nil
		}
	}
	return fmt.Errorf("cmdwrap: command %q is not allowed for service %q", binary, service)
}

// buildEnv constructs a single-entry credential slice for the legacy single
// env var path. Returns only the credential pair; appendEssentialEnv adds
// the system-level keys.
func buildEnv(envVar, credential string) []string {
	return []string{envVar + "=" + credential}
}

// buildEnvVarsMap validates and converts a map[string]string of env vars into
// "KEY=VALUE" pairs. Returns an error if any key is invalid or reserved.
func buildEnvVarsMap(envVars map[string]string) ([]string, error) {
	pairs := make([]string, 0, len(envVars))
	for k, v := range envVars {
		if !envVarPattern.MatchString(k) {
			return nil, fmt.Errorf("cmdwrap: env var key %q is invalid: must match ^[A-Z][A-Z0-9_]{0,63}$", k)
		}
		if reservedEnvVars[k] {
			return nil, fmt.Errorf("cmdwrap: env var key %q is a reserved system variable", k)
		}
		pairs = append(pairs, k+"="+v)
	}
	return pairs, nil
}

// appendEssentialEnv prepends essential env vars copied from the parent
// process (PATH, HOME, USER, TERM) to the given credential pairs, producing
// the complete minimal environment for a subprocess.
func appendEssentialEnv(credPairs []string) []string {
	env := make([]string, 0, len(essentialEnvKeys)+len(credPairs))
	for _, key := range essentialEnvKeys {
		if val, ok := os.LookupEnv(key); ok {
			env = append(env, key+"="+val)
		}
	}
	env = append(env, credPairs...)
	return env
}

// limitedBuffer is a bytes.Buffer that refuses to grow beyond maxOutputBytes.
// Once the limit is reached, further writes are silently discarded and the
// truncation marker is appended.
type limitedBuffer struct {
	buf       bytes.Buffer
	truncated bool
}

// Write implements io.Writer.
func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.truncated {
		return len(p), nil
	}
	remaining := maxOutputBytes - b.buf.Len()
	if len(p) > remaining {
		_, _ = b.buf.Write(p[:remaining])
		b.truncated = true
		_, _ = b.buf.WriteString(truncationMarker)
		return len(p), nil
	}
	_, err := b.buf.Write(p)
	return len(p), err
}

// String returns the buffered content as a string.
func (b *limitedBuffer) String() string {
	return b.buf.String()
}

// ensure limitedBuffer implements io.Writer at compile time.
var _ io.Writer = (*limitedBuffer)(nil)
