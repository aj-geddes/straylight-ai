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

// Wrapper executes subprocesses with credentials injected as environment
// variables and sanitizes their output.
type Wrapper struct {
	resolver  CredentialResolver
	sanitizer Sanitizer
	guard     egress.Guard
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
		if !envVarPattern.MatchString(req.EnvVar) {
			return nil, fmt.Errorf("cmdwrap: env_var %q is invalid: must match ^[A-Z][A-Z0-9_]{0,63}$", req.EnvVar)
		}
		if reservedEnvVars[req.EnvVar] {
			return nil, fmt.Errorf("cmdwrap: env_var %q is a reserved system variable", req.EnvVar)
		}

		credential, err := w.resolver.GetCredential(req.Service)
		if err != nil {
			return nil, fmt.Errorf("cmdwrap: %w", err)
		}
		envPairs = buildEnv(req.EnvVar, credential)
	}

	// Parse the command string into argv.
	argv, err := splitCommand(req.Command)
	if err != nil {
		return nil, fmt.Errorf("cmdwrap: %w", err)
	}

	// Enforce command allowlist.
	if err := checkAllowlist(argv[0], req.Service, req.AllowedCommands); err != nil {
		return nil, err
	}

	// Egress pre-flight: extract URL-shaped args and deny if any resolve to a
	// blocked destination. This is best-effort (ADR-010 v1): only args that look
	// like URLs are parsed; env-driven or config-driven targets are not checked.
	if err := w.checkEgressPreflight(ctx, argv, svc); err != nil {
		return nil, err
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

// checkAllowlist returns an error if the binary name is not in allowed, or nil
// if allowed is empty (meaning all commands are permitted).
func checkAllowlist(binary, service string, allowed []string) error {
	if len(allowed) == 0 {
		return nil
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
