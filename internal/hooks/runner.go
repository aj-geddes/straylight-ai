// Package hooks provides Claude Code hook script implementations.
// runner.go provides stdin/stdout runner functions for use as MCP subcommands.
package hooks

import (
	"encoding/json"
	"io"
)

// preToolUseDecision is the JSON output for a PreToolUse hook response.
type preToolUseDecision struct {
	Decision string `json:"decision"`
	Reason   string `json:"reason,omitempty"`
}

// RunPreToolUse reads a PreToolUseInput JSON from stdin, runs the
// PreToolUseChecker, and writes the decision JSON to stdout.
//
// Exit codes:
//   - 0: allow
//   - 1: internal error (malformed input)
//   - 2: block
func RunPreToolUse(stdin io.Reader, stdout io.Writer, services ServiceLister) int {
	var input PreToolUseInput
	if err := json.NewDecoder(stdin).Decode(&input); err != nil {
		writeJSON(stdout, preToolUseDecision{Decision: "allow"})
		return 1
	}

	checker := NewPreToolUseChecker(services)
	allow, msg := checker.Check(input)

	if allow {
		writeJSON(stdout, preToolUseDecision{Decision: "allow"})
		return 0
	}

	writeJSON(stdout, preToolUseDecision{Decision: "block", Reason: msg})
	return 2
}

// RunPostToolUse reads a PostToolUseOutput JSON from stdin, runs the
// PostToolUseProcessor, and writes the sanitized output JSON to stdout.
//
// Exit codes:
//   - 0: success
//   - 1: internal error (malformed input)
func RunPostToolUse(stdin io.Reader, stdout io.Writer, sanitizer Sanitizer) int {
	var output PostToolUseOutput
	if err := json.NewDecoder(stdin).Decode(&output); err != nil {
		return 1
	}

	processor := NewPostToolUseProcessor(sanitizer)
	result := processor.Process(output)

	if err := json.NewEncoder(stdout).Encode(result); err != nil {
		return 1
	}
	return 0
}

// writeJSON encodes v as JSON to w. Errors are silently ignored because hook
// runners cannot usefully recover from write failures to stdout.
func writeJSON(w io.Writer, v interface{}) {
	_ = json.NewEncoder(w).Encode(v)
}
