package hooks

// posttooluse.go processes tool output after execution to sanitize any
// credentials that may appear in command output or API responses.

import (
	"regexp"
	"strings"
)

// Sanitizer redacts credentials from arbitrary text.
// Implemented by *sanitizer.Sanitizer from internal/sanitizer.
type Sanitizer interface {
	Sanitize(input string) string
}

// PostToolUseOutput is the JSON payload Claude Code sends to a PostToolUse hook.
type PostToolUseOutput struct {
	ToolName   string                 `json:"tool_name"`
	ToolOutput map[string]interface{} `json:"tool_output"`
}

// PostToolUseProcessor sanitizes tool output by running it through a Sanitizer
// and applying additional built-in patterns for connection strings.
type PostToolUseProcessor struct {
	sanitizer Sanitizer
}

// connectionStringPatterns are regexes applied to stdout/stderr regardless of
// the sanitizer configuration. They redact connection strings that contain
// embedded credentials (user:pass@host).
var connectionStringPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?:postgresql|postgres|mysql|mongodb|redis)://\S+`),
}

// NewPostToolUseProcessor creates a PostToolUseProcessor backed by the given sanitizer.
func NewPostToolUseProcessor(sanitizer Sanitizer) *PostToolUseProcessor {
	return &PostToolUseProcessor{sanitizer: sanitizer}
}

// Process sanitizes the stdout and stderr fields of the tool output.
// Applies the sanitizer first, then additional connection-string patterns.
// All other fields in ToolOutput are preserved unchanged.
// If ToolOutput is nil, the output is returned as-is.
func (p *PostToolUseProcessor) Process(output PostToolUseOutput) PostToolUseOutput {
	if output.ToolOutput == nil {
		return output
	}

	// Work on a shallow copy to avoid mutating the caller's map.
	sanitized := make(map[string]interface{}, len(output.ToolOutput))
	for k, v := range output.ToolOutput {
		sanitized[k] = v
	}

	for _, field := range []string{"stdout", "stderr"} {
		if val, ok := sanitized[field]; ok {
			if s, ok := val.(string); ok {
				s = p.sanitizer.Sanitize(s)
				s = applyConnectionStringPatterns(s)
				sanitized[field] = s
			}
		}
	}

	return PostToolUseOutput{
		ToolName:   output.ToolName,
		ToolOutput: sanitized,
	}
}

// applyConnectionStringPatterns redacts connection strings that may contain
// embedded passwords. The entire URI is replaced so no credential leaks through
// partial matching.
func applyConnectionStringPatterns(text string) string {
	if !strings.Contains(text, "://") {
		return text
	}
	result := text
	for _, re := range connectionStringPatterns {
		result = re.ReplaceAllLiteralString(result, "[REDACTED:connection-string]")
	}
	return result
}
