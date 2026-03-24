package hooks

// posttooluse.go processes tool output after execution to sanitize any
// credentials that may appear in command output or API responses.

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

// PostToolUseProcessor sanitizes tool output by running it through a Sanitizer.
type PostToolUseProcessor struct {
	sanitizer Sanitizer
}

// NewPostToolUseProcessor creates a PostToolUseProcessor backed by the given sanitizer.
func NewPostToolUseProcessor(sanitizer Sanitizer) *PostToolUseProcessor {
	return &PostToolUseProcessor{sanitizer: sanitizer}
}

// Process sanitizes the stdout and stderr fields of the tool output.
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
				sanitized[field] = p.sanitizer.Sanitize(s)
			}
		}
	}

	return PostToolUseOutput{
		ToolName:   output.ToolName,
		ToolOutput: sanitized,
	}
}
