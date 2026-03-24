package hooks

import (
	"testing"
)

// stubSanitizer is a test double for the Sanitizer interface.
type stubSanitizer struct {
	replacements map[string]string
}

func (s *stubSanitizer) Sanitize(input string) string {
	result := input
	for old, new := range s.replacements {
		result = replaceAll(result, old, new)
	}
	return result
}

// replaceAll replaces all occurrences of old with new in s.
func replaceAll(s, old, new string) string {
	if old == "" || old == new {
		return s
	}
	result := ""
	for {
		idx := indexStr(s, old)
		if idx < 0 {
			result += s
			break
		}
		result += s[:idx] + new
		s = s[idx+len(old):]
	}
	return result
}

func indexStr(s, sub string) int {
	if len(sub) > len(s) {
		return -1
	}
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func newProcessorWithReplacements(replacements map[string]string) *PostToolUseProcessor {
	return NewPostToolUseProcessor(&stubSanitizer{replacements: replacements})
}

func newPassthroughProcessor() *PostToolUseProcessor {
	return NewPostToolUseProcessor(&stubSanitizer{replacements: map[string]string{}})
}

// ---------------------------------------------------------------------------
// Basic output pass-through
// ---------------------------------------------------------------------------

func TestPostToolUse_PassesThroughCleanOutput(t *testing.T) {
	processor := newPassthroughProcessor()
	input := PostToolUseOutput{
		ToolName: "Bash",
		ToolOutput: map[string]interface{}{
			"stdout": "hello world\n",
			"stderr": "",
		},
	}
	result := processor.Process(input)
	if result.ToolOutput["stdout"] != "hello world\n" {
		t.Errorf("stdout changed unexpectedly: %v", result.ToolOutput["stdout"])
	}
}

// ---------------------------------------------------------------------------
// Sanitization of stdout
// ---------------------------------------------------------------------------

func TestPostToolUse_SanitizesCredentialInStdout(t *testing.T) {
	processor := newProcessorWithReplacements(map[string]string{
		"sk-test-1234567890abcdef": "[REDACTED:stripe-key]",
	})
	input := PostToolUseOutput{
		ToolName: "Bash",
		ToolOutput: map[string]interface{}{
			"stdout": "key=sk-test-1234567890abcdef\n",
			"stderr": "",
		},
	}
	result := processor.Process(input)
	stdout, ok := result.ToolOutput["stdout"].(string)
	if !ok {
		t.Fatal("stdout should be a string")
	}
	if stdout == "key=sk-test-1234567890abcdef\n" {
		t.Error("credential was not sanitized from stdout")
	}
	if !containsStr(stdout, "[REDACTED:stripe-key]") {
		t.Errorf("expected redaction marker in stdout, got: %q", stdout)
	}
}

// ---------------------------------------------------------------------------
// Sanitization of stderr
// ---------------------------------------------------------------------------

func TestPostToolUse_SanitizesCredentialInStderr(t *testing.T) {
	processor := newProcessorWithReplacements(map[string]string{
		"ghp_secrettoken123456789012345678901234": "[REDACTED:github-token]",
	})
	input := PostToolUseOutput{
		ToolName: "Bash",
		ToolOutput: map[string]interface{}{
			"stdout": "",
			"stderr": "error: token ghp_secrettoken123456789012345678901234 rejected",
		},
	}
	result := processor.Process(input)
	stderr, ok := result.ToolOutput["stderr"].(string)
	if !ok {
		t.Fatal("stderr should be a string")
	}
	if containsStr(stderr, "ghp_secrettoken123456789012345678901234") {
		t.Error("credential was not sanitized from stderr")
	}
}

// ---------------------------------------------------------------------------
// Missing fields
// ---------------------------------------------------------------------------

func TestPostToolUse_HandlesMissingStdout(t *testing.T) {
	processor := newPassthroughProcessor()
	input := PostToolUseOutput{
		ToolName:   "Bash",
		ToolOutput: map[string]interface{}{},
	}
	// Should not panic.
	result := processor.Process(input)
	if result.ToolOutput == nil {
		t.Error("ToolOutput should not be nil")
	}
}

func TestPostToolUse_HandlesNilToolOutput(t *testing.T) {
	processor := newPassthroughProcessor()
	input := PostToolUseOutput{
		ToolName:   "Bash",
		ToolOutput: nil,
	}
	// Should not panic.
	result := processor.Process(input)
	_ = result
}

// ---------------------------------------------------------------------------
// Preserves non-string fields
// ---------------------------------------------------------------------------

func TestPostToolUse_PreservesNonStringFields(t *testing.T) {
	processor := newPassthroughProcessor()
	input := PostToolUseOutput{
		ToolName: "Bash",
		ToolOutput: map[string]interface{}{
			"stdout":    "clean output\n",
			"exit_code": 0,
		},
	}
	result := processor.Process(input)
	code, ok := result.ToolOutput["exit_code"]
	if !ok {
		t.Error("exit_code field should be preserved")
	}
	if code != 0 {
		t.Errorf("exit_code should remain 0, got %v", code)
	}
}

// ---------------------------------------------------------------------------
// Tool name is preserved
// ---------------------------------------------------------------------------

func TestPostToolUse_PreservesToolName(t *testing.T) {
	processor := newPassthroughProcessor()
	input := PostToolUseOutput{
		ToolName: "Bash",
		ToolOutput: map[string]interface{}{
			"stdout": "output",
		},
	}
	result := processor.Process(input)
	if result.ToolName != "Bash" {
		t.Errorf("expected ToolName=Bash, got %q", result.ToolName)
	}
}
