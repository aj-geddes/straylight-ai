package hooks

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// RunPreToolUse — happy path
// ---------------------------------------------------------------------------

func TestRunPreToolUse_AllowsCleanBashCommand(t *testing.T) {
	input := `{"tool_name":"Bash","tool_input":{"command":"ls -la"}}`
	stdin := strings.NewReader(input)
	var stdout bytes.Buffer

	code := RunPreToolUse(stdin, &stdout, &stubServiceLister{})
	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(stdout.Bytes(), &resp); err != nil {
		t.Fatalf("response is not valid JSON: %v (body: %q)", err, stdout.String())
	}
	if resp["decision"] != "allow" {
		t.Errorf("expected decision=allow, got %v", resp["decision"])
	}
}

func TestRunPreToolUse_BlocksCredentialEnvVar(t *testing.T) {
	input := `{"tool_name":"Bash","tool_input":{"command":"echo $STRIPE_API_KEY"}}`
	stdin := strings.NewReader(input)
	var stdout bytes.Buffer

	code := RunPreToolUse(stdin, &stdout, &stubServiceLister{})
	if code != 2 {
		t.Errorf("expected exit code 2, got %d", code)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(stdout.Bytes(), &resp); err != nil {
		t.Fatalf("response is not valid JSON: %v (body: %q)", err, stdout.String())
	}
	if resp["decision"] != "block" {
		t.Errorf("expected decision=block, got %v", resp["decision"])
	}
	if resp["reason"] == "" || resp["reason"] == nil {
		t.Error("expected non-empty reason field")
	}
}

func TestRunPreToolUse_BlocksCatDotEnv(t *testing.T) {
	input := `{"tool_name":"Bash","tool_input":{"command":"cat .env"}}`
	stdin := strings.NewReader(input)
	var stdout bytes.Buffer

	code := RunPreToolUse(stdin, &stdout, &stubServiceLister{})
	if code != 2 {
		t.Errorf("expected exit code 2, got %d", code)
	}
}

func TestRunPreToolUse_BlocksCatOpenBaoPath(t *testing.T) {
	input := `{"tool_name":"Bash","tool_input":{"command":"cat /data/openbao/init.json"}}`
	stdin := strings.NewReader(input)
	var stdout bytes.Buffer

	code := RunPreToolUse(stdin, &stdout, &stubServiceLister{})
	if code != 2 {
		t.Errorf("expected exit code 2, got %d", code)
	}
}

// ---------------------------------------------------------------------------
// RunPreToolUse — malformed input
// ---------------------------------------------------------------------------

func TestRunPreToolUse_InvalidJSONReturnsError(t *testing.T) {
	stdin := strings.NewReader(`not json`)
	var stdout bytes.Buffer

	code := RunPreToolUse(stdin, &stdout, &stubServiceLister{})
	// Should return an error code (non-zero, but not 2) or handle gracefully.
	// Per spec, invalid input should not cause a panic and should return code 1.
	if code == 2 {
		t.Error("malformed JSON should not produce exit code 2 (block)")
	}
}

// ---------------------------------------------------------------------------
// RunPostToolUse — happy path
// ---------------------------------------------------------------------------

func TestRunPostToolUse_PassesThroughCleanOutput(t *testing.T) {
	input := `{"tool_name":"Bash","tool_output":{"stdout":"hello world\n","stderr":""}}`
	stdin := strings.NewReader(input)
	var stdout bytes.Buffer

	code := RunPostToolUse(stdin, &stdout, &stubSanitizer{replacements: map[string]string{}})
	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(stdout.Bytes(), &resp); err != nil {
		t.Fatalf("response is not valid JSON: %v (body: %q)", err, stdout.String())
	}
	toolOutput, ok := resp["tool_output"].(map[string]interface{})
	if !ok {
		t.Fatal("expected tool_output to be an object")
	}
	if toolOutput["stdout"] != "hello world\n" {
		t.Errorf("stdout changed unexpectedly: %v", toolOutput["stdout"])
	}
}

func TestRunPostToolUse_SanitizesCredentialInOutput(t *testing.T) {
	input := `{"tool_name":"Bash","tool_output":{"stdout":"key=sk-test-1234567890abcdef\n","stderr":""}}`
	stdin := strings.NewReader(input)
	var stdout bytes.Buffer

	sanitizer := &stubSanitizer{
		replacements: map[string]string{
			"sk-test-1234567890abcdef": "[REDACTED:stripe-key]",
		},
	}

	code := RunPostToolUse(stdin, &stdout, sanitizer)
	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(stdout.Bytes(), &resp); err != nil {
		t.Fatalf("response is not valid JSON: %v (body: %q)", err, stdout.String())
	}
	toolOutput, ok := resp["tool_output"].(map[string]interface{})
	if !ok {
		t.Fatal("expected tool_output to be an object")
	}
	outStdout := toolOutput["stdout"].(string)
	if containsStr(outStdout, "sk-test-1234567890abcdef") {
		t.Error("credential should have been sanitized from stdout")
	}
}

// ---------------------------------------------------------------------------
// RunPostToolUse — malformed input
// ---------------------------------------------------------------------------

func TestRunPostToolUse_InvalidJSONReturnsError(t *testing.T) {
	stdin := strings.NewReader(`{bad json}`)
	var stdout bytes.Buffer

	code := RunPostToolUse(stdin, &stdout, &stubSanitizer{replacements: map[string]string{}})
	if code == 0 {
		t.Error("invalid JSON should not return exit code 0")
	}
}

// ---------------------------------------------------------------------------
// Latency benchmark: hooks must add < 50ms per invocation
// ---------------------------------------------------------------------------

func BenchmarkRunPreToolUse(b *testing.B) {
	input := `{"tool_name":"Bash","tool_input":{"command":"ls -la"}}`
	lister := &stubServiceLister{}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		stdin := strings.NewReader(input)
		var stdout bytes.Buffer
		RunPreToolUse(stdin, &stdout, lister)
	}
}

func BenchmarkRunPostToolUse(b *testing.B) {
	input := `{"tool_name":"Bash","tool_output":{"stdout":"hello world\n","stderr":""}}`
	sanitizer := &stubSanitizer{replacements: map[string]string{}}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		stdin := strings.NewReader(input)
		var stdout bytes.Buffer
		RunPostToolUse(stdin, &stdout, sanitizer)
	}
}

// TestHookLatencyUnder50ms verifies hook invocations complete within 50ms.
func TestHookLatencyUnder50ms(t *testing.T) {
	const maxLatency = 50 * time.Millisecond
	const iterations = 100

	input := `{"tool_name":"Bash","tool_input":{"command":"ls -la"}}`
	lister := &stubServiceLister{}

	start := time.Now()
	for i := 0; i < iterations; i++ {
		stdin := strings.NewReader(input)
		var stdout bytes.Buffer
		RunPreToolUse(stdin, &stdout, lister)
	}
	elapsed := time.Since(start)
	avg := elapsed / iterations

	if avg > maxLatency {
		t.Errorf("average hook latency %v exceeds 50ms threshold", avg)
	}
}
