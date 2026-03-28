package hooks

import (
	"testing"

	"github.com/straylight-ai/straylight/internal/services"
)

// stubServiceLister is a test double for ServiceLister.
type stubServiceLister struct {
	svcs []services.Service
}

func (s *stubServiceLister) List() []services.Service {
	return s.svcs
}

func newCheckerWithServices(svcs ...services.Service) *PreToolUseChecker {
	return NewPreToolUseChecker(&stubServiceLister{svcs: svcs})
}

func newEmptyChecker() *PreToolUseChecker {
	return NewPreToolUseChecker(&stubServiceLister{})
}

// ---------------------------------------------------------------------------
// Credential env var detection
// ---------------------------------------------------------------------------

func TestPreToolUse_BlocksStripeEnvVar(t *testing.T) {
	checker := newEmptyChecker()
	input := PreToolUseInput{
		ToolName: "Bash",
		ToolInput: map[string]interface{}{
			"command": "echo $STRIPE_API_KEY",
		},
	}
	allow, msg := checker.Check(input)
	if allow {
		t.Error("expected block, got allow")
	}
	if msg == "" {
		t.Error("expected non-empty block reason")
	}
}

func TestPreToolUse_BlocksGhTokenEnvVar(t *testing.T) {
	checker := newEmptyChecker()
	input := PreToolUseInput{
		ToolName: "Bash",
		ToolInput: map[string]interface{}{
			"command": "curl -H 'Authorization: Bearer $GH_TOKEN' https://api.github.com",
		},
	}
	allow, _ := checker.Check(input)
	if allow {
		t.Error("expected block for $GH_TOKEN reference")
	}
}

func TestPreToolUse_BlocksOpenAIEnvVar(t *testing.T) {
	checker := newEmptyChecker()
	input := PreToolUseInput{
		ToolName: "Bash",
		ToolInput: map[string]interface{}{
			"command": "export OPENAI_API_KEY=$OPENAI_API_KEY",
		},
	}
	allow, _ := checker.Check(input)
	if allow {
		t.Error("expected block for $OPENAI_API_KEY reference")
	}
}

func TestPreToolUse_AllowsCleanCommand(t *testing.T) {
	checker := newEmptyChecker()
	input := PreToolUseInput{
		ToolName: "Bash",
		ToolInput: map[string]interface{}{
			"command": "ls -la",
		},
	}
	allow, _ := checker.Check(input)
	if !allow {
		t.Error("expected allow for clean command")
	}
}

func TestPreToolUse_AllowsSafePipeline(t *testing.T) {
	checker := newEmptyChecker()
	input := PreToolUseInput{
		ToolName: "Bash",
		ToolInput: map[string]interface{}{
			"command": "find . -name '*.go' | head -10",
		},
	}
	allow, _ := checker.Check(input)
	if !allow {
		t.Error("expected allow for find/head pipeline")
	}
}

// ---------------------------------------------------------------------------
// Credential file detection
// ---------------------------------------------------------------------------

func TestPreToolUse_BlocksCatDotEnv(t *testing.T) {
	checker := newEmptyChecker()
	input := PreToolUseInput{
		ToolName: "Bash",
		ToolInput: map[string]interface{}{
			"command": "cat .env",
		},
	}
	allow, msg := checker.Check(input)
	if allow {
		t.Error("expected block for cat .env")
	}
	if msg == "" {
		t.Error("expected non-empty block reason")
	}
}

func TestPreToolUse_BlocksCatOpenBaoInitJSON(t *testing.T) {
	checker := newEmptyChecker()
	input := PreToolUseInput{
		ToolName: "Bash",
		ToolInput: map[string]interface{}{
			"command": "cat ~/.straylight-ai/data/openbao/init.json",
		},
	}
	allow, _ := checker.Check(input)
	if allow {
		t.Error("expected block for cat of openbao init.json via home path")
	}
}

func TestPreToolUse_BlocksCatAbsoluteOpenBaoPath(t *testing.T) {
	checker := newEmptyChecker()
	input := PreToolUseInput{
		ToolName: "Bash",
		ToolInput: map[string]interface{}{
			"command": "cat /data/openbao/init.json",
		},
	}
	allow, _ := checker.Check(input)
	if allow {
		t.Error("expected block for cat /data/openbao/init.json")
	}
}

// ---------------------------------------------------------------------------
// Suggestion text
// ---------------------------------------------------------------------------

func TestPreToolUse_BlockReasonSuggestsAlternative(t *testing.T) {
	checker := newEmptyChecker()
	input := PreToolUseInput{
		ToolName: "Bash",
		ToolInput: map[string]interface{}{
			"command": "echo $STRIPE_API_KEY",
		},
	}
	_, msg := checker.Check(input)
	if msg == "" {
		t.Fatal("expected non-empty message")
	}
	// The message should mention the recommended alternative tools.
	found := false
	for _, substr := range []string{"straylight_api_call", "straylight_exec"} {
		if contains(msg, substr) {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("block reason should suggest straylight_api_call or straylight_exec, got: %q", msg)
	}
}

// ---------------------------------------------------------------------------
// Non-Bash tool: Write/Edit with env var in file content
// ---------------------------------------------------------------------------

func TestPreToolUse_BlocksWriteToolWithEnvVar(t *testing.T) {
	checker := newEmptyChecker()
	input := PreToolUseInput{
		ToolName: "Write",
		ToolInput: map[string]interface{}{
			"content": "STRIPE_API_KEY=$STRIPE_API_KEY\nOPENAI_API_KEY=$OPENAI_API_KEY",
		},
	}
	allow, _ := checker.Check(input)
	if allow {
		t.Error("expected block for Write tool with credential env var reference")
	}
}

func TestPreToolUse_AllowsWriteWithNoCredentials(t *testing.T) {
	checker := newEmptyChecker()
	input := PreToolUseInput{
		ToolName: "Write",
		ToolInput: map[string]interface{}{
			"content": "Hello, world!",
		},
	}
	allow, _ := checker.Check(input)
	if !allow {
		t.Error("expected allow for Write tool with safe content")
	}
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

func TestPreToolUse_EmptyCommand(t *testing.T) {
	checker := newEmptyChecker()
	input := PreToolUseInput{
		ToolName:  "Bash",
		ToolInput: map[string]interface{}{},
	}
	allow, _ := checker.Check(input)
	if !allow {
		t.Error("expected allow for empty command")
	}
}

func TestPreToolUse_NilToolInput(t *testing.T) {
	checker := newEmptyChecker()
	input := PreToolUseInput{
		ToolName:  "Bash",
		ToolInput: nil,
	}
	allow, _ := checker.Check(input)
	if !allow {
		t.Error("expected allow for nil tool input")
	}
}

// ---------------------------------------------------------------------------
// Service-derived credential env vars
// ---------------------------------------------------------------------------

func TestPreToolUse_BlocksServiceDerivedEnvVar(t *testing.T) {
	svc := services.Service{
		Name:    "my-service",
		Type:    "http_proxy",
		Target:  "https://api.example.com",
		Inject:  "header",
		Status:  "available",
	}
	checker := newCheckerWithServices(svc)
	// Service name "my-service" => "MY_SERVICE"; checker should block $MY_SERVICE_API_KEY.
	input := PreToolUseInput{
		ToolName: "Bash",
		ToolInput: map[string]interface{}{
			"command": "echo $MY_SERVICE_API_KEY",
		},
	}
	allow, _ := checker.Check(input)
	if allow {
		t.Error("expected block for service-derived env var $MY_SERVICE_API_KEY")
	}
}

func TestPreToolUse_AllowsNonCredentialWhenServicesRegistered(t *testing.T) {
	svc := services.Service{
		Name:   "my-service",
		Type:   "http_proxy",
		Target: "https://api.example.com",
		Inject: "header",
		Status: "available",
	}
	checker := newCheckerWithServices(svc)
	input := PreToolUseInput{
		ToolName: "Bash",
		ToolInput: map[string]interface{}{
			"command": "go build ./...",
		},
	}
	allow, _ := checker.Check(input)
	if !allow {
		t.Error("expected allow for safe command with registered services")
	}
}

// ---------------------------------------------------------------------------
// Enhanced sensitive file patterns (Phase 1c additions)
// ---------------------------------------------------------------------------

func TestPreToolUse_BlocksCatPemFile(t *testing.T) {
	checker := newEmptyChecker()
	input := PreToolUseInput{
		ToolName: "Bash",
		ToolInput: map[string]interface{}{
			"command": "cat server.pem",
		},
	}
	allow, msg := checker.Check(input)
	if allow {
		t.Error("expected block for cat server.pem")
	}
	if msg == "" {
		t.Error("expected non-empty block reason")
	}
}

func TestPreToolUse_BlocksCatKeyFile(t *testing.T) {
	checker := newEmptyChecker()
	input := PreToolUseInput{
		ToolName: "Bash",
		ToolInput: map[string]interface{}{
			"command": "cat private.key",
		},
	}
	allow, _ := checker.Check(input)
	if allow {
		t.Error("expected block for cat private.key")
	}
}

func TestPreToolUse_BlocksCatIdRsa(t *testing.T) {
	checker := newEmptyChecker()
	input := PreToolUseInput{
		ToolName: "Bash",
		ToolInput: map[string]interface{}{
			"command": "cat ~/.ssh/id_rsa",
		},
	}
	allow, _ := checker.Check(input)
	if allow {
		t.Error("expected block for cat id_rsa")
	}
}

func TestPreToolUse_BlocksCatIdEd25519(t *testing.T) {
	checker := newEmptyChecker()
	input := PreToolUseInput{
		ToolName: "Bash",
		ToolInput: map[string]interface{}{
			"command": "cat ~/.ssh/id_ed25519",
		},
	}
	allow, _ := checker.Check(input)
	if allow {
		t.Error("expected block for cat id_ed25519")
	}
}

func TestPreToolUse_BlocksCatCredentialsJSON(t *testing.T) {
	checker := newEmptyChecker()
	input := PreToolUseInput{
		ToolName: "Bash",
		ToolInput: map[string]interface{}{
			"command": "cat credentials.json",
		},
	}
	allow, _ := checker.Check(input)
	if allow {
		t.Error("expected block for cat credentials.json")
	}
}

func TestPreToolUse_BlocksCatServiceAccountKey(t *testing.T) {
	checker := newEmptyChecker()
	input := PreToolUseInput{
		ToolName: "Bash",
		ToolInput: map[string]interface{}{
			"command": "cat serviceAccountKey.json",
		},
	}
	allow, _ := checker.Check(input)
	if allow {
		t.Error("expected block for cat serviceAccountKey.json")
	}
}

func TestPreToolUse_BlocksCatAWSCredentials(t *testing.T) {
	checker := newEmptyChecker()
	input := PreToolUseInput{
		ToolName: "Bash",
		ToolInput: map[string]interface{}{
			"command": "cat ~/.aws/credentials",
		},
	}
	allow, _ := checker.Check(input)
	if allow {
		t.Error("expected block for cat ~/.aws/credentials")
	}
}

func TestPreToolUse_BlocksReadOfSSHPrivateKey(t *testing.T) {
	checker := newEmptyChecker()
	input := PreToolUseInput{
		ToolName: "Read",
		ToolInput: map[string]interface{}{
			"file_path": "/home/user/.ssh/id_rsa",
		},
	}
	allow, _ := checker.Check(input)
	if allow {
		t.Error("expected block for Read of id_rsa")
	}
}

func TestPreToolUse_EnhancedBlockReasonSuggestsStraylightReadFile(t *testing.T) {
	checker := newEmptyChecker()
	input := PreToolUseInput{
		ToolName: "Bash",
		ToolInput: map[string]interface{}{
			"command": "cat server.pem",
		},
	}
	_, msg := checker.Check(input)
	if msg == "" {
		t.Fatal("expected non-empty message")
	}
	if !contains(msg, "straylight_read_file") {
		t.Errorf("block reason for sensitive file should suggest straylight_read_file, got: %q", msg)
	}
}

func TestPreToolUse_DotEnvBlockReasonSuggestsStraylightReadFile(t *testing.T) {
	checker := newEmptyChecker()
	input := PreToolUseInput{
		ToolName: "Bash",
		ToolInput: map[string]interface{}{
			"command": "cat .env",
		},
	}
	_, msg := checker.Check(input)
	if !contains(msg, "straylight_read_file") {
		t.Errorf("block reason for .env should suggest straylight_read_file, got: %q", msg)
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsStr(s, substr))
}

func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
