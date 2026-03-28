// Package firewall provides redacted file reading and sensitive file detection
// for the Straylight Sensitive File Firewall (ADR-013).
package firewall_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/straylight-ai/straylight/internal/firewall"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newDefaultFirewall(t *testing.T) *firewall.Firewall {
	t.Helper()
	return firewall.NewFirewall(firewall.DefaultConfig())
}

func writeTestFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("write test file %s: %v", path, err)
	}
	return path
}

// ---------------------------------------------------------------------------
// IsBlockedFile — exact name matches
// ---------------------------------------------------------------------------

func TestIsBlockedFile_DotEnvBlocked(t *testing.T) {
	fw := newDefaultFirewall(t)
	if !fw.IsBlockedFile(".env") {
		t.Error("expected .env to be blocked")
	}
}

func TestIsBlockedFile_DotEnvLocalBlocked(t *testing.T) {
	fw := newDefaultFirewall(t)
	if !fw.IsBlockedFile(".env.local") {
		t.Error("expected .env.local to be blocked")
	}
}

func TestIsBlockedFile_DotEnvProductionBlocked(t *testing.T) {
	fw := newDefaultFirewall(t)
	if !fw.IsBlockedFile(".env.production") {
		t.Error("expected .env.production to be blocked")
	}
}

func TestIsBlockedFile_DotEnvStagingBlocked(t *testing.T) {
	fw := newDefaultFirewall(t)
	if !fw.IsBlockedFile(".env.staging") {
		t.Error("expected .env.staging to be blocked")
	}
}

func TestIsBlockedFile_PemFileBlocked(t *testing.T) {
	fw := newDefaultFirewall(t)
	if !fw.IsBlockedFile("server.pem") {
		t.Error("expected server.pem to be blocked")
	}
}

func TestIsBlockedFile_KeyFileBlocked(t *testing.T) {
	fw := newDefaultFirewall(t)
	if !fw.IsBlockedFile("private.key") {
		t.Error("expected private.key to be blocked")
	}
}

func TestIsBlockedFile_IdRsaBlocked(t *testing.T) {
	fw := newDefaultFirewall(t)
	if !fw.IsBlockedFile("id_rsa") {
		t.Error("expected id_rsa to be blocked")
	}
}

func TestIsBlockedFile_IdRsaPubNotBlocked(t *testing.T) {
	// id_rsa.pub is the public key — should not be blocked
	fw := newDefaultFirewall(t)
	if fw.IsBlockedFile("id_rsa.pub") {
		t.Error("expected id_rsa.pub to be allowed (public key)")
	}
}

func TestIsBlockedFile_IdEd25519Blocked(t *testing.T) {
	fw := newDefaultFirewall(t)
	if !fw.IsBlockedFile("id_ed25519") {
		t.Error("expected id_ed25519 to be blocked")
	}
}

func TestIsBlockedFile_CredentialsJSONBlocked(t *testing.T) {
	fw := newDefaultFirewall(t)
	if !fw.IsBlockedFile("credentials.json") {
		t.Error("expected credentials.json to be blocked")
	}
}

func TestIsBlockedFile_ServiceAccountKeyBlocked(t *testing.T) {
	fw := newDefaultFirewall(t)
	if !fw.IsBlockedFile("serviceAccountKey.json") {
		t.Error("expected serviceAccountKey.json to be blocked")
	}
}

func TestIsBlockedFile_InitJSONBlocked(t *testing.T) {
	fw := newDefaultFirewall(t)
	if !fw.IsBlockedFile("init.json") {
		t.Error("expected init.json to be blocked")
	}
}

func TestIsBlockedFile_SafeFileNotBlocked(t *testing.T) {
	fw := newDefaultFirewall(t)
	safe := []string{"main.go", "config.yaml", "README.md", "package.json", "index.html"}
	for _, name := range safe {
		if fw.IsBlockedFile(name) {
			t.Errorf("expected %q to be allowed", name)
		}
	}
}

func TestIsBlockedFile_WithFullPath(t *testing.T) {
	fw := newDefaultFirewall(t)
	if !fw.IsBlockedFile("/home/user/project/.env") {
		t.Error("expected full path to .env to be blocked")
	}
}

// ---------------------------------------------------------------------------
// ReadFileRedacted — blocked files return helpful error
// ---------------------------------------------------------------------------

func TestReadFileRedacted_BlockedFileReturnsError(t *testing.T) {
	tmpDir := t.TempDir()
	fw := firewall.NewFirewall(firewall.FirewallConfig{
		ProjectRoot: tmpDir,
	})

	path := writeTestFile(t, tmpDir, ".env", "SECRET=my-secret-value")

	_, err := fw.ReadFileRedacted(path)
	if err == nil {
		t.Fatal("expected error for blocked file, got nil")
	}
	if !strings.Contains(err.Error(), "blocked") {
		t.Errorf("error should mention 'blocked', got: %q", err.Error())
	}
	if !strings.Contains(err.Error(), "straylight_read_file") || !strings.Contains(err.Error(), "vault") {
		t.Errorf("error should suggest using Straylight vault, got: %q", err.Error())
	}
}

// ---------------------------------------------------------------------------
// ReadFileRedacted — .env-style KEY=VALUE redaction
// ---------------------------------------------------------------------------

func TestReadFileRedacted_EnvStyleValuesRedacted(t *testing.T) {
	tmpDir := t.TempDir()
	fw := firewall.NewFirewall(firewall.FirewallConfig{
		ProjectRoot: tmpDir,
	})

	content := "DATABASE_URL=postgres://user:password@localhost/mydb\nAPP_NAME=myapp\n"
	path := writeTestFile(t, tmpDir, "app.env", content)

	result, err := fw.ReadFileRedacted(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if strings.Contains(result.Content, "password") {
		t.Error("password should be redacted from connection string")
	}
	if !strings.Contains(result.Content, "APP_NAME=myapp") {
		t.Error("non-secret APP_NAME value should be preserved")
	}
	if result.Redactions == 0 {
		t.Error("expected at least one redaction")
	}
}

func TestReadFileRedacted_EnvFileKeyValueRedacted(t *testing.T) {
	tmpDir := t.TempDir()
	fw := firewall.NewFirewall(firewall.FirewallConfig{
		ProjectRoot: tmpDir,
	})

	// Write a plain .ini-style env file (not in blocked patterns by file name)
	content := "STRIPE_KEY=sk_live_abcdefghijklmnopqrstuvwx\nDEBUG=true\n"
	path := writeTestFile(t, tmpDir, "secrets.env", content)

	result, err := fw.ReadFileRedacted(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if strings.Contains(result.Content, "sk_live_") {
		t.Error("stripe key should be redacted")
	}
	if !strings.Contains(result.Content, "DEBUG=true") {
		t.Error("DEBUG=true should be preserved")
	}
}

// ---------------------------------------------------------------------------
// ReadFileRedacted — YAML structured key redaction
// ---------------------------------------------------------------------------

func TestReadFileRedacted_YAMLPasswordKeyRedacted(t *testing.T) {
	tmpDir := t.TempDir()
	fw := firewall.NewFirewall(firewall.FirewallConfig{
		ProjectRoot: tmpDir,
	})

	content := "database:\n  host: db.example.com\n  port: 5432\n  password: supersecret123\n"
	path := writeTestFile(t, tmpDir, "config.yaml", content)

	result, err := fw.ReadFileRedacted(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if strings.Contains(result.Content, "supersecret123") {
		t.Error("password value should be redacted")
	}
	if !strings.Contains(result.Content, "host: db.example.com") {
		t.Error("non-secret host value should be preserved")
	}
	if !strings.Contains(result.Content, "port: 5432") {
		t.Error("non-secret port value should be preserved")
	}
	if result.Redactions == 0 {
		t.Error("expected at least one redaction")
	}
}

func TestReadFileRedacted_YAMLTokenKeyRedacted(t *testing.T) {
	tmpDir := t.TempDir()
	fw := firewall.NewFirewall(firewall.FirewallConfig{
		ProjectRoot: tmpDir,
	})

	content := "github:\n  token: ghp_1234567890abcdefghij1234567890abcdef\n  owner: myorg\n"
	path := writeTestFile(t, tmpDir, "config.yml", content)

	result, err := fw.ReadFileRedacted(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if strings.Contains(result.Content, "ghp_") {
		t.Error("github token should be redacted")
	}
	if !strings.Contains(result.Content, "owner: myorg") {
		t.Error("owner value should be preserved")
	}
}

func TestReadFileRedacted_YAMLStructurePreserved(t *testing.T) {
	tmpDir := t.TempDir()
	fw := firewall.NewFirewall(firewall.FirewallConfig{
		ProjectRoot: tmpDir,
	})

	content := "database:\n  host: db.example.com\n  password: topsecret\napp:\n  name: myapp\n  debug: false\n"
	path := writeTestFile(t, tmpDir, "config.yaml", content)

	result, err := fw.ReadFileRedacted(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(result.Content, "database:") {
		t.Error("yaml structure key 'database:' should be preserved")
	}
	if !strings.Contains(result.Content, "host: db.example.com") {
		t.Error("yaml host value should be preserved")
	}
	if !strings.Contains(result.Content, "app:") {
		t.Error("yaml structure key 'app:' should be preserved")
	}
	if !strings.Contains(result.Content, "name: myapp") {
		t.Error("yaml name value should be preserved")
	}
}

// ---------------------------------------------------------------------------
// ReadFileRedacted — JSON config redaction
// ---------------------------------------------------------------------------

func TestReadFileRedacted_JSONSecretKeyRedacted(t *testing.T) {
	tmpDir := t.TempDir()
	fw := firewall.NewFirewall(firewall.FirewallConfig{
		ProjectRoot: tmpDir,
	})

	content := `{"database": {"host": "db.example.com", "password": "dbpassword123", "port": 5432}}`
	path := writeTestFile(t, tmpDir, "config.json", content)

	result, err := fw.ReadFileRedacted(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if strings.Contains(result.Content, "dbpassword123") {
		t.Error("JSON password value should be redacted")
	}
	if !strings.Contains(result.Content, "db.example.com") {
		t.Error("JSON host value should be preserved")
	}
}

func TestReadFileRedacted_JSONAPIKeyRedacted(t *testing.T) {
	tmpDir := t.TempDir()
	fw := firewall.NewFirewall(firewall.FirewallConfig{
		ProjectRoot: tmpDir,
	})

	content := `{"service": "stripe", "api_key": "sk_live_xxxxxxxxxxxxxxxxxxxxxxxxxxx", "mode": "production"}`
	path := writeTestFile(t, tmpDir, "settings.json", content)

	result, err := fw.ReadFileRedacted(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if strings.Contains(result.Content, "sk_live_") {
		t.Error("api_key value should be redacted")
	}
	if !strings.Contains(result.Content, "production") {
		t.Error("mode value should be preserved")
	}
}

// ---------------------------------------------------------------------------
// ReadFileRedacted — non-sensitive files pass through unchanged
// ---------------------------------------------------------------------------

func TestReadFileRedacted_SafeFilePassesThrough(t *testing.T) {
	tmpDir := t.TempDir()
	fw := firewall.NewFirewall(firewall.FirewallConfig{
		ProjectRoot: tmpDir,
	})

	content := "package main\n\nfunc main() {\n\tprintln(\"hello world\")\n}\n"
	path := writeTestFile(t, tmpDir, "main.go", content)

	result, err := fw.ReadFileRedacted(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Content != content {
		t.Errorf("safe file content should be unchanged\nwant: %q\ngot:  %q", content, result.Content)
	}
	if result.Redactions != 0 {
		t.Errorf("expected 0 redactions for safe file, got %d", result.Redactions)
	}
}

func TestReadFileRedacted_MarkdownPassesThrough(t *testing.T) {
	tmpDir := t.TempDir()
	fw := firewall.NewFirewall(firewall.FirewallConfig{
		ProjectRoot: tmpDir,
	})

	content := "# My Project\n\nThis is a README.\n"
	path := writeTestFile(t, tmpDir, "README.md", content)

	result, err := fw.ReadFileRedacted(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Content != content {
		t.Error("markdown should pass through unchanged")
	}
}

// ---------------------------------------------------------------------------
// ReadFileRedacted — connection string redaction in output
// ---------------------------------------------------------------------------

func TestReadFileRedacted_ConnectionStringInYAMLRedacted(t *testing.T) {
	tmpDir := t.TempDir()
	fw := firewall.NewFirewall(firewall.FirewallConfig{
		ProjectRoot: tmpDir,
	})

	content := "db:\n  url: postgresql://myuser:mysecretpassword@localhost:5432/mydb\n  name: mydb\n"
	path := writeTestFile(t, tmpDir, "database.yaml", content)

	result, err := fw.ReadFileRedacted(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if strings.Contains(result.Content, "mysecretpassword") {
		t.Error("password in connection string should be redacted")
	}
	if result.Redactions == 0 {
		t.Error("expected at least one redaction for connection string")
	}
}

// ---------------------------------------------------------------------------
// ReadFileRedacted — Redaction struct fields
// ---------------------------------------------------------------------------

func TestReadFileRedacted_RedactionIncludesPatternLabel(t *testing.T) {
	tmpDir := t.TempDir()
	fw := firewall.NewFirewall(firewall.FirewallConfig{
		ProjectRoot: tmpDir,
	})

	content := "token: ghp_1234567890abcdefghij1234567890abcdef\n"
	path := writeTestFile(t, tmpDir, "config.yaml", content)

	result, err := fw.ReadFileRedacted(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.RedactedPatterns) == 0 {
		t.Error("expected redacted patterns list to be non-empty")
	}
}

func TestReadFileRedacted_RedactionCountMatchesActual(t *testing.T) {
	tmpDir := t.TempDir()
	fw := firewall.NewFirewall(firewall.FirewallConfig{
		ProjectRoot: tmpDir,
	})

	// Two distinct secret patterns
	content := "password: secretvalue\ntoken: ghp_1234567890abcdefghij1234567890abcdef\n"
	path := writeTestFile(t, tmpDir, "config.yaml", content)

	result, err := fw.ReadFileRedacted(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Redactions < 2 {
		t.Errorf("expected at least 2 redactions, got %d", result.Redactions)
	}
}

// ---------------------------------------------------------------------------
// Path traversal prevention
// ---------------------------------------------------------------------------

func TestReadFileRedacted_PathTraversalRejected(t *testing.T) {
	tmpDir := t.TempDir()
	fw := firewall.NewFirewall(firewall.FirewallConfig{
		ProjectRoot: tmpDir,
	})

	traversalPaths := []string{
		"../../etc/passwd",
		tmpDir + "/../../etc/passwd",
		tmpDir + "/../secret.txt",
	}

	for _, p := range traversalPaths {
		_, err := fw.ReadFileRedacted(p)
		if err == nil {
			t.Errorf("expected path traversal rejection for %q, got nil error", p)
			continue
		}
		if !strings.Contains(err.Error(), "outside") && !strings.Contains(err.Error(), "traversal") && !strings.Contains(err.Error(), "denied") {
			t.Errorf("path traversal error should mention 'outside', 'traversal', or 'denied', got: %q", err.Error())
		}
	}
}

func TestReadFileRedacted_AbsolutePathOutsideRootRejected(t *testing.T) {
	tmpDir := t.TempDir()
	fw := firewall.NewFirewall(firewall.FirewallConfig{
		ProjectRoot: tmpDir,
	})

	// /etc/passwd is outside tmpDir
	_, err := fw.ReadFileRedacted("/etc/passwd")
	if err == nil {
		t.Error("expected error for /etc/passwd outside project root")
	}
}

func TestReadFileRedacted_PathInsideRootAllowed(t *testing.T) {
	tmpDir := t.TempDir()
	fw := firewall.NewFirewall(firewall.FirewallConfig{
		ProjectRoot: tmpDir,
	})

	path := writeTestFile(t, tmpDir, "safe.go", "package main\n")

	_, err := fw.ReadFileRedacted(path)
	if err != nil {
		t.Errorf("expected no error for file inside project root, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Symlink resolution
// ---------------------------------------------------------------------------

func TestReadFileRedacted_SymlinkOutsideRootRejected(t *testing.T) {
	tmpDir := t.TempDir()
	fw := firewall.NewFirewall(firewall.FirewallConfig{
		ProjectRoot: tmpDir,
	})

	// Create a symlink inside tmpDir pointing outside
	linkPath := filepath.Join(tmpDir, "escape.txt")
	// Point to /etc/hosts (which is outside tmpDir)
	if err := os.Symlink("/etc/hosts", linkPath); err != nil {
		t.Skipf("cannot create symlink (may need elevated permissions): %v", err)
	}

	_, err := fw.ReadFileRedacted(linkPath)
	if err == nil {
		t.Error("expected error for symlink pointing outside project root")
	}
}

// ---------------------------------------------------------------------------
// File size limit
// ---------------------------------------------------------------------------

func TestReadFileRedacted_FileSizeLimitEnforcedWithWarning(t *testing.T) {
	tmpDir := t.TempDir()
	fw := firewall.NewFirewall(firewall.FirewallConfig{
		ProjectRoot: tmpDir,
		MaxFileSize: 10, // 10 bytes
	})

	content := "This content is longer than ten bytes."
	path := writeTestFile(t, tmpDir, "large.txt", content)

	result, err := fw.ReadFileRedacted(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Warning == "" {
		t.Error("expected a warning for oversized file")
	}
	if !strings.Contains(result.Warning, "truncated") && !strings.Contains(result.Warning, "size") {
		t.Errorf("warning should mention truncation or size, got: %q", result.Warning)
	}
}

// ---------------------------------------------------------------------------
// FileSize in result
// ---------------------------------------------------------------------------

func TestReadFileRedacted_FileSizePopulated(t *testing.T) {
	tmpDir := t.TempDir()
	fw := firewall.NewFirewall(firewall.FirewallConfig{
		ProjectRoot: tmpDir,
	})

	content := "hello world\n"
	path := writeTestFile(t, tmpDir, "hello.txt", content)

	result, err := fw.ReadFileRedacted(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.FileSize != int64(len(content)) {
		t.Errorf("expected FileSize=%d, got %d", len(content), result.FileSize)
	}
}

// ---------------------------------------------------------------------------
// Default config values
// ---------------------------------------------------------------------------

func TestDefaultConfig_HasBlockedPatterns(t *testing.T) {
	cfg := firewall.DefaultConfig()
	if len(cfg.BlockedPatterns) == 0 {
		t.Error("default config should have blocked patterns")
	}
}

func TestDefaultConfig_HasStructuredKeys(t *testing.T) {
	cfg := firewall.DefaultConfig()
	if len(cfg.StructuredKeyPatterns) == 0 {
		t.Error("default config should have structured key patterns")
	}
}

func TestDefaultConfig_HasMaxFileSize(t *testing.T) {
	cfg := firewall.DefaultConfig()
	if cfg.MaxFileSize <= 0 {
		t.Error("default config MaxFileSize should be positive")
	}
}

// ---------------------------------------------------------------------------
// TOML redaction
// ---------------------------------------------------------------------------

func TestReadFileRedacted_TOMLPasswordRedacted(t *testing.T) {
	tmpDir := t.TempDir()
	fw := firewall.NewFirewall(firewall.FirewallConfig{
		ProjectRoot: tmpDir,
	})

	content := "[database]\nhost = \"localhost\"\npassword = \"tomlsecret\"\nport = 5432\n"
	path := writeTestFile(t, tmpDir, "config.toml", content)

	result, err := fw.ReadFileRedacted(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if strings.Contains(result.Content, "tomlsecret") {
		t.Error("TOML password should be redacted")
	}
	if !strings.Contains(result.Content, "host") {
		t.Error("TOML host key should be preserved")
	}
}
