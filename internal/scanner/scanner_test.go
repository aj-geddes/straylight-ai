// Package scanner_test exercises the project secret scanner.
//
// Tests follow the TDD protocol: written before implementation, using temp
// directories and fixture files so no real secrets appear in this repository.
package scanner_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/straylight-ai/straylight/internal/scanner"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// tmpDir creates a temporary directory and returns its path along with a
// cleanup function.  Files are created via writeFile.
func tmpDir(t *testing.T) (string, func()) {
	t.Helper()
	dir, err := os.MkdirTemp("", "scanner-test-*")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	return dir, func() { os.RemoveAll(dir) }
}

// writeFile writes content to path (relative to base), creating intermediate
// directories as needed.
func writeFile(t *testing.T, base, rel, content string) {
	t.Helper()
	full := filepath.Join(base, rel)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(full), err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", full, err)
	}
}

// writeBinaryFile writes a file whose first bytes contain a NULL byte.
func writeBinaryFile(t *testing.T, base, rel string) {
	t.Helper()
	content := []byte{0x00, 0x01, 0x02, 0x03, 0x04}
	full := filepath.Join(base, rel)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(full), err)
	}
	if err := os.WriteFile(full, content, 0o644); err != nil {
		t.Fatalf("write binary file %s: %v", full, err)
	}
}

// findingsByFile returns all findings for a given relative file path.
func findingsByFile(findings []scanner.Finding, rel string) []scanner.Finding {
	var out []scanner.Finding
	for _, f := range findings {
		if strings.HasSuffix(filepath.ToSlash(f.File), rel) {
			out = append(out, f)
		}
	}
	return out
}

// hasFindingWithPattern returns true if any finding matches the given pattern label.
func hasFindingWithPattern(findings []scanner.Finding, pattern string) bool {
	for _, f := range findings {
		if f.Pattern == pattern {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Scanner construction
// ---------------------------------------------------------------------------

func TestNewScanner_ReturnsNonNilScanner(t *testing.T) {
	s := scanner.New()
	if s == nil {
		t.Fatal("New() returned nil")
	}
}

// ---------------------------------------------------------------------------
// ScanFile: basic pattern detection
// ---------------------------------------------------------------------------

func TestScanFile_DetectsAWSAccessKey(t *testing.T) {
	dir, cleanup := tmpDir(t)
	defer cleanup()

	writeFile(t, dir, "config.env", "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE123\n")

	s := scanner.New()
	findings, err := s.ScanFile(filepath.Join(dir, "config.env"))
	if err != nil {
		t.Fatalf("ScanFile: %v", err)
	}
	if !hasFindingWithPattern(findings, "aws-access-key") {
		t.Errorf("expected aws-access-key finding, got: %v", findings)
	}
}

func TestScanFile_DetectsGitHubToken(t *testing.T) {
	dir, cleanup := tmpDir(t)
	defer cleanup()

	writeFile(t, dir, "config.yaml", "github_token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890\n")

	s := scanner.New()
	findings, err := s.ScanFile(filepath.Join(dir, "config.yaml"))
	if err != nil {
		t.Fatalf("ScanFile: %v", err)
	}
	if !hasFindingWithPattern(findings, "github-token") {
		t.Errorf("expected github-token finding, got: %v", findings)
	}
}

func TestScanFile_DetectsStripeKey(t *testing.T) {
	dir, cleanup := tmpDir(t)
	defer cleanup()

	writeFile(t, dir, "config.env", "STRIPE_SECRET=sk_live_ABCDEFGHIJKLMNOPQRSTUVWX\n")

	s := scanner.New()
	findings, err := s.ScanFile(filepath.Join(dir, "config.env"))
	if err != nil {
		t.Fatalf("ScanFile: %v", err)
	}
	if !hasFindingWithPattern(findings, "stripe-key") {
		t.Errorf("expected stripe-key finding, got: %v", findings)
	}
}

func TestScanFile_DetectsOpenAIKey(t *testing.T) {
	dir, cleanup := tmpDir(t)
	defer cleanup()

	// 48-char alphanum suffix for the standard sk- pattern
	writeFile(t, dir, "keys.txt", "key=sk-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n")

	s := scanner.New()
	findings, err := s.ScanFile(filepath.Join(dir, "keys.txt"))
	if err != nil {
		t.Fatalf("ScanFile: %v", err)
	}
	if !hasFindingWithPattern(findings, "openai-key") {
		t.Errorf("expected openai-key finding, got: %v", findings)
	}
}

func TestScanFile_DetectsBearerToken(t *testing.T) {
	dir, cleanup := tmpDir(t)
	defer cleanup()

	writeFile(t, dir, "curl.sh", `curl -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9" https://api.example.com`+"\n")

	s := scanner.New()
	findings, err := s.ScanFile(filepath.Join(dir, "curl.sh"))
	if err != nil {
		t.Fatalf("ScanFile: %v", err)
	}
	if !hasFindingWithPattern(findings, "bearer-token") {
		t.Errorf("expected bearer-token finding, got: %v", findings)
	}
}

func TestScanFile_DetectsConnectionString(t *testing.T) {
	dir, cleanup := tmpDir(t)
	defer cleanup()

	writeFile(t, dir, "db.env", "DATABASE_URL=postgresql://user:password@localhost:5432/mydb\n")

	s := scanner.New()
	findings, err := s.ScanFile(filepath.Join(dir, "db.env"))
	if err != nil {
		t.Fatalf("ScanFile: %v", err)
	}
	if !hasFindingWithPattern(findings, "connection-string") {
		t.Errorf("expected connection-string finding, got: %v", findings)
	}
}

// ---------------------------------------------------------------------------
// ScanFile: scanner-specific patterns
// ---------------------------------------------------------------------------

func TestScanFile_DetectsPEMPrivateKey(t *testing.T) {
	dir, cleanup := tmpDir(t)
	defer cleanup()

	writeFile(t, dir, "key.pem", "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\n-----END RSA PRIVATE KEY-----\n")

	s := scanner.New()
	findings, err := s.ScanFile(filepath.Join(dir, "key.pem"))
	if err != nil {
		t.Fatalf("ScanFile: %v", err)
	}
	if !hasFindingWithPattern(findings, "private-key") {
		t.Errorf("expected private-key finding, got: %v", findings)
	}
}

func TestScanFile_DetectsGenericPEMPrivateKey(t *testing.T) {
	dir, cleanup := tmpDir(t)
	defer cleanup()

	writeFile(t, dir, "key.pem", "-----BEGIN PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\n-----END PRIVATE KEY-----\n")

	s := scanner.New()
	findings, err := s.ScanFile(filepath.Join(dir, "key.pem"))
	if err != nil {
		t.Fatalf("ScanFile: %v", err)
	}
	if !hasFindingWithPattern(findings, "private-key") {
		t.Errorf("expected private-key finding for generic PEM, got: %v", findings)
	}
}

func TestScanFile_DetectsEnvSecret(t *testing.T) {
	dir, cleanup := tmpDir(t)
	defer cleanup()

	writeFile(t, dir, ".env", "API_KEY=supersecretvalue123\n")

	s := scanner.New()
	findings, err := s.ScanFile(filepath.Join(dir, ".env"))
	if err != nil {
		t.Fatalf("ScanFile: %v", err)
	}
	if !hasFindingWithPattern(findings, "env-secret") {
		t.Errorf("expected env-secret finding, got: %v", findings)
	}
}

func TestScanFile_DetectsSlackWebhook(t *testing.T) {
	dir, cleanup := tmpDir(t)
	defer cleanup()

	writeFile(t, dir, "notify.sh", "WEBHOOK=https://hooks.slack.com/services/T01234567/B01234567/AbCdEfGhIjKlMnOpQrStUvWx\n")

	s := scanner.New()
	findings, err := s.ScanFile(filepath.Join(dir, "notify.sh"))
	if err != nil {
		t.Fatalf("ScanFile: %v", err)
	}
	if !hasFindingWithPattern(findings, "slack-webhook") {
		t.Errorf("expected slack-webhook finding, got: %v", findings)
	}
}

func TestScanFile_DetectsSendGridKey(t *testing.T) {
	dir, cleanup := tmpDir(t)
	defer cleanup()

	// SendGrid key: SG. + 22 chars + . + 43 chars
	writeFile(t, dir, "mail.env", "SENDGRID_KEY=SG.ABCDEFGHIJKLMNOPQRSTUV.ABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890123456\n")

	s := scanner.New()
	findings, err := s.ScanFile(filepath.Join(dir, "mail.env"))
	if err != nil {
		t.Fatalf("ScanFile: %v", err)
	}
	if !hasFindingWithPattern(findings, "sendgrid-key") {
		t.Errorf("expected sendgrid-key finding, got: %v", findings)
	}
}

// ---------------------------------------------------------------------------
// ScanFile: line number accuracy
// ---------------------------------------------------------------------------

func TestScanFile_LineNumberIsAccurate(t *testing.T) {
	dir, cleanup := tmpDir(t)
	defer cleanup()

	// Secret is on line 3 (1-indexed)
	writeFile(t, dir, "config.env",
		"HOST=localhost\n"+
			"PORT=5432\n"+
			"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE123\n"+
			"DEBUG=true\n")

	s := scanner.New()
	findings, err := s.ScanFile(filepath.Join(dir, "config.env"))
	if err != nil {
		t.Fatalf("ScanFile: %v", err)
	}

	awsFindings := make([]scanner.Finding, 0)
	for _, f := range findings {
		if f.Pattern == "aws-access-key" {
			awsFindings = append(awsFindings, f)
		}
	}

	if len(awsFindings) == 0 {
		t.Fatal("expected at least one aws-access-key finding")
	}
	if awsFindings[0].Line != 3 {
		t.Errorf("expected line 3, got line %d", awsFindings[0].Line)
	}
}

func TestScanFile_LineNumberOneForFirstLine(t *testing.T) {
	dir, cleanup := tmpDir(t)
	defer cleanup()

	writeFile(t, dir, "keys.txt", "AKIAIOSFODNN7EXAMPLE123 is the key\n")

	s := scanner.New()
	findings, err := s.ScanFile(filepath.Join(dir, "keys.txt"))
	if err != nil {
		t.Fatalf("ScanFile: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	if findings[0].Line != 1 {
		t.Errorf("expected line 1 for first line match, got %d", findings[0].Line)
	}
}

// ---------------------------------------------------------------------------
// ScanFile: snippet redaction
// ---------------------------------------------------------------------------

func TestScanFile_SnippetDoesNotContainRawSecret(t *testing.T) {
	dir, cleanup := tmpDir(t)
	defer cleanup()

	const awsKey = "AKIAIOSFODNN7EXAMPLE123"
	writeFile(t, dir, "config.env", "AWS_ACCESS_KEY_ID="+awsKey+"\n")

	s := scanner.New()
	findings, err := s.ScanFile(filepath.Join(dir, "config.env"))
	if err != nil {
		t.Fatalf("ScanFile: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	// The match field must not contain the full raw secret value
	match := findings[0].Match
	if match == awsKey {
		t.Errorf("finding Match must not be the raw secret value, got exact key: %q", match)
	}
}

func TestScanFile_SnippetIsNotEmpty(t *testing.T) {
	dir, cleanup := tmpDir(t)
	defer cleanup()

	writeFile(t, dir, "config.env", "AKIAIOSFODNN7EXAMPLE123\n")

	s := scanner.New()
	findings, err := s.ScanFile(filepath.Join(dir, "config.env"))
	if err != nil {
		t.Fatalf("ScanFile: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	if findings[0].Match == "" {
		t.Error("finding Match must not be empty")
	}
}

// ---------------------------------------------------------------------------
// ScanFile: severity classification
// ---------------------------------------------------------------------------

func TestScanFile_AWSKeyHasHighSeverity(t *testing.T) {
	dir, cleanup := tmpDir(t)
	defer cleanup()

	writeFile(t, dir, "config.env", "AKIAIOSFODNN7EXAMPLE123\n")

	s := scanner.New()
	findings, err := s.ScanFile(filepath.Join(dir, "config.env"))
	if err != nil {
		t.Fatalf("ScanFile: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	if findings[0].Severity != "high" {
		t.Errorf("AWS access key should have high severity, got: %q", findings[0].Severity)
	}
}

func TestScanFile_PrivateKeyHasHighSeverity(t *testing.T) {
	dir, cleanup := tmpDir(t)
	defer cleanup()

	writeFile(t, dir, "key.pem", "-----BEGIN RSA PRIVATE KEY-----\n")

	s := scanner.New()
	findings, err := s.ScanFile(filepath.Join(dir, "key.pem"))
	if err != nil {
		t.Fatalf("ScanFile: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	for _, f := range findings {
		if f.Pattern == "private-key" && f.Severity != "high" {
			t.Errorf("private-key should have high severity, got: %q", f.Severity)
		}
	}
}

// ---------------------------------------------------------------------------
// ScanFile: binary file handling
// ---------------------------------------------------------------------------

func TestScanFile_BinaryFileReturnsNoFindings(t *testing.T) {
	dir, cleanup := tmpDir(t)
	defer cleanup()

	writeBinaryFile(t, dir, "image.bin")

	s := scanner.New()
	findings, err := s.ScanFile(filepath.Join(dir, "image.bin"))
	if err != nil {
		t.Fatalf("ScanFile binary: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("binary file should return no findings, got: %v", findings)
	}
}

// ---------------------------------------------------------------------------
// ScanFile: large file handling
// ---------------------------------------------------------------------------

func TestScanFile_LargeFileIsSkippedReturnsNoFindings(t *testing.T) {
	dir, cleanup := tmpDir(t)
	defer cleanup()

	// Write a file > 1 MB
	large := strings.Repeat("AKIAIOSFODNN7EXAMPLE123\n", 60000) // ~1.4 MB
	writeFile(t, dir, "large.txt", large)

	s := scanner.New()
	findings, err := s.ScanFile(filepath.Join(dir, "large.txt"))
	if err != nil {
		t.Fatalf("ScanFile large: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("large file should be skipped (no findings), got %d findings", len(findings))
	}
}

// ---------------------------------------------------------------------------
// ScanFile: nonexistent file
// ---------------------------------------------------------------------------

func TestScanFile_NonexistentFileReturnsError(t *testing.T) {
	s := scanner.New()
	_, err := s.ScanFile("/does/not/exist/file.txt")
	if err == nil {
		t.Error("expected error for nonexistent file, got nil")
	}
}

// ---------------------------------------------------------------------------
// ScanDirectory: basic traversal
// ---------------------------------------------------------------------------

func TestScanDirectory_FindsSecretsInSubdirectory(t *testing.T) {
	dir, cleanup := tmpDir(t)
	defer cleanup()

	writeFile(t, dir, "src/config.go", `package config
const awsKey = "AKIAIOSFODNN7EXAMPLE123"
`)

	s := scanner.New()
	result, err := s.ScanDirectory(dir)
	if err != nil {
		t.Fatalf("ScanDirectory: %v", err)
	}
	if !hasFindingWithPattern(result.Findings, "aws-access-key") {
		t.Errorf("expected aws-access-key finding in subdirectory scan, got: %v", result.Findings)
	}
}

func TestScanDirectory_ReturnsFilesScannedCount(t *testing.T) {
	dir, cleanup := tmpDir(t)
	defer cleanup()

	writeFile(t, dir, "a.txt", "nothing here\n")
	writeFile(t, dir, "b.txt", "nothing here either\n")
	writeFile(t, dir, "sub/c.txt", "also clean\n")

	s := scanner.New()
	result, err := s.ScanDirectory(dir)
	if err != nil {
		t.Fatalf("ScanDirectory: %v", err)
	}
	if result.FilesScanned < 3 {
		t.Errorf("expected at least 3 files scanned, got %d", result.FilesScanned)
	}
}

func TestScanDirectory_ReturnsFilesSkippedCount(t *testing.T) {
	dir, cleanup := tmpDir(t)
	defer cleanup()

	writeBinaryFile(t, dir, "image.bin")
	writeFile(t, dir, "clean.txt", "nothing here\n")

	s := scanner.New()
	result, err := s.ScanDirectory(dir)
	if err != nil {
		t.Fatalf("ScanDirectory: %v", err)
	}
	if result.FilesSkipped < 1 {
		t.Errorf("expected at least 1 file skipped (binary), got %d", result.FilesSkipped)
	}
}

// ---------------------------------------------------------------------------
// ScanDirectory: excluded paths
// ---------------------------------------------------------------------------

func TestScanDirectory_SkipsGitDirectory(t *testing.T) {
	dir, cleanup := tmpDir(t)
	defer cleanup()

	// Secret inside .git should NOT be reported
	writeFile(t, dir, ".git/config", "AKIAIOSFODNN7EXAMPLE123\n")
	// Clean file outside .git
	writeFile(t, dir, "README.md", "# My Project\n")

	s := scanner.New()
	result, err := s.ScanDirectory(dir)
	if err != nil {
		t.Fatalf("ScanDirectory: %v", err)
	}
	for _, f := range result.Findings {
		if strings.Contains(filepath.ToSlash(f.File), ".git/") {
			t.Errorf("should not scan .git directory, but found: %s", f.File)
		}
	}
}

func TestScanDirectory_SkipsNodeModules(t *testing.T) {
	dir, cleanup := tmpDir(t)
	defer cleanup()

	writeFile(t, dir, "node_modules/some-lib/index.js", "var key = 'AKIAIOSFODNN7EXAMPLE123';\n")
	writeFile(t, dir, "src/app.js", "// nothing here\n")

	s := scanner.New()
	result, err := s.ScanDirectory(dir)
	if err != nil {
		t.Fatalf("ScanDirectory: %v", err)
	}
	for _, f := range result.Findings {
		if strings.Contains(filepath.ToSlash(f.File), "node_modules/") {
			t.Errorf("should not scan node_modules, but found: %s", f.File)
		}
	}
}

func TestScanDirectory_SkipsVendorDirectory(t *testing.T) {
	dir, cleanup := tmpDir(t)
	defer cleanup()

	writeFile(t, dir, "vendor/pkg/code.go", `const key = "AKIAIOSFODNN7EXAMPLE123"`+"\n")
	writeFile(t, dir, "main.go", "package main\n")

	s := scanner.New()
	result, err := s.ScanDirectory(dir)
	if err != nil {
		t.Fatalf("ScanDirectory: %v", err)
	}
	for _, f := range result.Findings {
		if strings.Contains(filepath.ToSlash(f.File), "vendor/") {
			t.Errorf("should not scan vendor directory, but found: %s", f.File)
		}
	}
}

func TestScanDirectory_SkipsBinaryFiles(t *testing.T) {
	dir, cleanup := tmpDir(t)
	defer cleanup()

	writeBinaryFile(t, dir, "app.bin")
	writeFile(t, dir, "readme.txt", "nothing here\n")

	s := scanner.New()
	result, err := s.ScanDirectory(dir)
	if err != nil {
		t.Fatalf("ScanDirectory: %v", err)
	}
	// Binary file should be counted in skipped, not scanned
	if result.FilesSkipped == 0 {
		t.Error("expected binary file to increment files_skipped")
	}
}

func TestScanDirectory_NoSymlinkFollowing(t *testing.T) {
	dir, cleanup := tmpDir(t)
	defer cleanup()

	// Create a target file OUTSIDE the scan root
	outside, err := os.MkdirTemp("", "scanner-outside-*")
	if err != nil {
		t.Fatalf("create outside dir: %v", err)
	}
	defer os.RemoveAll(outside)

	outsideFile := filepath.Join(outside, "secret.txt")
	if err := os.WriteFile(outsideFile, []byte("AKIAIOSFODNN7EXAMPLE123\n"), 0o644); err != nil {
		t.Fatalf("write outside file: %v", err)
	}

	// Create a symlink inside dir pointing to outside
	symlinkPath := filepath.Join(dir, "link_to_secret.txt")
	if err := os.Symlink(outsideFile, symlinkPath); err != nil {
		t.Skipf("symlinks not supported: %v", err)
	}

	s := scanner.New()
	result, err := s.ScanDirectory(dir)
	if err != nil {
		t.Fatalf("ScanDirectory: %v", err)
	}

	// The symlink should not be followed
	for _, f := range result.Findings {
		if strings.Contains(f.File, "link_to_secret") {
			t.Errorf("scanner followed symlink, found finding at: %s", f.File)
		}
	}
}

// ---------------------------------------------------------------------------
// ScanDirectory: nonexistent directory
// ---------------------------------------------------------------------------

func TestScanDirectory_NonexistentDirectoryReturnsError(t *testing.T) {
	s := scanner.New()
	_, err := s.ScanDirectory("/does/not/exist/directory")
	if err == nil {
		t.Error("expected error for nonexistent directory, got nil")
	}
}

// ---------------------------------------------------------------------------
// ScanDirectory: summary statistics
// ---------------------------------------------------------------------------

func TestScanDirectory_SummaryBySeverity(t *testing.T) {
	dir, cleanup := tmpDir(t)
	defer cleanup()

	writeFile(t, dir, "high.env", "AKIAIOSFODNN7EXAMPLE123\n")

	s := scanner.New()
	result, err := s.ScanDirectory(dir)
	if err != nil {
		t.Fatalf("ScanDirectory: %v", err)
	}
	if result.Summary.High == 0 {
		t.Errorf("expected at least 1 high-severity finding, got Summary: %+v", result.Summary)
	}
}

func TestScanDirectory_SummaryByType(t *testing.T) {
	dir, cleanup := tmpDir(t)
	defer cleanup()

	writeFile(t, dir, "keys.env", "AKIAIOSFODNN7EXAMPLE123\n")

	s := scanner.New()
	result, err := s.ScanDirectory(dir)
	if err != nil {
		t.Fatalf("ScanDirectory: %v", err)
	}
	if result.Summary.ByType["aws-access-key"] == 0 {
		t.Errorf("expected aws-access-key in ByType summary, got: %v", result.Summary.ByType)
	}
}

func TestScanDirectory_SummaryTotalMatchesFindingsLen(t *testing.T) {
	dir, cleanup := tmpDir(t)
	defer cleanup()

	writeFile(t, dir, "mixed.env", "AKIAIOSFODNN7EXAMPLE123\nsk_live_ABCDEFGHIJKLMNOPQRSTUVWX\n")

	s := scanner.New()
	result, err := s.ScanDirectory(dir)
	if err != nil {
		t.Fatalf("ScanDirectory: %v", err)
	}
	total := result.Summary.High + result.Summary.Medium + result.Summary.Low
	if total != len(result.Findings) {
		t.Errorf("Summary total (%d) != len(Findings) (%d)", total, len(result.Findings))
	}
}

// ---------------------------------------------------------------------------
// GenerateIgnoreRules
// ---------------------------------------------------------------------------

func TestGenerateIgnoreRules_ReturnsNonEmptyString(t *testing.T) {
	findings := []scanner.Finding{
		{File: "/project/secrets/.env", Line: 1, Pattern: "env-secret", Severity: "high", Match: "[REDACTED]"},
		{File: "/project/config/keys.go", Line: 5, Pattern: "aws-access-key", Severity: "high", Match: "[REDACTED]"},
	}

	result := scanner.GenerateIgnoreRules(findings, ".claudeignore")
	if result == "" {
		t.Error("GenerateIgnoreRules returned empty string for non-empty findings")
	}
}

func TestGenerateIgnoreRules_ContainsFilePathsFromFindings(t *testing.T) {
	findings := []scanner.Finding{
		{File: "/project/.env", Line: 1, Pattern: "env-secret", Severity: "high", Match: "[REDACTED]"},
	}

	result := scanner.GenerateIgnoreRules(findings, ".claudeignore")
	if !strings.Contains(result, ".env") {
		t.Errorf("generated rules should contain '.env', got: %q", result)
	}
}

func TestGenerateIgnoreRules_ContainsHeader(t *testing.T) {
	findings := []scanner.Finding{
		{File: "/project/.env", Line: 1, Pattern: "env-secret", Severity: "high", Match: "[REDACTED]"},
	}

	result := scanner.GenerateIgnoreRules(findings, ".claudeignore")
	if !strings.Contains(result, "#") {
		t.Errorf("generated rules should contain comment header, got: %q", result)
	}
}

func TestGenerateIgnoreRules_EmptyFindingsReturnsEmptyOrComment(t *testing.T) {
	result := scanner.GenerateIgnoreRules(nil, ".claudeignore")
	// Either empty or just a comment is acceptable
	lines := strings.Split(strings.TrimSpace(result), "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			t.Errorf("empty findings should produce only comments or empty output, got line: %q", trimmed)
		}
	}
}

func TestGenerateIgnoreRules_DeduplicatesFiles(t *testing.T) {
	findings := []scanner.Finding{
		{File: "/project/.env", Line: 1, Pattern: "env-secret", Severity: "high", Match: "[REDACTED]"},
		{File: "/project/.env", Line: 2, Pattern: "aws-access-key", Severity: "high", Match: "[REDACTED]"},
	}

	result := scanner.GenerateIgnoreRules(findings, ".claudeignore")

	// Count occurrences of .env in the output
	count := strings.Count(result, ".env")
	if count > 1 {
		t.Errorf("expected .env to appear only once (deduplication), got %d occurrences in:\n%s", count, result)
	}
}

// ---------------------------------------------------------------------------
// ScanDirectory: multi-pattern file
// ---------------------------------------------------------------------------

func TestScanDirectory_MultipleSecretsInOneFile(t *testing.T) {
	dir, cleanup := tmpDir(t)
	defer cleanup()

	writeFile(t, dir, "secrets.env",
		"AWS_KEY=AKIAIOSFODNN7EXAMPLE123\n"+
			"STRIPE_KEY=sk_live_ABCDEFGHIJKLMNOPQRSTUVWX\n"+
			"NORMAL_VAR=hello\n")

	s := scanner.New()
	result, err := s.ScanDirectory(dir)
	if err != nil {
		t.Fatalf("ScanDirectory: %v", err)
	}
	if len(result.Findings) < 2 {
		t.Errorf("expected at least 2 findings for file with 2 secrets, got %d", len(result.Findings))
	}
}

func TestScanDirectory_CleanDirectoryHasNoFindings(t *testing.T) {
	dir, cleanup := tmpDir(t)
	defer cleanup()

	writeFile(t, dir, "README.md", "# My Clean Project\nNo secrets here.\n")
	writeFile(t, dir, "main.go", "package main\n\nfunc main() {}\n")

	s := scanner.New()
	result, err := s.ScanDirectory(dir)
	if err != nil {
		t.Fatalf("ScanDirectory: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Errorf("clean directory should have no findings, got: %v", result.Findings)
	}
}

// ---------------------------------------------------------------------------
// Finding struct field validation
// ---------------------------------------------------------------------------

func TestFinding_FileFieldIsPopulated(t *testing.T) {
	dir, cleanup := tmpDir(t)
	defer cleanup()

	writeFile(t, dir, "config.env", "AKIAIOSFODNN7EXAMPLE123\n")

	s := scanner.New()
	findings, err := s.ScanFile(filepath.Join(dir, "config.env"))
	if err != nil {
		t.Fatalf("ScanFile: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	if findings[0].File == "" {
		t.Error("Finding.File must not be empty")
	}
}

func TestFinding_PatternFieldIsPopulated(t *testing.T) {
	dir, cleanup := tmpDir(t)
	defer cleanup()

	writeFile(t, dir, "config.env", "AKIAIOSFODNN7EXAMPLE123\n")

	s := scanner.New()
	findings, err := s.ScanFile(filepath.Join(dir, "config.env"))
	if err != nil {
		t.Fatalf("ScanFile: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	if findings[0].Pattern == "" {
		t.Error("Finding.Pattern must not be empty")
	}
}

func TestFinding_SeverityIsValid(t *testing.T) {
	dir, cleanup := tmpDir(t)
	defer cleanup()

	writeFile(t, dir, "config.env", "AKIAIOSFODNN7EXAMPLE123\n")

	s := scanner.New()
	findings, err := s.ScanFile(filepath.Join(dir, "config.env"))
	if err != nil {
		t.Fatalf("ScanFile: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	valid := map[string]bool{"high": true, "medium": true, "low": true}
	for _, f := range findings {
		if !valid[f.Severity] {
			t.Errorf("invalid severity %q, must be high/medium/low", f.Severity)
		}
	}
}

// ---------------------------------------------------------------------------
// BuildSummary exported function
// ---------------------------------------------------------------------------

func TestBuildSummary_CountsBySeeverity(t *testing.T) {
	findings := []scanner.Finding{
		{Pattern: "aws-access-key", Severity: "high", File: "a.txt", Line: 1, Match: "AK[...]"},
		{Pattern: "aws-access-key", Severity: "high", File: "b.txt", Line: 2, Match: "AK[...]"},
		{Pattern: "bearer-token", Severity: "medium", File: "c.txt", Line: 3, Match: "Be[...]"},
		{Pattern: "generic-secret", Severity: "low", File: "d.txt", Line: 4, Match: "se[...]"},
	}

	summary := scanner.BuildSummary(findings)

	if summary.Total != 4 {
		t.Errorf("Total = %d, want 4", summary.Total)
	}
	if summary.High != 2 {
		t.Errorf("High = %d, want 2", summary.High)
	}
	if summary.Medium != 1 {
		t.Errorf("Medium = %d, want 1", summary.Medium)
	}
	if summary.Low != 1 {
		t.Errorf("Low = %d, want 1", summary.Low)
	}
}

func TestBuildSummary_ByTypeMap(t *testing.T) {
	findings := []scanner.Finding{
		{Pattern: "aws-access-key", Severity: "high", File: "a.txt", Line: 1, Match: "AK[...]"},
		{Pattern: "aws-access-key", Severity: "high", File: "b.txt", Line: 2, Match: "AK[...]"},
		{Pattern: "github-token", Severity: "high", File: "c.txt", Line: 3, Match: "gh[...]"},
	}

	summary := scanner.BuildSummary(findings)

	if summary.ByType["aws-access-key"] != 2 {
		t.Errorf("ByType[aws-access-key] = %d, want 2", summary.ByType["aws-access-key"])
	}
	if summary.ByType["github-token"] != 1 {
		t.Errorf("ByType[github-token] = %d, want 1", summary.ByType["github-token"])
	}
}

func TestBuildSummary_EmptyFindings(t *testing.T) {
	summary := scanner.BuildSummary(nil)

	if summary.Total != 0 {
		t.Errorf("Total = %d, want 0", summary.Total)
	}
	if summary.ByType == nil {
		t.Error("ByType must not be nil")
	}
}
