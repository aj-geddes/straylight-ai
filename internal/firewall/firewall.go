// Package firewall provides the Sensitive File Firewall for Straylight-AI
// (ADR-013). It reads files with secrets automatically redacted and blocks
// access to files that are entirely too sensitive to serve even in redacted form.
package firewall

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// defaultMaxFileSize is 1 MiB — the upper bound for files the firewall reads.
const defaultMaxFileSize = 1024 * 1024

// blockedFileMessage is the template for the error returned when a blocked file
// is accessed. It guides the user to store credentials in the Straylight vault.
const blockedFileMessage = "file %q is blocked by the Straylight sensitive-file firewall. " +
	"Store credentials in the Straylight vault and use straylight_read_file to access " +
	"configuration files with secrets safely redacted."

// pathDeniedMessage is the template for the error returned when a path traversal
// or out-of-root access attempt is detected.
const pathDeniedMessage = "access denied: path %q is outside the project root %q"

// FirewallConfig holds the configuration for a Firewall instance.
type FirewallConfig struct {
	// ProjectRoot is the directory the firewall is allowed to read from.
	// Paths outside this root (including via symlinks) are rejected.
	// An empty ProjectRoot disables the root check.
	ProjectRoot string

	// BlockedPatterns are glob patterns matched against the file base name.
	// Files matching any blocked pattern are fully blocked — reading them returns
	// an error that guides the user to the Straylight vault.
	BlockedPatterns []string

	// StructuredKeyPatterns are key names in YAML, JSON, and TOML documents
	// whose values should be redacted. Matching is case-insensitive.
	StructuredKeyPatterns []string

	// MaxFileSize is the maximum file size (in bytes) the firewall will read.
	// Files larger than this limit are truncated and a warning is included in
	// the ReadResult. A value of 0 uses the default (1 MiB).
	MaxFileSize int64
}

// DefaultConfig returns a FirewallConfig pre-populated with sensible defaults
// for common sensitive file patterns and structured key names.
func DefaultConfig() FirewallConfig {
	return FirewallConfig{
		BlockedPatterns: []string{
			".env",
			".env.*",
			"*.pem",
			"*.key",
			"id_rsa",
			"id_ed25519",
			"credentials.json",
			"serviceAccountKey.json",
			"init.json",
		},
		StructuredKeyPatterns: []string{
			"password",
			"secret",
			"token",
			"api_key",
			"apiKey",
			"access_key",
			"secret_key",
			"connection_string",
			"database_url",
			"private_key",
		},
		MaxFileSize: defaultMaxFileSize,
	}
}

// ReadResult is the output of a successful ReadFileRedacted call.
type ReadResult struct {
	// Content is the file content with secrets replaced by [STRAYLIGHT:…] tokens.
	Content string `json:"content"`

	// Redactions is the total number of values that were redacted.
	Redactions int `json:"redactions"`

	// RedactedPatterns lists the pattern labels that matched at least once.
	RedactedPatterns []string `json:"redacted_patterns"`

	// FileSize is the on-disk size of the file in bytes.
	FileSize int64 `json:"file_size"`

	// Warning is non-empty when the file was truncated or another non-fatal
	// issue was encountered.
	Warning string `json:"warning,omitempty"`
}

// Firewall reads files with automatic secret redaction and blocks access to
// entirely sensitive files. All public methods are safe for concurrent use
// because Firewall holds no mutable state after construction.
type Firewall struct {
	cfg FirewallConfig
}

// NewFirewall creates a Firewall from the given config. Fields left at zero
// values are filled from DefaultConfig:
//   - MaxFileSize of 0 uses the 1 MiB default.
//   - Empty BlockedPatterns adopts the default blocked pattern list.
//   - Empty StructuredKeyPatterns adopts the default structured key list.
func NewFirewall(cfg FirewallConfig) *Firewall {
	defaults := DefaultConfig()
	if cfg.MaxFileSize <= 0 {
		cfg.MaxFileSize = defaults.MaxFileSize
	}
	if len(cfg.BlockedPatterns) == 0 {
		cfg.BlockedPatterns = defaults.BlockedPatterns
	}
	if len(cfg.StructuredKeyPatterns) == 0 {
		cfg.StructuredKeyPatterns = defaults.StructuredKeyPatterns
	}
	return &Firewall{cfg: cfg}
}

// IsBlockedFile returns true if the given path (or its base name) matches any
// of the configured blocked patterns. Matching is glob-style against the base
// name of the path.
func (f *Firewall) IsBlockedFile(path string) bool {
	base := filepath.Base(path)
	for _, pattern := range f.cfg.BlockedPatterns {
		matched, err := filepath.Match(pattern, base)
		if err == nil && matched {
			return true
		}
	}
	return false
}

// ReadFileRedacted reads the file at path, applies secret redaction, and
// returns the sanitised content together with redaction metadata.
//
// Errors are returned for:
//   - blocked files (the file name matches a blocked pattern)
//   - path traversal (the resolved path is outside the project root)
//   - symlinks pointing outside the project root
//   - files that cannot be read (I/O errors)
func (f *Firewall) ReadFileRedacted(path string) (*ReadResult, error) {
	// Resolve the path to its absolute, symlink-free form.
	resolved, err := resolvePath(path)
	if err != nil {
		return nil, fmt.Errorf("resolve path: %w", err)
	}

	// Enforce project root boundary.
	if f.cfg.ProjectRoot != "" {
		rootResolved, err := filepath.EvalSymlinks(f.cfg.ProjectRoot)
		if err != nil {
			// Fall back to clean path if EvalSymlinks fails (root may not exist yet).
			rootResolved = filepath.Clean(f.cfg.ProjectRoot)
		}
		rootResolved, _ = filepath.Abs(rootResolved)

		if !strings.HasPrefix(resolved, rootResolved+string(os.PathSeparator)) &&
			resolved != rootResolved {
			return nil, fmt.Errorf(pathDeniedMessage, path, f.cfg.ProjectRoot)
		}
	}

	// Block files matching sensitive name patterns.
	if f.IsBlockedFile(resolved) {
		return nil, fmt.Errorf(blockedFileMessage, filepath.Base(resolved))
	}

	// Read the file.
	info, err := os.Stat(resolved)
	if err != nil {
		return nil, fmt.Errorf("stat %q: %w", path, err)
	}

	fileSize := info.Size()
	var warning string
	readLimit := f.cfg.MaxFileSize

	data, err := readWithLimit(resolved, readLimit)
	if err != nil {
		return nil, fmt.Errorf("read %q: %w", path, err)
	}

	if fileSize > readLimit {
		warning = fmt.Sprintf("file truncated to %d bytes (actual size: %d bytes)", readLimit, fileSize)
	}

	// Apply redaction.
	content, redactions, patterns := f.redact(string(data), resolved)

	return &ReadResult{
		Content:          content,
		Redactions:       redactions,
		RedactedPatterns: patterns,
		FileSize:         fileSize,
		Warning:          warning,
	}, nil
}

// redact applies all three redaction layers to content and returns the
// sanitised text, the total redaction count, and the matched pattern labels.
func (f *Firewall) redact(content, path string) (string, int, []string) {
	ext := strings.ToLower(filepath.Ext(path))
	result := content
	total := 0
	patternSet := map[string]struct{}{}

	// Layer 1: Structured key redaction for YAML, JSON, TOML.
	switch ext {
	case ".yaml", ".yml":
		result, total = redactYAMLKeys(result, f.cfg.StructuredKeyPatterns, patternSet)
	case ".json":
		result, total = redactJSONKeys(result, f.cfg.StructuredKeyPatterns, patternSet)
	case ".toml":
		result, total = redactTOMLKeys(result, f.cfg.StructuredKeyPatterns, patternSet)
	}

	// Layer 2: Pattern-based redaction for known secret formats.
	patternCount := 0
	result, patternCount = applyBuiltinPatterns(result, patternSet)
	total += patternCount

	// Build sorted pattern slice.
	patterns := make([]string, 0, len(patternSet))
	for p := range patternSet {
		patterns = append(patterns, p)
	}

	return result, total, patterns
}

// ---------------------------------------------------------------------------
// Path helpers
// ---------------------------------------------------------------------------

// resolvePath resolves path to an absolute, cleaned form. It evaluates
// symlinks if possible, falling back to filepath.Abs + filepath.Clean.
func resolvePath(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		// If the file does not exist yet, EvalSymlinks fails.
		// Return the cleaned absolute path so callers can produce useful errors.
		return filepath.Clean(abs), nil
	}
	return resolved, nil
}

// readWithLimit reads at most limit bytes from the file at path.
func readWithLimit(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	buf := make([]byte, limit)
	n, err := f.Read(buf)
	if err != nil && n == 0 {
		return nil, err
	}
	return buf[:n], nil
}

// ---------------------------------------------------------------------------
// Structured-key redaction (YAML, JSON, TOML)
// ---------------------------------------------------------------------------

// redactYAMLKeys redacts values for matching keys in YAML content.
// It uses a line-oriented approach that preserves indentation and structure.
// Pattern: key: value  ->  key: [STRAYLIGHT:structured-key:key]
func redactYAMLKeys(content string, keys []string, matched map[string]struct{}) (string, int) {
	// Build a case-insensitive key set.
	keySet := make(map[string]struct{}, len(keys))
	for _, k := range keys {
		keySet[strings.ToLower(k)] = struct{}{}
	}

	lines := strings.Split(content, "\n")
	count := 0

	for i, line := range lines {
		stripped := strings.TrimLeft(line, " \t")
		colonIdx := strings.Index(stripped, ":")
		if colonIdx <= 0 {
			continue
		}
		key := stripped[:colonIdx]
		if _, ok := keySet[strings.ToLower(key)]; !ok {
			continue
		}
		rest := stripped[colonIdx+1:]
		// rest is ": value" or ": " or ""
		value := strings.TrimLeft(rest, " \t")
		if value == "" || value == "{}" || value == "[]" || value == "null" || value == "~" {
			// Empty or structured value — nothing to redact.
			continue
		}
		// Preserve any YAML block indicator or multi-line value start.
		if strings.HasPrefix(value, "|") || strings.HasPrefix(value, ">") {
			continue
		}

		indent := line[:len(line)-len(stripped)]
		placeholder := fmt.Sprintf("[STRAYLIGHT:structured-key:%s]", key)
		lines[i] = fmt.Sprintf("%s%s: %s", indent, key, placeholder)
		count++
		matched["structured-key:"+key] = struct{}{}
	}

	return strings.Join(lines, "\n"), count
}

// redactJSONKeys redacts values for matching keys in JSON content using
// regex replacement. This preserves the overall JSON structure while hiding
// secret string values.
func redactJSONKeys(content string, keys []string, matched map[string]struct{}) (string, int) {
	count := 0
	result := content

	for _, key := range keys {
		// Match "key": "value" patterns (string values only).
		// Pattern: "key"\s*:\s*"value"
		pattern := `(?i)"` + regexp.QuoteMeta(key) + `"\s*:\s*"([^"\\]|\\.)*"`
		re := regexp.MustCompile(pattern)

		replaced := re.ReplaceAllStringFunc(result, func(s string) string {
			// Find the colon and replace everything after it.
			colon := strings.Index(s, ":")
			if colon < 0 {
				return s
			}
			keyPart := s[:colon+1]
			count++
			matched["structured-key:"+strings.ToLower(key)] = struct{}{}
			return keyPart + ` "[STRAYLIGHT:structured-key:` + strings.ToLower(key) + `]"`
		})
		result = replaced
	}

	return result, count
}

// redactTOMLKeys redacts values for matching keys in TOML content.
// Handles key = "value" and key = 'value' forms.
func redactTOMLKeys(content string, keys []string, matched map[string]struct{}) (string, int) {
	keySet := make(map[string]struct{}, len(keys))
	for _, k := range keys {
		keySet[strings.ToLower(k)] = struct{}{}
	}

	lines := strings.Split(content, "\n")
	count := 0

	for i, line := range lines {
		stripped := strings.TrimLeft(line, " \t")
		eqIdx := strings.Index(stripped, "=")
		if eqIdx <= 0 {
			continue
		}
		key := strings.TrimRight(stripped[:eqIdx], " \t")
		if _, ok := keySet[strings.ToLower(key)]; !ok {
			continue
		}
		value := strings.TrimLeft(stripped[eqIdx+1:], " \t")
		if value == "" {
			continue
		}
		// Only redact string values (quoted).
		if !strings.HasPrefix(value, `"`) && !strings.HasPrefix(value, `'`) {
			continue
		}

		indent := line[:len(line)-len(stripped)]
		placeholder := fmt.Sprintf(`"[STRAYLIGHT:structured-key:%s]"`, key)
		lines[i] = fmt.Sprintf("%s%s = %s", indent, key, placeholder)
		count++
		matched["structured-key:"+strings.ToLower(key)] = struct{}{}
	}

	return strings.Join(lines, "\n"), count
}

// ---------------------------------------------------------------------------
// Pattern-based redaction (built-in secret patterns)
// ---------------------------------------------------------------------------

// secretPattern pairs a compiled regex with a label for the replacement token.
type secretPattern struct {
	re     *regexp.Regexp
	label  string
	prefix string // fast-path: if non-empty and absent, skip the regex
}

// builtinSecretPatterns mirrors the sanitizer patterns and adds connection
// string patterns for MySQL and more.
var builtinSecretPatterns = []secretPattern{
	// Stripe keys
	{re: regexp.MustCompile(`(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{24,}`), label: "stripe-key", prefix: "k_"},
	// GitHub fine-grained PAT
	{re: regexp.MustCompile(`github_pat_[A-Za-z0-9_]{82}`), label: "github-token", prefix: "github_pat_"},
	// GitHub classic tokens
	{re: regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{36}`), label: "github-token", prefix: "gh"},
	// OpenAI project key
	{re: regexp.MustCompile(`sk-proj-[A-Za-z0-9_-]{80,}`), label: "openai-key", prefix: "sk-proj-"},
	// OpenAI standard key
	{re: regexp.MustCompile(`sk-[A-Za-z0-9]{48}`), label: "openai-key", prefix: "sk-"},
	// AWS access key ID
	{re: regexp.MustCompile(`AKIA[A-Z0-9]{16}`), label: "aws-access-key", prefix: "AKIA"},
	// Bearer token
	{re: regexp.MustCompile(`Bearer [A-Za-z0-9._~+/=-]{20,}`), label: "bearer-token", prefix: "Bearer "},
	// Basic auth
	{re: regexp.MustCompile(`Basic [A-Za-z0-9+/=]{20,}`), label: "basic-auth", prefix: "Basic "},
	// Connection strings: postgresql/postgres, mysql, mongodb, redis
	{re: regexp.MustCompile(`(?:postgresql|postgres|mysql|mongodb|redis)://\S+`), label: "connection-string", prefix: "://"},
}

// applyBuiltinPatterns runs all built-in secret patterns against content.
// Matched substrings are replaced with [STRAYLIGHT:label] tokens.
// Returns the sanitised content and the count of replacements made.
func applyBuiltinPatterns(content string, matched map[string]struct{}) (string, int) {
	result := content
	total := 0

	for _, p := range builtinSecretPatterns {
		if p.prefix != "" && !strings.Contains(result, p.prefix) {
			continue
		}
		label := p.label
		token := "[STRAYLIGHT:" + label + "]"
		newResult := p.re.ReplaceAllLiteralString(result, token)
		if newResult != result {
			// Count occurrences replaced.
			matches := p.re.FindAllString(result, -1)
			total += len(matches)
			matched[label] = struct{}{}
		}
		result = newResult
	}

	return result, total
}
