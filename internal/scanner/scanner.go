package scanner

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	// maxFileSize is the largest file the scanner will read (1 MiB).
	// Files larger than this are counted as skipped.
	maxFileSize int64 = 1 * 1024 * 1024

	// binaryProbeSize is the number of bytes read to detect binary files.
	binaryProbeSize = 512
)

// defaultExcludeDirs is the set of directory names that are always skipped.
// These are matched against each path component, not just the base name, so
// "vendor" matches both "vendor/" at the root and "sub/vendor/" nested.
var defaultExcludeDirs = map[string]bool{
	".git":          true,
	"node_modules":  true,
	"vendor":        true,
	".venv":         true,
	"venv":          true,
	"dist":          true,
	"build":         true,
	"__pycache__":   true,
	".mypy_cache":   true,
	".tox":          true,
	"coverage":      true,
}

// Scanner walks a directory tree and reports files containing secrets.
// The zero value is not usable; call New() to create an instance.
type Scanner struct {
	// patterns is the list of detection patterns (from sanitizer + scanner-only).
	// Populated from the package-level allPatterns slice by New().
	patterns []scanPattern
}

// New creates a Scanner with all built-in detection patterns loaded.
func New() *Scanner {
	return &Scanner{
		patterns: allPatterns,
	}
}

// ScanDirectory walks root recursively and returns all findings.
// It skips:
//   - directories in defaultExcludeDirs (by path component name)
//   - symbolic links (not followed)
//   - binary files (NULL byte in first 512 bytes)
//   - files larger than maxFileSize
//
// Returns an error only if root does not exist or cannot be read.
func (s *Scanner) ScanDirectory(root string) (*ScanResult, error) {
	// Validate that root exists and is a directory.
	fi, err := os.Lstat(root)
	if err != nil {
		return nil, fmt.Errorf("scanner: stat %q: %w", root, err)
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("scanner: %q is not a directory", root)
	}

	start := time.Now()
	result := &ScanResult{
		Findings: []Finding{},
	}

	walkErr := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			// Skip paths we cannot access rather than aborting the whole scan.
			return nil
		}

		// Never follow symlinks.
		if d.Type()&os.ModeSymlink != 0 {
			result.FilesSkipped++
			return nil
		}

		// Skip excluded directories and prevent descending into them.
		if d.IsDir() {
			if isExcludedDir(path, root) {
				return filepath.SkipDir
			}
			return nil
		}

		// Only process regular files.
		if !d.Type().IsRegular() {
			result.FilesSkipped++
			return nil
		}

		findings, skipped := s.scanFilePath(path)
		if skipped {
			result.FilesSkipped++
			return nil
		}

		result.FilesScanned++
		result.Findings = append(result.Findings, findings...)
		return nil
	})

	if walkErr != nil {
		return nil, fmt.Errorf("scanner: walk %q: %w", root, walkErr)
	}

	result.DurationMS = time.Since(start).Milliseconds()
	result.Summary = buildSummary(result.Findings)
	return result, nil
}

// ScanFile scans a single file and returns all findings.
// Returns an error if the file cannot be opened or read.
// Returns an empty (non-nil) slice for binary or oversized files rather than
// an error, because skipping is expected behaviour.
func (s *Scanner) ScanFile(path string) ([]Finding, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("scanner: stat %q: %w", path, err)
	}
	if fi.IsDir() {
		return nil, fmt.Errorf("scanner: %q is a directory, not a file", path)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return []Finding{}, nil
	}

	findings, _ := s.scanFilePath(path)
	return findings, nil
}

// scanFilePath performs the actual scan of a single file path.
// The second return value is true when the file was skipped (binary or large).
// It never returns a non-nil error; read errors cause the file to be skipped.
func (s *Scanner) scanFilePath(path string) (findings []Finding, skipped bool) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, true
	}

	// Skip files larger than maxFileSize.
	if fi.Size() > maxFileSize {
		return nil, true
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, true
	}
	defer f.Close()

	// Binary detection: read first binaryProbeSize bytes.
	probe := make([]byte, binaryProbeSize)
	n, _ := f.Read(probe)
	if isBinary(probe[:n]) {
		return nil, true
	}

	// Seek back to the beginning so the line scanner sees the full file.
	if _, err := f.Seek(0, 0); err != nil {
		return nil, true
	}

	var results []Finding
	lineNum := 0
	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		for _, p := range s.patterns {
			// Fast-path gate: skip regex if literal prefix is absent.
			if p.prefix != "" && !strings.Contains(line, p.prefix) {
				continue
			}
			loc := p.re.FindStringIndex(line)
			if loc == nil {
				continue
			}
			raw := line[loc[0]:loc[1]]
			results = append(results, Finding{
				File:     path,
				Line:     lineNum,
				Column:   loc[0] + 1, // 1-indexed
				Pattern:  p.label,
				Match:    redactMatch(raw),
				Severity: p.severity,
			})
		}
	}

	return results, false
}

// isExcludedDir returns true if any path component of dirPath (relative to
// root) matches an entry in defaultExcludeDirs.
func isExcludedDir(dirPath, root string) bool {
	rel, err := filepath.Rel(root, dirPath)
	if err != nil {
		return false
	}
	parts := strings.Split(filepath.ToSlash(rel), "/")
	for _, part := range parts {
		if defaultExcludeDirs[part] {
			return true
		}
	}
	return false
}

// isBinary returns true if the byte slice contains a NULL byte, which is a
// reliable heuristic for binary content in the first 512 bytes.
func isBinary(data []byte) bool {
	for _, b := range data {
		if b == 0 {
			return true
		}
	}
	return false
}

// redactMatch produces a safe preview of a matched secret.  The middle portion
// of the value is replaced with "[...]" so the reviewer can identify the
// pattern type without the actual secret being present in the finding.
//
// The number of revealed characters is capped at 20% of the match length to
// prevent excessive disclosure of short secrets.  A minimum of 1 character
// per side is shown when the match is long enough to avoid full masking, but
// never more than 4 characters per side.  Matches of 10 characters or fewer
// are fully masked.
func redactMatch(raw string) string {
	n := len(raw)

	// Compute per-side reveal: 10% of total length, clamped to [1, 4].
	// This means at most 20% total is revealed (10% prefix + 10% suffix).
	perSide := n / 10
	if perSide < 1 {
		perSide = 1
	}
	if perSide > 4 {
		perSide = 4
	}

	// Mask entirely if the match is short enough that revealing perSide chars
	// on each side would still expose more than 20% of the secret, or if
	// perSide*2 >= n (nothing to hide).
	if n <= perSide*2 || n <= 10 {
		return strings.Repeat("*", n)
	}

	return raw[:perSide] + "[...]" + raw[n-perSide:]
}
