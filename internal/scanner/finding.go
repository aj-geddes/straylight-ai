// Package scanner provides project-directory scanning for secrets and
// sensitive files before AI coding assistants read them.
//
// Patterns are shared with internal/sanitizer to guarantee that anything the
// scanner detects the sanitizer will also redact, and vice versa.
package scanner

// Finding represents a single secret detected during a scan.
type Finding struct {
	// File is the absolute path to the file containing the secret.
	File string `json:"file"`

	// Line is the 1-indexed line number of the match.
	Line int `json:"line"`

	// Column is the 1-indexed column of the match start on that line.
	Column int `json:"column"`

	// Pattern is the human-readable pattern label (e.g., "aws-access-key").
	Pattern string `json:"pattern"`

	// Match is a redacted preview of the match.  The actual secret value is
	// replaced so that the finding itself does not expose the credential.
	Match string `json:"match"`

	// Severity is one of "high", "medium", or "low".
	Severity string `json:"severity"`
}

// Summary aggregates finding counts by severity and by pattern type.
type Summary struct {
	// Total is the total number of findings (High + Medium + Low).
	Total int `json:"total"`

	// High, Medium, Low are counts by severity bucket.
	High   int `json:"high"`
	Medium int `json:"medium"`
	Low    int `json:"low"`

	// ByType maps pattern label (e.g., "aws-access-key") to finding count.
	ByType map[string]int `json:"by_type"`
}

// ScanResult holds the full output of a directory scan.
type ScanResult struct {
	// Findings contains one entry per detected secret location.
	Findings []Finding `json:"findings"`

	// FilesScanned is the number of files that were read and pattern-matched.
	FilesScanned int `json:"files_scanned"`

	// FilesSkipped is the number of files that were excluded (binary, too
	// large, in an excluded path, or a symlink).
	FilesSkipped int `json:"files_skipped"`

	// DurationMS is the wall-clock scan time in milliseconds.
	DurationMS int64 `json:"duration_ms"`

	// Summary provides aggregate statistics over Findings.
	Summary Summary `json:"summary"`
}

// BuildSummary constructs a Summary from a slice of findings.
// It is exported so that callers (e.g. the MCP handler) can rebuild the summary
// after applying a severity filter to the original finding slice.
func BuildSummary(findings []Finding) Summary {
	return buildSummary(findings)
}

// buildSummary constructs a Summary from a slice of findings.
func buildSummary(findings []Finding) Summary {
	s := Summary{
		Total:  len(findings),
		ByType: make(map[string]int, 8),
	}
	for _, f := range findings {
		switch f.Severity {
		case "high":
			s.High++
		case "medium":
			s.Medium++
		default:
			s.Low++
		}
		s.ByType[f.Pattern]++
	}
	return s
}
