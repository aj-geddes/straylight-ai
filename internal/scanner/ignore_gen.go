package scanner

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

// GenerateIgnoreRules produces ignore-file content for AI coding assistant
// tools (e.g. .claudeignore, .cursorignore) from a slice of findings.
//
// The tool parameter is the target filename (used only in the header comment).
// Files are deduplicated so each path appears at most once.
func GenerateIgnoreRules(findings []Finding, tool string) string {
	if len(findings) == 0 {
		return fmt.Sprintf("# Straylight-AI generated ignore rules (%s)\n# No findings — project looks clean.\n", tool)
	}

	// Deduplicate file paths while preserving first-seen order.
	seen := make(map[string]bool, len(findings))
	var unique []string
	for _, f := range findings {
		if !seen[f.File] {
			seen[f.File] = true
			unique = append(unique, f.File)
		}
	}
	sort.Strings(unique)

	var b strings.Builder
	fmt.Fprintf(&b, "# Straylight-AI recommended ignore rules (%s)\n", tool)
	fmt.Fprintf(&b, "# Generated from scan: %d finding(s) in %d file(s)\n", len(findings), len(unique))
	fmt.Fprintf(&b, "#\n")
	fmt.Fprintf(&b, "# Add these rules to your %s file to prevent AI tools from reading\n", tool)
	fmt.Fprintf(&b, "# files that contain secrets.\n\n")

	// Group by directory for readability.
	byDir := make(map[string][]string)
	for _, path := range unique {
		dir := filepath.Dir(path)
		base := filepath.Base(path)
		byDir[dir] = append(byDir[dir], base)
	}

	// Sort directories for deterministic output.
	dirs := make([]string, 0, len(byDir))
	for d := range byDir {
		dirs = append(dirs, d)
	}
	sort.Strings(dirs)

	for _, dir := range dirs {
		bases := byDir[dir]
		sort.Strings(bases)
		for _, base := range bases {
			// Use just the base filename as the ignore rule; most AI ignore
			// files support glob patterns so this covers all locations.
			fmt.Fprintf(&b, "%s\n", base)
		}
	}

	return b.String()
}
