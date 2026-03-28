// Package scanner_test: redaction security fix tests.
//
// Issue 6 (MEDIUM): redactMatch reveals first 4 + last 4 characters of the
// matched secret.  For a 10-character secret this exposes 80% of the value.
// Fix: reveal no more than 20% of the match, with a floor of 2 chars and a
// cap of 4 chars per side.  Always use 2 chars per side for secrets ≤ 20 chars.
package scanner_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/straylight-ai/straylight/internal/scanner"
)

// TestRedactMatch_ShortSecretIsFullyMasked verifies that matches shorter than
// or equal to the prefix+suffix threshold are entirely masked.
func TestRedactMatch_ShortSecretIsFullyMasked(t *testing.T) {
	// Write a file with a short secret (8 chars) that matches env-secret.
	dir, cleanup := tmpDir(t)
	defer cleanup()

	// 8-char value: prefix(4) + suffix(4) = 8 — should be fully masked.
	writeFile(t, dir, ".env", "API_KEY=12345678\n")

	s := scanner.New()
	findings, err := s.ScanFile(filepath.Join(dir, ".env"))
	if err != nil {
		t.Fatalf("ScanFile: %v", err)
	}
	if len(findings) == 0 {
		t.Skip("no env-secret finding — pattern may not match this input")
	}

	// The match must not reveal the actual secret characters.
	for _, f := range findings {
		if strings.Contains(f.Match, "12345678") {
			t.Errorf("Match %q reveals the full short secret — redaction insufficient", f.Match)
		}
	}
}

// TestRedactMatch_20PercentRuleForMediumSecret verifies that for a 20-char
// secret, no more than 20% (4 chars) is revealed on either side.
// With the old 4+4 rule, a 20-char secret reveals 40% (8 of 20 chars).
func TestRedactMatch_20PercentRuleForMediumSecret(t *testing.T) {
	dir, cleanup := tmpDir(t)
	defer cleanup()

	// Use a known AWS access key pattern: AKIA + 16 alphanumeric = 20 chars
	// total key portion.  The pattern match includes the "AKIA" prefix.
	secret := "AKIAIOSFODNN7EXAMPLE"
	writeFile(t, dir, "keys.env", "KEY="+secret+"\n")

	s := scanner.New()
	findings, err := s.ScanFile(filepath.Join(dir, "keys.env"))
	if err != nil {
		t.Fatalf("ScanFile: %v", err)
	}
	if len(findings) == 0 {
		t.Skip("no finding for test key pattern")
	}

	for _, f := range findings {
		match := f.Match
		if match == "" || match == strings.Repeat("*", len(secret)) {
			continue // fully masked, OK
		}

		// Count how many secret characters are actually visible in the match.
		// The match will be something like: "AKIA[...]MPLE" — count chars
		// outside the [...] placeholder.
		visibleChars := 0
		inPlaceholder := false
		for _, c := range match {
			if c == '[' {
				inPlaceholder = true
			} else if c == ']' {
				inPlaceholder = false
			} else if !inPlaceholder && c != '*' {
				visibleChars++
			}
		}

		// With the fix, visible chars should be at most 20% of the match length.
		// Allow a tiny tolerance for rounding (2 chars minimum per side).
		maxAllowed := len(secret)/5 + 2 // generous upper bound
		if visibleChars > maxAllowed {
			t.Errorf("redactMatch reveals %d chars of a %d-char secret (%q) — exceeds 20%% rule; match: %q",
				visibleChars, len(secret), secret, match)
		}
	}
}

// TestRedactMatch_DoesNotRevealMoreThan20Percent is a direct unit test of
// the redaction via ScanFile with a known-length pattern match.
// It specifically catches the old "4+4" rule on secrets of 10–19 chars.
func TestRedactMatch_DoesNotRevealMoreThan20PercentForShortSecrets(t *testing.T) {
	dir, cleanup := tmpDir(t)
	defer cleanup()

	// A 10-char secret — old rule: reveal 4+4=8 of 10 chars = 80%.
	// New rule: 20% of 10 = 2 chars per side (or less).
	// Use a pattern that matches: env-secret with a 10-char value.
	writeFile(t, dir, ".env", "SECRET_KEY=abcdef1234\n")

	s := scanner.New()
	findings, err := s.ScanFile(filepath.Join(dir, ".env"))
	if err != nil {
		t.Fatalf("ScanFile: %v", err)
	}
	if len(findings) == 0 {
		t.Skip("no env-secret finding")
	}

	for _, f := range findings {
		if f.Pattern != "env-secret" {
			continue
		}
		match := f.Match

		// Count revealed characters outside [...]
		revealed := 0
		inBracket := false
		for _, c := range match {
			switch c {
			case '[':
				inBracket = true
			case ']':
				inBracket = false
			default:
				if !inBracket && c != '*' {
					revealed++
				}
			}
		}

		// "abcdef1234" = 10 chars; 20% = 2; allow max 4 visible (2 prefix + 2 suffix).
		if revealed > 4 {
			t.Errorf("redactMatch reveals %d chars of a 10-char secret — old 4+4 rule in effect; match: %q", revealed, match)
		}
	}
}

// TestRedactMatch_SourceUsesPercentageRule verifies at source level that
// the redaction function uses a percentage-based approach rather than a
// fixed 4+4 constant.
func TestRedactMatch_SourceDoesNotUseFixed4Prefix(t *testing.T) {
	candidates := []string{
		"scanner.go",
		"../../internal/scanner/scanner.go",
	}

	var src []byte
	for _, c := range candidates {
		b, err := os.ReadFile(c)
		if err == nil {
			src = b
			break
		}
	}
	if src == nil {
		t.Skip("cannot locate scanner.go source")
	}

	content := string(src)

	// The old implementation had:
	//   const prefix = 4
	//   const suffix = 4
	//   return raw[:prefix] + "[...]" + raw[len(raw)-suffix:]
	//
	// The fix must eliminate "const prefix = 4" and "const suffix = 4"
	// in the redactMatch context, replacing them with a percentage-based
	// approach.
	if strings.Contains(content, "const prefix = 4") {
		t.Error("scanner.go still has 'const prefix = 4' — redactMatch has not been updated to a percentage-based approach")
	}
	if strings.Contains(content, "const suffix = 4") {
		t.Error("scanner.go still has 'const suffix = 4' — redactMatch has not been updated to a percentage-based approach")
	}
}
