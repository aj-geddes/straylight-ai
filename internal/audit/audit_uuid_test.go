// Package audit_test: UUID security fix tests.
//
// Issue 5 (MEDIUM): newUUID uses math/rand for random bytes.
// Fix: switch to crypto/rand for cryptographically secure random bytes.
package audit_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/straylight-ai/straylight/internal/audit"
)

// TestNewUUID_DoesNotUseMathRand verifies that the audit package no longer
// imports or uses math/rand for UUID generation.  math/rand is not suitable
// for security-critical identifiers in audit trails because its output is
// predictable given the seed.
//
// This is a source-level check: the audit.go file must not call rand.Uint32
// or rand.Uint64 from math/rand in the newUUID function.
func TestNewUUID_DoesNotUseMathRand(t *testing.T) {
	// Find the audit.go source file relative to the test binary's location.
	// In a standard module layout, the source is at internal/audit/audit.go.
	candidates := []string{
		"audit.go",
		"../../internal/audit/audit.go",
	}

	var src []byte
	for _, candidate := range candidates {
		b, err := os.ReadFile(candidate)
		if err == nil {
			src = b
			break
		}
		// Try relative to the test file location.
		abs, _ := filepath.Abs(candidate)
		b, err = os.ReadFile(abs)
		if err == nil {
			src = b
			break
		}
	}

	// If we couldn't find the source (e.g., running from binary), skip.
	if src == nil {
		// Try from module root.
		wd, _ := os.Getwd()
		for _, rel := range []string{"audit.go", filepath.Join(wd, "audit.go")} {
			b, err := os.ReadFile(rel)
			if err == nil {
				src = b
				break
			}
		}
	}

	if src == nil {
		t.Skip("cannot locate audit.go source — skipping source-level check")
	}

	content := string(src)

	// The import block must not include math/rand.
	// We check the import block specifically rather than the whole file
	// to avoid false positives from comments that mention math/rand.
	importBlock := extractImportBlock(content)
	if strings.Contains(importBlock, "math/rand") {
		t.Error("audit.go imports math/rand — switch to crypto/rand for UUID generation")
	}

	// The code (outside comments) must not call math/rand functions.
	if strings.Contains(content, "rand.Uint32()") {
		t.Error("audit.go calls rand.Uint32() (math/rand) — switch to crypto/rand")
	}
	if strings.Contains(content, "rand.Uint64()") {
		t.Error("audit.go calls rand.Uint64() (math/rand) — switch to crypto/rand")
	}
}

// TestNewUUID_UniqueAcrossRapidEmissions verifies that IDs remain unique
// under concurrent load, which would fail with a poorly seeded PRNG.
func TestNewUUID_UniqueAcrossRapidEmissions(t *testing.T) {
	dir := t.TempDir()
	l, err := audit.NewLogger(dir, 0)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	defer l.Close()

	const n = 1000
	// Emit events as fast as possible — many will share the same millisecond.
	for i := 0; i < n; i++ {
		l.Emit(audit.Event{Type: audit.EventToolCall})
	}

	// Let the writer goroutine flush.
	time.Sleep(100 * time.Millisecond)

	recent := l.Recent(n)

	ids := make(map[string]bool, len(recent))
	for _, ev := range recent {
		if ev.ID == "" {
			t.Error("event ID must not be empty")
			continue
		}
		if ids[ev.ID] {
			t.Errorf("duplicate event ID detected: %q — math/rand may have been used", ev.ID)
		}
		ids[ev.ID] = true
	}
}

// TestNewUUID_HasExpectedFormat verifies the UUID has the expected
// "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" hexadecimal format.
func TestNewUUID_HasExpectedFormat(t *testing.T) {
	dir := t.TempDir()
	l, err := audit.NewLogger(dir, 0)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	defer l.Close()

	l.Emit(audit.Event{Type: audit.EventToolCall})
	time.Sleep(30 * time.Millisecond)

	recent := l.Recent(1)
	if len(recent) == 0 {
		t.Fatal("no events in ring buffer")
	}

	id := recent[0].ID
	// UUID format: 8-4-4-4-12 hexadecimal chars
	parts := splitUUID(id)
	if len(parts) != 5 {
		t.Fatalf("UUID %q does not have 5 dash-separated groups", id)
	}
	expected := []int{8, 4, 4, 4, 12}
	for i, part := range parts {
		if len(part) != expected[i] {
			t.Errorf("UUID group %d: got %d chars (%q), want %d", i, len(part), part, expected[i])
		}
		if !isHex(part) {
			t.Errorf("UUID group %d %q contains non-hex characters", i, part)
		}
	}
}

// extractImportBlock returns only the import(...) section of a Go source file.
func extractImportBlock(src string) string {
	start := strings.Index(src, "import (")
	if start < 0 {
		return ""
	}
	end := strings.Index(src[start:], ")")
	if end < 0 {
		return src[start:]
	}
	return src[start : start+end+1]
}

func splitUUID(s string) []string {
	var parts []string
	current := ""
	for _, c := range s {
		if c == '-' {
			parts = append(parts, current)
			current = ""
		} else {
			current += string(c)
		}
	}
	if current != "" {
		parts = append(parts, current)
	}
	return parts
}

func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}
