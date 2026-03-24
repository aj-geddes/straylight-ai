// Package sanitizer implements output sanitization to detect and redact
// credentials that may appear in proxied API responses or command output.
//
// Implemented in WP-1.3.
package sanitizer

import (
	"fmt"
	"strings"
	"sync"
)

// CredentialStore provides live credential values for value-based matching.
// Implementations typically delegate to the OpenBao vault client.
type CredentialStore interface {
	// GetAllCredentials returns a snapshot of all stored credential values
	// keyed by service name.
	GetAllCredentials() map[string]string
}

// Sanitizer redacts credentials from arbitrary text using two complementary
// strategies:
//
//  1. Value matching (higher priority): exact substring search for all
//     registered credential values in a single O(n) pass using strings.Replacer.
//     Replacement text: [REDACTED:<service-name>].
//
//  2. Pattern matching: sequential regex passes for each built-in credential
//     format (see patterns.go). Patterns are pre-compiled once at init time
//     and each has an optional literal prefix that enables a fast path: if the
//     prefix is absent from the text the regex is skipped entirely.
//     Replacement text: [REDACTED:<pattern-label>].
//
// Value matching runs first so that service-specific labels take priority over
// generic pattern labels when the same text matches both.
//
// All public methods are safe for concurrent use.
type Sanitizer struct {
	mu     sync.RWMutex
	values map[string]string // service name -> credential value
	store  CredentialStore
}

// NewSanitizer creates a ready-to-use Sanitizer with all built-in patterns
// pre-compiled (see patterns.go).
func NewSanitizer() *Sanitizer {
	return &Sanitizer{
		values: make(map[string]string),
	}
}

// RegisterValue adds a known credential value for exact-match sanitization.
// If the service name already exists its value is overwritten.
// Values shorter than 8 characters are silently ignored to avoid excessive
// false positives on common short strings.
func (s *Sanitizer) RegisterValue(serviceName string, value string) {
	if len(value) < 8 {
		return
	}
	s.mu.Lock()
	s.values[serviceName] = value
	s.mu.Unlock()
}

// UnregisterValue removes a credential value so it is no longer matched.
// It is safe to call UnregisterValue for a name that was never registered.
func (s *Sanitizer) UnregisterValue(serviceName string) {
	s.mu.Lock()
	delete(s.values, serviceName)
	s.mu.Unlock()
}

// SetCredentialStore installs a CredentialStore whose values are consulted on
// every Sanitize call.  Values from the store supplement (but do not replace)
// values registered via RegisterValue.  Pass nil to clear the store.
func (s *Sanitizer) SetCredentialStore(store CredentialStore) {
	s.mu.Lock()
	s.store = store
	s.mu.Unlock()
}

// Sanitize returns a copy of input with all detected credentials replaced.
// It runs value matching before pattern matching so that registered service
// names appear in the replacement text when available.
func (s *Sanitizer) Sanitize(input string) string {
	if input == "" {
		return input
	}

	s.mu.RLock()
	values := make(map[string]string, len(s.values))
	for k, v := range s.values {
		values[k] = v
	}
	store := s.store
	s.mu.RUnlock()

	// Merge values from the CredentialStore. Explicitly registered values take
	// priority: if a service name already appears in values, the store entry is
	// skipped so the caller-supplied label wins.
	if store != nil {
		for name, val := range store.GetAllCredentials() {
			if _, exists := values[name]; !exists {
				values[name] = val
			}
		}
	}

	result := applyValueMatching(input, values)
	result = applyPatternMatching(result)
	return result
}

// applyValueMatching replaces all registered credential values in a single
// O(n) pass using strings.Replacer regardless of the number of values.
func applyValueMatching(input string, values map[string]string) string {
	if len(values) == 0 {
		return input
	}

	// Build the alternating old/new slice that strings.NewReplacer expects.
	pairs := make([]string, 0, len(values)*2)
	for name, val := range values {
		if val == "" || len(val) < 8 {
			continue
		}
		pairs = append(pairs, val, fmt.Sprintf("[REDACTED:%s]", name))
	}
	if len(pairs) == 0 {
		return input
	}

	return strings.NewReplacer(pairs...).Replace(input)
}

// applyPatternMatching applies each built-in regex pattern, using the
// pattern's literal prefix (if any) as a fast-path gate: if the prefix is not
// present in the text the expensive regex is skipped entirely.
func applyPatternMatching(input string) string {
	result := input
	for _, p := range builtinPatterns {
		// Fast path: if a literal prefix is set and absent, skip the regex.
		if p.prefix != "" && !strings.Contains(result, p.prefix) {
			continue
		}
		result = p.re.ReplaceAllLiteralString(result, p.redacted)
	}
	return result
}
