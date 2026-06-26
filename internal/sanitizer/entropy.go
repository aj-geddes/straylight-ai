// Package sanitizer implements output sanitization to detect and redact credentials.
package sanitizer

import (
	"math"
	"regexp"
)

const (
	// entropyMinLength is the minimum token length for entropy-based detection.
	// Tokens shorter than this are very unlikely to be machine-generated secrets
	// and are at higher risk of false-positive matches.
	entropyMinLength = 28

	// entropyThreshold is the minimum Shannon entropy (bits per character) that
	// a token must have to be considered a potential secret. A uniformly random
	// 62-char alphanum alphabet yields ~5.95 bits; English prose words are
	// typically 3.0–3.5 bits. 3.5 is intentionally conservative.
	entropyThreshold = 3.5
)

// candidateTokenRE matches standalone alphanumeric runs of entropyMinLength or
// more characters. Word boundaries ensure we do not match partial tokens inside
// longer identifiers containing underscores or hyphens.
var candidateTokenRE = regexp.MustCompile(`\b[A-Za-z0-9]{28,}\b`)

// applyEntropyMatching scans input for high-entropy alphanumeric tokens that
// were not caught by exact-value or pattern matching. If a token meets all of
// the following criteria it is replaced with [REDACTED:high-entropy]:
//
//  1. Length >= entropyMinLength (28)
//  2. Shannon entropy >= entropyThreshold (3.5 bits/char)
//  3. Contains at least 2 of: uppercase letter, lowercase letter, digit
//  4. Is NOT composed entirely of hex digits (0-9a-fA-F) — avoids matching
//     git SHAs, content hashes, and similar hex strings that appear in prose
func applyEntropyMatching(input string) string {
	if input == "" {
		return input
	}

	type span struct {
		start int
		end   int
	}

	locs := candidateTokenRE.FindAllStringIndex(input, -1)
	if len(locs) == 0 {
		return input
	}

	// Collect spans to redact; process right-to-left later.
	var toRedact []span
	for _, loc := range locs {
		token := input[loc[0]:loc[1]]
		if isHighEntropyToken(token) {
			toRedact = append(toRedact, span{loc[0], loc[1]})
		}
	}

	if len(toRedact) == 0 {
		return input
	}

	// Apply replacements right-to-left to preserve offsets.
	result := input
	for i := len(toRedact) - 1; i >= 0; i-- {
		sp := toRedact[i]
		result = result[:sp.start] + "[REDACTED:high-entropy]" + result[sp.end:]
	}
	return result
}

// isHighEntropyToken returns true when token looks like a machine-generated
// secret based on length, Shannon entropy, charset diversity, and a hex-only
// exclusion to reduce false positives on hashes and SHAs.
func isHighEntropyToken(token string) bool {
	if len(token) < entropyMinLength {
		return false
	}

	// Reject tokens composed solely of hex characters (0-9, a-f, A-F).
	// These are likely content hashes, git SHAs, or UUIDs that appear
	// legitimately in prose and logs.
	if isHexOnly(token) {
		return false
	}

	// Require at least two character classes (upper, lower, digit).
	if charsetDiversity(token) < 2 {
		return false
	}

	return shannonEntropy(token) >= entropyThreshold
}

// shannonEntropy computes the Shannon entropy of s in bits per character.
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[byte]int, 64)
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	n := float64(len(s))
	h := 0.0
	for _, count := range freq {
		p := float64(count) / n
		h -= p * math.Log2(p)
	}
	return h
}

// isHexOnly returns true if every byte of s is a hex digit (0-9, a-f, A-F).
func isHexOnly(s string) bool {
	for i := 0; i < len(s); i++ {
		b := s[i]
		if !((b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')) {
			return false
		}
	}
	return true
}

// charsetDiversity returns the number of character classes present in s,
// counting uppercase letters, lowercase letters, and decimal digits separately.
func charsetDiversity(s string) int {
	var hasUpper, hasLower, hasDigit bool
	for i := 0; i < len(s); i++ {
		b := s[i]
		switch {
		case b >= 'A' && b <= 'Z':
			hasUpper = true
		case b >= 'a' && b <= 'z':
			hasLower = true
		case b >= '0' && b <= '9':
			hasDigit = true
		}
	}
	n := 0
	if hasUpper {
		n++
	}
	if hasLower {
		n++
	}
	if hasDigit {
		n++
	}
	return n
}
