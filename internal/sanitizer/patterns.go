// Package sanitizer implements output sanitization to detect and redact
// credentials that may appear in proxied API responses or command output.
package sanitizer

import (
	"fmt"
	"regexp"
)

// credentialPattern pairs a compiled regex with a pre-built replacement
// string and an optional literal prefix used as a fast-path gate.
type credentialPattern struct {
	re       *regexp.Regexp
	redacted string // pre-computed "[REDACTED:<label>]"
	// prefix is a literal string that must be present in the text for this
	// pattern to have any chance of matching. When non-empty, strings.Contains
	// is used as a cheap gate before running the regex.  Must be a genuine
	// prefix of the pattern (not derived from an alternation root).
	prefix string
}

// newPattern creates a credentialPattern with a literal prefix hint.
func newPattern(pattern, label, prefix string) credentialPattern {
	return credentialPattern{
		re:       regexp.MustCompile(pattern),
		redacted: fmt.Sprintf("[REDACTED:%s]", label),
		prefix:   prefix,
	}
}

// ExportedPattern is a read-only view of a credentialPattern exposed for use
// by other packages (e.g. internal/scanner).  It contains only the fields
// needed for detection: the compiled regex expression source string, the
// human-readable label, and an optional literal prefix hint.
type ExportedPattern struct {
	// Pattern is the original regex source string (not compiled).
	Pattern string
	// Label is the human-readable credential type, e.g. "aws-access-key".
	Label string
	// Prefix is the literal prefix used as a fast-path gate.  May be empty.
	Prefix string
}

// Patterns returns a copy of the built-in credential patterns so that other
// packages can apply the same detection logic without duplicating regexes.
// The returned slice is a snapshot; it is safe to read concurrently but
// callers must not modify elements.
func Patterns() []ExportedPattern {
	out := make([]ExportedPattern, len(builtinPatterns))
	for i, p := range builtinPatterns {
		out[i] = ExportedPattern{
			Pattern: p.re.String(),
			Label:   labelFromRedacted(p.redacted),
			Prefix:  p.prefix,
		}
	}
	return out
}

// labelFromRedacted extracts the label from a pre-built "[REDACTED:<label>]"
// string, e.g. "[REDACTED:aws-access-key]" -> "aws-access-key".
func labelFromRedacted(redacted string) string {
	// Format is "[REDACTED:<label>]"
	const prefix = "[REDACTED:"
	if len(redacted) < len(prefix)+1 {
		return redacted
	}
	inner := redacted[len(prefix):]
	if n := len(inner); n > 0 && inner[n-1] == ']' {
		return inner[:n-1]
	}
	return inner
}

// builtinPatterns contains pre-compiled regex patterns for common credential
// formats ordered from most specific to least specific, ensuring that accurate
// labels appear before generic ones have a chance to match.
//
// All character classes are kept flat (no nested quantifiers) to guarantee
// O(n) matching and avoid catastrophic backtracking.
var builtinPatterns = []credentialPattern{
	// --- Stripe ---
	// sk_live_*, sk_test_*, pk_live_*, pk_test_*, rk_live_*, rk_test_*
	// Minimum 24 alphanum chars after the prefix.
	// No single literal prefix covers all variants; use "k_" as common infix.
	newPattern(`(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{24,}`, "stripe-key", "k_"),

	// --- GitHub fine-grained PAT ---
	// github_pat_ followed by exactly 82 alphanumeric/underscore chars.
	// Declared before the short gh*_ pattern so this longer variant matches first.
	newPattern(`github_pat_[A-Za-z0-9_]{82}`, "github-token", "github_pat_"),

	// --- GitHub classic tokens ---
	// ghp_, gho_, ghu_, ghs_, ghr_ each followed by exactly 36 alphanum chars.
	newPattern(`gh[pousr]_[A-Za-z0-9]{36}`, "github-token", "gh"),

	// --- OpenAI project key ---
	// sk-proj- followed by 80+ chars of alphanum, dash, underscore.
	// Declared before the generic sk- pattern so the longer variant matches first.
	newPattern(`sk-proj-[A-Za-z0-9_-]{80,}`, "openai-key", "sk-proj-"),

	// --- OpenAI standard key ---
	// sk- followed by exactly 48 alphanum chars.
	newPattern(`sk-[A-Za-z0-9]{48}`, "openai-key", "sk-"),

	// --- AWS access key ID ---
	// AKIA followed by exactly 16 uppercase letters/digits.
	newPattern(`AKIA[A-Z0-9]{16}`, "aws-access-key", "AKIA"),

	// --- Generic Bearer token ---
	// "Bearer " followed by 20+ token-safe characters.
	// The character class is a single flat set to prevent nested-quantifier backtracking.
	newPattern(`Bearer [A-Za-z0-9._~+/=-]{20,}`, "bearer-token", "Bearer "),

	// --- Generic Basic auth ---
	// "Basic " followed by 20+ base64 characters.
	newPattern(`Basic [A-Za-z0-9+/=]{20,}`, "basic-auth", "Basic "),

	// --- Connection strings ---
	// postgresql://, mongodb://, redis:// followed by non-whitespace chars.
	// "://" is the common infix shared by all three.
	newPattern(`(?:postgresql|mongodb|redis)://\S+`, "connection-string", "://"),

	// --- AWS STS temporary access key ID ---
	// ASIA prefix (temporary/session credentials) followed by exactly 16 uppercase chars.
	// Listed after AKIA to avoid masking the more specific root-key pattern.
	newPattern(`ASIA[A-Z0-9]{16}`, "aws-session-key", "ASIA"),

	// --- AWS session token ---
	// Session tokens are long base64 strings beginning with "//" or contain
	// "AQoXb3JnYW5pemF0aW9u" prefix. Detect by looking for the "//AQo" pattern
	// common to AWS temp session tokens.
	newPattern(`//AQo[A-Za-z0-9+/=]{40,}`, "aws-session-token", "//AQo"),

	// --- GCP access token ---
	// Google OAuth2 access tokens begin with "ya29." followed by 100+ base64url chars.
	newPattern(`ya29\.[A-Za-z0-9_-]{100,}`, "gcp-access-token", "ya29."),

	// --- Azure bearer token (JWT) ---
	// Azure AD tokens are JWTs: three base64url segments separated by dots.
	// The header always starts with "eyJ" ({"alg": or {"typ":).
	// Pattern: eyJ<20+>.<20+>.<20+>
	newPattern(`eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}`, "azure-jwt-token", "eyJ"),
}
