package scanner

import (
	"regexp"

	"github.com/straylight-ai/straylight/internal/sanitizer"
)

// scanPattern pairs a compiled regex with metadata used during file scanning.
type scanPattern struct {
	re       *regexp.Regexp
	label    string // human-readable type, e.g. "aws-access-key"
	severity string // "high", "medium", or "low"
	prefix   string // literal fast-path gate (may be empty)
}

// allPatterns is the combined set of patterns used by the scanner.
// It is built once at package initialisation from:
//  1. sanitizer.Patterns()  – patterns shared with the output sanitizer
//  2. scannerOnlyPatterns   – patterns relevant only for file content
var allPatterns []scanPattern

func init() {
	// Import sanitizer built-in patterns.  All sanitizer patterns are
	// considered high severity because they cover AWS keys, GitHub tokens, etc.
	for _, ep := range sanitizer.Patterns() {
		sev := sanitizerPatternSeverity(ep.Label)
		allPatterns = append(allPatterns, scanPattern{
			re:       regexp.MustCompile(ep.Pattern),
			label:    ep.Label,
			severity: sev,
			prefix:   ep.Prefix,
		})
	}

	// Append scanner-only patterns.
	allPatterns = append(allPatterns, scannerOnlyPatterns...)
}

// sanitizerPatternSeverity maps a sanitizer pattern label to a severity level.
// All sanitizer patterns that cover credentials are high severity; bearer/basic
// tokens are medium because they may appear in logs legitimately.
func sanitizerPatternSeverity(label string) string {
	switch label {
	case "bearer-token", "basic-auth":
		return "medium"
	default:
		return "high"
	}
}

// scannerOnlyPatterns are patterns that are relevant for file content scanning
// but do not appear in API responses (e.g. PEM blocks, .env assignments).
var scannerOnlyPatterns = []scanPattern{
	// PEM private keys – covers RSA, EC, DSA, OPENSSH, and generic PKCS8
	{
		re:       regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`),
		label:    "private-key",
		severity: "high",
		prefix:   "-----BEGIN",
	},
	// .env file secret assignments: KEY=value where KEY contains a secret hint
	{
		re:       regexp.MustCompile(`(?i)(?:PASSWORD|SECRET|TOKEN|API_KEY|PRIVATE_KEY)\s*=\s*\S{8,}`),
		label:    "env-secret",
		severity: "high",
		prefix:   "",
	},
	// Slack incoming webhook URLs
	{
		re:       regexp.MustCompile(`https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+`),
		label:    "slack-webhook",
		severity: "high",
		prefix:   "hooks.slack.com",
	},
	// SendGrid API keys: SG. + 22 alphanum/dash/underscore chars + . + 43 chars
	{
		re:       regexp.MustCompile(`SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}`),
		label:    "sendgrid-key",
		severity: "high",
		prefix:   "SG.",
	},
	// Twilio auth tokens: "twilio" (case-insensitive) near a 32-char hex string
	{
		re:       regexp.MustCompile(`(?i)twilio.*[0-9a-f]{32}`),
		label:    "twilio-token",
		severity: "medium",
		prefix:   "",
	},
}
