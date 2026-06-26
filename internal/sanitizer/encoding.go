// Package sanitizer implements output sanitization to detect and redact credentials.
package sanitizer

import (
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// Pre-compiled regexes for locating candidate encoded spans in text.
// Minimum lengths are chosen so that the smallest detectable credential
// (AKIA + 16 chars = 20 bytes) encodes to at least that many characters
// in each scheme, with margin for false-positive suppression.
var (
	// encodedStdBase64 matches standard-base64 runs long enough to encode a
	// 20-byte credential (ceil(20/3)*4 = 28 chars), plus margin.
	encodedStdBase64 = regexp.MustCompile(`[A-Za-z0-9+/]{28,}={0,2}`)

	// encodedURLBase64 matches URL-safe base64 with the same length bound.
	encodedURLBase64 = regexp.MustCompile(`[A-Za-z0-9_-]{28,}={0,2}`)

	// encodedHex matches even-length hex runs long enough to encode 20 bytes
	// (40 hex chars). We require even length for valid byte decoding.
	encodedHex = regexp.MustCompile(`[0-9a-fA-F]{40,}`)

	// encodedPct matches three or more consecutive %XX triplets so that a
	// 20-byte credential encoded per-byte (%41%4B... = 60 chars = 20 triplets)
	// is covered. Three triplets (9 chars, 3 decoded bytes) is the minimum
	// guard — pattern matching on the decoded text handles the rest.
	encodedPct = regexp.MustCompile(`(?:%[0-9A-Fa-f]{2}){3,}`)
)

// encodedSpan records a span in the original string and its replacement label.
type encodedSpan struct {
	start int
	end   int
	label string // full "[REDACTED:xxx]" string
}

// applyEncodedMatching scans input for base64-, hex-, and percent-encoded
// credential spans. For each candidate span it decodes the bytes, runs
// applyPatternMatching on the decoded text, and — if a credential is found —
// replaces the ORIGINAL encoded span in the output with the redaction label
// from the inner match. The rest of the document is left unchanged.
//
// Replacements are applied right-to-left so that byte offsets remain valid
// across successive substitutions.
func applyEncodedMatching(input string) string {
	if input == "" {
		return input
	}

	var spans []encodedSpan

	spans = append(spans, findBase64Spans(input, encodedStdBase64, base64.StdEncoding)...)
	spans = append(spans, findBase64Spans(input, encodedURLBase64, base64.URLEncoding)...)
	spans = append(spans, findHexSpans(input)...)
	spans = append(spans, findPctSpans(input)...)

	if len(spans) == 0 {
		return input
	}

	// Deduplicate and sort by start descending so right-to-left replacement
	// does not corrupt byte offsets. When two spans overlap, the first one
	// (lowest start) wins; overlapping later ones are dropped.
	spans = deduplicateSpans(spans)

	result := input
	for i := len(spans) - 1; i >= 0; i-- {
		sp := spans[i]
		result = result[:sp.start] + sp.label + result[sp.end:]
	}
	return result
}

// findBase64Spans returns spans for base64-encoded credentials using enc.
func findBase64Spans(input string, re *regexp.Regexp, enc *base64.Encoding) []encodedSpan {
	var spans []encodedSpan
	for _, loc := range re.FindAllStringIndex(input, -1) {
		start, end := loc[0], loc[1]
		candidate := input[start:end]

		decoded, err := enc.DecodeString(candidate)
		if err != nil {
			// Padding might be off; try raw variant (no padding).
			rawEnc := enc.WithPadding(base64.NoPadding)
			trimmed := strings.TrimRight(candidate, "=")
			decoded, err = rawEnc.DecodeString(trimmed)
			if err != nil {
				continue
			}
		}

		label := matchedRedactionLabel(string(decoded))
		if label != "" {
			spans = append(spans, encodedSpan{start, end, label})
		}
	}
	return spans
}

// findHexSpans returns spans for hex-encoded credentials.
func findHexSpans(input string) []encodedSpan {
	var spans []encodedSpan
	for _, loc := range encodedHex.FindAllStringIndex(input, -1) {
		start, end := loc[0], loc[1]
		candidate := input[start:end]

		// Hex decoding requires even length; trim one char if odd.
		if len(candidate)%2 != 0 {
			candidate = candidate[:len(candidate)-1]
			end = start + len(candidate)
		}

		decoded, err := hex.DecodeString(candidate)
		if err != nil {
			continue
		}

		label := matchedRedactionLabel(string(decoded))
		if label != "" {
			spans = append(spans, encodedSpan{start, end, label})
		}
	}
	return spans
}

// findPctSpans returns spans for percent-encoded credentials.
func findPctSpans(input string) []encodedSpan {
	var spans []encodedSpan
	for _, loc := range encodedPct.FindAllStringIndex(input, -1) {
		start, end := loc[0], loc[1]
		candidate := input[start:end]

		decoded, err := url.QueryUnescape(candidate)
		if err != nil {
			continue
		}

		label := matchedRedactionLabel(decoded)
		if label != "" {
			spans = append(spans, encodedSpan{start, end, label})
		}
	}
	return spans
}

// matchedRedactionLabel runs applyPatternMatching on text and returns the
// first [REDACTED:...] label found in the output, or "" if the text was
// unchanged (i.e., no credential detected).
func matchedRedactionLabel(text string) string {
	result := applyPatternMatching(text)
	if result == text {
		return ""
	}
	// Extract the first [REDACTED:...] token from the result.
	start := strings.Index(result, "[REDACTED:")
	if start == -1 {
		return ""
	}
	end := strings.IndexByte(result[start:], ']')
	if end == -1 {
		return ""
	}
	return result[start : start+end+1]
}

// deduplicateSpans sorts spans by start position ascending, then removes
// any span that overlaps with a previously retained span. Returns the
// deduplicated slice sorted by start ascending (for right-to-left iteration
// by the caller, which iterates backwards).
func deduplicateSpans(spans []encodedSpan) []encodedSpan {
	sort.Slice(spans, func(i, j int) bool {
		return spans[i].start < spans[j].start
	})

	kept := spans[:0]
	maxEnd := -1
	for _, sp := range spans {
		if sp.start < maxEnd {
			// Overlaps with an already-retained span; skip.
			continue
		}
		kept = append(kept, sp)
		if sp.end > maxEnd {
			maxEnd = sp.end
		}
	}
	return kept
}
