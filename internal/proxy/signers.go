// Package proxy — HMACInjector and AWSSigV4Injector signer implementations.
package proxy

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"text/template"
	"time"

	"github.com/straylight-ai/straylight/internal/services"
)

// ---------------------------------------------------------------------------
// HMACInjector
// ---------------------------------------------------------------------------

// HMACInjector computes an HMAC signature over a configurable signed-string
// template and sets the result in a named request header.
// It is stateless except for the injectable clock (Now), shared across goroutines.
type HMACInjector struct {
	// Now returns the current time. Defaults to time.Now when nil. Inject an
	// alternate clock in tests to produce deterministic signatures.
	Now func() time.Time
}

// Inject computes the HMAC signature and sets the configured header on req.
// Body, if present, is read, hashed/included, and restored so downstream
// consumers can still read it.
func (h *HMACInjector) Inject(req *http.Request, fields map[string]string, config services.InjectionConfig) error {
	if config.Sign == nil || config.Sign.HMAC == nil {
		return fmt.Errorf("hmac_signature: Sign.HMAC config is nil")
	}
	spec := config.Sign.HMAC

	// Validate algorithm early (fail-closed).
	switch spec.Algorithm {
	case "sha256", "sha512":
	default:
		return fmt.Errorf("hmac_signature: unsupported algorithm %q (must be sha256 or sha512)", spec.Algorithm)
	}

	// Resolve HMAC key from credential fields.
	key, ok := fields[spec.SecretField]
	if !ok {
		return fmt.Errorf("hmac_signature: credential field %q not found", spec.SecretField)
	}

	// Read and restore the body.
	var bodyBytes []byte
	if req.Body != nil {
		var err error
		bodyBytes, err = io.ReadAll(req.Body)
		if err != nil {
			return fmt.Errorf("hmac_signature: reading body: %w", err)
		}
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	}

	// Compute timestamp (unix seconds as string) if requested.
	var tsStr string
	if spec.IncludeTimestamp {
		now := h.now()
		tsStr = fmt.Sprintf("%d", now.Unix())
		if spec.TimestampHeader != "" {
			req.Header.Set(spec.TimestampHeader, tsStr)
		}
	}

	// Build template data: timestamp, method, path, body, plus all fields.
	data := make(map[string]interface{}, len(fields)+4)
	for k, v := range fields {
		data[k] = v
	}
	data["timestamp"] = tsStr
	data["method"] = req.Method
	data["path"] = req.URL.Path
	data["body"] = string(bodyBytes)

	// Render the signed-string template.
	signed, err := renderSignedString(spec.SignedString, data)
	if err != nil {
		return fmt.Errorf("hmac_signature: rendering signed_string: %w", err)
	}

	// Compute HMAC.
	mac, err := computeHMAC(spec.Algorithm, []byte(key), []byte(signed))
	if err != nil {
		return fmt.Errorf("hmac_signature: computing HMAC: %w", err)
	}

	// Encode.
	var encoded string
	switch spec.Encoding {
	case "hex":
		encoded = hex.EncodeToString(mac)
	case "base64":
		encoded = base64.StdEncoding.EncodeToString(mac)
	default:
		return fmt.Errorf("hmac_signature: unsupported encoding %q (must be hex or base64)", spec.Encoding)
	}

	req.Header.Set(spec.HeaderName, spec.HeaderPrefix+encoded)
	return nil
}

// now returns h.Now() if set, otherwise time.Now().
func (h *HMACInjector) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now()
}

// computeHMAC computes HMAC using the given algorithm (sha256 or sha512).
func computeHMAC(algorithm string, key, data []byte) ([]byte, error) {
	switch algorithm {
	case "sha256":
		mac := hmac.New(sha256.New, key)
		mac.Write(data)
		return mac.Sum(nil), nil
	case "sha512":
		mac := hmac.New(sha512.New, key)
		mac.Write(data)
		return mac.Sum(nil), nil
	default:
		return nil, fmt.Errorf("unsupported algorithm %q", algorithm)
	}
}

// renderSignedString executes a text/template signed-string with the bounded
// safe function set (same as customAuthFuncs).
func renderSignedString(tmplStr string, data map[string]interface{}) (string, error) {
	t, err := template.New("").Option("missingkey=error").Funcs(customAuthFuncs).Parse(tmplStr)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// ---------------------------------------------------------------------------
// AWSSigV4Injector
// ---------------------------------------------------------------------------

// AWSSigV4Injector computes AWS Signature Version 4 and sets the Authorization
// header (plus X-Amz-Date and, when present, X-Amz-Security-Token).
// Parameterized by region + service so the same signer covers S3-compatible
// stores (R2, MinIO, Spaces, B2) and every SigV4 AWS service.
// Stateless except for the injectable clock; safe to share across goroutines.
type AWSSigV4Injector struct {
	// Now returns the current time. Defaults to time.Now when nil.
	Now func() time.Time
}

// Inject computes SigV4 and sets the appropriate headers on req.
func (a *AWSSigV4Injector) Inject(req *http.Request, fields map[string]string, config services.InjectionConfig) error {
	if config.Sign == nil || config.Sign.AWS == nil {
		return fmt.Errorf("aws_sigv4: Sign.AWS config is nil")
	}
	awsCfg := config.Sign.AWS

	// Resolve credentials from fields.
	accessKeyID, ok := fields["access_key_id"]
	if !ok || accessKeyID == "" {
		return fmt.Errorf("aws_sigv4: credential field 'access_key_id' is required")
	}
	secretAccessKey, ok := fields["secret_access_key"]
	if !ok || secretAccessKey == "" {
		return fmt.Errorf("aws_sigv4: credential field 'secret_access_key' is required")
	}
	sessionToken := fields["session_token"] // optional

	// Region: credential field overrides config.
	region := awsCfg.Region
	if r, ok := fields["region"]; ok && r != "" {
		region = r
	}
	service := awsCfg.Service

	now := a.now()
	dateTime := now.UTC().Format("20060102T150405Z")
	date := dateTime[:8]

	// Read and restore body; compute payload hash.
	var bodyBytes []byte
	if req.Body != nil {
		var err error
		bodyBytes, err = io.ReadAll(req.Body)
		if err != nil {
			return fmt.Errorf("aws_sigv4: reading body: %w", err)
		}
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	}
	payloadHash := hashSHA256Hex(bodyBytes)

	// Set mandatory AWS headers before computing canonical request.
	req.Header.Set("X-Amz-Date", dateTime)
	if sessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", sessionToken)
	}

	// Determine the host header value.
	host := req.URL.Host
	if host == "" {
		host = req.Host
	}
	req.Header.Set("Host", host)

	// Build signed headers list (lowercase, sorted).
	signedHeadersList, canonicalHeaders := buildCanonicalHeaders(req)

	// Build canonical URI (percent-encoded path).
	canonicalURI := req.URL.EscapedPath()
	if canonicalURI == "" {
		canonicalURI = "/"
	}

	// Build canonical query string per AWS SigV4: RFC 3986 percent-encoding
	// with %20 for space (not +), sorted by encoded key then encoded value.
	// url.Values.Encode() is NOT used here because it emits '+' for spaces and
	// sorts by decoded key — both incorrect for SigV4.
	canonicalQuery := awsCanonicalQueryString(req.URL.RawQuery)

	// Canonical request.
	canonicalRequest := strings.Join([]string{
		req.Method,
		canonicalURI,
		canonicalQuery,
		canonicalHeaders,
		signedHeadersList,
		payloadHash,
	}, "\n")

	// String to sign.
	credentialScope := strings.Join([]string{date, region, service, "aws4_request"}, "/")
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		dateTime,
		credentialScope,
		hashSHA256Hex([]byte(canonicalRequest)),
	}, "\n")

	// Derive signing key.
	signingKey := deriveSigningKey(secretAccessKey, date, region, service)

	// Compute signature.
	sigHMAC := hmacSHA256(signingKey, []byte(stringToSign))
	signature := hex.EncodeToString(sigHMAC)

	// Build Authorization header.
	auth := fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		accessKeyID, credentialScope, signedHeadersList, signature,
	)
	req.Header.Set("Authorization", auth)

	return nil
}

// now returns a.Now() if set, otherwise time.Now().
func (a *AWSSigV4Injector) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

// awsPercentEncode encodes s using RFC 3986 percent-encoding as required by AWS
// SigV4: all characters except the unreserved set (A-Z a-z 0-9 - _ . ~) are
// encoded. Spaces become %20, NOT +. This is NOT the same as
// url.QueryEscape / url.Values.Encode which use + for spaces.
func awsPercentEncode(s string) string {
	// Pre-sized buffer: most chars pass through unchanged.
	var buf []byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~' {
			buf = append(buf, c)
		} else {
			buf = append(buf, '%',
				"0123456789ABCDEF"[c>>4],
				"0123456789ABCDEF"[c&0x0F],
			)
		}
	}
	return string(buf)
}

// awsCanonicalQueryString builds the AWS SigV4 canonical query string from a
// raw query string (as found in url.URL.RawQuery). It:
//  1. Splits on '&' to get individual key=value pairs.
//  2. Percent-decodes each key and value (handling existing %XX and + escapes).
//  3. Re-encodes using awsPercentEncode (%20 for spaces, RFC 3986 unreserved set).
//  4. Sorts the resulting encoded key=value pairs lexicographically by encoded key,
//     then by encoded value for duplicate keys.
//  5. Joins with '&'.
//
// An empty rawQuery returns an empty string.
func awsCanonicalQueryString(rawQuery string) string {
	if rawQuery == "" {
		return ""
	}

	type kv struct {
		key string
		val string
	}

	pairs := strings.Split(rawQuery, "&")
	kvs := make([]kv, 0, len(pairs))

	for _, pair := range pairs {
		if pair == "" {
			continue
		}
		k, v, _ := strings.Cut(pair, "=")

		// Decode: both url.QueryUnescape and url.PathUnescape handle %XX;
		// QueryUnescape also treats '+' as space (correct for query strings).
		dk, err := url.QueryUnescape(k)
		if err != nil {
			dk = k
		}
		dv, err := url.QueryUnescape(v)
		if err != nil {
			dv = v
		}

		kvs = append(kvs, kv{
			key: awsPercentEncode(dk),
			val: awsPercentEncode(dv),
		})
	}

	// Sort by encoded key, then by encoded value for ties.
	sort.Slice(kvs, func(i, j int) bool {
		if kvs[i].key != kvs[j].key {
			return kvs[i].key < kvs[j].key
		}
		return kvs[i].val < kvs[j].val
	})

	var sb strings.Builder
	for i, p := range kvs {
		if i > 0 {
			sb.WriteByte('&')
		}
		sb.WriteString(p.key)
		sb.WriteByte('=')
		sb.WriteString(p.val)
	}
	return sb.String()
}

// buildCanonicalHeaders returns the signed-headers string and the canonical
// headers block for AWS SigV4. It includes "host" and all x-amz-* headers,
// plus any other headers we set, sorted alphabetically.
func buildCanonicalHeaders(req *http.Request) (signedHeaders, canonicalHeaders string) {
	// Collect lowercase header names and their trimmed values.
	headers := map[string]string{}

	// Always include host.
	host := req.URL.Host
	if host == "" {
		host = req.Host
	}
	headers["host"] = host

	// Include all headers set by us (x-amz-*, and any others on the request).
	for k, vals := range req.Header {
		lk := strings.ToLower(k)
		// Include host (already added), x-amz-*, and content-type.
		switch {
		case lk == "host":
			// already added
		case strings.HasPrefix(lk, "x-amz-"):
			headers[lk] = strings.TrimSpace(vals[0])
		case lk == "content-type":
			headers[lk] = strings.TrimSpace(vals[0])
		}
	}

	// Sort header names.
	names := make([]string, 0, len(headers))
	for k := range headers {
		names = append(names, k)
	}
	sort.Strings(names)

	var canonLines []string
	for _, n := range names {
		canonLines = append(canonLines, n+":"+headers[n])
	}
	canonicalHeaders = strings.Join(canonLines, "\n") + "\n"
	signedHeaders = strings.Join(names, ";")
	return signedHeaders, canonicalHeaders
}

// deriveSigningKey computes the SigV4 signing key using the HMAC chain:
// HMAC(HMAC(HMAC(HMAC("AWS4"+secret, date), region), service), "aws4_request").
func deriveSigningKey(secret, date, region, service string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secret), []byte(date))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte(service))
	kSigning := hmacSHA256(kService, []byte("aws4_request"))
	return kSigning
}

// hmacSHA256 computes HMAC-SHA256(key, data).
func hmacSHA256(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

// hashSHA256Hex returns the lowercase hex-encoded SHA-256 hash of data.
func hashSHA256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}
