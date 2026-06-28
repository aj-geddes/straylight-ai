package proxy_test

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/straylight-ai/straylight/internal/proxy"
	"github.com/straylight-ai/straylight/internal/services"
)

// TestAWSSigV4Injector_CanonicalQuerySpacesEncodedAsPercent20 verifies that query
// parameter values containing spaces are encoded as %20 (RFC 3986), not as +
// (application/x-www-form-urlencoded). AWS SigV4 requires %20; using + produces
// a different canonical query string and therefore a wrong signature that AWS
// will reject.
//
// Expected signature (canonical query uses %20):
//
//	19ae0c45426639a4aba143ac40afd2ccbdbd0c36058777c1e5b8372b9db99e15
//
// Buggy signature (canonical query uses +):
//
//	abd8e25f3c3657dbe42e1f47e8db9b8e4f14bda687013e6410fab31d18109909
//
// These values were computed against the AWS SigV4 reference algorithm with
// the canonical request pinned below.
func TestAWSSigV4Injector_CanonicalQuerySpacesEncodedAsPercent20(t *testing.T) {
	pinnedTime := time.Date(2013, 5, 24, 0, 0, 0, 0, time.UTC)

	// Build a GET request whose RawQuery encodes spaces as %20 (proper).
	// After url.Parse, URL.Query() will decode these to " "; the issue is
	// whether URL.Query().Encode() re-encodes them as "+" or "%20".
	req, err := http.NewRequest(http.MethodGet, "https://example.amazonaws.com/?Prefix=my%20key&token=abc%20def", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header = make(http.Header)

	inj := &proxy.AWSSigV4Injector{
		Now: func() time.Time { return pinnedTime },
	}
	cfg := services.InjectionConfig{
		Type: services.InjectionAWSSigV4,
		Sign: &services.SignSpec{
			AWS: &services.AWSSignSpec{
				Region:  "us-east-1",
				Service: "s3",
			},
		},
	}
	fields := map[string]string{
		"access_key_id":     "AKIAIOSFODNN7EXAMPLE",
		"secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	}

	if err := inj.Inject(req, fields, cfg); err != nil {
		t.Fatalf("Inject() error = %v", err)
	}

	auth := req.Header.Get("Authorization")
	if !strings.Contains(auth, "Signature=") {
		t.Fatalf("Authorization header missing Signature=: %q", auth)
	}

	// Extract the hex signature value.
	sigIdx := strings.Index(auth, "Signature=")
	got := auth[sigIdx+len("Signature="):]
	if comma := strings.IndexByte(got, ','); comma >= 0 {
		got = got[:comma]
	}

	// Correct AWS SigV4 signature for this request (spaces as %20).
	const wantSignature = "19ae0c45426639a4aba143ac40afd2ccbdbd0c36058777c1e5b8372b9db99e15"
	// Buggy signature (url.Values.Encode uses + for spaces): abd8e25f3c3657dbe42e1f47e8db9b8e4f14bda687013e6410fab31d18109909
	if got != wantSignature {
		t.Errorf("SigV4 signature mismatch:\n  got  = %s\n  want = %s\n  (if got matches abd8e25f..., the canonical query used '+' instead of '%%20' for spaces)", got, wantSignature)
	}
}

// TestAWSSigV4Injector_CanonicalQuerySortsByEncodedKey verifies that query
// parameters are sorted by their URI-encoded key names (RFC 3986 percent-encoding),
// not their decoded key names. url.Values.Encode() sorts by decoded key, which
// can differ from encoded-key order for keys containing characters that percent-encode
// to a byte sequence with a different sort position than the raw character.
//
// This test uses the same well-defined request as CanonicalQuerySpacesEncodedAsPercent20
// and asserts that the final signature is deterministic and correct.
func TestAWSSigV4Injector_CanonicalQuerySortsByEncodedKey(t *testing.T) {
	pinnedTime := time.Date(2013, 5, 24, 0, 0, 0, 0, time.UTC)

	// Request with two query params where encoded sort matches RFC 3986 order.
	// After fix: canonical query must be "Prefix=my%20key&token=abc%20def" (P before t).
	req, err := http.NewRequest(http.MethodGet, "https://example.amazonaws.com/?token=abc%20def&Prefix=my%20key", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header = make(http.Header)

	inj := &proxy.AWSSigV4Injector{
		Now: func() time.Time { return pinnedTime },
	}
	cfg := services.InjectionConfig{
		Type: services.InjectionAWSSigV4,
		Sign: &services.SignSpec{
			AWS: &services.AWSSignSpec{
				Region:  "us-east-1",
				Service: "s3",
			},
		},
	}
	fields := map[string]string{
		"access_key_id":     "AKIAIOSFODNN7EXAMPLE",
		"secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	}

	if err := inj.Inject(req, fields, cfg); err != nil {
		t.Fatalf("Inject() error = %v", err)
	}

	auth := req.Header.Get("Authorization")
	sigIdx := strings.Index(auth, "Signature=")
	if sigIdx < 0 {
		t.Fatalf("Authorization header missing Signature=: %q", auth)
	}
	got := auth[sigIdx+len("Signature="):]
	if comma := strings.IndexByte(got, ','); comma >= 0 {
		got = got[:comma]
	}

	// The canonical query must be "Prefix=my%20key&token=abc%20def" regardless of
	// the original order in the URL (SigV4 requires sorting). This is the same
	// expected signature as the previous test because only the sort order differs —
	// both inputs produce the same sorted canonical query.
	const wantSignature = "19ae0c45426639a4aba143ac40afd2ccbdbd0c36058777c1e5b8372b9db99e15"
	if got != wantSignature {
		t.Errorf("SigV4 canonical query sort mismatch:\n  got  = %s\n  want = %s", got, wantSignature)
	}
}
