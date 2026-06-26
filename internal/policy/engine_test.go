// Package policy gates tool calls on request shape before credential injection.
package policy

import (
	"testing"
)

// TestEvaluate_ZeroPolicy verifies that a zero/nil Policy allows everything
// (backward compatibility -- existing services with no policy are unaffected).
func TestEvaluate_ZeroPolicy(t *testing.T) {
	eng := New()
	dec := eng.Evaluate(Request{
		Service: "stripe",
		Method:  "DELETE",
		Path:    "/v1/charges/ch_1",
		Host:    "api.stripe.com",
		Tool:    "straylight_api_call",
	}, Policy{})
	if !dec.Allowed {
		t.Errorf("zero policy: expected Allowed=true, got false (reason: %s)", dec.Reason)
	}
}

// TestEvaluate_MethodDenied verifies that a disallowed HTTP method is rejected.
func TestEvaluate_MethodDenied(t *testing.T) {
	eng := New()
	pol := Policy{AllowedMethods: []string{"GET"}}

	tests := []struct {
		name   string
		method string
	}{
		{"POST denied", "POST"},
		{"DELETE denied", "DELETE"},
		{"PUT denied", "PUT"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dec := eng.Evaluate(Request{
				Service: "stripe",
				Method:  tt.method,
				Host:    "api.stripe.com",
				Tool:    "straylight_api_call",
			}, pol)
			if dec.Allowed {
				t.Errorf("method %q: expected Denied, got Allowed", tt.method)
			}
			if dec.Reason == "" {
				t.Error("expected non-empty Reason on deny")
			}
		})
	}
}

// TestEvaluate_MethodAllowed verifies that an allowed method passes the gate.
func TestEvaluate_MethodAllowed(t *testing.T) {
	eng := New()
	pol := Policy{AllowedMethods: []string{"GET"}}
	dec := eng.Evaluate(Request{
		Service: "stripe",
		Method:  "GET",
		Host:    "api.stripe.com",
		Tool:    "straylight_api_call",
	}, pol)
	if !dec.Allowed {
		t.Errorf("GET with AllowedMethods:[GET]: expected Allowed, got Denied (reason: %s)", dec.Reason)
	}
}

// TestEvaluate_MethodCaseInsensitive verifies lowercase method strings are normalized.
func TestEvaluate_MethodCaseInsensitive(t *testing.T) {
	eng := New()
	pol := Policy{AllowedMethods: []string{"GET"}}
	dec := eng.Evaluate(Request{
		Service: "stripe",
		Method:  "get",
		Host:    "api.stripe.com",
		Tool:    "straylight_api_call",
	}, pol)
	if !dec.Allowed {
		t.Errorf("lowercase 'get' should match AllowedMethods:[GET], got Denied (reason: %s)", dec.Reason)
	}
}

// TestEvaluate_PathPrefixDenied verifies that a request with a non-matching path
// is rejected when AllowedPathPrefixes is configured.
func TestEvaluate_PathPrefixDenied(t *testing.T) {
	eng := New()
	pol := Policy{AllowedPathPrefixes: []string{"/v1/charges"}}
	dec := eng.Evaluate(Request{
		Service: "stripe",
		Method:  "GET",
		Path:    "/v1/refunds",
		Host:    "api.stripe.com",
		Tool:    "straylight_api_call",
	}, pol)
	if dec.Allowed {
		t.Errorf("path /v1/refunds with prefix [/v1/charges]: expected Denied, got Allowed")
	}
}

// TestEvaluate_PathPrefixAllowed verifies that a matching path prefix allows the call.
func TestEvaluate_PathPrefixAllowed(t *testing.T) {
	eng := New()
	pol := Policy{AllowedPathPrefixes: []string{"/v1/charges"}}
	dec := eng.Evaluate(Request{
		Service: "stripe",
		Method:  "GET",
		Path:    "/v1/charges/ch_1",
		Host:    "api.stripe.com",
		Tool:    "straylight_api_call",
	}, pol)
	if !dec.Allowed {
		t.Errorf("path /v1/charges/ch_1 with prefix [/v1/charges]: expected Allowed, got Denied (reason: %s)", dec.Reason)
	}
}

// TestEvaluate_PathTraversalCleaned verifies that path traversal sequences are
// cleaned before prefix matching, defeating /v1/../admin style escapes.
func TestEvaluate_PathTraversalCleaned(t *testing.T) {
	eng := New()
	pol := Policy{AllowedPathPrefixes: []string{"/v1/charges"}}
	dec := eng.Evaluate(Request{
		Service: "stripe",
		Method:  "GET",
		Path:    "/v1/charges/../admin",
		Host:    "api.stripe.com",
		Tool:    "straylight_api_call",
	}, pol)
	if dec.Allowed {
		t.Errorf("path /v1/charges/../admin should be cleaned to /v1/admin and denied, got Allowed")
	}
}

// TestEvaluate_PathPercentDecoded verifies that percent-encoded traversal is decoded
// before cleaning, defeating %%2e%2e style escapes.
func TestEvaluate_PathPercentDecoded(t *testing.T) {
	eng := New()
	pol := Policy{AllowedPathPrefixes: []string{"/v1/charges"}}
	dec := eng.Evaluate(Request{
		Service: "stripe",
		Method:  "GET",
		Path:    "/v1/charges/%2e%2e/admin",
		Host:    "api.stripe.com",
		Tool:    "straylight_api_call",
	}, pol)
	if dec.Allowed {
		t.Errorf("percent-encoded path /v1/charges/%%2e%%2e/admin should be denied after cleaning, got Allowed")
	}
}

// TestEvaluate_HostDenied verifies that a non-matching host is rejected when
// AllowedHosts is configured.
func TestEvaluate_HostDenied(t *testing.T) {
	eng := New()
	pol := Policy{AllowedHosts: []string{"api.stripe.com"}}
	dec := eng.Evaluate(Request{
		Service: "stripe",
		Method:  "GET",
		Path:    "/v1/charges",
		Host:    "attacker.example.com",
		Tool:    "straylight_api_call",
	}, pol)
	if dec.Allowed {
		t.Errorf("host attacker.example.com with AllowedHosts:[api.stripe.com]: expected Denied, got Allowed")
	}
}

// TestEvaluate_HostAllowedExact verifies exact host matching.
func TestEvaluate_HostAllowedExact(t *testing.T) {
	eng := New()
	pol := Policy{AllowedHosts: []string{"api.stripe.com"}}
	dec := eng.Evaluate(Request{
		Service: "stripe",
		Method:  "GET",
		Path:    "/v1/charges",
		Host:    "api.stripe.com",
		Tool:    "straylight_api_call",
	}, pol)
	if !dec.Allowed {
		t.Errorf("exact host match api.stripe.com: expected Allowed, got Denied (reason: %s)", dec.Reason)
	}
}

// TestEvaluate_HostAllowedWildcard verifies wildcard *.suffix host matching.
func TestEvaluate_HostAllowedWildcard(t *testing.T) {
	eng := New()
	pol := Policy{AllowedHosts: []string{"*.stripe.com"}}
	dec := eng.Evaluate(Request{
		Service: "stripe",
		Method:  "GET",
		Path:    "/v1/charges",
		Host:    "api.stripe.com",
		Tool:    "straylight_api_call",
	}, pol)
	if !dec.Allowed {
		t.Errorf("wildcard *.stripe.com should match api.stripe.com: expected Allowed, got Denied (reason: %s)", dec.Reason)
	}
}

// TestEvaluate_HostWildcardNotMatchesParentDomain verifies *.suffix does not match
// the bare suffix (e.g. *.stripe.com must not match stripe.com).
func TestEvaluate_HostWildcardNotMatchesParentDomain(t *testing.T) {
	eng := New()
	pol := Policy{AllowedHosts: []string{"*.stripe.com"}}
	dec := eng.Evaluate(Request{
		Service: "stripe",
		Method:  "GET",
		Path:    "/v1/charges",
		Host:    "stripe.com",
		Tool:    "straylight_api_call",
	}, pol)
	if dec.Allowed {
		t.Errorf("*.stripe.com should NOT match bare stripe.com: expected Denied, got Allowed")
	}
}

// TestEvaluate_AllDimensionsPass verifies a request that satisfies all three
// configured dimensions is allowed.
func TestEvaluate_AllDimensionsPass(t *testing.T) {
	eng := New()
	pol := Policy{
		AllowedMethods:      []string{"GET", "POST"},
		AllowedPathPrefixes: []string{"/v1/charges", "/v1/customers"},
		AllowedHosts:        []string{"api.stripe.com"},
	}
	dec := eng.Evaluate(Request{
		Service: "stripe",
		Method:  "POST",
		Path:    "/v1/customers",
		Host:    "api.stripe.com",
		Tool:    "straylight_api_call",
	}, pol)
	if !dec.Allowed {
		t.Errorf("fully-matching request: expected Allowed, got Denied (reason: %s)", dec.Reason)
	}
}

// TestEvaluate_OneDimensionFailsDeniesAll verifies that failing any one configured
// dimension causes denial, even when the other dimensions would pass.
func TestEvaluate_OneDimensionFailsDeniesAll(t *testing.T) {
	eng := New()
	pol := Policy{
		AllowedMethods:      []string{"GET"},
		AllowedPathPrefixes: []string{"/v1/charges"},
		AllowedHosts:        []string{"api.stripe.com"},
	}
	dec := eng.Evaluate(Request{
		Service: "stripe",
		Method:  "DELETE",
		Path:    "/v1/charges",
		Host:    "api.stripe.com",
		Tool:    "straylight_api_call",
	}, pol)
	if dec.Allowed {
		t.Errorf("failing method dimension: expected Denied, got Allowed")
	}
}

// TestEvaluate_PartialPolicy_OnlyMethodConfigured verifies that when only
// AllowedMethods is set, path and host dimensions are unrestricted.
func TestEvaluate_PartialPolicy_OnlyMethodConfigured(t *testing.T) {
	eng := New()
	pol := Policy{AllowedMethods: []string{"GET"}}
	dec := eng.Evaluate(Request{
		Service: "stripe",
		Method:  "GET",
		Path:    "/any/path",
		Host:    "any.host.example.com",
		Tool:    "straylight_api_call",
	}, pol)
	if !dec.Allowed {
		t.Errorf("only method configured, GET matches: expected Allowed, got Denied (reason: %s)", dec.Reason)
	}
}
