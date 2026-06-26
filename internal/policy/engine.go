// Package policy gates tool calls on request shape (HTTP method, path-prefix,
// destination host) against a per-service, default-deny-when-configured policy.
// It is evaluated BEFORE any credential is injected.
package policy

import (
	"net/url"
	"path"
	"strings"
)

// Request is the credential-free shape of a tool call being evaluated.
type Request struct {
	Service string // name of the configured service
	Method  string // upper-cased HTTP method; "" for non-HTTP tools (exec)
	Path    string // request path; "" when not applicable
	Host    string // destination host (from the service Target / request)
	Tool    string // e.g. "straylight_api_call", "straylight_exec"
}

// Decision is the outcome of an evaluation. Reason is safe to log, audit, or
// surface to the agent and never contains credential material.
type Decision struct {
	Allowed bool
	Reason  string
}

// Policy is the per-service rule set. A nil/zero Policy allows everything
// (backward compatibility). Within a configured dimension, only listed values
// are permitted (default-deny per dimension).
type Policy struct {
	// AllowedMethods, when non-empty, restricts to these HTTP methods
	// (case-insensitive). Empty = all methods allowed.
	AllowedMethods []string
	// AllowedPathPrefixes, when non-empty, requires the cleaned request path
	// to start with one of these prefixes. Empty = all paths allowed.
	AllowedPathPrefixes []string
	// AllowedHosts, when non-empty, restricts to these destination hosts
	// (exact or "*.suffix"). Empty = all hosts allowed.
	AllowedHosts []string
}

// Engine evaluates Requests against Policies.
type Engine interface {
	Evaluate(req Request, pol Policy) Decision
}

// engine is the concrete, stateless implementation of Engine.
type engine struct{}

// New returns the default Engine.
func New() Engine {
	return &engine{}
}

// Evaluate applies pol to req and returns a Decision. It is a pure function
// with no side effects; callers are responsible for emitting audit events on deny.
//
// Evaluation order (cheapest first):
//  1. Zero policy -> allow (compat).
//  2. Method check.
//  3. Host check.
//  4. Path check (path is cleaned after percent-decode to defeat traversal).
//  5. All configured dimensions passed -> allow.
func (e *engine) Evaluate(req Request, pol Policy) Decision {
	if isZeroPolicy(pol) {
		return Decision{Allowed: true, Reason: "allowed by default"}
	}

	if len(pol.AllowedMethods) > 0 {
		methodUpper := strings.ToUpper(req.Method)
		permitted := false
		for _, m := range pol.AllowedMethods {
			if strings.ToUpper(m) == methodUpper {
				permitted = true
				break
			}
		}
		if !permitted {
			return Decision{Allowed: false, Reason: "method " + req.Method + " not permitted for service " + req.Service}
		}
	}

	if len(pol.AllowedHosts) > 0 {
		permitted := false
		for _, h := range pol.AllowedHosts {
			if matchHost(req.Host, h) {
				permitted = true
				break
			}
		}
		if !permitted {
			return Decision{Allowed: false, Reason: "host " + req.Host + " not permitted for service " + req.Service}
		}
	}

	if len(pol.AllowedPathPrefixes) > 0 {
		cleanedPath := cleanPath(req.Path)
		permitted := false
		for _, prefix := range pol.AllowedPathPrefixes {
			if strings.HasPrefix(cleanedPath, prefix) {
				permitted = true
				break
			}
		}
		if !permitted {
			return Decision{Allowed: false, Reason: "path " + cleanedPath + " not permitted for service " + req.Service}
		}
	}

	return Decision{Allowed: true, Reason: "allowed"}
}

// isZeroPolicy reports whether pol has no configured dimensions.
// A zero policy preserves backward-compatible allow-all behavior.
func isZeroPolicy(pol Policy) bool {
	return len(pol.AllowedMethods) == 0 &&
		len(pol.AllowedPathPrefixes) == 0 &&
		len(pol.AllowedHosts) == 0
}

// matchHost reports whether actual matches the allowed host pattern.
// Supports exact match or wildcard "*.suffix" (e.g., "*.stripe.com" matches
// "api.stripe.com" but not bare "stripe.com").
func matchHost(actual, allowed string) bool {
	if actual == allowed {
		return true
	}
	if strings.HasPrefix(allowed, "*.") {
		suffix := allowed[1:] // ".stripe.com"
		return strings.HasSuffix(actual, suffix) && len(actual) > len(suffix)
	}
	return false
}

// cleanPath percent-decodes rawPath and then applies path.Clean to defeat
// directory traversal attacks (e.g. "/v1/../admin" -> "/v1/admin") and
// percent-encoded variants ("%2e%2e" -> "..").
func cleanPath(rawPath string) string {
	decoded, err := url.PathUnescape(rawPath)
	if err != nil {
		decoded = rawPath
	}
	return path.Clean(decoded)
}
