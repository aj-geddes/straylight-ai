// Package egress enforces a default-deny outbound network policy: SSRF target
// classes (cloud metadata, link-local, private ranges) are blocked unless a
// per-service allowlist explicitly permits the destination host or CIDR.
//
// The authoritative check runs inside the proxy's DialContext on the IP that
// the dialer actually connects to, defeating DNS rebinding and covering
// redirect re-dials (ADR-010).
package egress

import (
	"context"
	"fmt"
	"net"
)

// Decision is the outcome of an egress check.
type Decision struct {
	// Allowed reports whether the destination is permitted.
	Allowed bool
	// Reason is a human-readable explanation safe to log or audit.
	// Never contains credential material.
	Reason string
}

// Policy is the per-service egress allowlist evaluated by a Guard.
// A nil/zero Policy means "default denylist only" (block SSRF classes,
// allow public destinations).
type Policy struct {
	// AllowHosts are destination hostnames permitted even if they resolve into
	// an otherwise-denied range. Exact string match only in v1.
	AllowHosts []string
	// AllowCIDRs are IP ranges explicitly permitted (e.g. an internal API at
	// 10.x). Empty = no private ranges permitted.
	AllowCIDRs []string
	// AllowLoopback permits 127.0.0.0/8 and ::1 (dev/local upstreams).
	AllowLoopback bool
}

// Guard classifies destinations against the default denylist and a Policy.
type Guard interface {
	// CheckIP classifies a single resolved IP against policy. This is the
	// authoritative check; it runs inside the proxy dialer on the IP actually
	// being connected to, defeating DNS rebinding.
	CheckIP(ip net.IP, policy Policy) Decision

	// CheckHost resolves host and applies CheckIP to every resulting address,
	// denying if ANY resolved address is denied (fail-closed). Used as the
	// pre-dial fast-filter on the proxy path and as the best-effort pre-flight
	// check on the exec path.
	CheckHost(ctx context.Context, host string, policy Policy) Decision
}

// deniedNet pairs a denylist network with a human-readable denial reason.
type deniedNet struct {
	network *net.IPNet
	reason  string
}

// guard is the concrete implementation of Guard.
type guard struct {
	denylist []deniedNet
}

// Compile-time assertion that *guard implements Guard.
var _ Guard = (*guard)(nil)

// New returns the default Guard seeded with the built-in SSRF denylist.
// The denylist is built once at construction time.
func New() Guard {
	return &guard{
		denylist: []deniedNet{
			{mustParseCIDR("169.254.169.254/32"), "cloud metadata endpoint (IMDS)"},
			{mustParseCIDR("169.254.0.0/16"), "link-local IPv4"},
			{mustParseCIDR("fe80::/10"), "link-local IPv6 (fe80::/10)"},
			{mustParseCIDR("10.0.0.0/8"), "private range (RFC1918 10/8)"},
			{mustParseCIDR("172.16.0.0/12"), "private range (RFC1918 172.16/12)"},
			{mustParseCIDR("192.168.0.0/16"), "private range (RFC1918 192.168/16)"},
			{mustParseCIDR("100.64.0.0/10"), "CGNAT (RFC6598)"},
			{mustParseCIDR("fc00::/7"), "unique-local IPv6 (fc00::/7)"},
			{mustParseCIDR("127.0.0.0/8"), "loopback IPv4"},
			{mustParseCIDR("::1/128"), "loopback IPv6"},
			{mustParseCIDR("0.0.0.0/8"), "unspecified address"},
		},
	}
}

// mustParseCIDR parses a CIDR string and panics if it is invalid.
// Only called with compile-time string literals in New(), so a panic here
// indicates a programming error, not a runtime condition.
func mustParseCIDR(cidr string) *net.IPNet {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		panic(fmt.Sprintf("egress: invalid denylist CIDR %q: %v", cidr, err))
	}
	return ipNet
}

// CheckIP classifies ip against policy and the built-in denylist.
//
// Order of precedence:
//  1. Unmap IPv4-in-IPv6 so the same denylist entries cover both forms.
//  2. AllowLoopback policy → allowed if loopback.
//  3. AllowCIDRs policy   → allowed if in any listed CIDR.
//  4. Denylist            → denied if in any denylist net.
//  5. Default             → allowed (public destination).
func (g *guard) CheckIP(ip net.IP, policy Policy) Decision {
	if ip == nil {
		return Decision{Allowed: false, Reason: "invalid IP address"}
	}

	// Unmap IPv4-mapped IPv6 (::ffff:x.x.x.x) so denylist IPv4 nets match.
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}

	// AllowLoopback overrides the denylist for loopback addresses only.
	if policy.AllowLoopback && ip.IsLoopback() {
		return Decision{Allowed: true, Reason: "allowed by policy: loopback"}
	}

	// AllowCIDRs: explicit per-service allowlist overrides the denylist.
	for _, cidr := range policy.AllowCIDRs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue // skip malformed CIDR entries
		}
		if ipNet.Contains(ip) {
			return Decision{Allowed: true, Reason: "allowed by policy: CIDR " + cidr}
		}
	}

	// Denylist check — fail-closed for any matching network.
	for _, denied := range g.denylist {
		if denied.network.Contains(ip) {
			return Decision{Allowed: false, Reason: "blocked: " + denied.reason}
		}
	}

	return Decision{Allowed: true, Reason: "allowed"}
}

// CheckHost resolves host and applies CheckIP to every resulting address.
// The check is fail-closed: if ANY resolved address is denied, the call
// returns denied immediately. This is also the pre-flight check for the
// exec path (best-effort, since child processes own their own sockets).
func (g *guard) CheckHost(ctx context.Context, host string, policy Policy) Decision {
	// AllowHosts: exact host match bypasses IP resolution entirely.
	for _, allowed := range policy.AllowHosts {
		if host == allowed {
			return Decision{Allowed: true, Reason: "allowed by policy: host " + host}
		}
	}

	// If host is an IP literal, classify it directly without DNS.
	if ip := net.ParseIP(host); ip != nil {
		return g.CheckIP(ip, policy)
	}

	// Resolve the hostname; fail-closed on resolution error.
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return Decision{Allowed: false, Reason: "resolution failed: " + err.Error()}
	}

	// Fail-closed: deny if ANY resolved address is denied.
	for _, addr := range addrs {
		if d := g.CheckIP(addr.IP, policy); !d.Allowed {
			return d
		}
	}

	return Decision{Allowed: true, Reason: "allowed"}
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// allowAllGuard is a Guard that permits every destination. Intended for use
// in unit tests that target httptest loopback servers without needing a real
// egress policy.
type allowAllGuard struct{}

// AllowAll returns a Guard that permits every IP and host. Use in tests only.
func AllowAll() Guard {
	return allowAllGuard{}
}

func (allowAllGuard) CheckIP(_ net.IP, _ Policy) Decision {
	return Decision{Allowed: true, Reason: "allow-all (test guard)"}
}

func (allowAllGuard) CheckHost(_ context.Context, _ string, _ Policy) Decision {
	return Decision{Allowed: true, Reason: "allow-all (test guard)"}
}

// Compile-time assertion that allowAllGuard implements Guard.
var _ Guard = allowAllGuard{}
