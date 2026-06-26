// Package egress_test contains tests for the default-deny egress guard.
// Tests follow the ADR-010 test plan: every SSRF denylist class must be covered
// by CheckIP tests and must deny.
package egress_test

import (
	"context"
	"net"
	"testing"

	"github.com/straylight-ai/straylight/internal/egress"
)

// ---------------------------------------------------------------------------
// CheckIP — default denylist (no policy overrides)
// ---------------------------------------------------------------------------

func TestCheckIP_DefaultDenylist(t *testing.T) {
	guard := egress.New()
	policy := egress.Policy{} // no allowlist overrides

	tests := []struct {
		name    string
		ip      string
		allowed bool
	}{
		// Cloud instance metadata — primary SSRF target
		{"cloud metadata 169.254.169.254", "169.254.169.254", false},
		// Link-local IPv4 range (covers IMDS and others in 169.254.0.0/16)
		{"link-local IPv4 169.254.1.1", "169.254.1.1", false},
		{"link-local IPv4 edge 169.254.255.255", "169.254.255.255", false},
		// RFC1918 private ranges — all three blocks
		{"RFC1918 10.0.0.1", "10.0.0.1", false},
		{"RFC1918 10.255.255.255", "10.255.255.255", false},
		{"RFC1918 172.16.0.1", "172.16.0.1", false},
		{"RFC1918 172.31.255.255", "172.31.255.255", false},
		{"RFC1918 192.168.0.0", "192.168.0.0", false},
		{"RFC1918 192.168.1.1", "192.168.1.1", false},
		// CGNAT / RFC6598 shared address space
		{"CGNAT 100.64.0.1", "100.64.0.1", false},
		{"CGNAT 100.127.255.255", "100.127.255.255", false},
		// Loopback — denied by default
		{"loopback IPv4 127.0.0.1", "127.0.0.1", false},
		{"loopback IPv4 127.1.2.3", "127.1.2.3", false},
		{"loopback IPv6 ::1", "::1", false},
		// Unspecified / "this host"
		{"unspecified 0.0.0.0", "0.0.0.0", false},
		// Link-local IPv6 (fe80::/10)
		{"link-local IPv6 fe80::1", "fe80::1", false},
		// Unique-local IPv6 (fc00::/7) — covers fc00:: and fd00::
		{"unique-local IPv6 fc00::1", "fc00::1", false},
		{"unique-local IPv6 fd00::1", "fd00::1", false},
		// IPv4-mapped IPv6 — must unmap and re-classify
		{"IPv4-mapped ::ffff:169.254.169.254", "::ffff:169.254.169.254", false},
		{"IPv4-mapped ::ffff:10.0.0.1", "::ffff:10.0.0.1", false},
		{"IPv4-mapped ::ffff:192.168.1.1", "::ffff:192.168.1.1", false},
		// Public IPs — must be allowed
		{"public 1.1.1.1 (Cloudflare)", "1.1.1.1", true},
		{"public 93.184.216.34 (example.com)", "93.184.216.34", true},
		{"public 8.8.8.8 (Google)", "8.8.8.8", true},
		{"public 104.26.10.229", "104.26.10.229", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("failed to parse IP %q", tt.ip)
			}
			d := guard.CheckIP(ip, policy)
			if d.Allowed != tt.allowed {
				t.Errorf("CheckIP(%s) = Allowed:%v Reason:%q, want Allowed:%v",
					tt.ip, d.Allowed, d.Reason, tt.allowed)
			}
			// Denied decisions must carry a non-empty, human-readable reason.
			if !tt.allowed && d.Reason == "" {
				t.Errorf("CheckIP(%s) denied but Reason is empty", tt.ip)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// CheckIP — AllowCIDRs policy override
// ---------------------------------------------------------------------------

func TestCheckIP_AllowCIDRs(t *testing.T) {
	guard := egress.New()

	tests := []struct {
		name       string
		ip         string
		allowCIDRs []string
		want       bool
	}{
		{
			name:       "10.x allowed by 10.0.0.0/8 policy",
			ip:         "10.1.2.3",
			allowCIDRs: []string{"10.0.0.0/8"},
			want:       true,
		},
		{
			name:       "192.168.x allowed by narrow policy CIDR",
			ip:         "192.168.10.5",
			allowCIDRs: []string{"192.168.10.0/24"},
			want:       true,
		},
		{
			name:       "172.16.x allowed by 172.16.0.0/12 policy",
			ip:         "172.16.0.1",
			allowCIDRs: []string{"172.16.0.0/12"},
			want:       true,
		},
		{
			name:       "10.x NOT in narrow allowlist remains denied",
			ip:         "10.2.0.1",
			allowCIDRs: []string{"10.1.0.0/24"},
			want:       false,
		},
		{
			name:       "link-local allowed by explicit link-local CIDR policy",
			ip:         "169.254.169.254",
			allowCIDRs: []string{"169.254.0.0/16"},
			want:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := egress.Policy{AllowCIDRs: tt.allowCIDRs}
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("failed to parse IP %q", tt.ip)
			}
			d := guard.CheckIP(ip, policy)
			if d.Allowed != tt.want {
				t.Errorf("CheckIP(%s, allowCIDRs=%v) = Allowed:%v Reason:%q, want Allowed:%v",
					tt.ip, tt.allowCIDRs, d.Allowed, d.Reason, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// CheckIP — AllowLoopback policy override
// ---------------------------------------------------------------------------

func TestCheckIP_AllowLoopback(t *testing.T) {
	guard := egress.New()

	tests := []struct {
		name          string
		ip            string
		allowLoopback bool
		want          bool
	}{
		{"127.0.0.1 denied by default", "127.0.0.1", false, false},
		{"::1 denied by default", "::1", false, false},
		{"127.0.0.1 allowed when AllowLoopback=true", "127.0.0.1", true, true},
		{"::1 allowed when AllowLoopback=true", "::1", true, true},
		// AllowLoopback does not unlock RFC1918 or link-local
		{"10.0.0.1 still denied with AllowLoopback=true", "10.0.0.1", true, false},
		{"169.254.169.254 still denied with AllowLoopback=true", "169.254.169.254", true, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := egress.Policy{AllowLoopback: tt.allowLoopback}
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("failed to parse IP %q", tt.ip)
			}
			d := guard.CheckIP(ip, policy)
			if d.Allowed != tt.want {
				t.Errorf("CheckIP(%s, allowLoopback=%v) = Allowed:%v Reason:%q, want Allowed:%v",
					tt.ip, tt.allowLoopback, d.Allowed, d.Reason, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// CheckHost — IP literal hosts (no live DNS needed)
// ---------------------------------------------------------------------------

func TestCheckHost_IPLiterals(t *testing.T) {
	guard := egress.New()
	ctx := context.Background()

	tests := []struct {
		name    string
		host    string
		policy  egress.Policy
		allowed bool
	}{
		// Blocked IP literals
		{"metadata IP literal blocked", "169.254.169.254", egress.Policy{}, false},
		{"RFC1918 10.x literal blocked", "10.0.0.1", egress.Policy{}, false},
		{"RFC1918 172.16.x literal blocked", "172.16.0.1", egress.Policy{}, false},
		{"RFC1918 192.168.x literal blocked", "192.168.0.1", egress.Policy{}, false},
		{"loopback 127.0.0.1 literal blocked by default", "127.0.0.1", egress.Policy{}, false},
		// Allowed by policy
		{"loopback allowed by AllowLoopback", "127.0.0.1", egress.Policy{AllowLoopback: true}, true},
		{"RFC1918 allowed by AllowCIDRs", "10.5.5.5", egress.Policy{AllowCIDRs: []string{"10.0.0.0/8"}}, true},
		// Public IP literal allowed
		{"public 1.1.1.1 literal allowed", "1.1.1.1", egress.Policy{}, true},
		{"public 8.8.8.8 literal allowed", "8.8.8.8", egress.Policy{}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := guard.CheckHost(ctx, tt.host, tt.policy)
			if d.Allowed != tt.allowed {
				t.Errorf("CheckHost(%q) = Allowed:%v Reason:%q, want Allowed:%v",
					tt.host, d.Allowed, d.Reason, tt.allowed)
			}
			if !tt.allowed && d.Reason == "" {
				t.Errorf("CheckHost(%q) denied but Reason is empty", tt.host)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// CheckHost — AllowHosts: exact host match permits a blocked IP destination
// ---------------------------------------------------------------------------

func TestCheckHost_AllowHosts_PermitsBlockedIPLiteral(t *testing.T) {
	guard := egress.New()
	ctx := context.Background()

	// Without AllowHosts: blocked.
	d := guard.CheckHost(ctx, "127.0.0.1", egress.Policy{})
	if d.Allowed {
		t.Fatal("127.0.0.1 should be blocked without policy")
	}

	// With AllowHosts containing the exact host: allowed.
	d = guard.CheckHost(ctx, "127.0.0.1", egress.Policy{AllowHosts: []string{"127.0.0.1"}})
	if !d.Allowed {
		t.Errorf("127.0.0.1 in AllowHosts should be allowed, got reason: %s", d.Reason)
	}
}

// TestCheckHost_FailClosed_DeniedIPLiteralDeniesHost verifies fail-closed behaviour:
// when a host resolves to a denied IP, the check denies. We use an IP literal so
// the test is deterministic without live DNS. The proxy DialContext test exercises
// the multi-address "any denied => deny" case.
func TestCheckHost_FailClosed_DeniedIPLiteralDeniesHost(t *testing.T) {
	guard := egress.New()
	ctx := context.Background()

	d := guard.CheckHost(ctx, "127.0.0.1", egress.Policy{})
	if d.Allowed {
		t.Error("CheckHost(127.0.0.1) without AllowLoopback must be denied (fail-closed)")
	}
}

// ---------------------------------------------------------------------------
// Construction and audit safety
// ---------------------------------------------------------------------------

func TestNew_ReturnsNonNilGuard(t *testing.T) {
	g := egress.New()
	if g == nil {
		t.Fatal("egress.New() returned nil")
	}
}

// TestCheckIP_DeniedDecisionHasReason confirms every denied decision carries a
// human-readable, non-empty Reason safe to log (per ADR-010 audit requirement).
func TestCheckIP_DeniedDecisionHasReason(t *testing.T) {
	guard := egress.New()
	policy := egress.Policy{}

	sensitiveIPs := []string{
		"169.254.169.254", "10.0.0.1", "172.16.0.1",
		"192.168.1.1", "127.0.0.1", "::1", "fe80::1",
	}
	for _, ipStr := range sensitiveIPs {
		ip := net.ParseIP(ipStr)
		d := guard.CheckIP(ip, policy)
		if d.Allowed {
			t.Errorf("expected %s to be denied", ipStr)
			continue
		}
		if len(d.Reason) < 5 {
			t.Errorf("Reason for %s is too short or empty: %q", ipStr, d.Reason)
		}
	}
}

// ---------------------------------------------------------------------------
// CheckHost — hostname resolution path (exercises LookupIPAddr branch)
// ---------------------------------------------------------------------------

// TestCheckHost_LocalhostDenied verifies that resolving "localhost" (which
// resolves to 127.0.0.1 or ::1) is denied by default without AllowLoopback.
func TestCheckHost_LocalhostDenied(t *testing.T) {
	guard := egress.New()
	ctx := context.Background()

	d := guard.CheckHost(ctx, "localhost", egress.Policy{})
	if d.Allowed {
		t.Error("CheckHost(localhost) without AllowLoopback should be denied (localhost resolves to loopback)")
	}
}

// TestCheckHost_LocalhostAllowedWithLoopback verifies that "localhost" is
// permitted when AllowLoopback is set, proving the hostname resolution path
// threads policy through CheckIP correctly.
func TestCheckHost_LocalhostAllowedWithLoopback(t *testing.T) {
	guard := egress.New()
	ctx := context.Background()

	d := guard.CheckHost(ctx, "localhost", egress.Policy{AllowLoopback: true})
	if !d.Allowed {
		t.Errorf("CheckHost(localhost) with AllowLoopback should be allowed, got: %s", d.Reason)
	}
}

// TestCheckHost_AllowHosts_Hostname verifies that a hostname listed in
// AllowHosts is allowed before any resolution is attempted.
func TestCheckHost_AllowHosts_Hostname(t *testing.T) {
	guard := egress.New()
	ctx := context.Background()

	// "localhost" is denied without AllowLoopback, but AllowHosts should
	// permit it before the IP resolution step.
	d := guard.CheckHost(ctx, "localhost", egress.Policy{AllowHosts: []string{"localhost"}})
	if !d.Allowed {
		t.Errorf("host in AllowHosts should be allowed pre-resolution, got: %s", d.Reason)
	}
}

// ---------------------------------------------------------------------------
// AllowAll guard tests
// ---------------------------------------------------------------------------

// TestAllowAll_AlwaysAllows verifies that the AllowAll guard permits every IP
// and host. Used in tests that target httptest loopback servers.
func TestAllowAll_AlwaysAllows(t *testing.T) {
	guard := egress.AllowAll()
	ctx := context.Background()
	policy := egress.Policy{}

	// All normally-denied IPs should be allowed.
	deniedIPs := []string{
		"169.254.169.254", "10.0.0.1", "127.0.0.1", "::1", "fe80::1",
	}
	for _, ipStr := range deniedIPs {
		ip := net.ParseIP(ipStr)
		d := guard.CheckIP(ip, policy)
		if !d.Allowed {
			t.Errorf("AllowAll.CheckIP(%s) should be allowed, got: %s", ipStr, d.Reason)
		}
	}

	// CheckHost should also always allow.
	d := guard.CheckHost(ctx, "127.0.0.1", policy)
	if !d.Allowed {
		t.Errorf("AllowAll.CheckHost(127.0.0.1) should be allowed, got: %s", d.Reason)
	}
}
