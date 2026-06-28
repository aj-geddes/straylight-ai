package server

import (
	"context"

	"github.com/straylight-ai/straylight/internal/egress"
	"github.com/straylight-ai/straylight/internal/mcpauth"
)

// egressSSRFGuard adapts egress.Guard to the mcpauth.SSRFGuard interface.
// mcpauth declares SSRFGuard as a consumer interface (IsHostAllowed(ctx,host) bool);
// egress.Guard uses CheckHost(ctx,host,Policy) Decision. This adapter bridges
// the two without creating an import cycle (server already imports both packages).
type egressSSRFGuard struct {
	g egress.Guard
}

// NewEgressSSRFGuard wraps an egress.Guard as an mcpauth.SSRFGuard. The
// returned guard uses a default-deny Policy (no AllowHosts, no AllowCIDRs,
// loopback not allowed), so JWKS fetches to private/link-local addresses are
// blocked by the built-in denylist — the same protection as the proxy path.
func NewEgressSSRFGuard(g egress.Guard) mcpauth.SSRFGuard {
	return &egressSSRFGuard{g: g}
}

// IsHostAllowed implements mcpauth.SSRFGuard. It calls CheckHost with a
// zero Policy (default-deny for private ranges) and returns whether the
// destination is allowed.
func (a *egressSSRFGuard) IsHostAllowed(ctx context.Context, host string) bool {
	return a.g.CheckHost(ctx, host, egress.Policy{}).Allowed
}

// Compile-time assertion that egressSSRFGuard satisfies mcpauth.SSRFGuard.
var _ mcpauth.SSRFGuard = (*egressSSRFGuard)(nil)
