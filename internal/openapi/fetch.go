package openapi

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/straylight-ai/straylight/internal/egress"
)

const (
	// maxSpecSize is the maximum byte size we accept for a fetched OpenAPI spec.
	// Specs larger than this are rejected to prevent memory exhaustion.
	maxSpecSize = 10 * 1024 * 1024 // 10 MiB
)

// FetchSpec resolves specURL through the egress Guard (CheckHost) BEFORE dialing,
// enforces a size cap, rejects non-2xx responses, and returns the raw bytes for
// use with FromSpec. The Guard's zero Policy (default denylist) is applied —
// internal, link-local, and loopback hosts are denied unless the caller passes
// a permissive Guard (e.g. egress.AllowAll() in tests).
func FetchSpec(ctx context.Context, g egress.Guard, specURL string) ([]byte, error) {
	parsed, err := url.Parse(specURL)
	if err != nil {
		return nil, fmt.Errorf("openapi: invalid spec URL %q: %w", specURL, err)
	}

	host := parsed.Hostname()

	// SSRF gate: check the host before dialing.
	d := g.CheckHost(ctx, host, egress.Policy{})
	if !d.Allowed {
		return nil, fmt.Errorf("openapi: spec URL %q rejected by egress guard: %s", specURL, d.Reason)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, specURL, nil)
	if err != nil {
		return nil, fmt.Errorf("openapi: build request for %q: %w", specURL, err)
	}
	req.Header.Set("Accept", "application/json, application/yaml, */*")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("openapi: fetch %q: %w", specURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("openapi: fetch %q: HTTP %d", specURL, resp.StatusCode)
	}

	// Read with a size cap to prevent memory exhaustion.
	limited := &io.LimitedReader{R: resp.Body, N: int64(maxSpecSize) + 1}
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("openapi: read body from %q: %w", specURL, err)
	}
	if limited.N <= 0 {
		return nil, fmt.Errorf("openapi: spec from %q exceeds %d-byte size limit", specURL, maxSpecSize)
	}

	return data, nil
}
