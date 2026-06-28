package openapi

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/straylight-ai/straylight/internal/egress"
)

const (
	// maxSpecSize is the maximum byte size we accept for a fetched OpenAPI spec.
	// Specs larger than this are rejected to prevent memory exhaustion.
	maxSpecSize = 10 * 1024 * 1024 // 10 MiB

	// fetchTimeout is the total per-request timeout for FetchSpec.
	fetchTimeout = 30 * time.Second

	// dialTimeout is the per-connection dial timeout inside the guarded transport.
	fetchDialTimeout = 10 * time.Second
)

// FetchSpec resolves specURL through the egress Guard (CheckHost) BEFORE dialing,
// enforces a size cap, rejects non-2xx responses, and returns the raw bytes for
// use with FromSpec. The Guard's zero Policy (default denylist) is applied —
// internal, link-local, and loopback hosts are denied unless the caller passes
// a permissive Guard (e.g. egress.AllowAll() in tests).
//
// SSRF defence — two layers:
//  1. Pre-flight: g.CheckHost on the initial URL host before building the request.
//  2. DialContext: g.CheckIP on every resolved IP before dialing. This catches
//     DNS rebinding and — combined with CheckRedirect refusing all redirects
//     (http.ErrUseLastResponse) — prevents SSRF via open redirects.
//
// Redirects are refused entirely: a 3xx response is returned as-is and then
// rejected by the non-2xx status check below.
func FetchSpec(ctx context.Context, g egress.Guard, specURL string) ([]byte, error) {
	parsed, err := url.Parse(specURL)
	if err != nil {
		return nil, fmt.Errorf("openapi: invalid spec URL %q: %w", specURL, err)
	}

	host := parsed.Hostname()

	// SSRF gate — layer 1: check the host before dialing.
	d := g.CheckHost(ctx, host, egress.Policy{})
	if !d.Allowed {
		return nil, fmt.Errorf("openapi: spec URL %q rejected by egress guard: %s", specURL, d.Reason)
	}

	// Build a purpose-built HTTP client per call (captures 'g' in the closure).
	dialer := &net.Dialer{Timeout: fetchDialTimeout}
	transport := &http.Transport{
		// SSRF gate — layer 2: re-check the resolved IP on every dial.
		// This defeats DNS rebinding and covers any redirect destinations that
		// bypass the pre-flight check (since we refuse redirects anyway).
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialHost, port, splitErr := net.SplitHostPort(addr)
			if splitErr != nil {
				return nil, fmt.Errorf("openapi: invalid address %q: %w", addr, splitErr)
			}

			ips, resolveErr := net.DefaultResolver.LookupIPAddr(ctx, dialHost)
			if resolveErr != nil {
				return nil, fmt.Errorf("openapi: resolve %q: %w", dialHost, resolveErr)
			}
			if len(ips) == 0 {
				return nil, fmt.Errorf("openapi: no addresses resolved for %q", dialHost)
			}

			for _, ipAddr := range ips {
				if ipd := g.CheckIP(ipAddr.IP, egress.Policy{}); !ipd.Allowed {
					return nil, fmt.Errorf("openapi: IP %s for %q rejected by egress guard: %s", ipAddr.IP, dialHost, ipd.Reason)
				}
			}

			// Dial the first vetted IP directly, pinning the address so the OS
			// does not issue a second, unchecked resolution.
			pinnedAddr := net.JoinHostPort(ips[0].IP.String(), port)
			return dialer.DialContext(ctx, network, pinnedAddr)
		},
	}

	client := &http.Client{
		Timeout:   fetchTimeout,
		Transport: transport,
		// Refuse all redirects: a 3xx response is returned as-is and rejected
		// by the non-2xx status check below. This closes the SSRF-via-redirect
		// attack surface entirely.
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, specURL, nil)
	if err != nil {
		return nil, fmt.Errorf("openapi: build request for %q: %w", specURL, err)
	}
	req.Header.Set("Accept", "application/json, application/yaml, */*")

	resp, err := client.Do(req)
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
