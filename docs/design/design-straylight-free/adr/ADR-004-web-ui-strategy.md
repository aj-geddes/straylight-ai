# ADR-004: Web UI Build and Serving Strategy

**Date**: 2026-03-22
**Status**: Proposed

## Context

Straylight-AI needs a Web UI for:
- Service management (add/remove/configure services)
- Paste-key credential entry
- OAuth flow initiation and callback handling
- Connection status monitoring
- Health overview dashboard

The UI runs on localhost only (not deployed to a CDN or public server). It must be part
of the single-container deployment with no additional infrastructure.

## Decision Drivers

- **Developer experience**: Fast iteration on UI during development
- **Production simplicity**: Minimal serving infrastructure
- **Container size**: UI assets should not bloat the image
- **Security**: No CDN or external asset loading; fully self-contained
- **Framework maturity**: Strong component ecosystem for dashboard UIs

## Options Considered

### Option 1: React SPA, built at image time, embedded in Go binary

Build the React app during the Docker multi-stage build. Copy the build output into the
Go source tree. Use `go:embed` to compile it into the Go binary. Serve via Go's
`http.FileServer`.

**Pros**:
- Single binary contains everything (backend + UI assets)
- No static file management at runtime
- Cache busting handled by React build hashing
- Zero additional processes or servers
- Smallest possible deployment footprint
- Assets are immutable after build

**Cons**:
- Requires rebuild of Go binary when UI changes (mitigated by multi-stage Docker build)
- Development requires running React dev server separately
- Go binary size increases by ~2-5 MB (compressed React build)

### Option 2: React SPA served by nginx sidecar

Run nginx as a second process in the container to serve static files. Go backend
handles API only.

**Pros**:
- nginx is optimized for static file serving
- Clear separation between API and static assets
- Standard deployment pattern

**Cons**:
- Third process in container (Go + OpenBao + nginx)
- More complex configuration
- nginx adds ~5 MB to image and uses additional memory
- Over-engineered for localhost-only serving of ~2 MB of assets

### Option 3: Server-side rendered (Go templates + htmx)

Skip React entirely. Use Go's html/template package with htmx for interactivity.

**Pros**:
- No JavaScript build pipeline
- Smallest asset footprint
- No client-side framework dependency
- Fastest initial page load

**Cons**:
- Limited interactivity for OAuth flow management
- Harder to build rich dashboard UI (service tiles, status indicators)
- htmx ecosystem for complex forms is immature
- Architecture doc specifies React; deviating adds coordination cost
- Fewer available developers for Go template UIs

## Decision

Chose **Option 1: React SPA embedded in Go binary** because:

1. **Single artifact deployment**. The Go binary is completely self-contained. No file
   paths to manage, no volume mounts for assets, no risk of missing files.

2. **React is specified in the architecture**. The architecture document designates React
   for the Web UI. Following this reduces coordination overhead and matches the expected
   skill set.

3. **nginx is overkill**. For a localhost-only UI serving < 5 MB of assets to a single
   user, Go's built-in HTTP server is more than adequate. Adding nginx adds complexity
   with zero benefit at this scale.

4. **Development experience is preserved**. During development, the React app runs via
   Vite dev server with hot reload, proxying API calls to the Go backend. The embed
   approach only applies to production builds.

## Consequences

**Positive**:
- Truly single-binary deployment (Go binary has everything)
- No runtime file dependencies for UI
- Works perfectly with `go:embed` and scratch container
- Development uses standard React tooling (Vite, hot reload)

**Negative**:
- UI changes require Docker image rebuild (but the multi-stage build caches well)
- Go binary grows by 2-5 MB (acceptable)

**Risks**:
- React build failures block Go binary build. Mitigation: CI pipeline builds React
  first as a separate stage; Go build stage only runs if React build succeeds.

**Tech Debt**: None.

## Implementation Notes

### Project Structure

```
web/
  package.json
  vite.config.ts
  src/
    App.tsx
    components/
      ServiceTile.tsx
      PasteKeyDialog.tsx
      OAuthButton.tsx
      StatusIndicator.tsx
      HealthDashboard.tsx
    pages/
      Dashboard.tsx
      ServiceConfig.tsx
      OAuthCallback.tsx
    api/
      client.ts           -- API client for Go backend
    types/
      service.ts
      health.ts
  dist/                    -- Build output (gitignored; built in Docker)

internal/
  web/
    embed.go               -- go:embed directive for web/dist
    handler.go             -- http.FileServer + SPA fallback
```

### Embed Pattern

```go
package web

import (
    "embed"
    "io/fs"
    "net/http"
)

//go:embed dist/*
var assets embed.FS

func Handler() http.Handler {
    dist, _ := fs.Sub(assets, "dist")
    fileServer := http.FileServer(http.FS(dist))
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Try to serve the file; fall back to index.html for SPA routing
        _, err := fs.Stat(dist, r.URL.Path[1:])
        if err != nil {
            r.URL.Path = "/"
        }
        fileServer.ServeHTTP(w, r)
    })
}
```

### React Tech Stack

- **Vite**: Build tool (fast, modern, good dev experience)
- **React 19**: UI framework
- **Tailwind CSS**: Utility-first styling (small build output)
- **React Query (TanStack Query)**: API state management
- **React Router**: Client-side routing

### Development Workflow

```bash
# Terminal 1: Go backend (with hot reload via air or similar)
go run ./cmd/straylight/

# Terminal 2: React dev server (proxies API to Go backend)
cd web && npm run dev
```

Vite config proxies `/api/*` to `http://localhost:9470`.

## Validation Criteria

- React build produces < 5 MB of assets (gzipped < 500 KB)
- Go binary with embedded assets is < 20 MB (excluding OpenBao)
- SPA routing works (deep links to /services/stripe load correctly)
- No external CDN or network requests for UI assets
- Hot reload works during development with Vite dev server
- All UI components render without JavaScript errors
