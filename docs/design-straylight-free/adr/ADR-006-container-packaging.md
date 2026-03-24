# ADR-006: Container Packaging Strategy

**Date**: 2026-03-22
**Status**: Proposed

## Context

Straylight-AI Personal runs as a single Docker container containing:
- OpenBao binary (sidecar process)
- Go binary (core server: proxy, API, MCP internal endpoint, OAuth handler)
- React SPA (embedded in Go binary)

The container must:
- Run on Docker and Podman
- Support linux/amd64 and linux/arm64
- Be as small as possible (faster `npx straylight-ai setup`)
- Run as non-root user
- Expose only port 9470 (Web UI + internal API)
- Mount ~/.straylight-ai/data/ for persistence

## Decision Drivers

- **Image size**: Directly affects first-run experience (download time)
- **Security**: Non-root, minimal attack surface, no unnecessary packages
- **Build reproducibility**: Consistent builds across CI environments
- **Multi-arch support**: Apple Silicon (arm64) is common among target users

## Options Considered

### Option 1: Multi-stage build with distroless base

Stage 1: Node.js image builds React SPA.
Stage 2: Go image builds the Go binary (with embedded React assets).
Stage 3: Distroless (or Alpine) runtime image with Go binary + OpenBao binary.

**Pros**:
- Smallest possible runtime image (< 60 MB total)
- No shell in final image (if using distroless) reduces attack surface
- Build tools never appear in runtime image
- Multi-stage is the Docker best practice

**Cons**:
- Distroless has no shell for debugging (can use Alpine instead for debug variant)
- Multi-stage builds are slightly more complex to maintain
- Must download OpenBao binary for the correct architecture in the build

### Option 2: Single-stage Alpine build

One stage: install Node.js, Go, and OpenBao in Alpine. Build everything in place.
Remove build tools at the end.

**Pros**:
- Simpler Dockerfile
- Shell available for debugging

**Cons**:
- Larger image (build artifacts and caches may remain)
- Layer caching is less effective
- `RUN rm -rf` does not reclaim space in lower layers
- More packages installed = more CVEs to manage

### Option 3: Nix-based reproducible build

Use Nix to build all components and produce a minimal Docker image.

**Pros**:
- Perfectly reproducible builds
- Can produce extremely minimal images
- Single dependency management system

**Cons**:
- Nix learning curve is steep
- CI setup is more complex
- Uncommon pattern; harder for contributors
- Overkill for a project with two build tools (npm + Go)

## Decision

Chose **Option 1: Multi-stage build with Alpine runtime** because:

1. **Smallest practical image**. Multi-stage ensures no build tools in the runtime image.
   Alpine provides a shell for debugging while staying under 60 MB total.

2. **Standard Docker best practice**. Multi-stage builds are well-understood, well-cached
   by CI systems, and produce predictable results.

3. **Multi-arch is straightforward**. Docker buildx with multi-stage handles linux/amd64
   and linux/arm64 via `--platform` flag. OpenBao publishes official binaries for both.

We use Alpine (not distroless) for the runtime base because the OpenBao process supervisor
benefits from having a shell available, and Alpine adds only ~5 MB.

## Consequences

**Positive**:
- Total image size < 60 MB
- No build tools or source code in runtime image
- Multi-arch support via docker buildx
- Shell available for debugging

**Negative**:
- Must manage OpenBao binary download for correct architecture in Dockerfile
- Alpine musl libc requires static compilation for Go (default behavior, no issue)

**Risks**:
- OpenBao binary download URL changes. Mitigation: pin version; download from GitHub
  releases with checksum verification.

**Tech Debt**: None.

## Implementation Notes

### Dockerfile

```dockerfile
# Stage 1: Build React SPA
FROM node:22-alpine AS web-builder
WORKDIR /build/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

# Stage 2: Build Go binary
FROM golang:1.23-alpine AS go-builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web-builder /build/web/dist ./web/dist
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /straylight ./cmd/straylight/
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /straylight-mcp ./cmd/straylight-mcp/

# Stage 3: Runtime
FROM alpine:3.21 AS runtime

# Install OpenBao
ARG OPENBAO_VERSION=2.5.1
ARG TARGETARCH
RUN apk add --no-cache ca-certificates curl && \
    curl -fsSL "https://github.com/openbao/openbao/releases/download/v${OPENBAO_VERSION}/bao_${OPENBAO_VERSION}_linux_${TARGETARCH}.zip" \
      -o /tmp/openbao.zip && \
    unzip /tmp/openbao.zip -d /usr/local/bin/ && \
    rm /tmp/openbao.zip && \
    apk del curl && \
    chmod +x /usr/local/bin/bao

# Create non-root user
RUN addgroup -S straylight && adduser -S straylight -G straylight

# Copy binaries
COPY --from=go-builder /straylight /usr/local/bin/straylight
COPY --from=go-builder /straylight-mcp /usr/local/bin/straylight-mcp

# Copy OpenBao configuration
COPY deploy/openbao.hcl /etc/straylight/openbao.hcl

# Create data directory
RUN mkdir -p /data && chown straylight:straylight /data

# Switch to non-root user
USER straylight

# Health check
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
  CMD ["/usr/local/bin/straylight", "health"]

EXPOSE 9470
VOLUME /data

ENTRYPOINT ["/usr/local/bin/straylight"]
CMD ["serve"]
```

### Multi-arch Build Command

```bash
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  --tag ghcr.io/straylight-ai/straylight:latest \
  --tag ghcr.io/straylight-ai/straylight:1.0.0 \
  --push \
  .
```

### Container Runtime Configuration

```bash
docker run -d \
  --name straylight-ai \
  -p 9470:9470 \
  -v ~/.straylight-ai/data:/data \
  --restart unless-stopped \
  ghcr.io/straylight-ai/straylight:latest
```

### Port Mapping

| Port | Purpose | Exposed |
|------|---------|---------|
| 9470 | Web UI + Internal API | Yes (localhost only) |
| 9443 | OpenBao (internal) | No (container-internal only) |

### Volume Mount

| Host Path | Container Path | Purpose |
|-----------|---------------|---------|
| ~/.straylight-ai/data/ | /data | OpenBao storage, unseal key, config |

### Directory Layout Inside Container

```
/data/
  openbao/                 -- OpenBao file storage backend
  openbao/init.json        -- Unseal key + root token (chmod 0600)
  config.yaml              -- User service configuration
/etc/straylight/
  openbao.hcl              -- OpenBao server configuration
/usr/local/bin/
  straylight               -- Main Go binary
  straylight-mcp           -- MCP host binary (also available for host extraction)
  bao                      -- OpenBao binary
```

## Validation Criteria

- Image builds successfully for linux/amd64 and linux/arm64
- Total image size < 60 MB per architecture
- Container starts and passes health check within 10 seconds
- Container runs as non-root user (verified by `docker exec whoami`)
- OpenBao data persists across container stop/start
- No build tools (node, go, npm) present in runtime image
- Port 9443 is not accessible from host
