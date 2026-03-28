# Stage 1: Build React SPA
FROM node:22-alpine AS web-builder
WORKDIR /build/web
# Copy package files first for layer caching — npm ci only re-runs when these change.
COPY web/package.json web/package-lock.json ./
RUN npm ci
# Copy source after installing dependencies so source changes don't bust the npm layer.
COPY web/ ./
RUN npm run build

# Stage 2: Build Go binary (with embedded SPA)
FROM golang:1.25.8-alpine AS go-builder
WORKDIR /build
# Download dependencies before copying source for layer caching.
COPY go.mod go.sum ./
RUN go mod download
# Copy the full source tree.
COPY . .
# Overlay the React build output so the embed.go directive finds real assets.
COPY --from=web-builder /build/web/dist ./internal/web/dist
# Build with static linking (CGO_ENABLED=0) and strip debug symbols (-s -w)
# to minimise binary size in the final image.
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /straylight ./cmd/straylight/
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /straylight-mcp ./cmd/straylight-mcp/

# Stage 3: Minimal Alpine runtime image
FROM alpine:3.23 AS runtime

# OpenBao version to install. Pin to a specific release for reproducibility.
ARG OPENBAO_VERSION=2.5.2
# TARGETARCH is set automatically by `docker buildx build --platform ...`.
# Values: amd64, arm64.
ARG TARGETARCH

# Install OpenBao from the official GitHub releases (.pkg.tar.zst format).
# The package contains usr/bin/bao which we move to /usr/local/bin/.
RUN apk add --no-cache ca-certificates curl zstd tar && \
    curl -fsSL \
      "https://github.com/openbao/openbao/releases/download/v${OPENBAO_VERSION}/openbao_${OPENBAO_VERSION}_linux_${TARGETARCH}.pkg.tar.zst" \
      -o /tmp/openbao.pkg.tar.zst && \
    mkdir -p /tmp/openbao && \
    tar -I zstd -xf /tmp/openbao.pkg.tar.zst -C /tmp/openbao && \
    cp /tmp/openbao/usr/bin/bao /usr/local/bin/bao && \
    chmod +x /usr/local/bin/bao && \
    rm -rf /tmp/openbao /tmp/openbao.pkg.tar.zst && \
    apk del curl zstd tar

# Create a dedicated non-root user and group for the container process.
# UID 10001 is chosen to be well above the range reserved for system accounts
# while remaining in the 16-bit uid range supported by all Linux kernels.
RUN addgroup -g 10001 -S straylight && \
    adduser -u 10001 -S straylight -G straylight

# Copy the compiled Go binaries from the build stage.
COPY --from=go-builder /straylight /usr/local/bin/straylight
COPY --from=go-builder /straylight-mcp /usr/local/bin/straylight-mcp

# Copy the OpenBao server configuration file.
RUN mkdir -p /etc/straylight
COPY deploy/openbao.hcl /etc/straylight/openbao.hcl

# Create the data directory and make it owned by the straylight user.
# This directory is intended to be mounted as a volume at runtime.
RUN mkdir -p /data && chown straylight:straylight /data

# Health check: calls the straylight binary's built-in health subcommand,
# which exits 0 when the server responds with HTTP 200.
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=3 \
  CMD ["/usr/local/bin/straylight", "health"]

EXPOSE 9470
VOLUME /data

USER straylight

ENTRYPOINT ["/usr/local/bin/straylight"]
CMD ["serve"]
