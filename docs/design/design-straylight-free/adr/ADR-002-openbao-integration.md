# ADR-002: OpenBao Integration Strategy

**Date**: 2026-03-22
**Status**: Proposed

## Context

Straylight-AI requires encrypted secret storage with leasing, revocation, and audit
capabilities. OpenBao (the open-source, MPL-licensed fork of HashiCorp Vault) provides
all of these features. The question is how to integrate OpenBao into the single-container
architecture.

The free tier uses only static secrets (KV v2 engine). Dynamic credentials are out of
scope. The container must start automatically with no manual unsealing. Secrets must
persist across container restarts via a volume mount at `~/.straylight-ai/data/`.

## Decision Drivers

- **Zero manual setup**: User should never interact with OpenBao directly
- **Persistence**: Secrets must survive container restarts
- **Security**: Auto-unseal must not weaken the security model for localhost use
- **Simplicity**: Single container, minimal moving parts
- **Licensing**: OpenBao is MPL-2.0, compatible with MIT/Apache-2.0

## Options Considered

### Option 1: Sidecar process in same container (managed by Go supervisor)

OpenBao runs as a separate process inside the container, started and supervised by the
Go main process. Communication via localhost HTTP (127.0.0.1:9443). OpenBao uses file
storage backend with data stored on the volume mount. Auto-unseal via transit key stored
in a file on the same volume (acceptable for localhost-only threat model).

**Pros**:
- OpenBao runs as its official binary; no forking or patching required
- Full OpenBao feature set available (KV v2, audit logging, leasing)
- Clear separation of concerns (Straylight Go process vs OpenBao process)
- OpenBao binary is well-tested in this configuration
- Health checks are straightforward (OpenBao has /v1/sys/health)
- Can upgrade OpenBao independently

**Cons**:
- Two processes to manage in one container (requires process supervisor logic)
- OpenBao startup adds 1-2 seconds to container boot time
- Must handle OpenBao process crashes and restarts
- Slightly more complex Dockerfile (need OpenBao binary)

### Option 2: Embed OpenBao as a Go library

Import OpenBao's server packages directly into the Go binary and start the server
in-process. This is theoretically possible since OpenBao is written in Go.

**Pros**:
- Single process; no IPC overhead
- Single binary deployment
- Tighter integration; can call OpenBao internals directly

**Cons**:
- OpenBao explicitly documents that importing as a library is unsupported
- Massive dependency tree (OpenBao is 500K+ lines of Go)
- Build time would be extreme (10+ minutes)
- Binary size balloons (100+ MB for OpenBao alone)
- Version upgrades require rebuilding entire binary
- Risk of internal API changes breaking the build
- No clear API stability guarantees for internal packages

### Option 3: External OpenBao (user manages separately)

Require the user to run OpenBao themselves and provide the address in config.

**Pros**:
- Simplest for Straylight-AI code (just an API client)
- User has full control over OpenBao configuration
- No OpenBao binary in the container

**Cons**:
- Violates the "install in one command" requirement
- User must understand OpenBao administration
- Unseal process becomes user's problem
- Dramatically worse user experience
- Support burden increases (every OpenBao config is different)

### Option 4: Replace OpenBao with built-in encrypted file store

Build a simple encrypted key-value store using Go's crypto libraries. AES-256-GCM
encryption with a master key derived from a machine-specific seed.

**Pros**:
- Zero external dependencies
- Single process, single binary
- Fastest startup
- Smallest container image

**Cons**:
- No audit logging (must build from scratch)
- No leasing or automatic rotation
- No policy engine
- Must implement and maintain crypto correctly (high risk)
- Missing features that OpenBao provides for free (seal/unseal, access control)
- Cannot leverage OpenBao ecosystem (plugins, engines) for future features
- Rolling own crypto is an anti-pattern for security-critical software

## Decision

Chose **Option 1: Sidecar process** because:

1. **No crypto DIY**. Rolling custom encrypted storage for a security product is
   unacceptable risk. OpenBao is battle-tested, audited, and purpose-built for this
   exact use case.

2. **Official binary is well-tested**. Running `bao server` as a subprocess is the
   supported, documented deployment model. Unlike embedding as a library, this path
   has thousands of production deployments.

3. **Clean upgrade path**. When the paid tier adds dynamic credentials (database engines,
   AWS STS), OpenBao already supports those features natively. No rearchitecting needed.

4. **Sidecar complexity is manageable**. The Go supervisor needs to: (a) start the
   process, (b) wait for health check, (c) auto-unseal, (d) restart on crash. This is
   ~200 lines of code.

5. **Localhost threat model makes auto-unseal acceptable**. For a single-user, localhost-
   only deployment, storing the unseal key on the same volume as the data is standard
   practice (identical to how Vault dev mode works, but with persistence).

## Consequences

**Positive**:
- Full OpenBao feature set available from day one
- Audit logging for free (OpenBao file audit backend)
- Proven crypto and storage implementation
- Future-proof for paid tier features

**Negative**:
- Container image ~30 MB larger due to OpenBao binary
- Two processes to manage (adds ~200 lines of supervisor code)
- 1-2 seconds added to container startup

**Risks**:
- OpenBao process crashes during operation. Mitigation: Go supervisor monitors the process
  and restarts it automatically. MCP/proxy operations return clear errors during
  OpenBao downtime rather than hanging.
- Auto-unseal key exposure. Mitigation: key file has 0600 permissions, container runs
  as non-root user, volume mount is user-owned. For localhost-only, this matches the
  threat model. The paid tier can add HSM/cloud KMS unseal.

**Tech Debt**:
- TD-001: Auto-unseal uses file-based key storage. Acceptable for localhost-only free
  tier. Paid tier should support cloud KMS auto-unseal (AWS KMS, GCP KMS).

## Implementation Notes

### OpenBao Configuration

```hcl
# /etc/straylight/openbao.hcl
storage "file" {
  path = "/data/openbao"
}

listener "tcp" {
  address     = "127.0.0.1:9443"
  tls_disable = true   # localhost-only; no TLS needed
}

disable_mlock = true    # Required for container environments
api_addr      = "http://127.0.0.1:9443"
ui            = false   # We have our own UI
```

### Initialization Flow

1. Container starts; Go supervisor checks if `/data/openbao/init.json` exists
2. If not initialized:
   a. Start OpenBao in server mode
   b. Call `PUT /v1/sys/init` with `secret_shares=1, secret_threshold=1`
   c. Save unseal key and root token to `/data/openbao/init.json` (chmod 0600)
   d. Unseal with `PUT /v1/sys/unseal`
   e. Enable KV v2 engine at `secret/`
   f. Create a policy for Straylight-AI operations
   g. Create an AppRole for the Go process
3. If already initialized:
   a. Start OpenBao
   b. Read unseal key from `/data/openbao/init.json`
   c. Unseal
   d. Authenticate via AppRole

### Secret Path Convention

```
secret/data/services/{service-name}/credential   -- API keys, tokens
secret/data/services/{service-name}/oauth         -- OAuth tokens (access + refresh)
secret/data/services/{service-name}/metadata      -- Service configuration
```

### Health Check

```go
func (s *Supervisor) waitForOpenBao(ctx context.Context) error {
    for i := 0; i < 30; i++ {
        resp, err := http.Get("http://127.0.0.1:9443/v1/sys/health")
        if err == nil && resp.StatusCode == 200 {
            return nil
        }
        select {
        case <-ctx.Done():
            return ctx.Err()
        case <-time.After(100 * time.Millisecond):
        }
    }
    return fmt.Errorf("openbao failed to start within 3 seconds")
}
```

## Validation Criteria

- OpenBao starts and becomes healthy within 3 seconds
- Secrets persist across container stop/start cycles
- OpenBao process crash triggers automatic restart within 1 second
- Secret storage and retrieval round-trips in < 10ms
- Unseal key file has correct permissions (0600)
- OpenBao only listens on 127.0.0.1 (verified by port scan test)
