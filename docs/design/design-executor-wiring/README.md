# Design Package: Safe Data-Plane Executor Wiring (Issue #14)

**Date**: 2026-06-28
**Author**: Architect Agent
**Status**: Proposed
**Depends on**: Wave-0 guards (#9) — ADR-010 (egress), ADR-011 (policy)

## Summary

Activate the four inert data-plane MCP tools (`read_file`, `scan`, `db_query`,
`exec`) by wiring their executors in `serve()` with the Wave-0 guards — without
re-opening the OpenBao unseal-key hole. The hard problem: `straylight_exec` runs
commands as UID 10001, which owns `<dataDir>/openbao/init.json` (0600 — unseal key
+ root token + AppRole secret), so a prompt-injected `cat /data/openbao/init.json`
exfiltrates the vault master secret. A command denylist is trivially bypassable
(`python -c`, `dd`, `xxd`, redirection). The design makes the read an OS-enforced
`permission denied` via privilege separation.

## Key Decisions

| Decision | ADR | Choice |
|----------|-----|--------|
| Safe-exec structural control | ADR-013 | Run exec children as a distinct lower-privileged uid (10101) that cannot read the `0600` init.json owned by 10001 — kernel-enforced, defeats the denylist-bypass class |
| Exec defense-in-depth | ADR-013 | Mandatory per-service `allowed_commands` + arg validation + ADR-010 egress pre-flight + ADR-011 policy gate + human-approval tier (A5) |
| Four-executor wiring | ADR-013 | read_file -> firewall (`BlockedDirs=<dataDir>/openbao`); scan -> scanner; db_query -> database.Manager (dynamic read-only creds); exec -> cmdwrap (uid split + allowlist + approval) |
| Phased activation | ADR-013 | Phase 1 read_file+scan, Phase 2 db_query (no runtime change), Phase 3 exec (requires cap_add SETUID,SETGID + second uid) |

## Flagged runtime/Dockerfile changes (maintainer confirmation)

- `deploy/docker-compose.yml`: `cap_add: [SETUID, SETGID]` alongside `cap_drop: ALL`
  (required to drop exec children to uid 10101).
- `deploy/Dockerfile`: add `straylight-exec` user/group (uid/gid 10101); keep
  `USER straylight` (10001).
- Without these: ship Phases 1-2 only; keep `straylight_exec` stubbed.

## Residual Risk (ships in docs, per THREAT-MODEL §2/§5)

The uid split protects init.json, not the authority a credential grants:
confused-deputy misuse of *allowed* commands remains; exec child sockets are
unmediated (nft/eBPF is the paydown, TD-1); CamoLeak through an approved host
remains; db_query's direct connection is not egress-gated (TD-2); the unseal key
still lives on disk readable by uid 10001 (A1c / KMS auto-unseal is the long-term
answer, TD-3); no per-request API auth (localhost-only trust boundary).

## Artifacts

```
docs/design/design-executor-wiring/
  README.md                                  # This file
  adr/
    ADR-013-safe-data-plane-activation.md    # Safe-exec analysis, wiring, phases, residual risk, tests
```
