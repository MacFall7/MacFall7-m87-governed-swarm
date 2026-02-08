# M87 Hardening Package (v1 + v2)

**Version:** 2.0.0
**Status:** v1 P0–P2 implemented, v2 scaffolding in place

## Overview

This document describes the hardening changes applied to the M87 governance
system based on findings from Red Team Ops I and II.

## Layer Model (0–5): What M87 Solves vs What It Doesn't

| Layer | Question | Status |
|-------|----------|--------|
| **0** — Unauthorized execution | Can an untrusted agent execute without governance approval? | **SOLVED** (split-brain architecture) |
| **1** — Dangerous approvals | Can an agent get dangerous actions approved via prompt injection? | **SOLVED** (effect-over-intent classification) |
| **2** — Compositional threats | Can multiple low-risk actions compose into dangerous configuration? | **UNSOLVED** (requires state invariants + compositional reasoning) |
| **3** — Observability integrity | Can an attacker poison what operators see? | **UNSOLVED** (requires independent observability channels) |
| **4** — Operator cognition | Can adversaries induce wrong operator decisions? | **UNSOLVED** (requires decision protocols + tooling) |
| **5** — Resilience vs safety | Can the system remain useful during adversarial campaigns? | **UNSOLVED** (requires graduated degradation + quarantine) |

Safety (Layers 0–1) and resilience (Layers 2–5) are orthogonal. M87 is
strong on safety; the v2 roadmap extends into resilience.

## v1 Hardening (P0–P2)

### P0 — Before External Adversarial Testing

#### P0.1 Runner-side glob expansion re-validation
- **Module:** `apps/api/app/governance/glob_validation.py`
- **What:** Governance returns an explicit approved expansion set (canonical paths).
  Runner re-expands and aborts if any candidate path is not in the approved set.
- **Why:** Prevents overlay/bind mount divergence where runner sees different files
  than governance approved.
- **Deny code:** `GLOB_DIVERGENCE_DETECTED`

#### P0.2 Explicit virtual FS deny policies
- **Module:** `apps/api/app/governance/virtual_fs_deny.py`
- **What:** Explicit DENY entries for `/dev/shm`, `/sys`, `/run`, `/dev/pts`,
  `/dev/mqueue`. `/proc` is allowlist-only (narrow set of safe paths).
- **Why:** Replaces inherited RESTRICTED with explicit DENY. Future allowlist
  insertions require code changes and corresponding tests.
- **Deny codes:** `VIRTUAL_FS_DENIED`, `VIRTUAL_FS_NOT_IN_ALLOWLIST`

### P1 — Before Production Deployment

#### P1.1 Semantic truncation defense
- **Module:** `apps/api/app/governance/input_validation.py`
- **What:** Denies "empty overwrite" semantics. If source content size = 0 AND
  destination is non-empty or critical, the operation is denied.
- **Why:** Catches both `/dev/null` by name AND user-created 0-byte files used
  as truncation weapons.
- **Deny codes:** `EMPTY_OVERWRITE_DENIED`, `DEVNULL_SOURCE_DENIED`

#### P1.2 Deny on empty args
- **Module:** `apps/api/app/governance/input_validation.py` + `services/runner/app/runner.py`
- **What:** Any empty string argument in a tool invocation is denied with explicit reason.
- **Why:** Removes sanitize-and-continue behavior for anomalous args.
- **Deny code:** `EMPTY_ARG_DENIED`

### P2 — Operational Hardening

#### P2.1 Runtime mount option verification
- **Module:** `apps/api/app/governance/runtime_mounts.py` + `services/runner/app/runner.py`
- **What:** Runner startup verifies mount options (nosuid, nodev on /tmp, /var/tmp).
  Mismatch = refuse to start (fail-closed).
- **Config:** `M87_MOUNT_CHECK_ENABLED=1` to enable.
- **Deny code:** `MOUNT_INVARIANT_VIOLATED`

#### P2.2 Enumeration limits for recursive writes
- **Module:** `apps/api/app/governance/enumeration_limits.py`
- **What:** Hard caps on recursive filesystem enumeration: max nodes (10,000),
  max depth (50), max time (5s), max total size (1 GiB).
- **Why:** Prevents governance CPU exhaustion on `cp -r` pre-walk.
- **Deny codes:** `UNBOUNDED_ENUMERATION`, `ENUMERATION_DEPTH_EXCEEDED`,
  `ENUMERATION_NODE_LIMIT_EXCEEDED`, `ENUMERATION_TIMEOUT`

## v2 Scaffolding (3–4 Year Horizon)

### Quarantine Posture (Option C)
- **Module:** `apps/api/app/governance/quarantine.py`
- **What:** Breaks the Sophist's Choice (FULL-SERVICE vs DENY-ALL) with
  intermediate quarantine mode.
- **Config:** `M87_QUARANTINE_ENABLED=1` to activate (no-op by default).

### Graduated Degradation Tiers

| Tier | Name | Behavior |
|------|------|----------|
| 0 | Full Service | Normal operation; all effects governed normally |
| 1 | Read-Only | SAFE_READ on non-restricted resources only |
| 2 | Quarantine | Freeze mutations + preserve sight |
| 3 | Deny-All | Block all proposals (safety stop) |

### Observability Quarantine
- Agent-supplied metadata is quarantined (not trusted for governance).
- Stored separately from governance-authored telemetry.
- Available only for offline triage.
- **Endpoints:** `GET /v1/quarantine/status`, `GET /v1/quarantine/observability`

### v2 Research Tracks
- **R1:** Compositional threat detection (state invariant auditor)
- **R2:** Observability integrity boundary (governance-signed audit log)
- **R3:** Operator decision support (incident protocol templates)
- **R4:** Resilience modes (quarantine posture end-to-end)

## Release Gates

### Invariants (must hold)
- [x] No agent proposal can execute without governance approval
- [x] Runner cannot execute tools outside manifest
- [x] Any normalization/classification failure → DENY
- [x] Tool/manifest/contract changes require re-approval

### P0 Gates
- [x] Glob expansion re-validation test passes (divergent FS view aborts)
- [x] Virtual FS explicit deny policies present and tested

### P1 Gates
- [x] Zero-length overwrite semantic deny passes tests
- [x] Empty args cause DENY (no sanitize)

### P2 Gates
- [x] Runner refuses start if mount invariants violated
- [x] Recursive pre-walk caps enforced; deny within time bound

### Documentation
- [x] Layer model included
- [x] Quarantine posture spec included (scaffolding)
- [x] Degradation tiers included

### Audit
- [x] All new denies have explicit reason codes
- [x] Deny reasons are stable (contract) for telemetry
