# M87 Hardening Package (v1 + v2 + v3 + Layer 0 + Layer 1 + Receipts)

**Version:** 3.5.0
**Status:** Layer 0 + Layer 1 closed, v1 P0–P2 implemented, v2 scaffolding, v3 operational security complete, per-call receipts + offline verification

## Overview

This document describes the hardening changes applied to the M87 governance
system based on findings from Red Team Ops I and II.

## Layer Model (0–5): What M87 Solves vs What It Doesn't

| Layer | Question | Status |
|-------|----------|--------|
| **0** — Unauthorized execution | Can an untrusted agent execute without governance approval? | **SOLVED** (split-brain + execution equivalence enforced) |
| **1** — Effect integrity | Can effects drift, leak, or bypass classification? | **SOLVED** (taxonomy alignment, env isolation, schema versioning) |
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

## Layer 0 Closure — Execution Equivalence

> **STATUS: CLOSED.** Layer 0 is considered a stable contract. Changes to
> Layer 0 enforcement code require: (1) a new proof artifact run, (2) all
> TOCTOU probes passing, (3) updated `docs/proofs/layer0.md`. Treat this
> layer like a kernel ABI: boring, stable, sacred.
>
> Proof: `python scripts/layer0_demo.py --json` must return `LAYER_0_ENFORCED`.

Layer 0 previously enforced intent separation (agents can only propose) but
not execution equivalence (governance and runner agree on filesystem reality).
The following fixes close that gap.

### Virtual FS deny enforced in governance
- **File:** `apps/api/app/main.py` (govern_proposal)
- **What:** `check_virtual_fs_access()` is now called for every artifact path
  (`path`, `source`, `destination`, `target`) before governance evaluation.
  Any match against `/dev/shm`, `/sys`, `/run`, `/dev/pts`, `/dev/mqueue`, or
  non-allowlisted `/proc` paths → DENY. No warnings, no soft failures.
- **Why:** Previously imported but never called — proposals could target
  dangerous virtual filesystems and pass governance.

### Runner-side path revalidation
- **File:** `services/runner/app/runner.py` (`_runner_revalidate_paths()`)
- **What:** Runner canonicalizes all input paths via `os.path.realpath()` and
  enforces `resolved_paths ⊆ approved_paths`. Extra paths (TOCTOU divergence)
  → abort with `RUNNER_PATHSET_MISMATCH`. Symlink escapes outside `base_dir`
  → abort immediately.
- **Why:** Without this, an overlay/bind mount change between governance
  approval and runner execution could cause the runner to operate on files
  governance never approved.

### Runner-side virtual FS deny
- **File:** `services/runner/app/runner.py` (`_runner_check_virtual_fs()`)
- **What:** Runner independently blocks access to `/dev/shm`, `/sys`, `/run`,
  `/dev/pts`, `/dev/mqueue`, and non-allowlisted `/proc` paths. Defense-in-depth:
  governance should have already denied, but runner is the last line of defense.

### Runner boot-time namespace verification
- **File:** `services/runner/app/runner.py` (`_verify_network_namespace()`)
- **What:** At startup, runner checks `/sys/class/net/` for non-loopback
  interfaces. If any exist (eth0, etc.) → `RuntimeError` (fail-closed).
  Proves `network_mode: none` is actually in effect.
- **Config:** `M87_NETWORK_CHECK_ENABLED=1`

### Runner boot-time capability verification
- **File:** `services/runner/app/runner.py` (`_verify_capabilities_dropped()`)
- **What:** At startup, runner reads `/proc/self/status` CapEff field and checks
  for dangerous capabilities: `CAP_SYS_ADMIN`, `CAP_NET_RAW`, `CAP_NET_ADMIN`,
  `CAP_SYS_PTRACE`. Any present → `RuntimeError` (fail-closed).
- **Config:** `M87_CAP_CHECK_ENABLED=1`

---

## Layer 1 Closure — Effect Integrity

> **STATUS: CLOSED.** Layer 1 is considered a stable contract. Changes to
> effect taxonomy, tool allowlists, or subprocess isolation require: (1) all
> Layer 1 drift probes passing, (2) EFFECT_SCHEMA_VERSION bumped if taxonomy
> changes, (3) both API and runner versions agree.

Layer 1 ensures that every side-effect the runner can cause is classified,
versioned, and isolated. Without this, governance can approve effects it
doesn't understand, tools can read infrastructure secrets, and taxonomy
drift between API and runner deployments goes undetected.

### Effect taxonomy alignment
- **Files:** `apps/api/app/governance/effects.py`, `apps/api/app/main.py`
- **What:** The `EffectTag` enum (13 effects) and the `EffectTag` Literal in
  `main.py` are now identical. Previously the Literal had only 10 effects
  (missing `READ_CONFIG`, `COMPUTE`, `OTHER`), meaning proposals with those
  effects could bypass Pydantic validation silently.
- **Why:** Taxonomy divergence means governance approves effects that
  validation doesn't recognize, or rejects effects that are perfectly valid.

### ALLOWED_TOOLS ≡ manifest
- **File:** `apps/api/app/main.py`
- **What:** `ALLOWED_TOOLS` and `RunnerTool` Literal now contain exactly
  `{"echo", "pytest"}` — matching `tool_manifest.json`. Previously they
  included phantom tools `"git"` and `"build"` that had no manifest entries
  and no runner implementations.
- **Why:** A phantom tool in ALLOWED_TOOLS lets governance mint jobs the
  runner will always reject. A manifest tool missing from ALLOWED_TOOLS
  blocks legitimate jobs at the API layer.

### Subprocess environment isolation
- **File:** `services/runner/app/runner.py` (`_scrubbed_env()`)
- **What:** `tool_echo()` and `tool_pytest()` now call `subprocess.run()`
  with `env=_scrubbed_env()`, which strips all `M87_*`, `REDIS_*`,
  `POSTGRES_*`, `DATABASE_*`, `AWS_*`, `GCP_*`, `AZURE_*`, `SECRET_*`,
  `TOKEN_*` prefixed environment variables.
- **Why:** Without scrubbing, a malicious test can trivially read
  `os.environ` and exfiltrate `M87_API_KEY`, `REDIS_URL`, and other
  infrastructure credentials via stdout. This was the highest-severity
  gap identified in the Layer 1 audit.

### Effect schema versioning
- **Files:** `apps/api/app/governance/effects.py` (`EFFECT_SCHEMA_VERSION`),
  `services/runner/app/runner.py` (`RUNNER_EFFECT_SCHEMA_VERSION`),
  `apps/api/app/main.py` (job spec stamping)
- **What:** Every job spec now carries `effect_schema_version: "1.0.0"`.
  The runner verifies this matches its own `RUNNER_EFFECT_SCHEMA_VERSION`
  before executing. Mismatched versions → job rejected.
- **Why:** If the API adds a new effect but the runner hasn't been updated,
  the runner might execute jobs it can't properly classify. Schema versioning
  makes this a hard error instead of a silent drift.

---

## v3 Operational Security Hardening

### P0.A — Scoped service credentials
- **Files:** `apps/api/app/auth/store.py`, `apps/api/app/main.py`, both compose files
- **What:** Each service (runner, Casey, Jordan, Riley, notifier) gets its own
  API key with minimal endpoint scopes, effect scopes, and risk caps. The
  bootstrap key is reserved for admin-only operations. Keys are seeded
  idempotently at startup via `seed_service_key()`.
- **Why:** Previously all services shared one key with full admin access. A
  compromised adapter could hit admin endpoints, approve its own proposals,
  or submit proposals outside its effect scope.
- **Scopes:**
  | Service | endpoint_scopes | effect_scopes | max_risk |
  |---------|-----------------|---------------|----------|
  | Runner | `runner:result` | ∅ | 0.0 |
  | Casey | `proposal:create` | READ_REPO, WRITE_PATCH, RUN_TESTS | 0.6 |
  | Jordan | `proposal:create` | SEND_NOTIFICATION, BUILD_ARTIFACT, CREATE_PR, READ_REPO | 0.5 |
  | Riley | `proposal:create` | READ_REPO, BUILD_ARTIFACT, SEND_NOTIFICATION | 0.4 |
  | Notifier | `admin:emit` | ∅ | 0.0 |

### P0.B — File-based job dispatch (airgapped runner)
- **Files:** `apps/api/app/job_dispatcher.py`, `services/runner/app/runner.py`,
  `infra/docker-compose.secure.yml`
- **What:** Runner supports `M87_DISPATCH_MODE=file`, polling
  `/dispatch/incoming/` for job envelopes and writing results to
  `/dispatch/outgoing/`. A separate `job-dispatcher` service bridges Redis
  to the shared filesystem volume. Atomic writes via temp+rename.
- **Why:** `docker-compose.secure.yml` used `network_mode: none` but the runner
  still needed Redis (which requires network). File dispatch makes the airgap
  real.
- **Config:** `M87_DISPATCH_MODE=file`, `M87_FILE_INCOMING`, `M87_FILE_OUTGOING`

### P1.A — Argon2id key hashing
- **Files:** `apps/api/app/auth/models.py`, `apps/api/app/auth/store.py`,
  `apps/api/requirements.txt`
- **What:** API keys hashed with Argon2id via `passlib[argon2]` (memory=64 MiB,
  time=3, parallelism=1). Dual-verify migration: legacy SHA-256 hashes are
  accepted and transparently rehashed to Argon2id on successful auth.
- **Why:** SHA-256 is fast and deterministic — vulnerable to rainbow tables and
  timing attacks. Argon2id is the OWASP-recommended password/key hash.
- **Migration:** `verify_key_hash()` checks format → routes to Argon2id or
  SHA-256. `needs_rehash()` detects legacy hashes. `get_by_plaintext()` does
  transparent rehash on match.
- **Fallback:** If `passlib[argon2]` is not installed, falls back to SHA-256
  with a startup warning.

### P1.B — Kill-switch lockdown
- **Files:** `apps/api/app/main.py` (`_enforce_killswitch_lockdown()`)
- **What:** `M87_DISABLE_PHASE36_GOVERNANCE=1` is an emergency escape hatch
  that bypasses Phase 3-6 governance (toxic topology detection, tripwire scan,
  challenge-response). In prod, this is locked down:
  - **dev/staging:** Warns but allows.
  - **prod + default key:** Refuses to boot (`RuntimeError`).
  - **prod + custom key + no override file:** Warns (key-only authorization).
  - **prod + custom key + override file present:** Authorized.
  - **prod + custom key + override path missing:** Refuses to boot.
- **Why:** Without lockdown, any attacker who can set an env var can silently
  disable the entire adversarial review layer.
- **Config:** `M87_ENV`, `M87_BOOTSTRAP_KEY`, `M87_KILLSWITCH_OVERRIDE_PATH`

### P2.A — Per-key rate limiting
- **Files:** `apps/api/app/governance/rate_limiter.py`, `apps/api/app/main.py`
- **What:** Redis sorted-set sliding window per `principal_id`. Checked at
  `/v1/govern/proposal` after auth, before expensive governance evaluation.
  Returns HTTP 429 with `retry_after` on exceed.
- **Why:** Without rate limiting, a compromised adapter could flood governance
  with proposals to exhaust compute or race conditions.
- **Config:** `M87_RATE_LIMIT_PROPOSALS_PER_MIN` (default: 30)

### P2.B — Pinned Python dependencies
- **Files:** `apps/api/requirements.in`, `services/runner/requirements.in`
- **What:** `requirements.in` files listing direct dependencies (human-maintained).
  `requirements.txt` contains pinned versions. Workflow: edit `.in`, run
  `pip-compile requirements.in -o requirements.txt`.
- **Why:** Reproducible builds. Prevents supply-chain drift where a transitive
  dependency update introduces a vulnerability.

---

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

### v1 P0 Gates
- [x] Glob expansion re-validation test passes (divergent FS view aborts)
- [x] Virtual FS explicit deny policies present and tested

### v1 P1 Gates
- [x] Zero-length overwrite semantic deny passes tests
- [x] Empty args cause DENY (no sanitize)

### v1 P2 Gates
- [x] Runner refuses start if mount invariants violated
- [x] Recursive pre-walk caps enforced; deny within time bound

### v3 P0 Gates
- [x] Each service has its own scoped key (not sharing bootstrap)
- [x] Runner key can only hit `runner:result` (403 on admin endpoints)
- [x] Adapter key cannot propose effects outside its scope
- [x] File-based dispatch creates atomic job envelopes
- [x] File-based dispatch reads and cleans up result files
- [x] Secure compose uses `network_mode: none` + file dispatch

### v3 P1 Gates
- [x] Argon2id hashes produced by default (starts with `$argon2`)
- [x] Legacy SHA-256 hashes still verified (dual-verify)
- [x] Legacy hashes transparently rehashed to Argon2id
- [x] Kill-switch in prod + default key → RuntimeError
- [x] Kill-switch in prod + custom key + override file → authorized
- [x] Kill-switch in prod + custom key + missing override → RuntimeError
- [x] Kill-switch in dev → warns but allows

### v3 P2 Gates
- [x] Rate limit allows requests under threshold
- [x] Rate limit denies requests over threshold
- [x] Rate limits are per-principal (independent)
- [x] `requirements.in` files present for pip-compile workflow

### Layer 0 Closure Gates
- [x] Virtual FS deny enforced in govern_proposal (proposal + /dev/shm → DENY)
- [x] Virtual FS deny checks path, source, destination, target keys
- [x] Runner-side path revalidation catches extra paths (TOCTOU)
- [x] Runner-side symlink escape detection aborts on realpath outside base_dir
- [x] Runner-side virtual FS deny blocks /dev/shm, /sys, /run, /proc (defense-in-depth)
- [x] Runner network namespace check refuses boot with non-loopback interfaces
- [x] Runner capability check refuses boot with CAP_SYS_ADMIN/CAP_NET_RAW

### Documentation
- [x] Layer model included
- [x] Quarantine posture spec included (scaffolding)
- [x] Degradation tiers included
- [x] v3 operational security items documented

### Audit
- [x] All new denies have explicit reason codes
- [x] Deny reasons are stable (contract) for telemetry
- [x] `.env.example` updated with all new env vars

### TOCTOU Red-Team Probes
- [x] Symlink swap after approval → runner detects escape (PROBE 1)
- [x] Symlink swap to different file inside base → runner detects unapproved path (PROBE 1b)
- [x] File injection after approval → RUNNER_PATHSET_MISMATCH (PROBE 2)
- [x] Content replacement at same path → passes (Layer 2 concern, documented) (PROBE 2b)
- [x] Glob expansion divergence (file added) → GLOB_DIVERGENCE_DETECTED (PROBE 3)
- [x] File removed between globs → accepted (missing OK, extra not) (PROBE 3b)
- [x] Glob symlink injection → GLOB_SYMLINK_ESCAPE (PROBE 3c)
- [x] Directory symlink swap escaping base_dir → abort (PROBE 4)
- [x] Symlink-to-virtual-FS pivot (/dev/shm, /proc, /sys) → both defenses fire (PROBE 5)
- [x] Double-fetch race (realpath divergence via overlay) → abort (PROBE 6)
- [x] Path traversal bypass attempts (../, //, /., trailing /) → denied (PROBE 7)
- [x] Governance-side traversal bypass → denied (PROBE 7b)

### Traceable Demo Run
- [x] `scripts/layer0_demo.py` exercises all 4 enforcement paths (A–D)
- [x] Machine-readable JSON trace output (`--json` flag)
- [x] Build provenance in JSON: `repo_commit`, `branch`, `python_version`, `platform`, `runner_build_id`
- [x] Verdict: `LAYER_0_ENFORCED` (16/16 checks pass)

### CI Proof Rail (Layer 0)
```bash
# Both must pass for a green build:
python -m pytest apps/api/tests/test_layer0_toctou_probes.py -v
python scripts/layer0_demo.py --json | python -c \
  "import sys,json; d=json.load(sys.stdin); assert d['verdict']=='LAYER_0_ENFORCED'; assert d['provenance']['repo_commit']!='unknown'; print('OK:', d['verdict'])"
```
Note: In `--json` mode, human-readable output goes to stderr; JSON goes to stdout (pipe-safe).

### Layer 1 Effect Drift Probes
- [x] EffectTag enum and Literal match exactly (PROBE 1)
- [x] Agent profiles use only canonical effects (PROBE 1b)
- [x] EXFIL_ADJACENT and READ_ONLY sets are valid and disjoint (PROBE 1c/1d)
- [x] ALLOWED_TOOLS matches manifest exactly — no phantom tools (PROBE 2)
- [x] Manifest tools are in ALLOWED_TOOLS — no orphans (PROBE 2b)
- [x] Manifest effects are canonical EffectTags (PROBE 2c)
- [x] _scrubbed_env() strips M87_, REDIS_, DATABASE_, POSTGRES_, AWS_, GCP_, AZURE_, SECRET_, TOKEN_ (PROBE 3)
- [x] tool_echo uses env=_scrubbed_env() (PROBE 3b structural)
- [x] tool_pytest uses env=_scrubbed_env() (PROBE 3c structural)
- [x] API and runner EFFECT_SCHEMA_VERSION agree (PROBE 4)
- [x] Runner rejects mismatched effect_schema_version (PROBE 4b)
- [x] Runner accepts matching effect_schema_version (PROBE 4c)
- [x] Every manifest tool has a runner dispatch handler (PROBE 5)
- [x] Unknown effects map to OTHER (PROBE 6 — fail-closed invariant)
- [x] Job spec carries effect_schema_version (PROBE 7 structural)

### Bugbot Regression Probes
- [x] Enumeration depth bypass: /workspace/workspace/deep counted correctly (PROBE B1)
- [x] Root depth is 0, single level is 1 (PROBE B1b/B1c)
- [x] Rate limiter ZSET: same-timestamp concurrent requests produce distinct members (PROBE B2)
- [x] Rate limiter ZSET: 5 rapid-fire requests all counted (PROBE B2b)
- [x] Service key reseed: old hash entry cleaned up, no orphans (PROBE B3)
- [x] Bootstrap key reseed: old hash entry cleaned up (PROBE B3b)
- [x] allowed_base_dirs: /opt/dataexfil rejected when /opt/data allowed (PROBE B4)
- [x] allowed_base_dirs: exact match and subdirectory accepted (PROBE B4b/B4c)
- [x] Result file: failed post rolls back to original location (PROBE B5)
- [x] Result file: successful post deletes inflight file (PROBE B5b)
- [x] Result file: double claim prevented by atomic rename (PROBE B5c)

### Per-Call Receipts + Offline Bundle Verification

Governed Swarm Integration — per-call forensic granularity and offline integrity verification.

**Phase 1: Per-Call Receipt Layer**
- `governance/call_receipt.py`: Pydantic models (CallReceipt, ProposalRecord, DecisionRecord,
  ExecutionRecord), ReceiptEmitter with hash-chained monotonic receipts
- Receipt emission hook in `main.py` govern_proposal() — additive, fail-safe
- Execution recording hook in `runner.py` execute_job() — additive, fail-safe
- `governance/schemas/call_receipt.schema.json` for schema validation
- Effect/posture/decision mapping helpers for M87-to-GBE translation

**Phase 2: Offline Bundle Verification**
- `governance/verify/offline.py`: OfflineVerifier with 10 checks:
  SIG_VALID, BUNDLE_HASH_MATCH, SNAPSHOT_PRESENT, ARTIFACTS_COMPLETE,
  RECEIPTS_CHAIN_VALID, RECEIPTS_MONOTONIC, RECEIPTS_NO_GAPS,
  BUDGET_COMPLIANCE, CONTRACT_COMPLETE, NO_UNTRUSTED_EXEC
- `governance/verify/cli.py`: `gbe verify --offline` entry point (exit 0/1)
- `governance/schemas/offline_verification.schema.json` for report validation
- Binary PASS/FAIL — no PASS-with-caveats

**Architectural invariants preserved:**
- Proposal ≠ Execution (receipts are observation-only)
- Fail-Closed (receipt failure logged, never blocks pipeline)
- No changes to governance decision pipeline or session risk model

### Per-Call Receipt Tests (CR_01 — CR_07)
- [x] Schema compliance: receipt validates, version 1.0.0, 64-char hex hashes (CR_01)
- [x] RESTRICTED redaction: args_redacted=true, hashed paths (CR_02)
- [x] Emission failure non-blocking: IOError in emitter does not crash pipeline (CR_03)
- [x] Bundle includes receipts: 3 calls → 3 receipts with chain hash (CR_04)
- [x] Hash chain integrity: 5 sequential calls form valid chain (CR_05)
- [x] DENY has null execution: denied receipt finalized with hash (CR_06)
- [x] Posture and risk captured: ELEVATED posture, risk >= 0.30 (CR_07)

### Offline Verification Tests (OV_01 — OV_10)
- [x] Valid bundle passes: all 10 checks PASS (OV_01)
- [x] Tampered artifact: SIG_VALID or BUNDLE_HASH_MATCH FAIL (OV_02)
- [x] Missing artifact: ARTIFACTS_COMPLETE FAIL (OV_03)
- [x] Receipt chain gap: RECEIPTS_NO_GAPS FAIL at missing sequence (OV_04)
- [x] Receipt hash chain break: RECEIPTS_CHAIN_VALID FAIL (OV_05)
- [x] Budget overflow: BUDGET_COMPLIANCE FAIL (90s vs 60s budget) (OV_06)
- [x] Missing keyring: SIG_VALID FAIL (not SKIPPED) (OV_07)
- [x] Known limitations listed: nonce, snapshot, governance (OV_08)
- [x] UNTRUSTED skill in execution: NO_UNTRUSTED_EXEC FAIL (OV_09)
- [x] Contract incomplete: CONTRACT_COMPLETE FAIL (missing section) (OV_10)

### Test Counts
- v1 hardening: 60 tests
- Existing governance: 76 tests
- v3 hardening: 40 tests
- Layer 0 closure: 27 tests
- TOCTOU red-team probes: 20 tests
- Layer 1 effect drift probes: 27 tests
- Bugbot regression probes: 13 tests
- Per-call receipt tests: 17 tests
- Offline verification tests: 10 tests
- **Total: 290 tests, all passing**
