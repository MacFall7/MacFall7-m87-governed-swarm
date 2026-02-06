# Proof Map

This document maps security claims to their enforcement mechanisms and verification tests.

**Purpose**: Convert the repository into evidence-grade material for auditors, security reviewers, and investors.

---

## Claim → Mechanism → Test → File Path

| Claim | Mechanism | Test | Proof Script |
|-------|-----------|------|--------------|
| **No autonomous execution** | Split-brain architecture: agents propose, runner executes | `test_governance.py::test_agents_cannot_execute` | `scripts/proof-test.sh` |
| **Approval required for jobs** | `govern_proposal()` gates all job minting | `test_governance.py::test_no_job_without_approval` | `scripts/proof-test.sh` |
| **READ_SECRETS always denied** | Hardcoded DENY in governance rules | `test_governance.py::test_secrets_always_denied` | `scripts/proof-test.sh` |
| **IRREVERSIBLE requires human** | Reversibility gate in API + Runner | `test_governance.py::test_irreversible_needs_human` | `scripts/proof-test.sh` |
| **DEH verified independently** | Runner recomputes envelope hash | `test_runner.py::test_deh_verification` | Runner logs on mismatch |
| **Manifest drift rejected** | Hash comparison at job execution | `test_runner.py::test_manifest_drift_rejected` | Runner logs on mismatch |
| **Budget exhaustion halts** | Preemptive try_* gates | `test_runner.py::test_budget_enforcement` | Runner error codes |
| **Completion requires artifacts** | Runner artifact check | `test_runner.py::test_artifact_required` | Runner error codes |
| **Toxic topology detected** | SessionRiskTracker sliding window | `test_governance.py::test_toxic_topology_*` | Redis session data |
| **Unknown state = DENY** | Default rejection in all paths | `test_governance.py::test_fail_closed_*` | N/A (absence of bypass) |
| **UI normalization fail-closed** | `normalizeIncomingGovernance()` | `governance-normalization.test.ts` | N/A (unit tests) |
| **Reconciliation re-validates** | `reconcileGovernanceState()` | `governance-normalization.test.ts::reconciliation_*` | N/A (unit tests) |

---

## Enforcement Layers

```
┌─────────────────────────────────────────────────────────────────────┐
│                           LAYER 1: API                               │
│  ┌─────────────────────────────────────────────────────────────────┐│
│  │ Phase 3: Session Risk Tracking (toxic topology detection)       ││
│  │ Phase 5: Code Artifact Inspection (tripwire scan)               ││
│  │ Phase 6: Human Override Protection (challenge-response)         ││
│  └─────────────────────────────────────────────────────────────────┘│
│                              ↓                                       │
│  govern_proposal() → ALLOW / DENY / REQUIRE_HUMAN                   │
│                              ↓                                       │
│  Job minted to m87:jobs (ONLY if approved)                          │
└─────────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│                          LAYER 2: RUNNER                             │
│  ┌─────────────────────────────────────────────────────────────────┐│
│  │ Manifest hash verification (supply-chain integrity)             ││
│  │ DEH verification (deployment envelope integrity)                ││
│  │ Reversibility gate (defense-in-depth)                           ││
│  │ Execution mode verification (tool capability check)             ││
│  │ Autonomy budget enforcement (preemptive limits)                 ││
│  │ Write scope gating (blast radius control)                       ││
│  │ Artifact-backed completion (verifiable results)                 ││
│  └─────────────────────────────────────────────────────────────────┘│
│                              ↓                                       │
│  execute_job() → completed (with artifacts) / failed                │
└─────────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│                           LAYER 3: UI                                │
│  ┌─────────────────────────────────────────────────────────────────┐│
│  │ normalizeIncomingGovernance() - fail-closed normalization       ││
│  │ reconcileGovernanceState() - re-validates cached data           ││
│  │ Data access layer - makes bypass structurally impossible        ││
│  └─────────────────────────────────────────────────────────────────┘│
│                              ↓                                       │
│  UI displays ONLY normalized GovernanceState                        │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Evidence Files

| Evidence Type | Location | Purpose |
|---------------|----------|---------|
| API governance tests | `apps/api/tests/test_governance.py` | Verify policy enforcement |
| Runner tests | `services/runner/tests/test_runner.py` | Verify execution controls |
| UI normalization tests | `apps/ui/lib/__tests__/governance-normalization.test.ts` | Verify fail-closed UI |
| Proof script | `scripts/proof-test.sh` | End-to-end invariant verification |
| Audit log | `m87:events` (Redis stream) | Runtime event trail |
| Manifest lock | `services/runner/manifest.lock.json` | Supply-chain hash |

---

## Kill-Switch Audit

These emergency overrides are documented for transparency:

| Kill-Switch | Effect | Audit Signal |
|-------------|--------|--------------|
| `M87_DISABLE_PHASE36_GOVERNANCE=1` | Disables Phase 3-6 in /v1 | Logs loudly on startup |
| `M87_DISABLE_V1_GOVERNANCE=1` | Returns 410 for /v1 endpoints | Safe: forces /v2 migration |

**Production constraint**: Kill-switches must emit Prometheus metrics and fail deployment if set outside dev/staging.

---

## Verification Checklist

For auditors and security reviewers:

- [ ] Run `./scripts/proof-test.sh` and verify all checks pass
- [ ] Inspect `apps/api/app/main.py::govern_proposal()` for hardcoded DENY rules
- [ ] Inspect `services/runner/app/runner.py::execute_job()` for defense-in-depth checks
- [ ] Verify manifest lock exists: `services/runner/manifest.lock.json`
- [ ] Verify UI tests pass: `cd apps/ui && npm test`
- [ ] Confirm Redis `m87:events` stream is populated with governance events
- [ ] Verify no direct tool execution in adapter code (grep for subprocess calls)

---

## Change Control

Any modification to governance enforcement **MUST**:

1. Update the corresponding test in the proof map
2. Run `./scripts/proof-test.sh` to verify invariants
3. Document the change in commit message with `[GOVERNANCE]` prefix
4. Be reviewed by a second engineer

**Violations of this process are audit findings.**
