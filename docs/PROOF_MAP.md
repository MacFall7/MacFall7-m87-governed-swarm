# Proof Map

This document maps security claims to their enforcement mechanisms and verification tests.

**Purpose**: Convert the repository into evidence-grade material for auditors, security reviewers, and investors.

---

## Claim → Mechanism → Test → File Path

| Claim | Mechanism | Test | Proof Script |
|-------|-----------|------|--------------|
| **No autonomous execution** | Split-brain architecture: agents propose, runner executes | `test_governance_invariants.py` | `scripts/proof-test.sh` |
| **Approval required for jobs** | `govern_proposal()` gates all job minting | `test_governance_invariants.py::TestGovernanceInvariants` | `scripts/proof-test.sh` |
| **READ_SECRETS always denied** | Hardcoded DENY in governance rules | `test_governance_invariants.py::test_read_secrets_*` | `scripts/proof-test.sh` |
| **IRREVERSIBLE requires human** | Reversibility gate in API + Runner | `test_reversibility_gate_invariants.py::TestReversibilityGateLogic` | `scripts/proof-test.sh` |
| **DEH verified independently** | Runner recomputes envelope hash | `services/runner/tests/test_runner.py::test_deh_*` | Runner logs on mismatch |
| **Manifest drift rejected** | Hash comparison at job execution | `services/runner/tests/test_runner.py::test_manifest_*` | Runner logs on mismatch |
| **Budget exhaustion halts** | Preemptive try_* gates | `test_reversibility_gate_invariants.py::TestRunnerBudgetMultiplier*` | Runner error codes |
| **Completion requires artifacts** | Runner artifact check | `services/runner/tests/test_runner.py::test_artifact_*` | Runner error codes |
| **Toxic topology detected** | SessionRiskTracker sliding window | `test_governance_redteam_invariants.py::TestSessionRiskTracker` | Redis session data |
| **Unknown state = DENY** | Default rejection in all paths | `test_governance_invariants.py::TestFailSafeInvariants` | N/A (absence of bypass) |
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
| Auth invariant tests | `apps/api/tests/test_auth_invariants.py` | Verify authentication checks |
| Governance invariant tests | `apps/api/tests/test_governance_invariants.py` | Verify policy enforcement |
| Red team invariant tests | `apps/api/tests/test_governance_redteam_invariants.py` | Verify attack resistance |
| Reversibility gate tests | `apps/api/tests/test_reversibility_gate_invariants.py` | Verify reversibility + budget |
| Runner tests | `services/runner/tests/test_runner.py` | Verify execution controls |
| UI normalization tests | `apps/ui/lib/__tests__/governance-normalization.test.ts` | Verify fail-closed UI |
| UI style compliance tests | `apps/ui/lib/__tests__/governance-style-compliance.test.ts` | Verify semantic tokens |
| Proof script | `scripts/proof-test.sh` | End-to-end invariant verification |
| Audit script | `scripts/audit.sh` | One-command evidence generation |
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

- [ ] Run `./scripts/audit.sh` and verify `AUDIT PASSED - GUARANTEES VERIFIED`
- [ ] Verify all 76 API tests pass (auth, governance, redteam, reversibility)
- [ ] Verify all 36 UI tests pass (normalization + style compliance)
- [ ] Inspect `apps/api/app/main.py::govern_proposal()` for hardcoded DENY rules
- [ ] Inspect `services/runner/app/runner.py::execute_job()` for defense-in-depth checks
- [ ] Look for `INTENT PRESERVATION` comments explaining rejection behavior
- [ ] Verify manifest lock exists: `services/runner/manifest.lock.json`
- [ ] Confirm Redis `m87:events` stream is populated with governance events
- [ ] Verify no direct tool execution in adapter code (grep for subprocess calls)
- [ ] Check CI badge is green: `https://github.com/MacFall7/MacFall7-m87-governed-swarm/actions`

---

## Change Control

Any modification to governance enforcement **MUST**:

1. Update the corresponding test in the proof map
2. Run `./scripts/proof-test.sh` to verify invariants
3. Document the change in commit message with `[GOVERNANCE]` prefix
4. Be reviewed by a second engineer

**Violations of this process are audit findings.**
