# Auditor Walkthrough

One-page guide for security reviewers, auditors, and investors.

**Time estimate**: 30-60 minutes for initial review

---

## Step 1: Read These Three Documents (15 min)

Read in this order:

1. **[README.md](../README.md)** (5 min)
   - Focus on: "Fail-Closed Guarantees" and "What This System Will Not Do"
   - These are the operator contract—what the system promises

2. **[docs/ARCHITECTURE.md](ARCHITECTURE.md)** (5 min)
   - Focus on: "Governing Laws" table at the top
   - Each law maps to enforcement code and tests

3. **[docs/PROOF_MAP.md](PROOF_MAP.md)** (5 min)
   - Focus on: "Claim → Mechanism → Test" table
   - This is the evidence chain

---

## Step 2: Run One Command (5-10 min)

```bash
./scripts/audit.sh
```

This script:
- Runs integration tests (7 invariants) - if API is running
- Runs API unit tests (76 tests: auth, governance, redteam, reversibility)
- Runs UI governance tests (36 tests: normalization + style compliance)
- Generates evidence in `evidence/` directory

**Expected output**: `AUDIT PASSED - GUARANTEES VERIFIED`

**Expected test counts**:
- API: 76 passed
- UI: 36 passed (1 skipped - broad style check)

If any test fails, the audit fails. Do not trust the system until all tests pass.

---

## Step 3: Inspect Three Files (10-20 min)

### 3.1 Governance Engine (`apps/api/app/main.py`)

Search for `def govern_proposal`:

```python
def govern_proposal(...):
    # This is where ALLOW/DENY/REQUIRE_HUMAN decisions happen
```

Verify:
- [ ] READ_SECRETS → always DENY (hardcoded)
- [ ] DEPLOY → REQUIRE_HUMAN
- [ ] Unknown effects → DENY
- [ ] Agent scope violations → DENY

### 3.2 Runner Enforcement (`services/runner/app/runner.py`)

Search for `def execute_job`:

```python
def execute_job(...):
    # This is where defense-in-depth happens
```

Verify:
- [ ] DEH (envelope hash) verified before execution
- [ ] Manifest hash checked before execution
- [ ] Budget exhaustion halts immediately
- [ ] Artifacts required for completion

Look for `INTENT PRESERVATION` comments—these explain why rejection is correct.

### 3.3 UI Normalization (`apps/ui/lib/governance/normalize.ts`)

Search for `normalizeIncomingGovernance`:

```typescript
export function normalizeIncomingGovernance(...):
    // This is the single entry point for all governance data
```

Verify:
- [ ] ANY blocking signal forces `blocked=true`
- [ ] Unknown enums default conservatively
- [ ] Reconciliation re-validates on load

---

## Step 4: Verify Kill-Switches (5 min)

Check for emergency overrides:

```bash
grep -r "M87_DISABLE" apps/api/ services/
```

Verify:
- [ ] Kill-switches log loudly on startup
- [ ] Kill-switches are documented in README
- [ ] No undocumented bypass mechanisms

---

## Step 5: Check CI Status

Visit the repository's GitHub Actions:

```
https://github.com/MacFall7/MacFall7-m87-governed-swarm/actions
```

Verify:
- [ ] CI badge is green on main branch
- [ ] Integration tests (proof-test.sh) run on every PR
- [ ] Test coverage includes governance code

---

## Red Flags to Watch For

During your review, these patterns indicate governance weakening:

| Pattern | Why It's Dangerous |
|---------|-------------------|
| `except ...: pass` | Swallowing verification errors |
| `if DEBUG:` around security checks | Debug mode bypasses |
| `# TODO: add check later` | Missing enforcement |
| `trust_score > threshold` | Auto-escalation of trust |
| `retry with budget *= 1.5` | Relaxing constraints on failure |

---

## Questions to Ask

1. "What happens if Redis is unavailable?"
   - Expected: API returns 503, no silent bypass

2. "What happens if an agent proposes READ_SECRETS?"
   - Expected: Always DENY, no override possible

3. "What happens if the manifest changes after a job is approved?"
   - Expected: Runner rejects (hash mismatch)

4. "What happens if the UI cache has stale data?"
   - Expected: Reconciliation re-validates, blocked if signals present

---

## Certification Statement

After completing this walkthrough:

> I have reviewed the M87 Governed Swarm governance architecture. The system implements defense-in-depth with fail-closed semantics at API, Runner, and UI layers. All claims in PROOF_MAP.md are backed by executable tests. The audit script (`./scripts/audit.sh`) passed with all tests green.

Date: _______________
Reviewer: _______________
Commit: _______________

---

## Contact

For questions about the governance architecture:
- Open an issue: https://github.com/MacFall7/MacFall7-m87-governed-swarm/issues
