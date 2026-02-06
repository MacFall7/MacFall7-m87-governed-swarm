---
paths:
  - "**/*"
---

# Meta-Constraints on Future Changes

These rules constrain what Claude Code may do when modifying this codebase.
They exist to prevent well-intentioned "improvements" from weakening security guarantees.

## NEVER Do These Things

### 1. Auto-Relax Constraints

**FORBIDDEN**: Adding code that automatically relaxes security constraints based on:
- Agent confidence scores
- Historical success rates
- "Safe" content detection
- Any form of learned trust

**Why**: Agents cannot escalate their own permissions. Any auto-relaxation creates an escalation path.

### 2. Replace Fail-Closed with Retries

**FORBIDDEN**: Changing rejection behavior to retry with weaker constraints. Examples:
- "If DEH verification fails, try without DEH"
- "If budget exceeded, request a budget increase"
- "If manifest drift detected, use cached manifest"

**Why**: Failure must not silently weaken policy. Retries with relaxed constraints are indistinguishable from attacks.

### 3. Add "Helpful Defaults" to Execution Paths

**FORBIDDEN**: Adding default behaviors that bypass checks. Examples:
- Default-allow for unknown effect tags
- Default-allow for missing reversibility class
- "Assume safe" for missing budget fields

**Why**: Unknown state must resolve to DENY. Helpful defaults create bypass vectors.

### 4. Create Fast Paths Around Governance

**FORBIDDEN**: Adding execution paths that skip governance checks. Examples:
- "Trusted agent" exemptions
- "Read-only" bypasses that don't verify read-only status
- "Internal" endpoints without authentication

**Why**: All execution must flow through governance. No exceptions.

### 5. Weaken Artifact Requirements

**FORBIDDEN**: Allowing completion without artifacts. Examples:
- "Minor changes don't need artifacts"
- "Trusted tools can skip artifact generation"
- Empty artifacts ({}) treated as valid

**Why**: Completion without proof is indistinguishable from lying about completion.

### 6. Add Configurable Security Overrides

**FORBIDDEN**: Making security checks configurable via:
- Environment variables (except documented kill-switches)
- Runtime configuration
- Per-request flags
- Agent preferences

**Why**: Security constraints are not preferences. Configuration creates attack surface.

## ALWAYS Do These Things

### 1. Preserve Rejection Behavior

When modifying error handling:
- Rejection must remain the default
- Error messages may be improved
- Error codes must not change meaning
- No silent fallbacks to permissive behavior

### 2. Maintain Defense-in-Depth

When adding new features:
- API checks remain even if runner checks exist
- Runner checks remain even if API checks exist
- UI normalization remains even if API returns normalized data

### 3. Document Intent

When modifying governance code:
- Add INTENT PRESERVATION comments explaining why rejection is correct
- Document what attacks the check prevents
- Explain why "helpful" alternatives would be dangerous

### 4. Update Proof Map

When modifying enforcement mechanisms:
- Update `docs/PROOF_MAP.md` with new claim → mechanism → test mapping
- Ensure tests cover the new enforcement
- Run `./scripts/proof-test.sh` before committing

## Red Flags in Code Review

These patterns suggest a governance weakening that should be rejected:

```python
# RED FLAG: Catching exceptions to continue
except VerificationError:
    log.warning("Verification failed, continuing anyway")

# RED FLAG: Conditional security checks
if not settings.STRICT_MODE:
    skip_deh_verification()

# RED FLAG: Trust escalation
if agent.trust_score > 0.9:
    allow_without_human_approval()

# RED FLAG: Retry with relaxation
for i in range(3):
    try:
        execute_with_full_checks()
    except BudgetExceeded:
        budget *= 1.5  # DANGEROUS
```

## Commit Message Requirements

Changes to governance enforcement must:
- Include `[GOVERNANCE]` prefix in commit message
- Explain which invariant is affected
- Reference the test that verifies the change
- Not be squashed with non-governance changes

Example:
```
[GOVERNANCE] Add cleanup_cost budget multiplier

Affects: Autonomy Budget enforcement (Law #6)
Test: test_runner.py::test_budget_multiplier_applied
Proof: Runner logs show adjusted budget values

This applies budget_multiplier at the enforcement point in runner,
not at mint time in API. Enforcement-time application ensures the
multiplier cannot be bypassed by job tampering.
```
