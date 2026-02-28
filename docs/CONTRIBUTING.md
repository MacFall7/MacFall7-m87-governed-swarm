# Contributing to M87 Governed Swarm

This document defines the process for contributing to M87, with special attention to governance-touching changes.

---

## Quick Start

1. Fork the repository
2. Create a feature branch
3. Make changes
4. Run `./scripts/audit.sh`
5. Commit with proper format
6. Open a pull request

---

## Commit Message Format

All commits must follow this format:

```
<type>: <short description>

<optional body>

<optional footer>
```

### Types

| Type | When to Use |
|------|-------------|
| `feat` | New feature |
| `fix` | Bug fix |
| `docs` | Documentation only |
| `test` | Adding or fixing tests |
| `refactor` | Code change that neither fixes nor adds |
| `chore` | Build, CI, tooling changes |
| `[GOVERNANCE]` | **Any change touching governance enforcement** |

### Governance Changes

Changes that touch governance enforcement **MUST**:

1. Use `[GOVERNANCE]` prefix
2. Explain which invariant is affected
3. Reference the test that verifies the change
4. Include proof that tests pass

**Example:**

```
[GOVERNANCE] Add cleanup_cost budget multiplier

Affects: Autonomy Budget enforcement (Law #6)
Test: test_runner.py::test_budget_multiplier_applied
Proof: Runner logs show adjusted budget values

This applies budget_multiplier at the enforcement point in runner,
not at mint time in API. Enforcement-time application ensures the
multiplier cannot be bypassed by job tampering.
```

### What Counts as Governance-Touching?

Any change to:
- `apps/api/app/main.py` (govern_proposal, Phase 3-6)
- `services/runner/app/runner.py` (execute_job, verification functions)
- `apps/ui/lib/governance/*.ts` (normalization, reconciliation)
- `.claude/rules/*.md` (Claude Code constraints)
- `docs/PROOF_MAP.md` or `docs/ARCHITECTURE.md` (governance docs)

---

## Pull Request Process

### For Non-Governance Changes

1. Ensure `./scripts/audit.sh` passes
2. Update documentation if needed
3. Request review from one maintainer

### For Governance Changes

1. Ensure `./scripts/audit.sh` passes
2. Update `docs/PROOF_MAP.md` if adding new enforcement
3. Add `INTENT PRESERVATION` comment if modifying rejection behavior
4. Request review from **two** maintainers
5. Explicitly acknowledge which Governing Law is affected

---

## Code Review Checklist

Reviewers should verify:

### For All Changes

- [ ] Tests pass (`./scripts/audit.sh`)
- [ ] Commit message follows format
- [ ] No hardcoded credentials or secrets
- [ ] No unnecessary dependencies added

### For Governance Changes

- [ ] Invariant is preserved or strengthened (never weakened)
- [ ] Test covers the new enforcement path
- [ ] PROOF_MAP.md updated if needed
- [ ] INTENT PRESERVATION comment explains why rejection is correct
- [ ] No "helpful defaults" that bypass checks
- [ ] No retry-with-relaxation patterns

---

## Forbidden Patterns

These patterns will be rejected in code review:

```python
# REJECTED: Swallowing verification errors
except VerificationError:
    pass

# REJECTED: Conditional security
if not settings.STRICT_MODE:
    skip_verification()

# REJECTED: Trust escalation
if agent.trust_score > 0.9:
    auto_approve()

# REJECTED: Retry with relaxation
for attempt in range(3):
    try:
        execute()
    except BudgetExceeded:
        budget *= 1.5  # NEVER DO THIS
```

---

## Testing Requirements

### Before Opening PR

```bash
# Run full audit
./scripts/audit.sh

# If touching API code
cd apps/api && pytest tests/ -v

# If touching UI code
cd apps/ui && npm test

# If touching runner code
cd services/runner && pytest tests/ -v
```

### CI Requirements

All PRs must pass:
- Unit tests (pytest)
- Integration tests (proof-test.sh)
- Lint checks (py_compile)

---

## Documentation Updates

When you change enforcement:

1. Update `docs/ARCHITECTURE.md` if a Governing Law is affected
2. Update `docs/PROOF_MAP.md` with claim → test mapping
3. Update `README.md` if guarantees change
4. Add/update INTENT PRESERVATION comments in code

---

## Questions?

- Open an issue for clarification
- Tag maintainers for governance questions
- Reference this document in PR descriptions

---

## License

By contributing, you agree that your contributions will be licensed under the Business Source License 1.1 — see [LICENSE](../LICENSE) for details.
