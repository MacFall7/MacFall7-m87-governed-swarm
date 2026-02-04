---
paths:
  - "services/runner/**"
---

# Runner Rules

Runner executes only approved decisions from the m87:jobs stream.

## Execution Model

1. Runner consumes ONLY from `m87:jobs` stream (NOT `m87:events`)
2. Jobs are minted ONLY after governance approval
3. Each job includes: job_id, proposal_id, tool, args, timeout_seconds

## Rules

- Runner executes only approved decisions
- Runner must log intent_id, proposal_id, job_id for every execution
- No dynamic capability expansion - tool allowlist is fixed
- Runner must report results back via /v1/runner/result
- Runner must use consumer groups for exactly-once processing

## Tool Allowlist

```python
TOOL_ALLOWLIST = {"echo", "pytest", "git", "build"}
```

- Tools outside allowlist are rejected
- No shell expansion or injection paths
- Arguments are validated before execution

## Prohibited Patterns

- Reading from m87:events stream
- Executing without a JobSpec
- Expanding tool allowlist dynamically
- Bypassing timeout enforcement
- Silent failure (must always report result)

## Failure Modes

- Unknown tool → reject, emit job.failed
- Timeout exceeded → kill, emit job.failed
- Exit code != 0 → emit job.failed with stderr
- Success → emit job.completed with stdout

---

## V1 Governance Rules (Runner)

### Tool Development

- Never introduce a new tool without:
  - Manifest entry with declared effects
  - Write-scope requirements
  - Artifact-backed completion support (or explicit failure)

### Network Egress

- Never add direct `requests.*` calls in tools
- All network egress must use `governed_request(tracker, ...)`
- External I/O is metered via `max_external_io` budget

### Governance Evidence

- Any governance check failure must be fail-closed with structured evidence
- Include `deh_evidence` when possible
- Include `autonomy_budget` and `autonomy_usage` in results
- Keep result payload bounded and JSON-serializable

### Preemptive Enforcement

Runner enforces Autonomy Budget preemptively:
- `try_step()` before each step
- `try_tool_call()` before tool dispatch
- `runtime_exceeded()` at multiple checkpoints
- `scope_rank()` for write-scope gating

### Defense-in-Depth

- Runner recomputes DEH independently (does not trust API)
- Open-weight models clamped to `safe_default` + `sandbox` write scope
- Artifact-backed completion: no "completed" without verifiable artifacts
