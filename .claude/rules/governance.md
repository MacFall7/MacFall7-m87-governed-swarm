---
paths:
  - "apps/api/**"
  - "packages/contracts/**"
---

# Governance Invariants

This system enforces governance invariants. All changes must preserve:

## Core Invariants

1. **No approval → no job**: Jobs are only minted after governance decision
2. **No API key → no mutation**: All mutating endpoints require X-M87-Key
3. **No scope → no proposal**: Agents cannot propose effects outside their scope
4. **No decision → no execution**: Runner only executes approved decisions

## Rules

- No code may bypass proposal → decision → execution flow
- No adapter may self-approve actions
- No direct side effects outside declared Effect contracts
- All mutations must be auditable via m87:events stream
- READ_SECRETS is absolutely forbidden regardless of agent

## Effect Tags (Canonical)

```
READ_REPO, WRITE_PATCH, RUN_TESTS, BUILD_ARTIFACT,
NETWORK_CALL, SEND_NOTIFICATION, CREATE_PR, MERGE, DEPLOY, READ_SECRETS
```

## Decision Types

- `ALLOW`: Immediate job mint
- `DENY`: No job, emit denial event
- `REQUIRE_HUMAN`: Pending approval queue
- `NEED_MORE_EVIDENCE`: Request more truth account data

---

## V1 Governance Hardening

### Deployment Envelope

Every job includes a `deployment_envelope` with:
- `model_id`, `model_source` (closed/open)
- `weights_hash`, `post_training_recipe_hash` (optional)
- `inference_policy`, `safety_mode`
- `autonomy_budget`

### Deployment Envelope Hash (DEH)

- `envelope_hash = SHA256(canonical_json(deployment_envelope))`
- Canonicalization: `exclude_none=True`, `sort_keys=True`, `separators=(',', ':')`
- Runner recomputes DEH independently and rejects mismatches

### Autonomy Budget

Rate and magnitude limits:
- `max_steps`, `max_tool_calls`, `max_parallel_agents`
- `max_runtime_seconds`, `max_external_io`
- `max_write_scope`: `none < sandbox < staging < prod`

### Artifact-Backed Completion

- Tasks cannot be marked complete without verifiable artifacts
- Artifact types: `files`, `diffs`, `logs`, `receipts`
- Each artifact includes a hash for verification

### Machine-Verifiable Evidence

All runner results include:
- `deh_evidence`: claimed vs recomputed hash + verified flag
- `autonomy_budget`: what was allowed (immutable snapshot)
- `autonomy_usage`: what was consumed
- `completion_artifacts`: verifiable proof of work
