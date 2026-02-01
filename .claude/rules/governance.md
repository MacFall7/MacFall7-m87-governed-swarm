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
