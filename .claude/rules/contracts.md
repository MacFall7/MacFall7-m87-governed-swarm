---
paths:
  - "packages/contracts/**"
---

# Contract Rules

TypeScript contracts are the source of truth for all data structures.

## Contract Files

| File          | Purpose                              |
|---------------|--------------------------------------|
| effects.ts    | Effect tag enum                      |
| intent.ts     | Intent schema                        |
| proposal.ts   | Proposal schema with truth_account   |
| decision.ts   | Governance decision schema           |
| job.ts        | JobSpec schema                       |

## Rules

- Python Pydantic models must conform to TS contracts
- No silent divergence allowed between TS and Python schemas
- Breaking changes require explicit version bump
- All fields must be explicitly typed (no `any`)
- Optional fields must be marked explicitly

## Validation

- API validates incoming proposals against contract
- Adapter SDK mirrors contract types in Pydantic
- Mismatched fields should fail fast, not silently coerce

## Change Protocol

1. Update TypeScript contract first
2. Update Python Pydantic models to match
3. Update adapter SDK models
4. Run contract conformance tests
5. Bump version if breaking
