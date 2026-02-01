---
paths:
  - "services/*-adapter/**"
  - "packages/adapter-sdk/**"
---

# Adapter Rules

Adapters are proposal generators. They do not execute or approve.

## Adapter Roles

| Agent  | Effects                                          | Max Risk |
|--------|--------------------------------------------------|----------|
| Casey  | READ_REPO, WRITE_PATCH, RUN_TESTS                | 0.6      |
| Jordan | SEND_NOTIFICATION, BUILD_ARTIFACT, CREATE_PR, READ_REPO | 0.5 |
| Riley  | READ_REPO, BUILD_ARTIFACT, SEND_NOTIFICATION     | 0.4      |
| Human  | All effects                                      | 1.0      |

## Rules

- Adapters do not reason about policy - server is authoritative
- Adapters do not decide - they only propose
- Adapters must validate effect scope before submission (client-side hint)
- Adapters must fail closed on errors
- Adapters must pass M87_API_KEY to authenticate proposals

## Prohibited Patterns

- Direct execution of any command
- Approval of any proposal
- Escalation of effect scope
- Modification of governance policy
- Access to effects outside declared scope

## Required Patterns

- Poll events via /v1/events
- Submit proposals via /v1/govern/proposal
- Include truth_account with observations and claims
- Log all proposal submissions with decision results
