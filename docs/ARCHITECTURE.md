# Architecture

Deep dive into the M87 Governed Swarm system design.

## Design Philosophy

M87 is built on one principle: **autonomy requires governance**.

Traditional agent systems give agents freedom to act. M87 inverts this: agents can only **propose**, and a separate governance layer **decides** what actually happens.

This creates:
- **Auditability**: Every action has a traceable decision
- **Control**: Humans can intervene at any point
- **Safety**: Agents cannot escalate their own permissions

## Core Flow

```
┌──────────┐     ┌──────────┐     ┌────────────┐     ┌─────────┐     ┌───────────┐
│  Intent  │ ──▶ │ Proposal │ ──▶ │ Governance │ ──▶ │   Job   │ ──▶ │ Execution │
└──────────┘     └──────────┘     └────────────┘     └─────────┘     └───────────┘
     │                │                  │                │                │
     │                │                  │                │                │
  Created by      Created by         Decides:         Minted only      Performed by
  user/system     adapters          ALLOW/DENY/       if approved       Runner
                                   REQUIRE_HUMAN
```

### 1. Intent

An intent is a request for something to happen. It can come from:
- A user via the API
- An external system
- A scheduled trigger

```json
{
  "intent_id": "i-abc123",
  "from": "user",
  "mode": "fix",
  "goal": "Fix the authentication bug in login.py"
}
```

### 2. Proposal

Adapters watch for intents and create proposals. A proposal specifies:
- What effects are needed (READ_REPO, WRITE_PATCH, etc.)
- A truth account (observations and claims supporting the proposal)
- A risk score

```json
{
  "proposal_id": "p-def456",
  "intent_id": "i-abc123",
  "agent": "Casey",
  "summary": "Fix null check in login.py:45",
  "effects": ["READ_REPO", "WRITE_PATCH", "RUN_TESTS"],
  "truth_account": {
    "observations": ["login.py:45 has uncaught exception"],
    "claims": [{"claim": "Fix is low risk", "confidence": 0.8}]
  },
  "risk_score": 0.3
}
```

### 3. Governance Decision

The governance engine evaluates the proposal against policy rules:

1. **READ_SECRETS** → Always DENY
2. **Agent scope violation** → DENY (agent proposing outside their effects)
3. **Risk threshold exceeded** → REQUIRE_HUMAN
4. **DEPLOY** → REQUIRE_HUMAN
5. **Otherwise** → ALLOW

### 4. Job

If the decision is ALLOW (or REQUIRE_HUMAN after approval), a JobSpec is minted:

```json
{
  "job_id": "j-ghi789",
  "proposal_id": "p-def456",
  "tool": "pytest",
  "args": ["tests/"],
  "timeout_seconds": 120
}
```

Jobs go to the `m87:jobs` Redis stream.

### 5. Execution

The Runner:
- Consumes from `m87:jobs` stream only
- Validates tool against allowlist
- Executes with timeout
- Reports result back to API

## Service Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                              External                                │
│                                                                     │
│   Users ──────▶ Dashboard (UI) ──────▶ Governance API               │
│                 :3000                   :8000                       │
└─────────────────────────────────────────────────────────────────────┘
                                            │
                                            │
┌─────────────────────────────────────────────────────────────────────┐
│                              Internal                                │
│                                                                     │
│   ┌─────────────┐    ┌─────────────┐    ┌─────────────┐            │
│   │   Casey     │    │   Jordan    │    │   Riley     │            │
│   │  Adapter    │    │  Adapter    │    │  Adapter    │            │
│   │             │    │             │    │             │            │
│   │ (code)      │    │ (delivery)  │    │ (analysis)  │            │
│   └──────┬──────┘    └──────┬──────┘    └──────┬──────┘            │
│          │                  │                  │                    │
│          └──────────────────┼──────────────────┘                    │
│                             │                                       │
│                             ▼                                       │
│                    ┌─────────────────┐                             │
│                    │  Governance API │                             │
│                    │    (FastAPI)    │                             │
│                    └────────┬────────┘                             │
│                             │                                       │
│          ┌──────────────────┼──────────────────┐                    │
│          │                  │                  │                    │
│          ▼                  ▼                  ▼                    │
│   ┌─────────────┐    ┌─────────────┐    ┌─────────────┐            │
│   │   Runner    │    │  Notifier   │    │    Redis    │            │
│   │             │    │             │    │             │            │
│   │ (executes   │    │ (observes   │    │ m87:events  │            │
│   │  jobs)      │    │  events)    │    │ m87:jobs    │            │
│   └─────────────┘    └─────────────┘    └─────────────┘            │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### Service Responsibilities

| Service | Responsibility | Can Propose | Can Execute | Can Approve |
|---------|---------------|-------------|-------------|-------------|
| API | Governance decisions | No | No | No (routes to humans) |
| Runner | Job execution | No | **Yes** | No |
| Notifier | Event observation | No | No | No |
| Casey | Code proposals | **Yes** | No | No |
| Jordan | Delivery proposals | **Yes** | No | No |
| Riley | Analysis proposals | **Yes** | No | No |
| Dashboard | Human interface | No | No | **Yes** (via API) |

## Redis Streams

M87 uses Redis Streams for event sourcing and job queuing.

### m87:events

The audit log. Every significant event is recorded here:

```
intent.created      - New intent received
proposal.allowed    - Proposal approved automatically
proposal.denied     - Proposal rejected
proposal.needs_approval - Proposal awaiting human approval
proposal.approved   - Human approved a proposal
job.created         - Job minted
job.completed       - Job finished successfully
job.failed          - Job failed
```

### m87:jobs

The work queue. Only approved jobs appear here:

```
{
  "job_id": "j-xxx",
  "proposal_id": "p-xxx",
  "tool": "pytest",
  "args": ["tests/"],
  "timeout_seconds": 120
}
```

### Consumer Groups

- **runner-group**: Runner consumes jobs exactly once
- **notifier-group**: Notifier observes events for alerting

## Agent Effect Scopes

Each agent has a defined scope of effects they can propose:

```
Casey:  {READ_REPO, WRITE_PATCH, RUN_TESTS}      max_risk: 0.6
Jordan: {SEND_NOTIFICATION, BUILD_ARTIFACT,      max_risk: 0.5
         CREATE_PR, READ_REPO}
Riley:  {READ_REPO, BUILD_ARTIFACT,              max_risk: 0.4
         SEND_NOTIFICATION}
Human:  {all effects}                            max_risk: 1.0
```

If an agent proposes an effect outside their scope, the proposal is **denied**.

If an agent proposes with a risk score above their threshold, the proposal requires **human approval**.

## Security Model

### Authentication

All mutating endpoints require the `X-M87-Key` header:

```bash
curl -X POST http://localhost:8000/v1/govern/proposal \
  -H "X-M87-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '...'
```

### Protected Endpoints

| Endpoint | Requires Auth |
|----------|---------------|
| POST /v1/govern/proposal | Yes |
| POST /v1/approve/{id} | Yes |
| POST /v1/deny/{id} | Yes |
| POST /v1/runner/result | Yes |
| GET /v1/events | No |
| GET /v1/agents | No |

### Network Isolation

- Redis has no public port (internal only)
- Adapters can only reach the API, not the runner
- Runner executes in isolation with a fixed tool allowlist

### Tool Allowlist

The runner only executes these tools:

```python
TOOL_ALLOWLIST = {"echo", "pytest", "git", "build"}
```

Any other tool is rejected.

## Failure Modes

M87 is designed to fail **closed** and **locally**:

| Failure | Behavior |
|---------|----------|
| Unknown effect | DENY |
| Agent scope violation | DENY |
| Unknown tool | Job rejected |
| Timeout exceeded | Job killed, marked failed |
| Redis unavailable | API returns 503 |
| Missing API key | 401 Unauthorized |

## Data Flow Example

1. User creates intent via API
2. Intent emitted to m87:events
3. Casey adapter sees intent.created
4. Casey builds proposal with effects [READ_REPO, WRITE_PATCH]
5. Casey submits proposal to /v1/govern/proposal
6. Governance checks:
   - Casey can propose READ_REPO, WRITE_PATCH ✓
   - Risk 0.3 < Casey's max 0.6 ✓
   - No READ_SECRETS ✓
   - Not DEPLOY ✓
7. Decision: ALLOW
8. Job minted to m87:jobs
9. Runner consumes job
10. Runner validates tool in allowlist
11. Runner executes with timeout
12. Runner reports result to /v1/runner/result
13. Result emitted to m87:events
14. Notifier sees job.completed, can alert

## Claude Code Integration

The `.claude/` directory teaches Claude Code to see this as a governed system:

```
.claude/
├── rules/           # Path-scoped governance rules
│   ├── governance.md
│   ├── adapters.md
│   ├── runner.md
│   ├── contracts.md
│   └── infra.md
├── settings.json    # Hooks and permissions
└── models/          # Model routing
    ├── explore.yaml
    └── implement.yaml
```

This ensures Claude Code:
- Respects governance boundaries when editing
- Understands what each service can/cannot do
- Doesn't accidentally break invariants

## Runner Governance Stack

The Runner enforces defense-in-depth governance for all JobSpecs pulled from `m87:jobs`.

```
┌─────────────────────────────────────────────────────────────┐
│                    RUNNER GOVERNANCE STACK                   │
├─────────────────────────────────────────────────────────────┤
│  (1) Capability Declaration                                  │
│      └─ DeploymentEnvelope + DEH verification                │
│                                                              │
│  (2) Rate & Blast-Radius Control                             │
│      └─ AutonomyBudget + preemptive try_* gates              │
│      └─ Write scope gating (scope_rank)                      │
│                                                              │
│  (3) Egress Hard-Stop                                        │
│      └─ governed_request() — single choke point              │
└─────────────────────────────────────────────────────────────┘
```

### Job Lifecycle (Governed)

1. API receives a Proposal and mints a JobSpec only after governance decisions.
2. API computes and pins:
   - `manifest_hash`
   - `deployment_envelope`
   - `envelope_hash` (DEH)
3. Runner consumes the JobSpec and enforces:
   - Manifest drift refusal (`manifest_hash` must match runner manifest)
   - DEH verification (recompute and compare)
   - Autonomy Budget gates (preemptive)
   - Artifact-backed completion enforcement
4. Runner reports bounded, sanitized results including governance evidence.

### Machine-Verifiable Evidence

Runner results include:
- `deh_evidence`:
  - `envelope_hash_verified` (bool)
  - `deh_claimed`
  - `deh_recomputed`
- `autonomy_budget` + `autonomy_usage`
- `completion_artifacts` (verifiable hashes)

### Trust Boundary

**All enforcement happens in the Runner—the only component authorized to execute tools—so policy can't be bypassed by upstream orchestration.**

---

## Extending the System

### Adding a New Agent

1. Define effect scope in `apps/api/app/main.py` AGENT_PROFILES
2. Create adapter in `services/{name}-adapter/`
3. Add to `docker-compose.yml`
4. Document in `.claude/rules/adapters.md`

### Adding a New Effect

1. Add to TypeScript contracts `packages/contracts/src/effects.ts`
2. Add to API effect validation
3. Update agent scopes if needed
4. Add to runner tool allowlist if executable

### Adding a New Policy Rule

1. Edit `govern_proposal()` in `apps/api/app/main.py`
2. Add rule before the final ALLOW fallback
3. Document in `.claude/rules/governance.md`
