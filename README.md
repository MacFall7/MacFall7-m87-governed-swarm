# M87 Governed Swarm

A policy-gated autonomous execution substrate. Agents propose, governance decides, runners execute.

```
Intent → Proposal → Decision → Job → Execution
         ↑                      ↑
      Adapters              Runner
      (propose)            (execute)
```

## Governance Hardening (V1)

This repo implements a fail-closed governance perimeter for all executable agent work via a hardened Runner.

### Runner Governance Stack

1. **Capability Declaration**
   - Deployment Envelope included in every job
   - **DEH (Deployment Envelope Hash)** computed at mint time
   - Runner recomputes DEH independently and rejects mismatches

2. **Rate & Blast-Radius Control**
   - **Autonomy Budget** enforced preemptively (steps, tool calls, runtime, external I/O)
   - Write-scope gating (`none < sandbox < staging < prod`)

3. **Egress Hard-Stop**
   - `governed_request()` is the **single choke point** for any tool network access
   - All external I/O is metered via `max_external_io` and runtime checks

### Result Integrity

- **Artifact-backed completion**: Runner must not report "completed" without verifiable artifacts
- **Machine-verifiable receipts**: Results include `deh_evidence` (claimed vs recomputed hash + verified flag)

**All enforcement happens in the Runner—the only component authorized to execute tools—so policy can't be bypassed by upstream orchestration.**

### API Governance (Phase 3-6)

The API enforces additional governance before jobs are even minted:

4. **Session Risk Tracking (Phase 3)**
   - Redis-backed sliding-window cumulative effect tracking
   - **Toxic topology detection**: Catches salami-slicing attacks (e.g., `READ_REPO` → `NETWORK_CALL`)
   - Fail-closed on Redis blindness for exfil-adjacent effects

5. **Code Artifact Inspection (Phase 5)**
   - Tripwire scan for exfil primitives (`import requests`, `subprocess`, `os.environ`, etc.)
   - Bounded inspection via subprocess (async-safe, DoS-resistant)

6. **Human Override Protection (Phase 6)**
   - Challenge-response for `REQUIRE_HUMAN` decisions
   - Proposal hash binding prevents replay and bait-switch attacks

### No Bypass Guarantee

**Both `/v1` and `/v2` governance endpoints flow through the same Phase 3-6 enforcement lane.**

No execution path can enqueue jobs without passing Phase 3-6 governance.

### UI Governance Observability Layer

The UI includes a **fail-closed normalization boundary** that ensures all governance data is consistently validated before display.

**Key Components:**

| Module | Purpose |
|--------|---------|
| `normalize.ts` | Single entry point for all governance data |
| `data.ts` | API client that makes normalization inescapable |
| `analytics.ts` | Governance metrics and dashboard computations |
| `persistence.ts` | Serialization with reconciliation on load |
| `types.ts` | Canonical TypeScript types |
| `mock.ts` | Test data that flows through normalization |

**Fail-Closed Invariants:**

1. **ANY blocking signal forces blocked=true** - No exceptions
2. **Unknown enums default conservatively** - Unknown reversibility → `HARD`, unknown cleanup_cost → `HIGH`
3. **Reconciliation on every load** - Cached/persisted data re-validates against fail-closed rules
4. **Budget exhaustion blocks** - `max_steps=0`, `max_tool_calls=0`, or `retries_remaining=0` triggers blocking

**Normalization Metadata:**

Every `GovernanceState` includes `_normalization` tracking:
- `normalized_at` - Timestamp of normalization
- `blocking_signals` - Array of detected blocking reasons
- `reconciliation_applied` - True IFF reconciliation changed derived state
- `unknown_fields` - Any unrecognized enum values defaulted conservatively

**Why This Matters:**

The normalization layer prevents **split-brain drift** where the UI shows "allowed" while the backend has actually blocked an action. By enforcing fail-closed semantics at the UI ingestion boundary, display state can never be more permissive than actual governance state.

---

## What This Is

M87 is a governed agent execution platform where:

- **Agents propose actions** but cannot execute them
- **Governance decides** what gets approved, denied, or escalated to humans
- **Runners execute** only what governance approves
- **Everything is auditable** via event streams

This is not "AI agents doing whatever." This is **autonomy under explicit authorization**.

## Core Invariants

| Invariant | Meaning |
|-----------|---------|
| No approval → no job | Jobs mint only after governance decision |
| No API key → no mutation | All mutations require authentication |
| No scope → no proposal | Agents can't propose outside their effect scope |
| No decision → no execution | Runner only executes approved decisions |

## Fail-Closed Guarantees

M87 is designed so that **ambiguity resolves to denial**, not permission.

| Condition | Behavior |
|-----------|----------|
| Unknown effect tag | DENY |
| Unknown reversibility class | DENY (Runner rejects) |
| Missing deployment envelope | DENY (Runner rejects) |
| DEH hash mismatch | DENY (Runner rejects) |
| Manifest hash drift | DENY (Runner rejects) |
| Budget field missing | Runner defaults applied (not infinite) |
| Redis unavailable | API returns 503 (no silent bypass) |
| Tool not in manifest | DENY (Runner rejects) |
| Sensor blindness (Phase 3) | DENY for exfil-adjacent effects |

**Why this matters**: In security-critical systems, "fail-open" creates exploitable gaps. M87 never assumes permission—it requires explicit proof of authorization at every layer.

## What This System Will Not Do

These are **anti-features**—capabilities deliberately excluded from M87:

| Excluded Capability | Reason |
|---------------------|--------|
| Auto-approve based on agent confidence | Agents cannot escalate their own permissions |
| Retry with relaxed constraints | Failure must not silently weaken policy |
| Execute without governance decision | No "fast path" that bypasses approval |
| Trust cached decisions indefinitely | Reconciliation re-validates on every load |
| Allow READ_SECRETS under any condition | Hardcoded DENY, no override mechanism |
| Permit IRREVERSIBLE without human | Human approval is non-negotiable for irreversible actions |
| Fallback to permissive defaults | Unknown state = rejection, not assumption |
| Skip artifact verification | Completion requires machine-verifiable proof |

**This is not a limitation—it's the product**. M87 exists to make these behaviors impossible by construction.

## Quick Start

```bash
# Clone
git clone https://github.com/MacFall7/MacFall7-m87-governed-swarm.git
cd MacFall7-m87-governed-swarm

# Configure
cp .env.example .env
# Edit .env and set M87_API_KEY to something secure

# Boot
./scripts/boot.sh fresh

# Verify
curl -s http://localhost:8000/health | jq
curl -s http://localhost:8000/v1/agents | jq

# Open dashboard
open http://localhost:3000
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        Dashboard (UI)                        │
│                     http://localhost:3000                    │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    Governance API                            │
│                  http://localhost:8000                       │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │  /v1/intent │  │ /v1/govern/ │  │ /v1/approve|deny    │  │
│  │             │  │  proposal   │  │  (human approval)   │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
        │                   │                    │
        ▼                   ▼                    ▼
┌─────────────────────────────────────────────────────────────┐
│                      Redis Streams                           │
│  ┌──────────────┐              ┌──────────────┐             │
│  │  m87:events  │              │   m87:jobs   │             │
│  │  (audit log) │              │ (work queue) │             │
│  └──────────────┘              └──────────────┘             │
└─────────────────────────────────────────────────────────────┘
        │                                │
        ▼                                ▼
┌───────────────┐                ┌───────────────┐
│   Adapters    │                │    Runner     │
│ Casey/Jordan/ │                │  (executes    │
│    Riley      │                │   jobs only)  │
│ (propose only)│                └───────────────┘
└───────────────┘
```

## Agent System

| Agent | Role | Effects | Max Risk |
|-------|------|---------|----------|
| Casey | Code changes + testing | READ_REPO, WRITE_PATCH, RUN_TESTS | 0.6 |
| Jordan | Delivery + notifications | SEND_NOTIFICATION, BUILD_ARTIFACT, CREATE_PR, READ_REPO | 0.5 |
| Riley | Analysis + reporting | READ_REPO, BUILD_ARTIFACT, SEND_NOTIFICATION | 0.4 |
| Human | Manual proposals | All effects | 1.0 |

Agents **propose only**. They cannot:
- Execute anything directly
- Approve their own proposals
- Access effects outside their scope

## Governance Decisions

| Decision | Meaning | Result |
|----------|---------|--------|
| ALLOW | Proposal approved | Job minted immediately |
| DENY | Proposal rejected | No job, denial logged |
| REQUIRE_HUMAN | Needs human approval | Queued in pending approvals |
| NEED_MORE_EVIDENCE | Insufficient truth account | Request more data |

## Effect Tags

```
READ_REPO          - Read repository contents
WRITE_PATCH        - Modify code files
RUN_TESTS          - Execute test suites
BUILD_ARTIFACT     - Create build outputs
NETWORK_CALL       - Make external HTTP requests
SEND_NOTIFICATION  - Send alerts/messages
CREATE_PR          - Create pull requests
MERGE              - Merge branches
DEPLOY             - Deploy to environments
READ_SECRETS       - Access secrets (ALWAYS DENIED)
```

## API Endpoints

| Endpoint | Method | Auth | Purpose |
|----------|--------|------|---------|
| /health | GET | No | Health check |
| /v1/agents | GET | No | List agent profiles |
| /v1/events | GET | No | Read event stream |
| /v1/jobs | GET | No | List jobs |
| /v1/pending-approvals | GET | No | List pending approvals |
| /v1/intent | POST | No | Create intent |
| /v1/govern/proposal | POST | **Yes** | Submit proposal |
| /v1/approve/{id} | POST | **Yes** | Approve proposal |
| /v1/deny/{id} | POST | **Yes** | Deny proposal |
| /v1/runner/result | POST | **Yes** | Report job result |

## Directory Structure

```
m87-governed-swarm/
├── .claude/                 # Claude Code control plane
│   ├── rules/              # Path-scoped governance rules
│   ├── models/             # Model routing configs
│   └── settings.json       # Hooks and permissions
├── apps/
│   ├── api/                # Governance API (FastAPI)
│   └── ui/                 # Dashboard + Governance Observability
│       └── lib/governance/ # Fail-closed normalization layer
├── services/
│   ├── runner/             # Job executor
│   ├── notifier/           # Event observer
│   ├── casey-adapter/      # Code agent
│   ├── jordan-adapter/     # Delivery agent
│   └── riley-adapter/      # Analysis agent
├── packages/
│   ├── contracts/          # TypeScript schemas (source of truth)
│   └── adapter-sdk/        # Python SDK for adapters
├── infra/
│   ├── docker-compose.yml  # Service orchestration
│   └── Dockerfile.*        # Container definitions
├── scripts/
│   ├── boot.sh             # Start the system
│   ├── status.sh           # Check system status
│   ├── proof-test.sh       # Verify invariants
│   └── rotate-key.sh       # Rotate API key
└── docs/                   # Documentation
```

## Scripts

```bash
# Boot the system
./scripts/boot.sh           # Normal boot
./scripts/boot.sh fresh     # Clean boot (rebuild all)

# Check status
./scripts/status.sh

# Verify invariants
./scripts/proof-test.sh

# Rotate API key
./scripts/rotate-key.sh
```

## Environment Variables

| Variable | Required | Default | Purpose |
|----------|----------|---------|---------|
| M87_API_KEY | Yes | - | API authentication key |
| REDIS_URL | No | redis://redis:6379/0 | Redis connection |
| ALLOWED_ORIGINS | No | localhost:3000 | CORS whitelist |
| M87_ENABLE_TEST_ENDPOINTS | No | false | Enable admin endpoints |

## Documentation

- [Installation Guide](docs/INSTALL.md) - Step-by-step setup
- [Architecture](docs/ARCHITECTURE.md) - System design + Governing Laws
- [Developer Guide](docs/DEVELOPER.md) - Contributing and extending
- [API Reference](docs/API.md) - Complete API documentation
- [Proof Map](docs/PROOF_MAP.md) - Claim → Mechanism → Test mapping (for auditors)
- [Troubleshooting](docs/TROUBLESHOOTING.md) - Common issues

## Verification

After boot, verify the system:

```bash
# 1. Health check
curl -s http://localhost:8000/health | jq
# Expected: {"ok": true, ...}

# 2. Agents registered
curl -s http://localhost:8000/v1/agents | jq
# Expected: Casey, Jordan, Riley with effect scopes

# 3. Auth gate works (should 401)
curl -i -X POST http://localhost:8000/v1/govern/proposal \
  -H "content-type: application/json" \
  -d '{"proposal_id":"test","intent_id":"i1","agent":"Casey","summary":"test","effects":["READ_REPO"],"truth_account":{"observations":[],"claims":[]}}'
# Expected: HTTP 401

# 4. Adapters running (no 401 spam)
docker compose -f infra/docker-compose.yml logs --tail=20 casey-adapter
```

## Philosophy

This system exists because autonomous agents need governance, not freedom.

The architecture enforces:
- **Separation of proposal and execution** - Agents can't act on their own decisions
- **Explicit authorization** - Every action requires a decision
- **Auditability** - Every event is logged to Redis streams
- **Fail-closed** - Unknown states result in denial, not permission

Claude Code operates as a **compiler** for this system, not a collaborator. It sees governance boundaries, not just files.

## License

MIT

## Session Reference

Built with Claude Code: https://claude.ai/code/session_01P2b9LjCqtqp84edTDPPyeJ
