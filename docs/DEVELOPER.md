# Developer Guide

Everything you need to know to contribute to M87 Governed Swarm.

## Development Setup

### Prerequisites

- Python 3.10+
- Node.js 18+ (for TypeScript contracts)
- Docker & Docker Compose
- Git

### Local Development Environment

```bash
# Clone the repository
git clone https://github.com/MacFall7/MacFall7-m87-governed-swarm.git
cd MacFall7-m87-governed-swarm

# Create Python virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install API dependencies
pip install -r apps/api/requirements.txt

# Install adapter SDK in development mode
pip install -e packages/adapter-sdk

# Install Node dependencies for contracts
cd packages/contracts
npm install
cd ../..

# Copy environment config
cp .env.example .env
# Edit .env with your settings
```

### Running Services Locally

**Option 1: Full Docker stack**

```bash
./scripts/boot.sh fresh
```

**Option 2: Mixed (Redis in Docker, API locally)**

```bash
# Start just Redis
docker compose -f infra/docker-compose.yml up -d redis

# Run API locally
cd apps/api
uvicorn app.main:app --reload --port 8000

# Run adapters locally (in separate terminals)
cd services/casey-adapter
python app/adapter.py
```

## Project Structure

```
m87-governed-swarm/
├── apps/
│   ├── api/                    # Governance API
│   │   └── app/
│   │       └── main.py         # FastAPI application
│   └── ui/                     # Dashboard
│       ├── lib/
│       │   ├── governance/     # Governance observability layer
│       │   │   ├── types.ts        # Canonical types
│       │   │   ├── normalize.ts    # Fail-closed normalization
│       │   │   ├── data.ts         # API client
│       │   │   ├── analytics.ts    # Metrics computation
│       │   │   ├── persistence.ts  # Serialization
│       │   │   ├── mock.ts         # Test data
│       │   │   └── index.ts        # Exports
│       │   └── __tests__/      # Test files
│       └── public/
│           └── index.html      # Single-page app
│
├── services/
│   ├── runner/                 # Job executor
│   │   └── app/
│   │       └── runner.py
│   ├── notifier/               # Event observer
│   │   └── app/
│   │       └── notifier.py
│   ├── casey-adapter/          # Code agent
│   │   └── app/
│   │       └── adapter.py
│   ├── jordan-adapter/         # Delivery agent
│   │   └── app/
│   │       └── adapter.py
│   └── riley-adapter/          # Analysis agent
│       └── app/
│           └── adapter.py
│
├── packages/
│   ├── contracts/              # TypeScript schemas
│   │   └── src/
│   │       ├── effects.ts
│   │       ├── intent.ts
│   │       ├── proposal.ts
│   │       ├── decision.ts
│   │       └── job.ts
│   └── adapter-sdk/            # Python SDK
│       └── adapter_sdk/
│           ├── __init__.py
│           ├── client.py
│           ├── models.py
│           └── utils.py
│
├── infra/                      # Infrastructure
│   ├── docker-compose.yml
│   └── Dockerfile.*
│
├── scripts/                    # Operational scripts
│   ├── boot.sh
│   ├── status.sh
│   ├── proof-test.sh
│   └── rotate-key.sh
│
├── docs/                       # Documentation
│
└── .claude/                    # Claude Code control plane
    ├── rules/
    ├── models/
    └── settings.json
```

## Key Files

| File | Purpose |
|------|---------|
| `apps/api/app/main.py` | Governance engine, all policy rules |
| `apps/ui/lib/governance/normalize.ts` | UI fail-closed normalization boundary |
| `apps/ui/lib/governance/data.ts` | UI governance data access layer |
| `packages/adapter-sdk/adapter_sdk/client.py` | SDK for building adapters |
| `services/runner/app/runner.py` | Job execution logic |
| `infra/docker-compose.yml` | Service orchestration |
| `.claude/rules/governance.md` | Governance invariants documentation |

## Adding a New Adapter

### 1. Create the adapter directory

```bash
mkdir -p services/my-adapter/app
```

### 2. Define the adapter

```python
# services/my-adapter/app/adapter.py
import os
from adapter_sdk import M87Client, build_proposal, should_submit, AGENT_EFFECT_SCOPES

AGENT_NAME = "MyAgent"
API_BASE = os.getenv("M87_API_BASE", "http://api:8000")
API_KEY = os.getenv("M87_API_KEY")

class MyAdapter:
    def __init__(self):
        self.client = M87Client(api_base=API_BASE, api_key=API_KEY)

    def create_proposal(self, intent_data):
        # Pre-flight check
        ok, warnings = should_submit(AGENT_NAME, ["READ_REPO"])
        if not ok:
            print(f"Warnings: {warnings}")

        # Build proposal
        proposal = build_proposal(
            agent=AGENT_NAME,
            summary="My proposal",
            effects=["READ_REPO"],
            observations=["Observed something"],
            risk_score=0.2,
        )

        # Submit
        decision = self.client.submit_proposal(proposal)
        print(f"Decision: {decision.decision}")
        return decision
```

### 3. Add agent profile to API

Edit `apps/api/app/main.py`:

```python
AGENT_PROFILES = {
    # ... existing agents ...
    "MyAgent": {
        "allowed_effects": {"READ_REPO", "SEND_NOTIFICATION"},
        "max_risk": 0.5,
        "description": "My custom agent",
    },
}
```

### 4. Create Dockerfile

```dockerfile
# services/my-adapter/Dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY packages/adapter-sdk /app/packages/adapter-sdk
COPY services/my-adapter/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install --no-cache-dir -e /app/packages/adapter-sdk

COPY services/my-adapter/app ./app

CMD ["python", "-u", "app/adapter.py"]
```

### 5. Add to docker-compose.yml

```yaml
my-adapter:
  build:
    context: ..
    dockerfile: services/my-adapter/Dockerfile
  environment:
    - REDIS_URL=redis://redis:6379/0
    - M87_API_BASE=http://api:8000
    - M87_API_KEY=${M87_API_KEY:-m87-dev-key-change-me}
  depends_on:
    api:
      condition: service_healthy
    redis:
      condition: service_healthy
  restart: unless-stopped
```

### 6. Document in rules

Add to `.claude/rules/adapters.md`:

```markdown
| MyAgent | READ_REPO, SEND_NOTIFICATION | 0.5 |
```

## Adding a New Policy Rule

Policy rules are evaluated in order in `govern_proposal()`:

```python
# apps/api/app/main.py

def govern_proposal(proposal, x_m87_key):
    verify_api_key(x_m87_key)

    # Rule 1: READ_SECRETS is forbidden
    if "READ_SECRETS" in proposal.effects:
        return deny("READ_SECRETS is forbidden")

    # Rule 2: Agent scope check
    # ... existing rules ...

    # NEW RULE: Add here, before the final ALLOW
    if "DANGEROUS_EFFECT" in proposal.effects:
        return deny("DANGEROUS_EFFECT not allowed")

    # Final rule: ALLOW
    return allow(proposal)
```

**Best practices:**
- Rules are evaluated top-to-bottom
- Put absolute denials first (READ_SECRETS)
- Put REQUIRE_HUMAN rules before ALLOW
- Document every rule in `.claude/rules/governance.md`

## Adding a New Effect Tag

### 1. Add to TypeScript contracts

```typescript
// packages/contracts/src/effects.ts
export type EffectTag =
  | "READ_REPO"
  | "WRITE_PATCH"
  // ... existing effects ...
  | "MY_NEW_EFFECT";  // Add here
```

### 2. Add to Python models

```python
# packages/adapter-sdk/adapter_sdk/models.py
EffectTag = Literal[
    "READ_REPO",
    "WRITE_PATCH",
    # ... existing effects ...
    "MY_NEW_EFFECT",  # Add here
]
```

### 3. Update agent scopes (if needed)

```python
# apps/api/app/main.py
AGENT_PROFILES = {
    "Casey": {
        "allowed_effects": {"READ_REPO", "WRITE_PATCH", "MY_NEW_EFFECT"},
        # ...
    },
}
```

### 4. Update runner tool allowlist (if executable)

```python
# services/runner/app/runner.py
TOOL_ALLOWLIST = {"echo", "pytest", "git", "build", "my_new_tool"}
```

## Testing

### Run syntax checks

```bash
python3 -m py_compile apps/api/app/main.py
python3 -m py_compile services/runner/app/runner.py
```

### Run UI governance tests

```bash
cd apps/ui
npm test                    # Run all tests
npm run test:watch          # Watch mode
npm run test:coverage       # With coverage
npm run typecheck           # Type checking only
```

### Run proof tests

```bash
./scripts/proof-test.sh
```

### Manual API testing

```bash
# Health check
curl -s http://localhost:8000/health | jq

# List agents
curl -s http://localhost:8000/v1/agents | jq

# Submit proposal (with auth)
curl -X POST http://localhost:8000/v1/govern/proposal \
  -H "Content-Type: application/json" \
  -H "X-M87-Key: $M87_API_KEY" \
  -d '{
    "proposal_id": "p-test",
    "intent_id": "i-test",
    "agent": "Casey",
    "summary": "Test proposal",
    "effects": ["READ_REPO"],
    "truth_account": {"observations": ["test"], "claims": []}
  }' | jq
```

## Code Style

### Python

- Use type hints
- Use Pydantic for data models
- Follow PEP 8
- Keep functions focused and small

### TypeScript

- Use strict typing
- Export types from index.ts
- No `any` types

### Commits

```bash
# Feature
git commit -m "feat: add new adapter for X"

# Fix
git commit -m "fix: correct proposal validation"

# Security
git commit -m "security: require auth on endpoint"

# Ops
git commit -m "ops: add health check to service"
```

## Debugging

### View service logs

```bash
# All services
docker compose -f infra/docker-compose.yml logs -f

# Specific service
docker compose -f infra/docker-compose.yml logs -f casey-adapter

# Last 50 lines
docker compose -f infra/docker-compose.yml logs --tail=50 api
```

### Check Redis streams

```bash
# Connect to Redis
docker compose -f infra/docker-compose.yml exec redis redis-cli

# View recent events
XRANGE m87:events - + COUNT 10

# View pending jobs
XRANGE m87:jobs - + COUNT 10

# Check consumer groups
XINFO GROUPS m87:jobs
```

### Check service status

```bash
./scripts/status.sh
```

## Common Development Tasks

### Rebuild a single service

```bash
docker compose -f infra/docker-compose.yml build api
docker compose -f infra/docker-compose.yml up -d api
```

### Reset Redis data

```bash
docker compose -f infra/docker-compose.yml down -v
docker compose -f infra/docker-compose.yml up -d
```

### View API routes

```bash
curl -s http://localhost:8000/openapi.json | jq '.paths | keys'
```

## Governance Guidelines (Do Not Bypass)

### 1. Tool effects are contracts

All tool behavior must be declared in the tool manifest. The Runner does not guess.

### 2. Fail-closed defaults

Missing governance fields (manifest hash, envelope hash, envelope) must result in refusal, not fallback execution.

### 3. All network I/O must go through `governed_request()`

Do not call `requests.*` directly inside tools. External I/O must be metered via Autonomy Budget.

### 4. Completed requires artifacts

Tools must return verifiable completion artifacts. The runner will force failure if a tool "succeeds" without artifacts.

### 5. Defense-in-depth

Runner must independently clamp risky configurations (e.g., open-weight models forced to `safe_default` + sandbox write scope).

### 6. Kill-switches (Emergency Only)

The following environment variables can disable governance for emergency rollback:

| Variable | Effect | Warning |
|----------|--------|---------|
| `M87_DISABLE_PHASE36_GOVERNANCE=1` | Disables Phase 3-6 in /v1 endpoint | **DANGEROUS**: Allows toxic topologies |
| `M87_DISABLE_V1_GOVERNANCE=1` | Returns 410 for all /v1 governance endpoints | Safe: forces migration to /v2 |

**Production requirements for kill-switches:**
- Log loudly on startup if enabled
- Emit Prometheus metric so it can't be silently left on
- Fail deployment if set outside dev/staging environment

---

## UI Governance Observability Layer

The `apps/ui/lib/governance/` module provides a fail-closed normalization boundary for all governance data consumed by the UI.

### Architecture

```
                    ┌─────────────────────────────────────────┐
                    │          UI Components                   │
                    │  (only see GovernanceState, never raw)  │
                    └──────────────────┬──────────────────────┘
                                       │
                    ┌──────────────────▼──────────────────────┐
                    │            data.ts                       │
                    │  fetchGovernanceState()                  │
                    │  subscribeToGovernance()                 │
                    │  (makes bypass structurally impossible)  │
                    └──────────────────┬──────────────────────┘
                                       │
                    ┌──────────────────▼──────────────────────┐
                    │         normalize.ts                     │
                    │  normalizeIncomingGovernance()           │
                    │  (SINGLE entry point for all data)       │
                    │  reconcileGovernanceState()              │
                    │  (re-applies fail-closed on load)        │
                    └──────────────────┬──────────────────────┘
                                       │
           ┌───────────────────────────┼───────────────────────┐
           │                           │                       │
┌──────────▼──────────┐   ┌────────────▼───────────┐   ┌──────▼─────┐
│   persistence.ts    │   │    analytics.ts        │   │  mock.ts   │
│   (serialize/load)  │   │  (metrics from         │   │ (test data │
│   (reconciles on    │   │   normalized state)    │   │  normalized)│
│    every load)      │   └────────────────────────┘   └────────────┘
└─────────────────────┘
```

### Key Files

| File | Purpose |
|------|---------|
| `types.ts` | Canonical types: `GovernanceState`, `RawGovernanceResponse`, enums |
| `normalize.ts` | `normalizeIncomingGovernance()` - THE ONLY entry point |
| `data.ts` | API client that enforces normalization by construction |
| `analytics.ts` | Metrics: block rate, cleanup cost distribution, budget usage |
| `persistence.ts` | Serialization with mandatory reconciliation on load |
| `mock.ts` | Mock data generators that flow through normalization |
| `index.ts` | Public exports |

### The Normalization Contract

**Rule 1: Single Entry Point**

All governance data MUST pass through `normalizeIncomingGovernance()`:

```typescript
import { normalizeIncomingGovernance } from "./governance";

// CORRECT: Use the normalization function
const state = normalizeIncomingGovernance(rawApiResponse);

// WRONG: Never cast or bypass
const state = rawApiResponse as GovernanceState; // DON'T DO THIS
```

**Rule 2: Fail-Closed on ANY Blocking Signal**

These conditions ALWAYS force `blocked=true`:

| Signal | Condition | Default Reason |
|--------|-----------|----------------|
| Explicit block | `raw.blocked === true` | Uses `raw.blocking_reason` |
| Reversibility gate | `reversibility_class === "HARD"` | `"REVERSIBILITY_GATE"` |
| Cleanup cost | `cleanup_cost_v2 === "IMPOSSIBLE"` | `"CLEANUP_IMPOSSIBLE"` |
| Step budget | `max_steps === 0` (when budget_state provided) | `"STEP_BUDGET"` |
| Tool budget | `max_tool_calls === 0` | `"TOOL_BUDGET"` |
| Retry budget | `retries_remaining === 0` | `"RETRIES_EXHAUSTED"` |

**Rule 3: Unknown Enums Default Conservatively**

```typescript
// Unknown reversibility → HARD (most restrictive)
const reversibility = REVERSIBILITY_VALUES.includes(raw.reversibility_class)
  ? raw.reversibility_class
  : "HARD";

// Unknown cleanup_cost → HIGH (most expensive)
const cleanupCost = CLEANUP_COST_VALUES.includes(raw.cleanup_cost_v2)
  ? raw.cleanup_cost_v2
  : "HIGH";
```

**Rule 4: Reconciliation on Every Load**

When loading from cache/persistence, `reconcileGovernanceState()` re-applies fail-closed rules:

```typescript
// persistence.ts always reconciles
export function loadGovernanceState(key: string): GovernanceState | null {
  const stored = localStorage.getItem(`gov:${key}`);
  if (!stored) return null;

  const raw = JSON.parse(stored);
  const restored = /* restore timestamps */;

  // MANDATORY: Reconcile before returning
  return reconcileGovernanceState(restored);
}
```

### Adding New Blocking Signals

1. Add the signal detection to `detectBlockingSignals()` in `normalize.ts`:

```typescript
// In detectBlockingSignals()
if (/* new blocking condition */) {
  signals.push("NEW_SIGNAL_NAME");
  if (!reason) reason = "NEW_SIGNAL_NAME";
}
```

2. Add a test case in `governance-normalization.test.ts`:

```typescript
it("should block when NEW_SIGNAL_NAME condition is met", () => {
  const raw = {
    blocked: false,
    // ... condition that triggers NEW_SIGNAL_NAME
  };
  const state = normalizeIncomingGovernance(raw);
  expect(state?.blocked).toBe(true);
  expect(state?.blocking_reason).toBe("NEW_SIGNAL_NAME");
});
```

3. Update `reconcileGovernanceState()` if the signal needs special handling during reconciliation.

### Running Tests

```bash
cd apps/ui

# Run all governance tests
npm test

# Run with watch mode
npm run test:watch

# Run with coverage
npm run test:coverage
```

Test files:
- `lib/__tests__/governance-normalization.test.ts` - Normalization boundary tests
- `lib/__tests__/governance-style-compliance.test.ts` - Semantic token enforcement

### Style Compliance

Governance UI components MUST use semantic tokens, not hardcoded Tailwind colors:

```typescript
// CORRECT: Semantic tokens
className="bg-risk-critical text-foreground"
className="border-risk-high"

// WRONG: Hardcoded colors
className="bg-red-500 text-gray-900"  // Will fail style compliance tests
```

Available semantic tokens:
- `risk-low`, `risk-medium`, `risk-high`, `risk-critical`, `risk-info`, `risk-purple`
- `foreground`, `background`, `muted`, `border`, `primary`, `secondary`, `destructive`, `accent`

### Why This Matters

The UI normalization layer prevents **split-brain drift**:

```
WITHOUT normalization:
  Backend: blocked=true (budget exhausted)
  UI cache: blocked=false (stale)
  User sees: "Allowed" ← DANGEROUS

WITH normalization:
  Backend: blocked=true
  UI cache: loaded → reconciled → blocked=true
  User sees: "Blocked" ← CORRECT
```

Every time governance data enters the UI—from API, WebSocket, cache, or mock—it passes through normalization. This makes the fail-closed guarantee **structural**, not just a convention.

---

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feat/my-feature`
3. Make changes following the style guide
4. Run syntax checks and proof tests
5. Commit with descriptive messages
6. Push and create a pull request

### Pull Request Checklist

- [ ] Syntax checks pass
- [ ] Proof tests pass
- [ ] New code has type hints
- [ ] Governance rules documented (if changed)
- [ ] Adapter rules documented (if new adapter)
- [ ] README updated (if needed)
