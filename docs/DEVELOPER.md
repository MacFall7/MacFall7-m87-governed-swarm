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
