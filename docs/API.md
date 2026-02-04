# API Reference

Complete documentation for the M87 Governance API.

**Base URL:** `http://localhost:8000`

## Authentication

Protected endpoints require the `X-M87-Key` header:

```bash
curl -X POST http://localhost:8000/v1/govern/proposal \
  -H "X-M87-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '...'
```

Missing or invalid API key returns:

```json
HTTP/1.1 401 Unauthorized
{"detail": "Invalid or missing API key"}
```

## Endpoints

---

### GET /health

Health check endpoint.

**Authentication:** None

**Response:**

```json
{
  "ok": true,
  "version": "0.1.3",
  "redis": "connected"
}
```

**Example:**

```bash
curl -s http://localhost:8000/health | jq
```

---

### GET /v1/agents

List all registered agent profiles with their effect scopes and risk thresholds.

**Authentication:** None

**Response:**

```json
{
  "agents": [
    {
      "name": "Casey",
      "allowed_effects": ["READ_REPO", "RUN_TESTS", "WRITE_PATCH"],
      "max_risk": 0.6,
      "description": "Code changes and testing"
    },
    {
      "name": "Jordan",
      "allowed_effects": ["BUILD_ARTIFACT", "CREATE_PR", "READ_REPO", "SEND_NOTIFICATION"],
      "max_risk": 0.5,
      "description": "Artifacts, notifications, PRs"
    },
    {
      "name": "Riley",
      "allowed_effects": ["BUILD_ARTIFACT", "READ_REPO", "SEND_NOTIFICATION"],
      "max_risk": 0.4,
      "description": "Analysis and reporting"
    },
    {
      "name": "Human",
      "allowed_effects": ["BUILD_ARTIFACT", "CREATE_PR", "DEPLOY", "MERGE", "NETWORK_CALL", "READ_REPO", "RUN_TESTS", "SEND_NOTIFICATION", "WRITE_PATCH"],
      "max_risk": 1.0,
      "description": "Manual human proposals"
    }
  ]
}
```

**Example:**

```bash
curl -s http://localhost:8000/v1/agents | jq
```

---

### GET /v1/events

Read events from the audit stream.

**Authentication:** None

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| limit | int | 200 | Maximum events to return |
| after | string | - | Only return events after this ID |

**Response:**

```json
{
  "events": [
    {
      "id": "1706745600000-0",
      "type": "intent.created",
      "payload": {
        "intent_id": "i-abc123",
        "from": "user",
        "mode": "fix",
        "goal": "Fix auth bug"
      }
    },
    {
      "id": "1706745601000-0",
      "type": "proposal.allowed",
      "payload": {
        "proposal_id": "p-def456",
        "agent": "Casey",
        "decision": "ALLOW",
        "reasons": ["Within agent scope", "Risk within threshold"]
      }
    }
  ]
}
```

**Event Types:**

| Type | Description |
|------|-------------|
| intent.created | New intent received |
| proposal.allowed | Proposal approved automatically |
| proposal.denied | Proposal rejected |
| proposal.needs_approval | Proposal awaiting human approval |
| proposal.approved | Human approved a proposal |
| job.created | Job minted |
| job.completed | Job finished successfully |
| job.failed | Job failed |

**Example:**

```bash
# Get last 50 events
curl -s "http://localhost:8000/v1/events?limit=50" | jq

# Get events after a specific ID
curl -s "http://localhost:8000/v1/events?after=1706745600000-0" | jq
```

---

### GET /v1/jobs

List jobs from the job stream.

**Authentication:** None

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| limit | int | 100 | Maximum jobs to return |

**Response:**

```json
{
  "jobs": [
    {
      "stream_id": "1706745602000-0",
      "job_id": "j-ghi789",
      "proposal_id": "p-def456",
      "tool": "pytest",
      "args": ["tests/"],
      "timeout_seconds": 120,
      "status": "completed",
      "output": "All tests passed"
    }
  ]
}
```

**Job Status:**

| Status | Description |
|--------|-------------|
| pending | Job created, not yet picked up |
| running | Job being executed |
| completed | Job finished successfully |
| failed | Job failed |

**Example:**

```bash
curl -s http://localhost:8000/v1/jobs | jq
```

---

### GET /v1/pending-approvals

List proposals awaiting human approval.

**Authentication:** None

**Response:**

```json
{
  "pending": [
    {
      "id": "1706745603000-0",
      "proposal_id": "p-xyz789",
      "payload": {
        "proposal_id": "p-xyz789",
        "agent": "Casey",
        "summary": "Deploy to production",
        "effects": ["DEPLOY"],
        "reasons": ["DEPLOY requires human approval"],
        "allowed_effects": ["DEPLOY"]
      }
    }
  ]
}
```

**Example:**

```bash
curl -s http://localhost:8000/v1/pending-approvals | jq
```

---

### POST /v1/intent

Create a new intent.

**Authentication:** None

**Request Body:**

```json
{
  "intent_id": "i-abc123",
  "from": "user",
  "mode": "fix",
  "goal": "Fix the authentication bug in login.py"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| intent_id | string | Yes | Unique intent identifier |
| from | string | Yes | Source of the intent |
| mode | string | No | Intent mode (fix, test, build, etc.) |
| goal | string | Yes | Description of what should happen |

**Response:**

```json
{
  "accepted": true,
  "intent_id": "i-abc123"
}
```

**Example:**

```bash
curl -X POST http://localhost:8000/v1/intent \
  -H "Content-Type: application/json" \
  -d '{
    "intent_id": "i-abc123",
    "from": "user",
    "mode": "fix",
    "goal": "Fix auth bug"
  }' | jq
```

---

### POST /v1/govern/proposal

Submit a proposal for governance review.

**Authentication:** Required

**Request Body:**

```json
{
  "proposal_id": "p-def456",
  "intent_id": "i-abc123",
  "agent": "Casey",
  "summary": "Fix null check in login.py:45",
  "effects": ["READ_REPO", "WRITE_PATCH", "RUN_TESTS"],
  "truth_account": {
    "observations": ["login.py:45 has uncaught exception"],
    "claims": [
      {"claim": "Fix is low risk", "confidence": 0.8}
    ]
  },
  "risk_score": 0.3
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| proposal_id | string | Yes | Unique proposal identifier |
| intent_id | string | Yes | Related intent ID |
| agent | string | Yes | Agent submitting (Casey, Jordan, Riley, Human) |
| summary | string | Yes | Human-readable description |
| effects | string[] | Yes | Effect tags requested |
| truth_account | object | Yes | Supporting evidence |
| truth_account.observations | string[] | Yes | Observed facts |
| truth_account.claims | object[] | No | Claims with confidence |
| risk_score | float | No | Risk assessment 0.0-1.0 |
| artifacts | object[] | No | Attached artifacts |

**Response (ALLOW):**

```json
{
  "proposal_id": "p-def456",
  "decision": "ALLOW",
  "reasons": ["Within agent scope", "Risk within threshold"],
  "allowed_effects": ["READ_REPO", "WRITE_PATCH", "RUN_TESTS"]
}
```

**Response (DENY):**

```json
{
  "proposal_id": "p-def456",
  "decision": "DENY",
  "reasons": ["READ_SECRETS is forbidden"]
}
```

**Response (REQUIRE_HUMAN):**

```json
{
  "proposal_id": "p-def456",
  "decision": "REQUIRE_HUMAN",
  "reasons": ["DEPLOY requires human approval"],
  "required_approvals": ["human"],
  "allowed_effects": ["DEPLOY"]
}
```

**Example:**

```bash
curl -X POST http://localhost:8000/v1/govern/proposal \
  -H "Content-Type: application/json" \
  -H "X-M87-Key: your-api-key" \
  -d '{
    "proposal_id": "p-test",
    "intent_id": "i-test",
    "agent": "Casey",
    "summary": "Read repository",
    "effects": ["READ_REPO"],
    "truth_account": {
      "observations": ["Need to analyze code"],
      "claims": []
    },
    "risk_score": 0.1
  }' | jq
```

---

### POST /v1/approve/{proposal_id}

Approve a pending proposal.

**Authentication:** Required

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| proposal_id | string | Proposal to approve |

**Response:**

```json
{
  "approved": true,
  "proposal_id": "p-xyz789",
  "job_id": "j-newjob123"
}
```

**Error (not found):**

```json
{
  "detail": "Proposal not found or already processed"
}
```

**Example:**

```bash
curl -X POST http://localhost:8000/v1/approve/p-xyz789 \
  -H "X-M87-Key: your-api-key" | jq
```

---

### POST /v1/deny/{proposal_id}

Deny a pending proposal.

**Authentication:** Required

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| proposal_id | string | Proposal to deny |

**Response:**

```json
{
  "denied": true,
  "proposal_id": "p-xyz789"
}
```

**Example:**

```bash
curl -X POST http://localhost:8000/v1/deny/p-xyz789 \
  -H "X-M87-Key: your-api-key" | jq
```

---

### POST /v1/runner/result

Report job execution result (used by Runner service).

**Authentication:** Required

**Request Body:**

```json
{
  "job_id": "j-ghi789",
  "status": "completed",
  "output": "All tests passed\n\n5 tests in 2.3s",
  "error": null
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| job_id | string | Yes | Job identifier |
| status | string | Yes | completed or failed |
| output | string | No | Stdout from execution |
| error | string | No | Error message if failed |

**Response:**

```json
{
  "recorded": true,
  "job_id": "j-ghi789"
}
```

**Example:**

```bash
curl -X POST http://localhost:8000/v1/runner/result \
  -H "Content-Type: application/json" \
  -H "X-M87-Key: your-api-key" \
  -d '{
    "job_id": "j-ghi789",
    "status": "completed",
    "output": "Success"
  }' | jq
```

---

## Effect Tags

| Tag | Description | Typical Agents |
|-----|-------------|----------------|
| READ_REPO | Read repository contents | All |
| WRITE_PATCH | Modify code files | Casey, Human |
| RUN_TESTS | Execute test suites | Casey, Human |
| BUILD_ARTIFACT | Create build outputs | Jordan, Riley, Human |
| NETWORK_CALL | Make external HTTP requests | Human |
| SEND_NOTIFICATION | Send alerts/messages | Jordan, Riley, Human |
| CREATE_PR | Create pull requests | Jordan, Human |
| MERGE | Merge branches | Human |
| DEPLOY | Deploy to environments | Human |
| READ_SECRETS | Access secrets | **ALWAYS DENIED** |

## Decision Flow

```
Proposal Submitted
       │
       ▼
┌──────────────────┐
│ READ_SECRETS?    │──Yes──▶ DENY
└────────┬─────────┘
         │ No
         ▼
┌──────────────────┐
│ Agent scope      │──No───▶ DENY
│ violation?       │
└────────┬─────────┘
         │ Yes (in scope)
         ▼
┌──────────────────┐
│ Risk > agent     │──Yes──▶ REQUIRE_HUMAN
│ threshold?       │
└────────┬─────────┘
         │ No
         ▼
┌──────────────────┐
│ DEPLOY effect?   │──Yes──▶ REQUIRE_HUMAN
└────────┬─────────┘
         │ No
         ▼
       ALLOW
```

## Error Responses

### 401 Unauthorized

```json
{
  "detail": "Invalid or missing API key"
}
```

### 404 Not Found

```json
{
  "detail": "Proposal not found or already processed"
}
```

### 422 Validation Error

```json
{
  "detail": [
    {
      "loc": ["body", "effects"],
      "msg": "field required",
      "type": "value_error.missing"
    }
  ]
}
```

### 503 Service Unavailable

```json
{
  "detail": "Redis connection failed"
}
```

## Runner Result Contract (V1 Governance)

Runner posts job completion to the API using the hardened result contract.

### Fields

| Field | Type | Description |
|-------|------|-------------|
| `job_id` | string | Job identifier |
| `proposal_id` | string | Related proposal |
| `status` | string | `completed`, `failed`, or `manifest_reject` |
| `output` | object | Execution output (sanitized, capped) |
| `manifest_hash` | string | Runner's manifest hash |
| `manifest_version` | string | Manifest version |
| `completion_artifacts` | object | Verifiable artifacts: `files`, `diffs`, `logs`, `receipts` |
| `envelope_hash` | string | DEH pinned at job mint time |
| `autonomy_budget` | object | Immutable budget snapshot applied by runner |
| `autonomy_usage` | object | Counters consumed during execution |
| `deh_evidence` | object | Machine-verifiable DEH proof |

### DEH Evidence Structure

```json
{
  "envelope_hash_verified": true,
  "deh_claimed": "abc123...",
  "deh_recomputed": "abc123...",
  "error": null
}
```

---

## Shadow Eval (V1)

### POST /v1/shadow-eval/trigger

Triggers a shadow evaluation run (admin-only). Current implementation is a stub with telemetry.

**Authentication:** Required (`admin:shadow-eval` scope)

**Request Body:**

```json
{
  "reason": "interval",
  "job_id": "j-xxx",
  "envelope_hash": "abc123..."
}
```

**Response:**

```json
{
  "eval_id": "eval-xxx",
  "envelope_hash": "abc123...",
  "eval_suite_hash": "000...",
  "drift_score": 0.0,
  "passed": true,
  "details": {},
  "run_at": "2024-01-01T00:00:00Z"
}
```

### GET /v1/shadow-eval/status

Returns shadow evaluation state and recent history.

**Authentication:** Required (`admin:shadow-eval` scope)

**Response:**

```json
{
  "jobs_since_last_eval": 42,
  "last_eval_at": "2024-01-01T00:00:00Z",
  "last_drift_score": 0.0,
  "trigger_interval": 100,
  "drift_threshold": 0.1,
  "recent_evals": []
}
```

---

## Rate Limits

Currently no rate limits are enforced. For production deployments, consider adding rate limiting at the reverse proxy level.

## OpenAPI Schema

The full OpenAPI schema is available at:

```
http://localhost:8000/openapi.json
```

Interactive documentation:

```
http://localhost:8000/docs
```
