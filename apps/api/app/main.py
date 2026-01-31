from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import List, Optional, Literal, Dict, Any, Set
import os
import json
import uuid
from redis import Redis

app = FastAPI(title="m87-governed-swarm-api", version="0.1.3")

# ---- Config
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
API_KEY = os.getenv("M87_API_KEY", "m87-dev-key-change-me")
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000").split(",")
ENABLE_TEST_ENDPOINTS = os.getenv("M87_ENABLE_TEST_ENDPOINTS", "false").lower() == "true"

# CORS - tightened for V1.2
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# ---- Redis connection
rdb = Redis.from_url(REDIS_URL, decode_responses=True)

# Stream keys
EVENT_STREAM = "m87:events"
JOB_STREAM = "m87:jobs"

# Runner tool allowlist
ALLOWED_TOOLS = {"echo", "pytest", "git", "build"}


# ---- V1.3: Agent Profiles (effect scopes + risk thresholds)
# Agents can ONLY propose effects in their allowed set.
# Server-side enforcement - adapters can hint but governance is law.
AGENT_PROFILES: Dict[str, Dict[str, Any]] = {
    "Casey": {
        "allowed_effects": {"READ_REPO", "WRITE_PATCH", "RUN_TESTS"},
        "max_risk": 0.6,
        "description": "Code changes and testing",
    },
    "Jordan": {
        "allowed_effects": {"SEND_NOTIFICATION", "BUILD_ARTIFACT", "CREATE_PR", "READ_REPO"},
        "max_risk": 0.5,
        "description": "Artifacts, notifications, PRs",
    },
    "Riley": {
        "allowed_effects": {"READ_REPO", "BUILD_ARTIFACT", "SEND_NOTIFICATION"},
        "max_risk": 0.4,
        "description": "Analysis and reporting",
    },
    # Human/manual proposals have full access (still subject to DEPLOY/SECRETS rules)
    "Human": {
        "allowed_effects": {
            "READ_REPO", "WRITE_PATCH", "RUN_TESTS", "BUILD_ARTIFACT",
            "NETWORK_CALL", "SEND_NOTIFICATION", "CREATE_PR", "MERGE", "DEPLOY"
        },
        "max_risk": 1.0,
        "description": "Manual human proposals",
    },
}

# Default profile for unknown agents (restrictive)
DEFAULT_AGENT_PROFILE = {
    "allowed_effects": {"READ_REPO"},
    "max_risk": 0.3,
    "description": "Unknown agent (restricted)",
}


# ---- Auth middleware
def verify_api_key(x_m87_key: Optional[str] = Header(None, alias="X-M87-Key")) -> bool:
    """Verify API key for protected endpoints."""
    if not x_m87_key or x_m87_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")
    return True


# ---- Minimal in-service models
EffectTag = Literal[
    "READ_REPO",
    "WRITE_PATCH",
    "RUN_TESTS",
    "BUILD_ARTIFACT",
    "NETWORK_CALL",
    "SEND_NOTIFICATION",
    "CREATE_PR",
    "MERGE",
    "DEPLOY",
    "READ_SECRETS",
]

Decision = Literal["ALLOW", "DENY", "REQUIRE_HUMAN", "NEED_MORE_EVIDENCE"]
RunnerTool = Literal["echo", "pytest", "git", "build"]


class Intent(BaseModel):
    intent_id: str
    from_: str = Field(alias="from")
    mode: str
    goal: str
    constraints: Optional[Dict[str, Any]] = None


class TruthAccount(BaseModel):
    observations: List[str]
    claims: List[Dict[str, Any]]


class Proposal(BaseModel):
    proposal_id: str
    intent_id: str
    agent: str
    summary: str
    effects: List[EffectTag]
    artifacts: Optional[List[Dict[str, str]]] = None
    truth_account: TruthAccount
    risk_score: Optional[float] = None


class GovernanceDecision(BaseModel):
    proposal_id: str
    decision: Decision
    reasons: List[str]
    required_approvals: Optional[List[str]] = None
    allowed_effects: Optional[List[EffectTag]] = None


class JobSpec(BaseModel):
    job_id: str
    proposal_id: str
    tool: RunnerTool
    inputs: Dict[str, Any] = {}
    sandbox: Dict[str, str] = {"network": "deny", "fs": "ro"}
    timeout_seconds: int = 60


# ---- Event + Job emission
def emit(event_type: str, payload: Dict[str, Any]) -> str:
    """Emit event to Redis stream, returns event ID."""
    event_id = rdb.xadd(EVENT_STREAM, {"type": event_type, "payload": json.dumps(payload)})
    return event_id


def enqueue_job(proposal_id: str, tool: str, inputs: Dict[str, Any] = None) -> str:
    """
    Mint a JobSpec and add to jobs stream.
    This is the ONLY way jobs get created - after governance.
    """
    if tool not in ALLOWED_TOOLS:
        raise ValueError(f"Tool '{tool}' not in allowlist: {ALLOWED_TOOLS}")

    job_id = str(uuid.uuid4())
    job = {
        "job_id": job_id,
        "proposal_id": proposal_id,
        "tool": tool,
        "inputs": inputs or {},
        "sandbox": {"network": "deny", "fs": "ro"},
        "timeout_seconds": 60,
    }

    # Add to jobs stream
    rdb.xadd(JOB_STREAM, {"job": json.dumps(job)})

    # Emit event that job was created
    emit("job.created", {"job_id": job_id, "proposal_id": proposal_id, "tool": tool})

    return job_id


def get_agent_profile(agent: str) -> Dict[str, Any]:
    """Get agent profile, returns default for unknown agents."""
    return AGENT_PROFILES.get(agent, DEFAULT_AGENT_PROFILE)


def check_agent_effects(agent: str, effects: List[str]) -> tuple[bool, Set[str]]:
    """
    Check if agent is allowed to propose these effects.
    Returns (all_allowed, disallowed_effects).
    """
    profile = get_agent_profile(agent)
    allowed = profile["allowed_effects"]
    requested = set(effects)
    disallowed = requested - allowed
    return len(disallowed) == 0, disallowed


def check_agent_risk(agent: str, risk_score: Optional[float]) -> tuple[bool, float]:
    """
    Check if proposal risk is within agent's threshold.
    Returns (within_threshold, max_allowed).
    """
    profile = get_agent_profile(agent)
    max_risk = profile["max_risk"]
    if risk_score is None:
        return True, max_risk
    return risk_score <= max_risk, max_risk


# ---- Endpoints

@app.get("/health")
def health():
    try:
        rdb.ping()
        return {"ok": True, "redis": "connected", "version": "0.1.3"}
    except Exception:
        return {"ok": False, "redis": "disconnected"}


@app.get("/v1/agents")
def list_agents():
    """List registered agent profiles and their effect scopes."""
    agents = []
    for name, profile in AGENT_PROFILES.items():
        agents.append({
            "name": name,
            "allowed_effects": sorted(profile["allowed_effects"]),
            "max_risk": profile["max_risk"],
            "description": profile["description"],
        })
    return {"agents": agents}


@app.post("/v1/intent")
def create_intent(intent: Intent, _: bool = Header(None, alias="X-M87-Key")):
    emit("intent.created", intent.model_dump(by_alias=True))
    return {"accepted": True, "intent_id": intent.intent_id}


@app.post("/v1/govern/proposal", response_model=GovernanceDecision)
def govern_proposal(proposal: Proposal):
    """
    Governance gate. Decides ALLOW/DENY/REQUIRE_HUMAN.

    V1.3 Policy rules (in order):
    1. READ_SECRETS → DENY (absolute)
    2. Agent effect scope violation → DENY
    3. Agent risk threshold exceeded → REQUIRE_HUMAN
    4. DEPLOY → REQUIRE_HUMAN
    5. Otherwise → ALLOW

    If ALLOW: immediately mints a job.
    If REQUIRE_HUMAN: stores pending, job minted on approval.
    """
    reasons: List[str] = []
    agent = proposal.agent

    # Rule 1: READ_SECRETS is absolutely forbidden
    if "READ_SECRETS" in proposal.effects:
        reasons.append("READ_SECRETS is forbidden.")
        decision = GovernanceDecision(
            proposal_id=proposal.proposal_id,
            decision="DENY",
            reasons=reasons,
        )
        emit("proposal.denied", {**decision.model_dump(), "agent": agent})
        return decision

    # Rule 2: Check agent effect scope
    effects_allowed, disallowed_effects = check_agent_effects(agent, proposal.effects)
    if not effects_allowed:
        reasons.append(f"Agent '{agent}' not allowed effects: {sorted(disallowed_effects)}")
        decision = GovernanceDecision(
            proposal_id=proposal.proposal_id,
            decision="DENY",
            reasons=reasons,
        )
        emit("proposal.denied", {**decision.model_dump(), "agent": agent})
        return decision

    # Rule 3: Check agent risk threshold
    risk_allowed, max_risk = check_agent_risk(agent, proposal.risk_score)
    if not risk_allowed:
        reasons.append(f"Risk {proposal.risk_score} exceeds agent '{agent}' max {max_risk}. Requires human review.")
        decision = GovernanceDecision(
            proposal_id=proposal.proposal_id,
            decision="REQUIRE_HUMAN",
            reasons=reasons,
            required_approvals=["mac"],
            allowed_effects=proposal.effects,
        )
        emit("proposal.needs_approval", {
            **decision.model_dump(),
            "summary": proposal.summary,
            "agent": agent,
            "risk_score": proposal.risk_score,
        })
        rdb.hset(f"m87:pending:{proposal.proposal_id}", mapping={
            "proposal": json.dumps(proposal.model_dump()),
            "decision": json.dumps(decision.model_dump()),
        })
        return decision

    # Rule 4: DEPLOY requires human approval
    if "DEPLOY" in proposal.effects:
        reasons.append("DEPLOY requires human approval.")
        decision = GovernanceDecision(
            proposal_id=proposal.proposal_id,
            decision="REQUIRE_HUMAN",
            reasons=reasons,
            required_approvals=["mac"],
            allowed_effects=[e for e in proposal.effects if e != "DEPLOY"],
        )
        emit("proposal.needs_approval", {
            **decision.model_dump(),
            "summary": proposal.summary,
            "agent": agent,
        })
        rdb.hset(f"m87:pending:{proposal.proposal_id}", mapping={
            "proposal": json.dumps(proposal.model_dump()),
            "decision": json.dumps(decision.model_dump()),
        })
        return decision

    # Rule 5: ALLOW - mint job immediately
    reasons.append(f"Allowed by policy. Agent '{agent}' within scope.")
    decision = GovernanceDecision(
        proposal_id=proposal.proposal_id,
        decision="ALLOW",
        reasons=reasons,
        allowed_effects=proposal.effects,
    )
    emit("proposal.allowed", {**decision.model_dump(), "agent": agent})

    # Mint the job
    enqueue_job(
        proposal_id=proposal.proposal_id,
        tool="echo",
        inputs={"message": f"[{agent}] {proposal.summary}"}
    )

    return decision


@app.post("/v1/approve/{proposal_id}")
def approve(proposal_id: str, x_m87_key: Optional[str] = Header(None, alias="X-M87-Key")):
    """Human approves a pending proposal. Mints the job."""
    verify_api_key(x_m87_key)

    pending_key = f"m87:pending:{proposal_id}"
    pending_data = rdb.hgetall(pending_key)

    if not pending_data:
        raise HTTPException(status_code=404, detail="No pending proposal found")

    proposal_data = json.loads(pending_data.get("proposal", "{}"))

    evt = {"proposal_id": proposal_id, "approved_by": "mac"}
    emit("proposal.approved", evt)

    job_id = enqueue_job(
        proposal_id=proposal_id,
        tool="echo",
        inputs={"message": f"Approved: {proposal_data.get('summary', 'unknown')}"}
    )

    rdb.delete(pending_key)

    return {"approved": True, "job_id": job_id, **evt}


@app.post("/v1/deny/{proposal_id}")
def deny(proposal_id: str, reason: str = "Denied by human", x_m87_key: Optional[str] = Header(None, alias="X-M87-Key")):
    """Human denies a pending proposal."""
    verify_api_key(x_m87_key)

    pending_key = f"m87:pending:{proposal_id}"

    evt = {"proposal_id": proposal_id, "denied_by": "mac", "reason": reason}
    emit("proposal.denied_by_human", evt)

    rdb.delete(pending_key)

    return {"denied": True, **evt}


@app.get("/v1/events")
def list_events(limit: int = 200, after: Optional[str] = None):
    """Get events from stream."""
    if after:
        items = rdb.xrange(EVENT_STREAM, min=f"({after}", max="+", count=limit)
    else:
        items = rdb.xrevrange(EVENT_STREAM, max="+", min="-", count=limit)
        items = list(reversed(items))

    events = []
    for event_id, fields in items:
        events.append({
            "id": event_id,
            "type": fields.get("type"),
            "payload": json.loads(fields.get("payload") or "{}")
        })
    return {"events": events}


@app.get("/v1/jobs")
def list_jobs(limit: int = 100, status: Optional[str] = None):
    """Get jobs from stream with derived status."""
    job_items = rdb.xrevrange(JOB_STREAM, max="+", min="-", count=limit)
    event_items = rdb.xrevrange(EVENT_STREAM, max="+", min="-", count=500)

    job_status = {}
    for _, fields in event_items:
        event_type = fields.get("type", "")
        payload = json.loads(fields.get("payload") or "{}")
        job_id = payload.get("job_id")

        if not job_id:
            continue

        if event_type == "job.completed" and job_id not in job_status:
            job_status[job_id] = {"status": "completed", "output": payload.get("output")}
        elif event_type == "job.failed" and job_id not in job_status:
            job_status[job_id] = {"status": "failed", "error": payload.get("error")}
        elif event_type == "job.started" and job_id not in job_status:
            job_status[job_id] = {"status": "running"}

    jobs = []
    for job_stream_id, fields in reversed(list(job_items)):
        job_data = json.loads(fields.get("job", "{}"))
        job_id = job_data.get("job_id")

        derived = job_status.get(job_id, {"status": "pending"})
        job_entry = {
            "stream_id": job_stream_id,
            **job_data,
            **derived,
        }

        if status is None or job_entry.get("status") == status:
            jobs.append(job_entry)

    return {"jobs": jobs}


@app.get("/v1/pending-approvals")
def pending_approvals():
    """Get proposals awaiting human approval."""
    items = rdb.xrevrange(EVENT_STREAM, max="+", min="-", count=1000)

    needs_approval = {}
    resolved = set()

    for event_id, fields in items:
        event_type = fields.get("type")
        payload = json.loads(fields.get("payload") or "{}")
        proposal_id = payload.get("proposal_id")

        if not proposal_id:
            continue

        if event_type in ("proposal.approved", "proposal.denied_by_human"):
            resolved.add(proposal_id)
        elif event_type == "proposal.needs_approval" and proposal_id not in resolved:
            if proposal_id not in needs_approval:
                needs_approval[proposal_id] = {
                    "id": event_id,
                    "proposal_id": proposal_id,
                    "payload": payload
                }

    return {"pending": list(needs_approval.values())}


@app.post("/v1/runner/result")
def runner_result(payload: Dict[str, Any], x_m87_key: Optional[str] = Header(None, alias="X-M87-Key")):
    """Runner reports job completion/failure."""
    verify_api_key(x_m87_key)

    job_id = payload.get("job_id")
    status = payload.get("status", "completed")

    if status == "completed":
        emit("job.completed", payload)
    else:
        emit("job.failed", payload)

    return {"ok": True}


@app.post("/v1/admin/emit")
def admin_emit(payload: Dict[str, Any], x_m87_key: Optional[str] = Header(None, alias="X-M87-Key")):
    """Admin endpoint to emit arbitrary events (for testing)."""
    if not ENABLE_TEST_ENDPOINTS:
        raise HTTPException(status_code=404, detail="Not found")

    verify_api_key(x_m87_key)

    event_type = payload.get("type")
    data = payload.get("payload", {})

    if not event_type:
        raise HTTPException(status_code=400, detail="Missing event type")

    emit(event_type, data)
    return {"ok": True, "emitted": event_type}
