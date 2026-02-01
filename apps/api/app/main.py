from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import List, Optional, Literal, Dict, Any, Set
import os
import json
import uuid
import logging
from datetime import datetime
from redis import Redis

from .auth import (
    KeyStore,
    KeyVerifier,
    AuthDecision,
    AuthReasonCode,
    emit_auth_event,
)

from .db import (
    init_db,
    check_db_health,
    PersistenceUnavailable,
    persist_api_key,
    persist_proposal,
    persist_decision,
    persist_job,
    persist_execution,
    update_api_key_enabled,
    delete_api_key as db_delete_key,
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="m87-governed-swarm-api", version="0.3.0")

# ---- Config
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
DATABASE_URL = os.getenv("DATABASE_URL", "")
BOOTSTRAP_KEY = os.getenv("M87_API_KEY", "m87-dev-key-change-me")
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000").split(",")
ENABLE_TEST_ENDPOINTS = os.getenv("M87_ENABLE_TEST_ENDPOINTS", "false").lower() == "true"

# ---- Global state: persistence availability
_db_available = False

# CORS - tightened for V1.2
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["*"],
)

# ---- Redis connection
rdb = Redis.from_url(REDIS_URL, decode_responses=True)

# ---- Auth system (V2.0 - scoped keys)
key_store = KeyStore(rdb)
key_verifier = KeyVerifier(key_store)

# Stream keys
EVENT_STREAM = "m87:events"
JOB_STREAM = "m87:jobs"

# Runner tool allowlist
ALLOWED_TOOLS = {"echo", "pytest", "git", "build"}


# ---- V1.3: Agent Profiles (effect scopes + risk thresholds)
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
    "Human": {
        "allowed_effects": {
            "READ_REPO", "WRITE_PATCH", "RUN_TESTS", "BUILD_ARTIFACT",
            "NETWORK_CALL", "SEND_NOTIFICATION", "CREATE_PR", "MERGE", "DEPLOY"
        },
        "max_risk": 1.0,
        "description": "Manual human proposals",
    },
}

DEFAULT_AGENT_PROFILE = {
    "allowed_effects": {"READ_REPO"},
    "max_risk": 0.3,
    "description": "Unknown agent (restricted)",
}


# ---- Event + Job emission (defined early for use in auth)
def emit(event_type: str, payload: Dict[str, Any]) -> str:
    """Emit event to Redis stream, returns event ID."""
    event_id = rdb.xadd(EVENT_STREAM, {"type": event_type, "payload": json.dumps(payload)})
    return event_id


# ---- Startup: Initialize database and seed bootstrap key
@app.on_event("startup")
async def startup_event():
    """Initialize the system on startup."""
    global _db_available
    logger.info("M87 API starting up (v0.3.0 - Postgres persistence)...")

    # Check Redis connection
    try:
        rdb.ping()
        logger.info("Redis connection OK")
    except Exception as e:
        logger.error(f"Redis connection failed: {e}")
        raise

    # Initialize database (Phase 2)
    if DATABASE_URL:
        try:
            if init_db():
                _db_available = True
                logger.info("Postgres connection OK - tables initialized")

                # Verify connectivity
                health = check_db_health()
                if not health["connected"]:
                    logger.error(f"Postgres health check failed: {health['error']}")
                    _db_available = False
            else:
                logger.error("Failed to initialize database tables")
                _db_available = False
        except Exception as e:
            logger.error(f"Postgres initialization failed: {e}")
            _db_available = False
    else:
        logger.warning("DATABASE_URL not configured - running without persistence")
        _db_available = False

    # Seed bootstrap key if it doesn't exist
    existing = key_store.get_by_plaintext(BOOTSTRAP_KEY)
    if not existing:
        record = key_store.seed_bootstrap_key(BOOTSTRAP_KEY)
        logger.info(f"Bootstrap key seeded: {record.key_id}")

        # Persist bootstrap key to Postgres if available
        if _db_available:
            try:
                persist_api_key(
                    key_id=record.key_id,
                    key_hash=record.key_hash,
                    principal_type=record.principal_type,
                    principal_id=record.principal_id,
                    endpoint_scopes=list(record.endpoint_scopes),
                    effect_scopes=list(record.effect_scopes),
                    max_risk=record.max_risk,
                    enabled=record.enabled,
                    description=record.description,
                )
            except Exception as e:
                logger.error(f"Failed to persist bootstrap key: {e}")
    else:
        logger.info(f"Bootstrap key already exists: {existing.key_id}")

    logger.info(f"M87 API ready (db_available={_db_available})")


# ---- Hard fail-safe helper (Phase 2)
def require_persistence():
    """
    Hard fail-safe: deny mutations if Postgres is unavailable.

    Raises HTTPException 503 if persistence is not available.
    """
    if not _db_available:
        logger.warning("Mutation denied: persistence unavailable")
        raise HTTPException(
            status_code=503,
            detail={
                "error": "DB_UNAVAILABLE",
                "message": "Persistence layer unavailable - mutations denied",
            }
        )


# ---- Auth helper
def verify_auth(
    x_m87_key: Optional[str],
    endpoint_scope: str,
    requested_effects: Optional[Set[str]] = None,
    risk_score: Optional[float] = None,
) -> AuthDecision:
    """
    Verify authentication and authorization for an endpoint.

    Raises HTTPException on failure.
    Returns AuthDecision on success (for logging principal info).
    """
    decision = key_verifier.verify(
        plaintext_key=x_m87_key,
        endpoint_scope=endpoint_scope,
        requested_effects=requested_effects,
        risk_score=risk_score,
    )

    # Log the auth decision
    emit_auth_event(decision, endpoint_scope, emit)

    if not decision.allowed:
        # Map reason codes to HTTP status codes
        if decision.reason_code in (AuthReasonCode.MISSING_KEY, AuthReasonCode.INVALID_KEY):
            raise HTTPException(status_code=401, detail=decision.reason)
        else:
            # Scope/permission errors are 403
            raise HTTPException(status_code=403, detail=decision.reason)

    return decision


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


class CreateKeyRequest(BaseModel):
    principal_type: str
    principal_id: str
    endpoint_scopes: List[str]
    effect_scopes: Optional[List[str]] = None
    max_risk: float = 1.0
    description: Optional[str] = None


# ---- Job minting
def enqueue_job(proposal_id: str, tool: str, inputs: Dict[str, Any] = None) -> str:
    """
    Mint a JobSpec and add to jobs stream.
    This is the ONLY way jobs get created - after governance.

    V0.3.0: Persists job to Postgres (write-through).
    """
    if tool not in ALLOWED_TOOLS:
        raise ValueError(f"Tool '{tool}' not in allowlist: {ALLOWED_TOOLS}")

    job_id = str(uuid.uuid4())
    sandbox = {"network": "deny", "fs": "ro"}
    timeout_seconds = 60
    job_inputs = inputs or {}

    job = {
        "job_id": job_id,
        "proposal_id": proposal_id,
        "tool": tool,
        "inputs": job_inputs,
        "sandbox": sandbox,
        "timeout_seconds": timeout_seconds,
    }

    # Phase 2: Persist job to Postgres (write-through)
    if _db_available:
        try:
            persist_job(
                job_id=job_id,
                proposal_id=proposal_id,
                tool=tool,
                inputs=job_inputs,
                sandbox=sandbox,
                timeout_seconds=timeout_seconds,
            )
        except PersistenceUnavailable as e:
            logger.error(f"Failed to persist job: {e}")
            raise HTTPException(
                status_code=503,
                detail={"error": "DB_WRITE_FAILED", "message": str(e)}
            )

    rdb.xadd(JOB_STREAM, {"job": json.dumps(job)})
    emit("job.created", {"job_id": job_id, "proposal_id": proposal_id, "tool": tool})

    return job_id


def get_agent_profile(agent: str) -> Dict[str, Any]:
    """Get agent profile, returns default for unknown agents."""
    return AGENT_PROFILES.get(agent, DEFAULT_AGENT_PROFILE)


def check_agent_effects(agent: str, effects: List[str]) -> tuple[bool, Set[str]]:
    """Check if agent is allowed to propose these effects."""
    profile = get_agent_profile(agent)
    allowed = profile["allowed_effects"]
    requested = set(effects)
    disallowed = requested - allowed
    return len(disallowed) == 0, disallowed


def check_agent_risk(agent: str, risk_score: Optional[float]) -> tuple[bool, float]:
    """Check if proposal risk is within agent's threshold."""
    profile = get_agent_profile(agent)
    max_risk = profile["max_risk"]
    if risk_score is None:
        return True, max_risk
    return risk_score <= max_risk, max_risk


# ---- Endpoints

@app.get("/health")
def health():
    """
    Health check endpoint.

    Returns health status for Redis and Postgres.
    System is "ok" only if all required services are available.
    """
    redis_ok = False
    try:
        rdb.ping()
        redis_ok = True
    except Exception:
        pass

    db_health = check_db_health() if DATABASE_URL else {"connected": False, "error": "Not configured"}

    # System is healthy if Redis is up and (DB is up or not configured)
    system_ok = redis_ok and (db_health["connected"] or not DATABASE_URL)

    return {
        "ok": system_ok,
        "version": "0.3.0",
        "redis": "connected" if redis_ok else "disconnected",
        "postgres": "connected" if db_health["connected"] else "disconnected",
        "persistence_available": _db_available,
    }


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
def govern_proposal(
    proposal: Proposal,
    x_m87_key: Optional[str] = Header(None, alias="X-M87-Key"),
):
    """
    Governance gate. Decides ALLOW/DENY/REQUIRE_HUMAN.
    Requires scoped API key with proposal:create scope.

    V2.0 Auth checks (in order):
    1. Key valid and enabled
    2. Key has proposal:create scope
    3. Key has effect scopes for requested effects
    4. Risk <= key's max_risk

    V1.3 Policy rules (after auth):
    1. READ_SECRETS → DENY (absolute)
    2. Agent effect scope violation → DENY
    3. Agent risk threshold exceeded → REQUIRE_HUMAN
    4. DEPLOY → REQUIRE_HUMAN
    5. Otherwise → ALLOW

    V0.3.0: Requires Postgres for write-through (hard fail-safe).
    """
    # Phase 2: Hard fail-safe - require persistence for mutations
    require_persistence()

    # V2.0: Scoped auth check
    auth = verify_auth(
        x_m87_key=x_m87_key,
        endpoint_scope="proposal:create",
        requested_effects=set(proposal.effects),
        risk_score=proposal.risk_score,
    )

    # Phase 2: Persist proposal to Postgres (write-through)
    try:
        persist_proposal(
            proposal_id=proposal.proposal_id,
            intent_id=proposal.intent_id,
            agent=proposal.agent,
            summary=proposal.summary,
            effects=list(proposal.effects),
            artifacts=proposal.artifacts,
            truth_account=proposal.truth_account.model_dump() if proposal.truth_account else None,
            risk_score=proposal.risk_score,
            principal_type=auth.principal_type,
            principal_id=auth.principal_id,
        )
    except PersistenceUnavailable as e:
        logger.error(f"Failed to persist proposal: {e}")
        raise HTTPException(
            status_code=503,
            detail={"error": "DB_WRITE_FAILED", "message": str(e)}
        )

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
        # Phase 2: Persist decision
        persist_decision(
            proposal_id=proposal.proposal_id,
            outcome="DENY",
            reasons=reasons,
            decided_by="policy",
        )
        emit("proposal.denied", {
            **decision.model_dump(),
            "agent": agent,
            "principal_id": auth.principal_id,
        })
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
        # Phase 2: Persist decision
        persist_decision(
            proposal_id=proposal.proposal_id,
            outcome="DENY",
            reasons=reasons,
            decided_by="policy",
        )
        emit("proposal.denied", {
            **decision.model_dump(),
            "agent": agent,
            "principal_id": auth.principal_id,
        })
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
        # Phase 2: Persist decision
        persist_decision(
            proposal_id=proposal.proposal_id,
            outcome="REQUIRE_HUMAN",
            reasons=reasons,
            decided_by="policy",
            required_approvals=["mac"],
            allowed_effects=list(proposal.effects),
        )
        emit("proposal.needs_approval", {
            **decision.model_dump(),
            "summary": proposal.summary,
            "agent": agent,
            "risk_score": proposal.risk_score,
            "principal_id": auth.principal_id,
        })
        rdb.hset(f"m87:pending:{proposal.proposal_id}", mapping={
            "proposal": json.dumps(proposal.model_dump()),
            "decision": json.dumps(decision.model_dump()),
        })
        return decision

    # Rule 4: DEPLOY requires human approval
    if "DEPLOY" in proposal.effects:
        reasons.append("DEPLOY requires human approval.")
        allowed = [e for e in proposal.effects if e != "DEPLOY"]
        decision = GovernanceDecision(
            proposal_id=proposal.proposal_id,
            decision="REQUIRE_HUMAN",
            reasons=reasons,
            required_approvals=["mac"],
            allowed_effects=allowed,
        )
        # Phase 2: Persist decision
        persist_decision(
            proposal_id=proposal.proposal_id,
            outcome="REQUIRE_HUMAN",
            reasons=reasons,
            decided_by="policy",
            required_approvals=["mac"],
            allowed_effects=allowed,
        )
        emit("proposal.needs_approval", {
            **decision.model_dump(),
            "summary": proposal.summary,
            "agent": agent,
            "principal_id": auth.principal_id,
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
    # Phase 2: Persist decision
    persist_decision(
        proposal_id=proposal.proposal_id,
        outcome="ALLOW",
        reasons=reasons,
        decided_by="policy",
        allowed_effects=list(proposal.effects),
    )
    emit("proposal.allowed", {
        **decision.model_dump(),
        "agent": agent,
        "principal_id": auth.principal_id,
    })

    enqueue_job(
        proposal_id=proposal.proposal_id,
        tool="echo",
        inputs={"message": f"[{agent}] {proposal.summary}"}
    )

    return decision


@app.post("/v1/approve/{proposal_id}")
def approve(proposal_id: str, x_m87_key: Optional[str] = Header(None, alias="X-M87-Key")):
    """Human approves a pending proposal. Requires proposal:approve scope."""
    # Phase 2: Hard fail-safe
    require_persistence()

    auth = verify_auth(x_m87_key, "proposal:approve")

    pending_key = f"m87:pending:{proposal_id}"
    pending_data = rdb.hgetall(pending_key)

    if not pending_data:
        raise HTTPException(status_code=404, detail="No pending proposal found")

    proposal_data = json.loads(pending_data.get("proposal", "{}"))

    # Phase 2: Persist human approval decision
    persist_decision(
        proposal_id=proposal_id,
        outcome="ALLOW",
        reasons=["Human approved"],
        decided_by=f"human:{auth.principal_id}",
    )

    evt = {
        "proposal_id": proposal_id,
        "approved_by": auth.principal_id,
    }
    emit("proposal.approved", evt)

    job_id = enqueue_job(
        proposal_id=proposal_id,
        tool="echo",
        inputs={"message": f"Approved: {proposal_data.get('summary', 'unknown')}"}
    )

    rdb.delete(pending_key)

    return {"approved": True, "job_id": job_id, **evt}


@app.post("/v1/deny/{proposal_id}")
def deny(
    proposal_id: str,
    reason: str = "Denied by human",
    x_m87_key: Optional[str] = Header(None, alias="X-M87-Key"),
):
    """Human denies a pending proposal. Requires proposal:deny scope."""
    # Phase 2: Hard fail-safe
    require_persistence()

    auth = verify_auth(x_m87_key, "proposal:deny")

    pending_key = f"m87:pending:{proposal_id}"

    # Phase 2: Persist human denial decision
    persist_decision(
        proposal_id=proposal_id,
        outcome="DENY",
        reasons=[reason],
        decided_by=f"human:{auth.principal_id}",
    )

    evt = {
        "proposal_id": proposal_id,
        "denied_by": auth.principal_id,
        "reason": reason,
    }
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
    """Runner reports job completion/failure. Requires runner:result scope."""
    # Phase 2: Hard fail-safe
    require_persistence()

    auth = verify_auth(x_m87_key, "runner:result")

    job_id = payload.get("job_id")
    status = payload.get("status", "completed")
    output = payload.get("output")
    error = payload.get("error")

    # Phase 2: Persist execution receipt
    try:
        persist_execution(
            job_id=job_id,
            status=status,
            output=output,
            error=error,
            runner_id=auth.principal_id,
        )
    except PersistenceUnavailable as e:
        logger.error(f"Failed to persist execution: {e}")
        raise HTTPException(
            status_code=503,
            detail={"error": "DB_WRITE_FAILED", "message": str(e)}
        )

    if status == "completed":
        emit("job.completed", payload)
    else:
        emit("job.failed", payload)

    return {"ok": True}


# ---- Admin endpoints (key management)

@app.post("/v1/admin/keys")
def create_key(
    request: CreateKeyRequest,
    x_m87_key: Optional[str] = Header(None, alias="X-M87-Key"),
):
    """Create a new API key. Requires admin:keys scope."""
    # Phase 2: Hard fail-safe
    require_persistence()

    verify_auth(x_m87_key, "admin:keys")

    plaintext, record = key_store.create_key(
        principal_type=request.principal_type,
        principal_id=request.principal_id,
        endpoint_scopes=set(request.endpoint_scopes),
        effect_scopes=set(request.effect_scopes) if request.effect_scopes else set(),
        max_risk=request.max_risk,
        description=request.description,
    )

    # Phase 2: Persist key to Postgres
    try:
        persist_api_key(
            key_id=record.key_id,
            key_hash=record.key_hash,
            principal_type=record.principal_type,
            principal_id=record.principal_id,
            endpoint_scopes=list(record.endpoint_scopes),
            effect_scopes=list(record.effect_scopes),
            max_risk=record.max_risk,
            enabled=record.enabled,
            expires_at=record.expires_at,
            description=record.description,
        )
    except PersistenceUnavailable as e:
        logger.error(f"Failed to persist key: {e}")
        # Rollback Redis write
        key_store.delete_key(record.key_id)
        raise HTTPException(
            status_code=503,
            detail={"error": "DB_WRITE_FAILED", "message": str(e)}
        )

    logger.info(f"Key created: {record.key_id} for {record.principal_type}:{record.principal_id}")

    return {
        "key_id": record.key_id,
        "key": plaintext,  # Only returned once at creation
        "principal_type": record.principal_type,
        "principal_id": record.principal_id,
        "endpoint_scopes": sorted(record.endpoint_scopes),
        "effect_scopes": sorted(record.effect_scopes),
        "max_risk": record.max_risk,
    }


@app.get("/v1/admin/keys")
def list_keys(x_m87_key: Optional[str] = Header(None, alias="X-M87-Key")):
    """List all API keys. Requires admin:keys scope."""
    verify_auth(x_m87_key, "admin:keys")

    keys = key_store.list_keys()
    return {
        "keys": [
            {
                "key_id": k.key_id,
                "principal_type": k.principal_type,
                "principal_id": k.principal_id,
                "endpoint_scopes": sorted(k.endpoint_scopes),
                "effect_scopes": sorted(k.effect_scopes),
                "max_risk": k.max_risk,
                "enabled": k.enabled,
                "created_at": k.created_at.isoformat() if k.created_at else None,
                "description": k.description,
            }
            for k in keys
        ]
    }


@app.post("/v1/admin/keys/{key_id}/disable")
def disable_key(key_id: str, x_m87_key: Optional[str] = Header(None, alias="X-M87-Key")):
    """Disable an API key. Requires admin:keys scope."""
    # Phase 2: Hard fail-safe
    require_persistence()

    verify_auth(x_m87_key, "admin:keys")

    if key_store.disable_key(key_id):
        # Phase 2: Persist to Postgres
        update_api_key_enabled(key_id, False)
        logger.info(f"Key disabled: {key_id}")
        return {"disabled": True, "key_id": key_id}
    raise HTTPException(status_code=404, detail="Key not found")


@app.post("/v1/admin/keys/{key_id}/enable")
def enable_key(key_id: str, x_m87_key: Optional[str] = Header(None, alias="X-M87-Key")):
    """Enable an API key. Requires admin:keys scope."""
    # Phase 2: Hard fail-safe
    require_persistence()

    verify_auth(x_m87_key, "admin:keys")

    if key_store.enable_key(key_id):
        # Phase 2: Persist to Postgres
        update_api_key_enabled(key_id, True)
        logger.info(f"Key enabled: {key_id}")
        return {"enabled": True, "key_id": key_id}
    raise HTTPException(status_code=404, detail="Key not found")


@app.delete("/v1/admin/keys/{key_id}")
def delete_key(key_id: str, x_m87_key: Optional[str] = Header(None, alias="X-M87-Key")):
    """Delete an API key. Requires admin:keys scope."""
    # Phase 2: Hard fail-safe
    require_persistence()

    verify_auth(x_m87_key, "admin:keys")

    if key_id == "key_bootstrap":
        raise HTTPException(status_code=400, detail="Cannot delete bootstrap key")

    if key_store.delete_key(key_id):
        # Phase 2: Persist to Postgres
        db_delete_key(key_id)
        logger.info(f"Key deleted: {key_id}")
        return {"deleted": True, "key_id": key_id}
    raise HTTPException(status_code=404, detail="Key not found")


@app.post("/v1/admin/emit")
def admin_emit(payload: Dict[str, Any], x_m87_key: Optional[str] = Header(None, alias="X-M87-Key")):
    """Admin endpoint to emit arbitrary events (for testing)."""
    if not ENABLE_TEST_ENDPOINTS:
        raise HTTPException(status_code=404, detail="Not found")

    verify_auth(x_m87_key, "admin:emit")

    event_type = payload.get("type")
    data = payload.get("payload", {})

    if not event_type:
        raise HTTPException(status_code=400, detail="Missing event type")

    emit(event_type, data)
    return {"ok": True, "emitted": event_type}
