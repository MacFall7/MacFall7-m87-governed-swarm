from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import List, Optional, Literal, Dict, Any
import os
import json
from redis import Redis

app = FastAPI(title="m87-governed-swarm-api", version="0.1.1")

# CORS for dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---- Redis connection
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
rdb = Redis.from_url(REDIS_URL, decode_responses=True)

STREAM_KEY = "m87:events"


# ---- Minimal in-service models (v1). We'll later generate from shared schemas.
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


# ---- Event emission via Redis Streams
def emit(event_type: str, payload: Dict[str, Any]) -> str:
    """Emit event to Redis stream, returns event ID."""
    event_id = rdb.xadd(STREAM_KEY, {"type": event_type, "payload": json.dumps(payload)})
    return event_id


@app.get("/health")
def health():
    try:
        rdb.ping()
        return {"ok": True, "redis": "connected"}
    except Exception:
        return {"ok": False, "redis": "disconnected"}


@app.post("/v1/intent")
def create_intent(intent: Intent):
    emit("intent.created", intent.model_dump(by_alias=True))
    return {"accepted": True, "intent_id": intent.intent_id}


@app.post("/v1/govern/proposal", response_model=GovernanceDecision)
def govern_proposal(proposal: Proposal):
    reasons: List[str] = []

    if "READ_SECRETS" in proposal.effects:
        reasons.append("READ_SECRETS is forbidden in v1 policy.")
        decision: GovernanceDecision = GovernanceDecision(
            proposal_id=proposal.proposal_id,
            decision="DENY",
            reasons=reasons,
        )
        emit("proposal.denied", decision.model_dump())
        return decision

    if "DEPLOY" in proposal.effects:
        reasons.append("DEPLOY requires human approval.")
        decision = GovernanceDecision(
            proposal_id=proposal.proposal_id,
            decision="REQUIRE_HUMAN",
            reasons=reasons,
            required_approvals=["mac"],
            allowed_effects=[e for e in proposal.effects if e != "DEPLOY"],
        )
        emit("proposal.needs_approval", decision.model_dump())
        return decision

    reasons.append("Allowed by v1 policy.")
    decision = GovernanceDecision(
        proposal_id=proposal.proposal_id,
        decision="ALLOW",
        reasons=reasons,
        allowed_effects=proposal.effects,
    )
    emit("proposal.allowed", decision.model_dump())
    return decision


@app.post("/v1/approve/{proposal_id}")
def approve(proposal_id: str):
    evt = {"proposal_id": proposal_id, "approved_by": "mac"}
    emit("proposal.approved", evt)
    return {"approved": True, **evt}


@app.post("/v1/deny/{proposal_id}")
def deny(proposal_id: str, reason: str = "Denied by human"):
    evt = {"proposal_id": proposal_id, "denied_by": "mac", "reason": reason}
    emit("proposal.denied_by_human", evt)
    return {"denied": True, **evt}


@app.get("/v1/events")
def list_events(limit: int = 200, after: Optional[str] = None):
    """
    Get events from stream.
    - limit: max events to return
    - after: stream ID to start after (for polling)
    """
    if after:
        # Streaming mode: get events after cursor
        items = rdb.xrange(STREAM_KEY, min=f"({after}", max="+", count=limit)
    else:
        # Timeline mode: get latest events (newest last)
        items = rdb.xrevrange(STREAM_KEY, max="+", min="-", count=limit)
        items = list(reversed(items))

    events = []
    for event_id, fields in items:
        events.append({
            "id": event_id,
            "type": fields.get("type"),
            "payload": json.loads(fields.get("payload") or "{}")
        })
    return {"events": events}


@app.get("/v1/pending-approvals")
def pending_approvals():
    """Get proposals awaiting human approval."""
    items = rdb.xrevrange(STREAM_KEY, max="+", min="-", count=1000)

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
def runner_result(payload: Dict[str, Any]):
    emit("runner.result", payload)
    return {"ok": True}
