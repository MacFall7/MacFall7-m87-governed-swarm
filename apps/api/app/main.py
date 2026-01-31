from fastapi import FastAPI
from pydantic import BaseModel, Field
from typing import List, Optional, Literal, Dict, Any
import uuid
import time

app = FastAPI(title="m87-governed-swarm-api", version="0.1.0")


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


# ---- In-memory event log (v1). We'll move to Postgres/Redis streams next.
EVENTS: List[Dict[str, Any]] = []


def emit(event_type: str, payload: Dict[str, Any]) -> None:
    EVENTS.append({"ts": time.time(), "type": event_type, "payload": payload})


@app.get("/health")
def health():
    return {"ok": True}


@app.post("/v1/intent")
def create_intent(intent: Intent):
    emit("intent.created", intent.model_dump(by_alias=True))
    return {"accepted": True, "intent_id": intent.intent_id}


@app.post("/v1/govern/proposal", response_model=GovernanceDecision)
def govern_proposal(proposal: Proposal):
    reasons: List[str] = []

    constraints = None
    # In v1 we don't persist intents yet; allow constraint overrides via proposal artifacts later.
    # Keep simple.

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
    # v1: approval just emits an event; runner will listen later
    evt = {"proposal_id": proposal_id, "approved_by": "mac"}
    emit("proposal.approved", evt)
    return {"approved": True, **evt}


@app.get("/v1/events")
def list_events(limit: int = 200):
    return {"events": EVENTS[-limit:]}


@app.post("/v1/runner/result")
def runner_result(payload: Dict[str, Any]):
    emit("runner.result", payload)
    return {"ok": True}
