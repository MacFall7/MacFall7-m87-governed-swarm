"""
Governance proposal route: single fail-closed choke point.

Wire order (fail-closed at each stage):
1. SessionRiskTracker (cumulative topology detection)
2. Tripwire scan on any code artifacts (Phase 4+5)
3. Require challenge-response if decision is REQUIRE_HUMAN
4. Commit effects only on ALLOW or human approval

All enforcement happens in the Runner—the only component authorized to
execute tools—so policy can't be bypassed by upstream orchestration.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

import redis

from ..session_risk import SessionRiskTracker
from ..governance.resource_limits import (
    bounded_python_tripwire_scan,
    GovernanceTimeout,
    GovernanceLimitExceeded,
)
from ..governance.adversarial_review import (
    stable_proposal_hash,
    generate_challenge,
    verify_challenge,
    Challenge,
)

router = APIRouter(prefix="/v2/govern", tags=["governance"])


# ---- Request/Response Models ----

class Artifact(BaseModel):
    type: str
    content: Optional[str] = None
    path: Optional[str] = None


class ProposalRequest(BaseModel):
    principal_id: str
    agent_name: str
    effects: List[str]
    artifacts: List[Artifact] = []
    proposal_id: Optional[str] = None
    summary: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


class ChallengeResponse(BaseModel):
    challenge_id: str
    proposal_hash: str
    prompt: str


class GovernanceResponse(BaseModel):
    decision: str  # ALLOW | REQUIRE_HUMAN | DENY
    reason: str
    challenge: Optional[ChallengeResponse] = None
    proposal_hash: Optional[str] = None


class ApprovalRequest(BaseModel):
    principal_id: str
    agent_name: str
    effects: List[str]
    proposal: Dict[str, Any]
    challenge_id: str
    answer: str


# ---- Dependencies ----

def get_redis() -> redis.Redis:
    """
    Get Redis connection.

    Replace with your existing dependency injection.
    """
    import os
    redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
    return redis.Redis.from_url(redis_url, decode_responses=False)


# ---- Routes ----

@router.post("/proposal", response_model=GovernanceResponse)
def govern_proposal(
    payload: ProposalRequest,
    r: redis.Redis = Depends(get_redis)
) -> GovernanceResponse:
    """
    Main governance choke point.

    Evaluates proposal against:
    1. Session risk (cumulative toxic topology detection)
    2. Code artifact tripwire scan
    3. Returns challenge if REQUIRE_HUMAN
    """
    tracker = SessionRiskTracker(r=r)

    # Phase 3: Evaluate against session history (toxic topologies)
    decision, reason = tracker.evaluate(
        payload.principal_id,
        payload.agent_name,
        payload.effects
    )

    # Phase 4/5: Inspect code artifacts BEFORE allowing execution paths
    tripwire_flags: List[str] = []
    for artifact in payload.artifacts:
        if artifact.type in ("python_code", "code", "shell_script"):
            code = artifact.content or ""
            try:
                scan = bounded_python_tripwire_scan(code)
            except GovernanceTimeout:
                raise HTTPException(
                    status_code=403,
                    detail="Governance scan blocked: timeout"
                )
            except GovernanceLimitExceeded as e:
                raise HTTPException(
                    status_code=403,
                    detail=f"Governance scan blocked: {str(e)}"
                )

            if not scan.get("ok", False):
                tripwire_flags.extend(scan.get("flags", []))

    # If tripwire flags found, escalate to REQUIRE_HUMAN
    if tripwire_flags and decision == "ALLOW":
        decision = "REQUIRE_HUMAN"
        reason = f"{reason} | Tripwire flags: {tripwire_flags}"

    # Compute stable proposal hash for challenge binding
    proposal_json = json.dumps(payload.model_dump(), sort_keys=True, default=str)
    p_hash = stable_proposal_hash(proposal_json)

    # Phase 6: Challenge-response for REQUIRE_HUMAN
    if decision == "REQUIRE_HUMAN":
        # Extract topology name from reason if present
        topology_name = "unknown_topology"
        if "Toxic topology detected:" in reason:
            try:
                topology_name = reason.split("Toxic topology detected:")[1].strip().split()[0]
            except Exception:
                pass

        challenge = generate_challenge(p_hash, topology_name)
        return GovernanceResponse(
            decision=decision,
            reason=reason,
            proposal_hash=p_hash,
            challenge=ChallengeResponse(
                challenge_id=challenge.challenge_id,
                proposal_hash=challenge.proposal_hash,
                prompt=challenge.prompt,
            ),
        )

    if decision == "DENY":
        return GovernanceResponse(
            decision=decision,
            reason=reason,
            proposal_hash=p_hash,
        )

    # ALLOW: commit effects only now
    try:
        tracker.commit(payload.principal_id, payload.agent_name, payload.effects)
    except Exception as e:
        # Commit failure should fail-closed
        raise HTTPException(
            status_code=503,
            detail=f"Failed to persist governance state (Redis): {str(e)}"
        )

    return GovernanceResponse(
        decision="ALLOW",
        reason=reason,
        proposal_hash=p_hash,
    )


@router.post("/approve", response_model=GovernanceResponse)
def approve_override(
    payload: ApprovalRequest,
    r: redis.Redis = Depends(get_redis)
) -> GovernanceResponse:
    """
    Human override approval with challenge-response verification.

    Requires:
    1. Valid challenge response (proves human read the warning)
    2. Challenge binding to original proposal (prevents bait-switch)
    """
    # Recompute proposal hash
    proposal_json = json.dumps(payload.proposal, sort_keys=True, default=str)
    p_hash = stable_proposal_hash(proposal_json)

    # Extract topology from effects or use generic
    topology_name = "unknown_topology"
    if "Toxic topology" in str(payload.proposal.get("reason", "")):
        try:
            topology_name = str(payload.proposal["reason"]).split("Toxic topology detected:")[1].strip().split()[0]
        except Exception:
            pass

    # Recreate challenge for verification
    ch = Challenge(
        challenge_id=payload.challenge_id,
        prompt="",  # Not needed for verification
        expected=topology_name,
        proposal_hash=p_hash,
    )

    # Verify the challenge
    result = verify_challenge(ch, payload.answer)
    if result.get("ok") != "true":
        raise HTTPException(
            status_code=403,
            detail=f"Approval blocked: {result.get('reason')}"
        )

    # Commit effects after successful verification
    tracker = SessionRiskTracker(r=r)
    try:
        tracker.commit(payload.principal_id, payload.agent_name, payload.effects)
    except Exception as e:
        raise HTTPException(
            status_code=503,
            detail=f"Failed to persist governance state (Redis): {str(e)}"
        )

    return GovernanceResponse(
        decision="ALLOW",
        reason="Human override approved with challenge-response",
        proposal_hash=p_hash,
    )
