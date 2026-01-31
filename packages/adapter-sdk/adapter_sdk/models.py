"""
M87 Adapter SDK - Pydantic models for proposals and governance.
Mirrors the API schemas for type-safe proposal submission.
"""

from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any, Literal

# Effect tags that can be requested in a proposal
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
    "READ_SECRETS",  # Always denied by policy
]

# Governance decisions
Decision = Literal["ALLOW", "DENY", "REQUIRE_HUMAN", "NEED_MORE_EVIDENCE"]


class TruthAccount(BaseModel):
    """
    Evidence supporting a proposal.
    - observations: What the agent observed (file contents, test results, etc.)
    - claims: Structured assertions with confidence levels
    """
    observations: List[str] = Field(default_factory=list)
    claims: List[Dict[str, Any]] = Field(default_factory=list)


class Proposal(BaseModel):
    """
    A proposal submitted by an agent for governance review.
    """
    proposal_id: str
    intent_id: str
    agent: str
    summary: str
    effects: List[EffectTag]
    artifacts: Optional[List[Dict[str, str]]] = None
    truth_account: TruthAccount
    risk_score: Optional[float] = Field(None, ge=0.0, le=1.0)


class GovernanceDecision(BaseModel):
    """
    Response from the governance engine.
    """
    proposal_id: str
    decision: Decision
    reasons: List[str]
    required_approvals: Optional[List[str]] = None
    allowed_effects: Optional[List[EffectTag]] = None


class AgentProfile(BaseModel):
    """
    Agent profile returned by /v1/agents endpoint.
    """
    name: str
    allowed_effects: List[str]
    max_risk: float
    description: str


class Event(BaseModel):
    """
    Event from the m87:events stream.
    """
    id: str
    type: str
    payload: Dict[str, Any]
