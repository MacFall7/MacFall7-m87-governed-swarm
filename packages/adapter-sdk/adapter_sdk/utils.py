"""
M87 Adapter SDK - Utility functions for adapters.
"""

import uuid
from typing import List, Dict, Any, Set, Optional
from .models import TruthAccount, Proposal, EffectTag


# Known agent effect scopes (client-side hints; server is authoritative)
AGENT_EFFECT_SCOPES: Dict[str, Set[str]] = {
    "Casey": {"READ_REPO", "WRITE_PATCH", "RUN_TESTS"},
    "Jordan": {"SEND_NOTIFICATION", "BUILD_ARTIFACT", "CREATE_PR", "READ_REPO"},
    "Riley": {"READ_REPO", "BUILD_ARTIFACT", "SEND_NOTIFICATION"},
    "Human": {
        "READ_REPO", "WRITE_PATCH", "RUN_TESTS", "BUILD_ARTIFACT",
        "NETWORK_CALL", "SEND_NOTIFICATION", "CREATE_PR", "MERGE", "DEPLOY"
    },
}

AGENT_MAX_RISK: Dict[str, float] = {
    "Casey": 0.6,
    "Jordan": 0.5,
    "Riley": 0.4,
    "Human": 1.0,
}

DEFAULT_ALLOWED_EFFECTS: Set[str] = {"READ_REPO"}
DEFAULT_MAX_RISK: float = 0.3


def generate_proposal_id(prefix: str = "p") -> str:
    """Generate a unique proposal ID."""
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


def generate_intent_id(prefix: str = "i") -> str:
    """Generate a unique intent ID."""
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


def format_truth_account(
    observations: List[str],
    claims: Optional[List[Dict[str, Any]]] = None,
) -> TruthAccount:
    """
    Format observations and claims into a TruthAccount.

    Args:
        observations: List of observed facts (e.g., file contents, test output)
        claims: List of structured claims with confidence levels

    Returns:
        TruthAccount object ready for proposal submission

    Example:
        truth = format_truth_account(
            observations=["tests/test_auth.py has 3 failing tests"],
            claims=[
                {"claim": "Auth module needs fix", "confidence": 0.8},
                {"claim": "Fix is low risk", "confidence": 0.6},
            ]
        )
    """
    return TruthAccount(
        observations=observations,
        claims=claims or [],
    )


def effect_budget_check(
    agent: str,
    effects: List[str],
) -> tuple[bool, Set[str]]:
    """
    Client-side check if agent is allowed to propose these effects.
    NOTE: Server is authoritative. This is just a local hint to catch issues early.

    Args:
        agent: Agent name (Casey, Jordan, Riley, Human)
        effects: List of effect tags being requested

    Returns:
        Tuple of (all_allowed, disallowed_effects)

    Example:
        allowed, denied = effect_budget_check("Casey", ["READ_REPO", "DEPLOY"])
        if not allowed:
            print(f"Cannot propose: {denied}")
    """
    allowed = AGENT_EFFECT_SCOPES.get(agent, DEFAULT_ALLOWED_EFFECTS)
    requested = set(effects)
    disallowed = requested - allowed
    return len(disallowed) == 0, disallowed


def risk_budget_check(
    agent: str,
    risk_score: Optional[float],
) -> tuple[bool, float]:
    """
    Client-side check if risk is within agent's threshold.
    NOTE: Server is authoritative. This is just a local hint.

    Args:
        agent: Agent name
        risk_score: Proposed risk score (0.0 to 1.0)

    Returns:
        Tuple of (within_threshold, max_allowed)
    """
    max_risk = AGENT_MAX_RISK.get(agent, DEFAULT_MAX_RISK)
    if risk_score is None:
        return True, max_risk
    return risk_score <= max_risk, max_risk


def build_proposal(
    agent: str,
    summary: str,
    effects: List[EffectTag],
    observations: List[str],
    claims: Optional[List[Dict[str, Any]]] = None,
    intent_id: Optional[str] = None,
    risk_score: Optional[float] = None,
    artifacts: Optional[List[Dict[str, str]]] = None,
) -> Proposal:
    """
    Build a complete Proposal object with generated IDs.

    Args:
        agent: Agent name submitting the proposal
        summary: Human-readable summary of the proposed action
        effects: List of effect tags being requested
        observations: List of observed facts supporting the proposal
        claims: Optional list of claims with confidence levels
        intent_id: Optional intent ID (generated if not provided)
        risk_score: Optional risk score (0.0 to 1.0)
        artifacts: Optional list of artifacts (patches, configs, etc.)

    Returns:
        Proposal object ready for submission

    Example:
        proposal = build_proposal(
            agent="Casey",
            summary="Fix authentication bug in login handler",
            effects=["READ_REPO", "WRITE_PATCH", "RUN_TESTS"],
            observations=[
                "login.py:45 has uncaught exception",
                "tests/test_login.py fails on line 23",
            ],
            risk_score=0.3,
        )
    """
    return Proposal(
        proposal_id=generate_proposal_id(),
        intent_id=intent_id or generate_intent_id(),
        agent=agent,
        summary=summary,
        effects=effects,
        truth_account=format_truth_account(observations, claims),
        risk_score=risk_score,
        artifacts=artifacts,
    )


def should_submit(
    agent: str,
    effects: List[str],
    risk_score: Optional[float] = None,
) -> tuple[bool, List[str]]:
    """
    Pre-flight check before submitting a proposal.
    Combines effect and risk budget checks.

    Args:
        agent: Agent name
        effects: Effects being requested
        risk_score: Optional risk score

    Returns:
        Tuple of (should_submit, list_of_warnings)

    Example:
        ok, warnings = should_submit("Casey", ["DEPLOY"], risk_score=0.9)
        if not ok:
            print("\\n".join(warnings))
    """
    warnings = []

    effects_ok, disallowed = effect_budget_check(agent, effects)
    if not effects_ok:
        warnings.append(f"Effects outside scope: {sorted(disallowed)}")

    risk_ok, max_risk = risk_budget_check(agent, risk_score)
    if not risk_ok:
        warnings.append(f"Risk {risk_score} exceeds max {max_risk}")

    # READ_SECRETS is always denied
    if "READ_SECRETS" in effects:
        warnings.append("READ_SECRETS is always denied by policy")

    return len(warnings) == 0, warnings
