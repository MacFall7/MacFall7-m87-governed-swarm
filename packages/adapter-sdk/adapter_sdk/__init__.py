"""
M87 Adapter SDK

Shared utilities for building agent adapters that submit proposals
to the M87 Governance API.

Example usage:

    from adapter_sdk import M87Client, build_proposal, should_submit

    # Pre-flight check
    ok, warnings = should_submit("Casey", ["READ_REPO", "WRITE_PATCH"])
    if not ok:
        print(f"Warnings: {warnings}")

    # Build proposal
    proposal = build_proposal(
        agent="Casey",
        summary="Fix bug in auth module",
        effects=["READ_REPO", "WRITE_PATCH", "RUN_TESTS"],
        observations=["auth.py:45 has null check missing"],
        risk_score=0.3,
    )

    # Submit for governance
    with M87Client("http://localhost:8000") as client:
        decision = client.submit_proposal(proposal)
        print(f"Decision: {decision.decision}")
"""

from .models import (
    EffectTag,
    Decision,
    TruthAccount,
    Proposal,
    GovernanceDecision,
    AgentProfile,
    Event,
)

from .client import (
    M87Client,
    submit_proposal,
    poll_events,
)

from .utils import (
    generate_proposal_id,
    generate_intent_id,
    format_truth_account,
    effect_budget_check,
    risk_budget_check,
    build_proposal,
    should_submit,
    AGENT_EFFECT_SCOPES,
    AGENT_MAX_RISK,
)

__version__ = "0.1.0"
__all__ = [
    # Models
    "EffectTag",
    "Decision",
    "TruthAccount",
    "Proposal",
    "GovernanceDecision",
    "AgentProfile",
    "Event",
    # Client
    "M87Client",
    "submit_proposal",
    "poll_events",
    # Utils
    "generate_proposal_id",
    "generate_intent_id",
    "format_truth_account",
    "effect_budget_check",
    "risk_budget_check",
    "build_proposal",
    "should_submit",
    "AGENT_EFFECT_SCOPES",
    "AGENT_MAX_RISK",
]
