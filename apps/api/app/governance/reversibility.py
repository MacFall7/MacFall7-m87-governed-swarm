"""
Reversibility Gate: first-class governance invariant for M87.

Enforces that non-read actions must declare reversibility class and (when required)
rollback proof. Irreversible actions never reach the runner without human approval.

Gate policy:
- READ-ONLY actions: bypass gate
- REVERSIBLE without rollback_proof: reject, downgrade to proposal
- PARTIALLY_REVERSIBLE without rollback_proof: allow only draft/preview mode
- IRREVERSIBLE without human approval: reject, require approval
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Set

from .effects import EffectTag, parse_effects, READ_ONLY_EFFECTS


class ReversibilityClass(str, Enum):
    """
    Reversibility classification for actions.

    REVERSIBLE: Full rollback exists and is automatable.
    PARTIALLY_REVERSIBLE: Rollback exists but is incomplete, lossy, or requires manual steps.
    IRREVERSIBLE: Rollback is not feasible (e.g., sending email, external notifications).
    """
    REVERSIBLE = "REVERSIBLE"
    PARTIALLY_REVERSIBLE = "PARTIALLY_REVERSIBLE"
    IRREVERSIBLE = "IRREVERSIBLE"


class CleanupCost(str, Enum):
    """
    V2 Upgrade: Cleanup cost classification for failed actions.

    Determines how expensive it is to recover from a failed action attempt.
    Affects autonomy budget allocation and retry policies.

    LOW: Cleanup is cheap/free (e.g., delete temp files, revert local changes).
         Autonomy: unlimited retries, full budget.
    MEDIUM: Cleanup has moderate cost (e.g., unpublish artifact, close PR).
         Autonomy: limited retries (3), reduced budget multiplier (0.8).
    HIGH: Cleanup is expensive/risky (e.g., database migration rollback, revoke deployment).
         Autonomy: single attempt (1), minimal budget multiplier (0.5).
    """
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


# Cleanup cost budget multipliers (affects max_steps, max_tool_calls)
CLEANUP_COST_BUDGET_MULTIPLIERS = {
    CleanupCost.LOW: 1.0,
    CleanupCost.MEDIUM: 0.8,
    CleanupCost.HIGH: 0.5,
}

# Cleanup cost retry limits
CLEANUP_COST_RETRY_LIMITS = {
    CleanupCost.LOW: None,  # Unlimited
    CleanupCost.MEDIUM: 3,
    CleanupCost.HIGH: 1,
}


class ExecutionMode(str, Enum):
    """Execution mode for actions."""
    COMMIT = "commit"       # Full execution with side effects
    DRAFT = "draft"         # Preview/dry-run, no side effects
    PREVIEW = "preview"     # Alias for draft


@dataclass(frozen=True)
class RollbackProof:
    """
    Structured evidence describing rollback steps or automated rollback procedure.

    Required for REVERSIBLE actions. Optional for PARTIALLY_REVERSIBLE.
    """
    description: str
    rollback_tool: Optional[str] = None  # Tool that can perform rollback
    rollback_args: Optional[Dict[str, Any]] = None  # Arguments for rollback tool
    manual_steps: Optional[List[str]] = None  # Manual steps if not fully automated

    @classmethod
    def from_dict(cls, data: Optional[Dict[str, Any]]) -> Optional["RollbackProof"]:
        """Parse RollbackProof from dict."""
        if not data:
            return None
        return cls(
            description=data.get("description", ""),
            rollback_tool=data.get("rollback_tool"),
            rollback_args=data.get("rollback_args"),
            manual_steps=data.get("manual_steps"),
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dict for serialization."""
        out = {"description": self.description}
        if self.rollback_tool:
            out["rollback_tool"] = self.rollback_tool
        if self.rollback_args:
            out["rollback_args"] = self.rollback_args
        if self.manual_steps:
            out["manual_steps"] = self.manual_steps
        return out


@dataclass(frozen=True)
class ReversibilityGateResult:
    """Result from reversibility gate evaluation."""
    allowed: bool
    reason: str
    safe_alternative: Optional[str] = None  # "draft", "preview", "approval_required"
    downgrade_to_proposal: bool = False
    # V2: Cleanup cost budget adjustments
    budget_multiplier: float = 1.0
    retry_limit: Optional[int] = None  # None = unlimited

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dict for responses."""
        out = {
            "allowed": self.allowed,
            "reason": self.reason,
        }
        if self.safe_alternative:
            out["safe_alternative"] = self.safe_alternative
        if self.downgrade_to_proposal:
            out["downgrade_to_proposal"] = self.downgrade_to_proposal
        if self.budget_multiplier != 1.0:
            out["budget_multiplier"] = self.budget_multiplier
        if self.retry_limit is not None:
            out["retry_limit"] = self.retry_limit
        return out


def is_read_only_action(effects: List[str]) -> bool:
    """Check if action is read-only based on effects."""
    parsed = parse_effects(effects)
    return parsed.issubset(READ_ONLY_EFFECTS)


def evaluate_reversibility_gate(
    effects: List[str],
    reversibility_class: Optional[str],
    rollback_proof: Optional[Dict[str, Any]],
    execution_mode: str = "commit",
    human_approved: bool = False,
    cleanup_cost: Optional[str] = None,
) -> ReversibilityGateResult:
    """
    Evaluate action against the Reversibility Gate.

    Gate policy:
    1. READ-ONLY actions bypass the gate.
    2. Missing reversibility_class → reject, downgrade to proposal.
    3. REVERSIBLE without rollback_proof → reject, downgrade to proposal.
    4. PARTIALLY_REVERSIBLE without rollback_proof → allow only draft/preview.
    5. IRREVERSIBLE without human approval → reject, require approval.

    V2 Extension: cleanup_cost affects budget allocation
    - LOW: full budget, unlimited retries
    - MEDIUM: 80% budget, 3 retries
    - HIGH: 50% budget, 1 attempt

    Args:
        effects: List of effect tags for the action
        reversibility_class: Declared reversibility class
        rollback_proof: Rollback proof dict (if any)
        execution_mode: "commit", "draft", or "preview"
        human_approved: Whether human has explicitly approved
        cleanup_cost: Optional cleanup cost classification (LOW/MEDIUM/HIGH)

    Returns:
        ReversibilityGateResult with decision, reasoning, and budget adjustments
    """
    # Parse cleanup_cost for budget adjustments
    budget_multiplier = 1.0
    retry_limit = None
    if cleanup_cost:
        try:
            cost = CleanupCost(cleanup_cost)
            budget_multiplier = CLEANUP_COST_BUDGET_MULTIPLIERS.get(cost, 1.0)
            retry_limit = CLEANUP_COST_RETRY_LIMITS.get(cost)
        except ValueError:
            # Unknown cleanup_cost defaults to conservative (MEDIUM)
            budget_multiplier = CLEANUP_COST_BUDGET_MULTIPLIERS[CleanupCost.MEDIUM]
            retry_limit = CLEANUP_COST_RETRY_LIMITS[CleanupCost.MEDIUM]
    # Rule 1: Read-only actions bypass the gate
    if is_read_only_action(effects):
        return ReversibilityGateResult(
            allowed=True,
            reason="Read-only action; reversibility gate bypassed."
        )

    # Rule 2: Missing reversibility_class → reject
    if not reversibility_class:
        return ReversibilityGateResult(
            allowed=False,
            reason="Non-read action missing reversibility_class declaration.",
            safe_alternative="proposal",
            downgrade_to_proposal=True,
        )

    # Parse class
    try:
        rev_class = ReversibilityClass(reversibility_class)
    except ValueError:
        return ReversibilityGateResult(
            allowed=False,
            reason=f"Invalid reversibility_class: {reversibility_class}",
            safe_alternative="proposal",
            downgrade_to_proposal=True,
        )

    # Parse mode
    mode = execution_mode.lower() if execution_mode else "commit"
    is_commit = mode == "commit"

    # Rule 3: REVERSIBLE requires rollback_proof
    if rev_class == ReversibilityClass.REVERSIBLE:
        if not rollback_proof:
            return ReversibilityGateResult(
                allowed=False,
                reason="REVERSIBLE action requires rollback_proof.",
                safe_alternative="proposal",
                downgrade_to_proposal=True,
            )
        # Has rollback proof - allowed with budget adjustments
        return ReversibilityGateResult(
            allowed=True,
            reason="REVERSIBLE action with valid rollback_proof.",
            budget_multiplier=budget_multiplier,
            retry_limit=retry_limit,
        )

    # Rule 4: PARTIALLY_REVERSIBLE without rollback_proof → only draft/preview
    if rev_class == ReversibilityClass.PARTIALLY_REVERSIBLE:
        if not rollback_proof and is_commit:
            return ReversibilityGateResult(
                allowed=False,
                reason="PARTIALLY_REVERSIBLE commit requires rollback_proof.",
                safe_alternative="draft",
                downgrade_to_proposal=True,
            )
        # Either has proof, or is draft/preview mode - with budget adjustments
        return ReversibilityGateResult(
            allowed=True,
            reason=f"PARTIALLY_REVERSIBLE action allowed in {mode} mode.",
            budget_multiplier=budget_multiplier,
            retry_limit=retry_limit,
        )

    # Rule 5: IRREVERSIBLE requires human approval
    if rev_class == ReversibilityClass.IRREVERSIBLE:
        if not human_approved:
            return ReversibilityGateResult(
                allowed=False,
                reason="IRREVERSIBLE action requires explicit human approval.",
                safe_alternative="approval_required",
                downgrade_to_proposal=True,
            )
        # Human approved - allowed with budget adjustments
        return ReversibilityGateResult(
            allowed=True,
            reason="IRREVERSIBLE action approved by human.",
            budget_multiplier=budget_multiplier,
            retry_limit=retry_limit,
        )

    # Fallback - should not reach here
    return ReversibilityGateResult(
        allowed=False,
        reason="Unknown reversibility_class state.",
        downgrade_to_proposal=True,
    )


def create_downgrade_response(
    original_action: Dict[str, Any],
    gate_result: ReversibilityGateResult,
) -> Dict[str, Any]:
    """
    Create a structured downgrade response when the gate blocks execution.

    Returns the original action intent with reversibility context for review.
    """
    return {
        "status": "blocked_by_reversibility_gate",
        "original_action": {
            "effects": original_action.get("effects", []),
            "summary": original_action.get("summary", ""),
            "reversibility_class": original_action.get("reversibility_class"),
            "execution_mode": original_action.get("execution_mode", "commit"),
        },
        "reversibility_gate": gate_result.to_dict(),
        "risk": "Action blocked due to reversibility policy violation.",
        "safe_alternative": gate_result.safe_alternative,
        "next_steps": _get_next_steps(gate_result),
    }


def _get_next_steps(gate_result: ReversibilityGateResult) -> List[str]:
    """Get actionable next steps based on gate result."""
    if gate_result.safe_alternative == "proposal":
        return [
            "Add reversibility_class declaration to the action.",
            "If REVERSIBLE, provide rollback_proof with rollback steps.",
        ]
    if gate_result.safe_alternative == "draft":
        return [
            "Provide rollback_proof for commit mode execution.",
            "Or execute in draft/preview mode for safe exploration.",
        ]
    if gate_result.safe_alternative == "approval_required":
        return [
            "Submit for human approval via governance channel.",
            "Include justification for the irreversible action.",
        ]
    return []
