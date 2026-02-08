"""
v2 Scaffolding — Quarantine Posture (Option C) + Degradation Tiers.

Breaks the Sophist's Choice (FULL-SERVICE vs DENY-ALL) with intermediate
modes that freeze mutations while maintaining non-mutating visibility.

This module provides:
- DegradationTier enum (Tier 0–3)
- QuarantinePosture state machine
- Entry/exit criteria evaluation
- Observability quarantine plumbing (agent metadata → quarantined store)

NOTE: This is scaffolding for v2. No behavior changes in v1 unless
explicitly activated via configuration.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Dict, List, Optional, Set


# ---- Degradation Tiers ----

class DegradationTier(IntEnum):
    """
    Graduated degradation tiers.

    Escalation is automatic based on risk + integrity signals.
    De-escalation is time-gated + operator-confirmed.
    """
    FULL_SERVICE = 0    # Normal operation; risk tracking active
    READ_ONLY = 1       # Allow SAFE_READ on non-restricted resources only
    QUARANTINE = 2      # Freeze mutations + preserve sight
    DENY_ALL = 3        # Block all proposals (safety stop)


# Tier descriptions for operator dashboards
TIER_DESCRIPTIONS: Dict[DegradationTier, str] = {
    DegradationTier.FULL_SERVICE: (
        "Normal operation. All governance rules active. "
        "Risk tracking and topology detection enabled."
    ),
    DegradationTier.READ_ONLY: (
        "Read-only safe band. Allow SAFE_READ on non-restricted resources. "
        "Block all writes/deletes/transmits. Governance decisioning online."
    ),
    DegradationTier.QUARANTINE: (
        "Quarantine mode. Block all mutations and policy changes. "
        "Allow only governance-authored state reports + bounded SAFE_READ. "
        "Independent verification and invariant audit sweeps triggered."
    ),
    DegradationTier.DENY_ALL: (
        "Deny-all safety stop. Block all proposals from reaching runner. "
        "Used when governance throughput compromised or integrity uncertain."
    ),
}


# Effects allowed at each tier
TIER_ALLOWED_EFFECTS: Dict[DegradationTier, Set[str]] = {
    DegradationTier.FULL_SERVICE: set(),  # Empty = all effects governed normally
    DegradationTier.READ_ONLY: {"READ_REPO", "READ_CONFIG", "COMPUTE"},
    DegradationTier.QUARANTINE: {"READ_REPO", "READ_CONFIG"},  # Bounded reads only
    DegradationTier.DENY_ALL: set(),  # Nothing allowed
}


# ---- Quarantine Entry Triggers ----

class QuarantineTrigger:
    """Reasons to enter quarantine."""
    SUSTAINED_ANOMALY = "sustained_anomaly_campaign"
    OBSERVABILITY_POISONING = "observability_poisoning_suspected"
    CROSS_SESSION_UNCERTAINTY = "cross_session_correlation_uncertainty"
    ECONOMIC_COERCION = "economic_coercion_throughput_collapse"
    COMPOSITION_SUSPICION = "emergent_composition_suspicion"
    OPERATOR_MANUAL = "operator_manual_trigger"
    INTEGRITY_SIGNAL = "governance_integrity_signal"


# ---- Quarantine Exit Criteria ----

@dataclass(frozen=True)
class ExitCriteria:
    """Requirements for exiting quarantine."""
    verification_clean: bool = False          # Independent channel confirms consistency
    invariant_audit_clean_intervals: int = 0  # Consecutive clean intervals
    required_clean_intervals: int = 3         # How many clean intervals needed
    operator_confirmed: bool = False          # Human sign-off
    cooldown_elapsed: bool = False            # Time gate passed
    cooldown_seconds: int = 300               # 5-minute default cooldown


# ---- Quarantine State ----

@dataclass
class QuarantineState:
    """
    Current quarantine posture state.

    NOTE: In production, this would be persisted to Redis/Postgres.
    For v2 scaffolding, this is in-memory only.
    """
    current_tier: DegradationTier = DegradationTier.FULL_SERVICE
    entered_at: Optional[float] = None
    trigger: Optional[str] = None
    trigger_details: Optional[Dict[str, Any]] = None

    # Exit tracking
    clean_intervals: int = 0
    last_verification_at: Optional[float] = None
    operator_confirmed_exit: bool = False

    # History
    tier_history: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "current_tier": self.current_tier.value,
            "tier_name": self.current_tier.name,
            "description": TIER_DESCRIPTIONS.get(self.current_tier, ""),
            "entered_at": self.entered_at,
            "trigger": self.trigger,
            "trigger_details": self.trigger_details,
            "clean_intervals": self.clean_intervals,
            "operator_confirmed_exit": self.operator_confirmed_exit,
            "history_length": len(self.tier_history),
        }


# ---- Quarantine Posture Manager ----

class QuarantinePostureManager:
    """
    Manages the quarantine posture state machine.

    Transition rules:
    - Escalation is automatic based on risk + integrity signals
    - De-escalation is time-gated + operator-confirmed
    - Tier transitions are logged to history

    NOTE: v2 scaffolding — behavior is no-op unless explicitly enabled
    via M87_QUARANTINE_ENABLED=1.
    """

    def __init__(self, enabled: bool = False):
        self.enabled = enabled
        self.state = QuarantineState()

    def get_state(self) -> QuarantineState:
        """Get current quarantine state."""
        return self.state

    def is_proposal_allowed(self, effects: List[str]) -> bool:
        """
        Check if a proposal is allowed under current tier.

        Returns True if all effects are allowed at the current tier.
        """
        if not self.enabled:
            return True  # v2 scaffolding: no-op when disabled

        tier = self.state.current_tier

        if tier == DegradationTier.FULL_SERVICE:
            return True  # All effects governed normally

        if tier == DegradationTier.DENY_ALL:
            return False  # Nothing allowed

        # READ_ONLY and QUARANTINE: check allowed effects
        allowed = TIER_ALLOWED_EFFECTS.get(tier, set())
        return all(e in allowed for e in effects)

    def escalate(
        self,
        target_tier: DegradationTier,
        trigger: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Escalate to a higher (more restrictive) tier.

        Escalation is only allowed upward (higher tier number).
        Returns True if escalation was performed.
        """
        if not self.enabled:
            return False

        if target_tier <= self.state.current_tier:
            return False  # Can only escalate upward

        # Record transition
        self.state.tier_history.append({
            "from_tier": self.state.current_tier.value,
            "to_tier": target_tier.value,
            "trigger": trigger,
            "details": details,
            "timestamp": time.time(),
            "direction": "escalate",
        })

        self.state.current_tier = target_tier
        self.state.entered_at = time.time()
        self.state.trigger = trigger
        self.state.trigger_details = details
        self.state.clean_intervals = 0
        self.state.operator_confirmed_exit = False

        return True

    def try_deescalate(
        self,
        target_tier: DegradationTier,
        operator_confirmed: bool = False,
    ) -> bool:
        """
        Attempt to de-escalate to a lower (less restrictive) tier.

        De-escalation requires:
        1. Target tier is lower than current
        2. Sufficient clean intervals
        3. Cooldown period elapsed
        4. Operator confirmation (for QUARANTINE → lower)

        Returns True if de-escalation was performed.
        """
        if not self.enabled:
            return False

        if target_tier >= self.state.current_tier:
            return False  # Can only de-escalate downward

        # Check cooldown
        if self.state.entered_at:
            elapsed = time.time() - self.state.entered_at
            if elapsed < ExitCriteria().cooldown_seconds:
                return False  # Cooldown not elapsed

        # Check clean intervals
        criteria = ExitCriteria()
        if self.state.clean_intervals < criteria.required_clean_intervals:
            return False

        # Quarantine exit requires operator confirmation
        if self.state.current_tier >= DegradationTier.QUARANTINE:
            if not operator_confirmed:
                return False

        # Record transition
        self.state.tier_history.append({
            "from_tier": self.state.current_tier.value,
            "to_tier": target_tier.value,
            "trigger": "de-escalation",
            "details": {
                "operator_confirmed": operator_confirmed,
                "clean_intervals": self.state.clean_intervals,
            },
            "timestamp": time.time(),
            "direction": "de-escalate",
        })

        self.state.current_tier = target_tier
        self.state.entered_at = time.time()
        self.state.trigger = None
        self.state.clean_intervals = 0

        return True

    def record_clean_interval(self) -> None:
        """Record a clean invariant audit interval."""
        self.state.clean_intervals += 1
        self.state.last_verification_at = time.time()


# ---- Observability Quarantine ----

@dataclass
class ObservabilityQuarantineStore:
    """
    v2 Scaffolding: Quarantined store for agent-supplied metadata.

    Agent-supplied metadata is NOT trusted for governance decisions.
    It is stored separately from governance-authored telemetry and
    made available only for offline triage.

    In production, this would be a separate database/stream.
    For v2 scaffolding, this is in-memory only.
    """
    entries: List[Dict[str, Any]] = field(default_factory=list)
    max_entries: int = 10_000

    def store(self, agent_id: str, metadata: Dict[str, Any]) -> None:
        """Store agent-supplied metadata in quarantined store."""
        entry = {
            "agent_id": agent_id,
            "metadata": metadata,
            "received_at": time.time(),
            "quarantined": True,
            "trust_level": "untrusted",
        }
        self.entries.append(entry)

        # Cap size to prevent memory exhaustion
        if len(self.entries) > self.max_entries:
            self.entries = self.entries[-self.max_entries:]

    def get_entries(
        self,
        agent_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Get quarantined entries, optionally filtered by agent_id."""
        filtered = self.entries
        if agent_id:
            filtered = [e for e in filtered if e["agent_id"] == agent_id]
        return filtered[-limit:]

    def clear(self) -> int:
        """Clear all entries. Returns count of cleared entries."""
        count = len(self.entries)
        self.entries.clear()
        return count


# ---- Global instances (v2 scaffolding, no-op by default) ----

import os as _os

_quarantine_enabled = _os.environ.get("M87_QUARANTINE_ENABLED", "0") == "1"

quarantine_manager = QuarantinePostureManager(enabled=_quarantine_enabled)
observability_quarantine = ObservabilityQuarantineStore()
