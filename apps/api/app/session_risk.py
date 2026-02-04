"""
SessionRiskTracker: Redis-backed sliding-window cumulative risk tracker.

Phase 3 hardening: Fail-closed when the sensor is blind.
Detects toxic topologies (salami slicing, confused deputy patterns).
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Iterable, Optional, Set, Tuple

import redis

from .governance.effects import EffectTag, parse_effects, EXFIL_ADJACENT_EFFECTS


Decision = str  # "ALLOW" | "REQUIRE_HUMAN" | "DENY"


@dataclass(frozen=True)
class ToxicTopology:
    """
    A toxic topology is a combination of effects that, when seen together
    in a session, indicates potential exfiltration or confused deputy attack.
    """
    name: str
    required: Tuple[EffectTag, ...]
    decision: Decision = "REQUIRE_HUMAN"


# Expanded toxic topologies for comprehensive coverage
TOXIC_TOPOLOGIES: Tuple[ToxicTopology, ...] = (
    # Data exfiltration patterns
    ToxicTopology("repo_read_then_network", (EffectTag.READ_REPO, EffectTag.NETWORK_CALL)),
    ToxicTopology("repo_read_then_notify", (EffectTag.READ_REPO, EffectTag.SEND_NOTIFICATION)),
    ToxicTopology("secrets_then_network", (EffectTag.READ_SECRETS, EffectTag.NETWORK_CALL), "DENY"),
    ToxicTopology("secrets_then_notify", (EffectTag.READ_SECRETS, EffectTag.SEND_NOTIFICATION), "DENY"),
    ToxicTopology("tests_then_network", (EffectTag.RUN_TESTS, EffectTag.NETWORK_CALL)),
    ToxicTopology("artifact_then_network", (EffectTag.BUILD_ARTIFACT, EffectTag.NETWORK_CALL)),

    # Supply chain attack patterns
    ToxicTopology("repo_read_then_pr", (EffectTag.READ_REPO, EffectTag.CREATE_PR)),
    ToxicTopology("write_then_merge", (EffectTag.WRITE_PATCH, EffectTag.MERGE)),
    ToxicTopology("write_then_deploy", (EffectTag.WRITE_PATCH, EffectTag.DEPLOY)),

    # Config exfiltration
    ToxicTopology("config_then_network", (EffectTag.READ_CONFIG, EffectTag.NETWORK_CALL)),
    ToxicTopology("config_then_notify", (EffectTag.READ_CONFIG, EffectTag.SEND_NOTIFICATION)),
)


class SessionRiskTracker:
    """
    Redis-backed sliding-window cumulative risk tracker.
    Fail-closed when the sensor is blind.

    Key invariant: If we can't see history, we escalate exfil-adjacent proposals.
    """

    def __init__(
        self,
        r: redis.Redis,
        window_seconds: int = 300,
        ttl_seconds: int = 1800,
        key_prefix: str = "m87:session_effects:",
    ) -> None:
        self.r = r
        self.window_seconds = int(window_seconds)
        self.ttl_seconds = int(ttl_seconds)
        self.key_prefix = key_prefix

    def _key(self, principal_id: str, agent_name: str) -> str:
        return f"{self.key_prefix}{principal_id}:{agent_name}"

    def get_history(self, principal_id: str, agent_name: str) -> Optional[Set[EffectTag]]:
        """
        Returns:
          - Set[EffectTag] if history available
          - None if Redis unavailable (sensor blind)
        """
        key = self._key(principal_id, agent_name)
        now = int(time.time())
        cutoff = now - self.window_seconds

        try:
            raw_items = self.r.zrangebyscore(key, cutoff, now)
        except Exception:
            return None

        effects: Set[str] = set()
        for item in raw_items:
            try:
                if isinstance(item, bytes):
                    effects.add(item.decode("utf-8"))
                else:
                    effects.add(str(item))
            except Exception:
                continue
        return parse_effects(effects)

    def evaluate(
        self,
        principal_id: str,
        agent_name: str,
        proposed_effects: Iterable[str],
    ) -> Tuple[Decision, str]:
        """
        Evaluate a proposal against session history.

        Returns (decision, reason) tuple.
        """
        proposed = parse_effects(proposed_effects)

        # If Redis is down, we are blind -> fail closed for any exfil-adjacent activity
        history = self.get_history(principal_id, agent_name)
        if history is None:
            # Check if any proposed effect is exfil-adjacent
            if proposed & EXFIL_ADJACENT_EFFECTS:
                return (
                    "REQUIRE_HUMAN",
                    "Risk sensor unavailable (Redis). Escalating exfil-adjacent proposal."
                )
            # Low-risk local compute-only proposals may proceed
            return (
                "ALLOW",
                "Risk sensor unavailable (Redis), but proposal contains no exfil-adjacent effects."
            )

        projected = set(history) | set(proposed)

        # Unknown effect tags become OTHER -> treat as suspicious
        if EffectTag.OTHER in proposed:
            return ("REQUIRE_HUMAN", "Unknown effect tag(s) present; escalating.")

        # Check toxic topologies
        for topo in TOXIC_TOPOLOGIES:
            if all(t in projected for t in topo.required):
                # Only trigger if the topo is newly satisfied by this proposal
                if not all(t in history for t in topo.required):
                    return (topo.decision, f"Toxic topology detected: {topo.name}")

        return ("ALLOW", "No toxic topology detected")

    def commit(self, principal_id: str, agent_name: str, approved_effects: Iterable[str]) -> None:
        """
        Commit approved effects to session history.

        Only call this AFTER a proposal is approved (ALLOW or human override).
        """
        key = self._key(principal_id, agent_name)
        now = int(time.time())
        effects = parse_effects(approved_effects)

        pipe = self.r.pipeline()
        for e in effects:
            pipe.zadd(key, {e.value: now})
        pipe.expire(key, self.ttl_seconds)
        pipe.execute()

    def clear_session(self, principal_id: str, agent_name: str) -> None:
        """Clear session history (for testing or session reset)."""
        key = self._key(principal_id, agent_name)
        self.r.delete(key)
