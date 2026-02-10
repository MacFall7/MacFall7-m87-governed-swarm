"""
Canonical EffectTag taxonomy for M87 governance.

All tool behavior must be declared using these tags.
Unknown effects are mapped to OTHER and treated as suspicious.

EFFECT_SCHEMA_VERSION is stamped into every governance decision and job spec.
The runner rejects jobs whose effect_schema_version doesn't match its own,
preventing silent taxonomy drift between API and runner deployments.
"""
from __future__ import annotations

from enum import Enum
from typing import Iterable, Set

# Bump this when adding, removing, or renaming any EffectTag.
# Runner and API must agree on this version; mismatches are fatal.
EFFECT_SCHEMA_VERSION = "1.0.0"


class EffectTag(str, Enum):
    """Canonical effect tags for M87 governance."""
    READ_REPO = "READ_REPO"
    READ_SECRETS = "READ_SECRETS"
    READ_CONFIG = "READ_CONFIG"
    COMPUTE = "COMPUTE"
    WRITE_PATCH = "WRITE_PATCH"
    RUN_TESTS = "RUN_TESTS"
    BUILD_ARTIFACT = "BUILD_ARTIFACT"
    CREATE_PR = "CREATE_PR"
    MERGE = "MERGE"
    DEPLOY = "DEPLOY"
    NETWORK_CALL = "NETWORK_CALL"
    SEND_NOTIFICATION = "SEND_NOTIFICATION"
    OTHER = "OTHER"


# Effects that can exfiltrate data (require special scrutiny)
EXFIL_ADJACENT_EFFECTS: Set[EffectTag] = {
    EffectTag.NETWORK_CALL,
    EffectTag.SEND_NOTIFICATION,
    EffectTag.CREATE_PR,
    EffectTag.MERGE,
    EffectTag.DEPLOY,
    EffectTag.READ_SECRETS,
}

# Effects that are read-only and low-risk
READ_ONLY_EFFECTS: Set[EffectTag] = {
    EffectTag.READ_REPO,
    EffectTag.READ_CONFIG,
    EffectTag.COMPUTE,
}


def parse_effects(raw: Iterable[str]) -> Set[EffectTag]:
    """
    Parse raw effect strings into canonical EffectTags.

    Unknown effects are mapped to OTHER (inherently suspicious).
    This ensures no unknown effect can bypass governance silently.
    """
    out: Set[EffectTag] = set()
    for x in raw:
        try:
            out.add(EffectTag(str(x)))
        except ValueError:
            # Unknown effects are inherently suspicious
            out.add(EffectTag.OTHER)
    return out


def is_exfil_adjacent(effects: Iterable[EffectTag]) -> bool:
    """Check if any effect is exfil-adjacent (can leak data)."""
    return bool(set(effects) & EXFIL_ADJACENT_EFFECTS)


def is_read_only(effects: Iterable[EffectTag]) -> bool:
    """Check if all effects are read-only."""
    return set(effects).issubset(READ_ONLY_EFFECTS)
