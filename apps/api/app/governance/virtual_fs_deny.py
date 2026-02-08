"""
P0.2 — Explicit virtual FS deny policies (PROBE_015_SYSTEMIC).

Replaces inherited RESTRICTED with explicit DENY for virtual mounts.
Prevents access to /dev/shm, /sys, /run, /dev/pts, /dev/mqueue, /proc
(with a narrow allowlist for /proc).

Resource manifest contains explicit entries; unit tests ensure future
"allowlist insertions" cannot implicitly relax these mounts.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, FrozenSet, List, Optional, Set


class VirtualFSPolicy(str, Enum):
    """Policy for virtual filesystem paths."""
    DENY = "DENY"               # Explicitly blocked, no exceptions
    ALLOWLIST = "ALLOWLIST"     # Allowed only for specific sub-paths
    ALLOW = "ALLOW"             # Fully allowed (only for safe paths)


# Deny reason codes (stable contract for telemetry)
VIRTUAL_FS_DENIED = "VIRTUAL_FS_DENIED"
VIRTUAL_FS_NOT_IN_ALLOWLIST = "VIRTUAL_FS_NOT_IN_ALLOWLIST"


@dataclass(frozen=True)
class VirtualFSRule:
    """A single virtual FS deny/allow rule."""
    mount_point: str
    policy: VirtualFSPolicy
    reason: str
    # Only used when policy == ALLOWLIST
    allowed_sub_paths: FrozenSet[str] = field(default_factory=frozenset)


@dataclass(frozen=True)
class VirtualFSCheckResult:
    """Result from checking a path against virtual FS policies."""
    allowed: bool
    path: str
    matched_rule: Optional[str] = None  # mount_point of matched rule
    deny_reason: Optional[str] = None
    deny_code: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "allowed": self.allowed,
            "path": self.path,
            "matched_rule": self.matched_rule,
            "deny_reason": self.deny_reason,
            "deny_code": self.deny_code,
        }


# ---- Canonical virtual FS deny rules ----
# These are explicit DENY entries in the resource manifest.
# Future "allowlist insertions" require modifying VIRTUAL_FS_RULES
# and adding corresponding tests.

VIRTUAL_FS_RULES: List[VirtualFSRule] = [
    VirtualFSRule(
        mount_point="/dev/shm",
        policy=VirtualFSPolicy.DENY,
        reason="Shared memory: cross-container IPC channel, potential covert exfiltration",
    ),
    VirtualFSRule(
        mount_point="/sys",
        policy=VirtualFSPolicy.DENY,
        reason="Sysfs: kernel parameter exposure, hardware enumeration, cgroup escape vector",
    ),
    VirtualFSRule(
        mount_point="/run",
        policy=VirtualFSPolicy.DENY,
        reason="Runtime data: socket access, PID files, potential privilege escalation",
    ),
    VirtualFSRule(
        mount_point="/dev/pts",
        policy=VirtualFSPolicy.DENY,
        reason="Pseudo-terminal devices: TTY hijacking, session injection",
    ),
    VirtualFSRule(
        mount_point="/dev/mqueue",
        policy=VirtualFSPolicy.DENY,
        reason="POSIX message queues: cross-process IPC, covert channel",
    ),
    VirtualFSRule(
        mount_point="/proc",
        policy=VirtualFSPolicy.ALLOWLIST,
        reason="Procfs: process info exposure, but /proc/self/status needed for resource monitoring",
        allowed_sub_paths=frozenset({
            "/proc/self/status",
            "/proc/self/limits",
            "/proc/self/cgroup",
            "/proc/version",
            "/proc/cpuinfo",
            "/proc/meminfo",
            "/proc/loadavg",
        }),
    ),
]


def _normalize_path(path: str) -> str:
    """Normalize path for comparison (remove trailing slash, resolve ..)."""
    import os.path
    # Don't use realpath here — we want to check the logical path,
    # not follow symlinks (that's glob_validation's job)
    return os.path.normpath(path)


def check_virtual_fs_access(path: str) -> VirtualFSCheckResult:
    """
    Check whether a path is allowed under virtual FS deny policies.

    Fail-closed: if a path matches a DENY rule, it is always denied.
    For ALLOWLIST rules, only explicitly listed sub-paths are allowed.

    Args:
        path: The filesystem path to check

    Returns:
        VirtualFSCheckResult with the access decision
    """
    normalized = _normalize_path(path)

    for rule in VIRTUAL_FS_RULES:
        rule_mount = _normalize_path(rule.mount_point)

        # Check if path is under this mount point
        if normalized == rule_mount or normalized.startswith(rule_mount + "/"):
            if rule.policy == VirtualFSPolicy.DENY:
                return VirtualFSCheckResult(
                    allowed=False,
                    path=path,
                    matched_rule=rule.mount_point,
                    deny_reason=rule.reason,
                    deny_code=VIRTUAL_FS_DENIED,
                )

            if rule.policy == VirtualFSPolicy.ALLOWLIST:
                # Check if the specific path is in the allowlist
                if normalized in {_normalize_path(p) for p in rule.allowed_sub_paths}:
                    return VirtualFSCheckResult(
                        allowed=True,
                        path=path,
                        matched_rule=rule.mount_point,
                    )
                return VirtualFSCheckResult(
                    allowed=False,
                    path=path,
                    matched_rule=rule.mount_point,
                    deny_reason=(
                        f"Path {path} under {rule.mount_point} is not in allowlist. "
                        f"{rule.reason}"
                    ),
                    deny_code=VIRTUAL_FS_NOT_IN_ALLOWLIST,
                )

    # Path doesn't match any virtual FS rule — allowed
    return VirtualFSCheckResult(
        allowed=True,
        path=path,
    )


def check_paths_batch(paths: List[str]) -> List[VirtualFSCheckResult]:
    """
    Check multiple paths against virtual FS policies.

    Returns results for all paths; caller should deny if ANY result
    has allowed=False.
    """
    return [check_virtual_fs_access(p) for p in paths]


def get_resource_manifest_entries() -> List[Dict[str, Any]]:
    """
    Return the virtual FS rules in resource manifest format.

    This is the canonical source of truth for virtual FS policies.
    Used by CI tests to verify no implicit relaxation occurs.
    """
    entries = []
    for rule in VIRTUAL_FS_RULES:
        entry = {
            "mount_point": rule.mount_point,
            "policy": rule.policy.value,
            "reason": rule.reason,
        }
        if rule.policy == VirtualFSPolicy.ALLOWLIST:
            entry["allowed_sub_paths"] = sorted(rule.allowed_sub_paths)
        entries.append(entry)
    return entries
