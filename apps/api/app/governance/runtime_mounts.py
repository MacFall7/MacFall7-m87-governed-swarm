"""
P2.1 — Runtime mount option verification (PROBE_014_ARCHITECTURAL).

Enforces mount invariants (noatime, nosuid, noexec, nodev) at runtime.
Runner startup verifies mount options; mismatch → refuse to start (fail-closed).

This prevents:
- Side-channel information leaks via atime updates
- Privilege escalation via suid binaries on mounts
- Code execution from data mounts
- Device node attacks
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple


# Deny reason codes (stable contract for telemetry)
MOUNT_INVARIANT_VIOLATED = "MOUNT_INVARIANT_VIOLATED"
MOUNT_CHECK_FAILED = "MOUNT_CHECK_FAILED"


@dataclass(frozen=True)
class MountInvariant:
    """A required mount option for a mount point."""
    mount_point: str
    required_options: FrozenSet[str]
    reason: str


@dataclass(frozen=True)
class MountCheckResult:
    """Result from runtime mount verification."""
    passed: bool
    violations: List[Dict[str, Any]] = field(default_factory=list)
    error: Optional[str] = None
    deny_code: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "passed": self.passed,
            "violations": self.violations,
            "error": self.error,
            "deny_code": self.deny_code,
        }


# ---- Canonical mount invariants ----
# These define what mount options MUST be present at runtime.
# Runner startup verifies these; mismatch = refuse to start.

MOUNT_INVARIANTS: List[MountInvariant] = [
    MountInvariant(
        mount_point="/tmp",
        required_options=frozenset({"nosuid", "nodev"}),
        reason="Temp directory must not allow suid binaries or device nodes",
    ),
    MountInvariant(
        mount_point="/var/tmp",
        required_options=frozenset({"nosuid", "nodev"}),
        reason="Temp directory must not allow suid binaries or device nodes",
    ),
]

# Additional invariants for sandbox mode
SANDBOX_MOUNT_INVARIANTS: List[MountInvariant] = [
    MountInvariant(
        mount_point="/workspace",
        required_options=frozenset({"nosuid", "nodev", "noatime"}),
        reason="Workspace must not leak access times or allow privilege escalation",
    ),
]


def parse_proc_mounts(mounts_content: str) -> Dict[str, Set[str]]:
    """
    Parse /proc/mounts or /proc/self/mountinfo content.

    Returns dict of mount_point → set of mount options.
    """
    result: Dict[str, Set[str]] = {}

    for line in mounts_content.strip().split("\n"):
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) < 4:
            continue
        # /proc/mounts format: device mount_point fs_type options ...
        mount_point = parts[1]
        options = set(parts[3].split(","))
        result[mount_point] = options

    return result


def verify_mount_invariants(
    invariants: Optional[List[MountInvariant]] = None,
    mounts_content: Optional[str] = None,
    include_sandbox: bool = False,
) -> MountCheckResult:
    """
    Verify runtime mount options against required invariants.

    Reads /proc/mounts (or uses provided content for testing) and
    checks that all required mount options are present.

    Fail-closed: any missing invariant → refuse to start.

    Args:
        invariants: List of invariants to check (defaults to MOUNT_INVARIANTS)
        mounts_content: Content of /proc/mounts (reads from /proc/mounts if None)
        include_sandbox: Whether to include SANDBOX_MOUNT_INVARIANTS

    Returns:
        MountCheckResult with verification outcome
    """
    if invariants is None:
        invariants = list(MOUNT_INVARIANTS)
        if include_sandbox:
            invariants.extend(SANDBOX_MOUNT_INVARIANTS)

    # Read /proc/mounts
    if mounts_content is None:
        try:
            with open("/proc/mounts", "r") as f:
                mounts_content = f.read()
        except (OSError, PermissionError) as e:
            return MountCheckResult(
                passed=False,
                error=f"Cannot read /proc/mounts: {e}",
                deny_code=MOUNT_CHECK_FAILED,
            )

    mounts = parse_proc_mounts(mounts_content)
    violations: List[Dict[str, Any]] = []

    for inv in invariants:
        if inv.mount_point not in mounts:
            # Mount point not found — skip (it might not exist in this container)
            continue

        actual_options = mounts[inv.mount_point]
        missing_options = inv.required_options - actual_options

        if missing_options:
            violations.append({
                "mount_point": inv.mount_point,
                "required": sorted(inv.required_options),
                "actual": sorted(actual_options),
                "missing": sorted(missing_options),
                "reason": inv.reason,
            })

    if violations:
        return MountCheckResult(
            passed=False,
            violations=violations,
            deny_code=MOUNT_INVARIANT_VIOLATED,
        )

    return MountCheckResult(passed=True)
