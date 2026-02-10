"""
P2.2 — Enumeration limits for recursive writes (PROBE_010_NOTE).

Prevents governance CPU exhaustion on `cp -r` pre-walk by enforcing
hard caps: max nodes, max depth, max time.

If any limit is exceeded, the operation is denied with
UNBOUNDED_ENUMERATION reason code.
"""
from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional


# Deny reason codes (stable contract for telemetry)
UNBOUNDED_ENUMERATION = "UNBOUNDED_ENUMERATION"
ENUMERATION_DEPTH_EXCEEDED = "ENUMERATION_DEPTH_EXCEEDED"
ENUMERATION_NODE_LIMIT_EXCEEDED = "ENUMERATION_NODE_LIMIT_EXCEEDED"
ENUMERATION_TIMEOUT = "ENUMERATION_TIMEOUT"


@dataclass(frozen=True)
class EnumerationLimits:
    """Hard caps for recursive filesystem enumeration."""
    max_nodes: int = 10_000           # Maximum files + directories
    max_depth: int = 50               # Maximum directory nesting depth
    max_time_seconds: float = 5.0     # Maximum wall-clock time for enumeration
    max_total_size_bytes: int = 1_073_741_824  # 1 GiB total size cap


@dataclass(frozen=True)
class EnumerationResult:
    """Result from bounded recursive enumeration."""
    allowed: bool
    node_count: int = 0
    max_depth_seen: int = 0
    total_size_bytes: int = 0
    elapsed_seconds: float = 0.0
    paths: Optional[List[str]] = None  # Only populated if allowed and requested
    deny_reason: Optional[str] = None
    deny_code: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "allowed": self.allowed,
            "node_count": self.node_count,
            "max_depth_seen": self.max_depth_seen,
            "total_size_bytes": self.total_size_bytes,
            "elapsed_seconds": round(self.elapsed_seconds, 3),
            "deny_reason": self.deny_reason,
            "deny_code": self.deny_code,
        }


DEFAULT_ENUMERATION_LIMITS = EnumerationLimits()


def bounded_recursive_enumerate(
    root_path: str,
    limits: EnumerationLimits = DEFAULT_ENUMERATION_LIMITS,
    collect_paths: bool = False,
) -> EnumerationResult:
    """
    Enumerate a directory tree with hard caps on nodes, depth, and time.

    Fail-closed: if any limit is exceeded, the entire operation is denied
    with an UNBOUNDED_ENUMERATION reason code.

    Args:
        root_path: The root directory to enumerate
        limits: Hard caps for enumeration
        collect_paths: Whether to collect path strings (expensive for large trees)

    Returns:
        EnumerationResult with enumeration outcome
    """
    start_time = time.monotonic()
    node_count = 0
    max_depth_seen = 0
    total_size = 0
    paths: List[str] = [] if collect_paths else []

    if not os.path.isdir(root_path):
        return EnumerationResult(
            allowed=False,
            deny_reason=f"Root path '{root_path}' is not a directory",
            deny_code=UNBOUNDED_ENUMERATION,
        )

    # Walk the tree with limit checks at each node
    try:
        for dirpath, dirnames, filenames in os.walk(root_path, followlinks=False):
            # Depth check — use relpath to avoid prefix-stripping bugs
            # (e.g. root="/workspace", dirpath="/workspace/workspace" would
            # collapse to "" with str.replace, undercounting depth)
            rel = os.path.relpath(dirpath, root_path)
            depth = 0 if rel == "." else (rel.count(os.sep) + 1)
            max_depth_seen = max(max_depth_seen, depth)

            if depth > limits.max_depth:
                return EnumerationResult(
                    allowed=False,
                    node_count=node_count,
                    max_depth_seen=max_depth_seen,
                    total_size_bytes=total_size,
                    elapsed_seconds=time.monotonic() - start_time,
                    deny_reason=(
                        f"Directory depth {depth} exceeds limit {limits.max_depth} "
                        f"at '{dirpath}'"
                    ),
                    deny_code=ENUMERATION_DEPTH_EXCEEDED,
                )

            # Time check
            elapsed = time.monotonic() - start_time
            if elapsed > limits.max_time_seconds:
                return EnumerationResult(
                    allowed=False,
                    node_count=node_count,
                    max_depth_seen=max_depth_seen,
                    total_size_bytes=total_size,
                    elapsed_seconds=elapsed,
                    deny_reason=(
                        f"Enumeration timeout: {elapsed:.1f}s exceeds limit "
                        f"{limits.max_time_seconds}s after {node_count} nodes"
                    ),
                    deny_code=ENUMERATION_TIMEOUT,
                )

            # Process directories
            for dirname in dirnames:
                node_count += 1
                if node_count > limits.max_nodes:
                    return EnumerationResult(
                        allowed=False,
                        node_count=node_count,
                        max_depth_seen=max_depth_seen,
                        total_size_bytes=total_size,
                        elapsed_seconds=time.monotonic() - start_time,
                        deny_reason=(
                            f"Node count {node_count} exceeds limit "
                            f"{limits.max_nodes}"
                        ),
                        deny_code=ENUMERATION_NODE_LIMIT_EXCEEDED,
                    )
                if collect_paths:
                    paths.append(os.path.join(dirpath, dirname))

            # Process files
            for filename in filenames:
                node_count += 1
                if node_count > limits.max_nodes:
                    return EnumerationResult(
                        allowed=False,
                        node_count=node_count,
                        max_depth_seen=max_depth_seen,
                        total_size_bytes=total_size,
                        elapsed_seconds=time.monotonic() - start_time,
                        deny_reason=(
                            f"Node count {node_count} exceeds limit "
                            f"{limits.max_nodes}"
                        ),
                        deny_code=ENUMERATION_NODE_LIMIT_EXCEEDED,
                    )

                filepath = os.path.join(dirpath, filename)
                if collect_paths:
                    paths.append(filepath)

                # Size tracking
                try:
                    stat = os.lstat(filepath)
                    total_size += stat.st_size
                except OSError:
                    pass  # Can't stat — skip size but still count node

                if total_size > limits.max_total_size_bytes:
                    return EnumerationResult(
                        allowed=False,
                        node_count=node_count,
                        max_depth_seen=max_depth_seen,
                        total_size_bytes=total_size,
                        elapsed_seconds=time.monotonic() - start_time,
                        deny_reason=(
                            f"Total size {total_size} bytes exceeds limit "
                            f"{limits.max_total_size_bytes} bytes"
                        ),
                        deny_code=UNBOUNDED_ENUMERATION,
                    )

    except PermissionError as e:
        return EnumerationResult(
            allowed=False,
            node_count=node_count,
            max_depth_seen=max_depth_seen,
            total_size_bytes=total_size,
            elapsed_seconds=time.monotonic() - start_time,
            deny_reason=f"Permission denied during enumeration: {e}",
            deny_code=UNBOUNDED_ENUMERATION,
        )

    elapsed = time.monotonic() - start_time
    return EnumerationResult(
        allowed=True,
        node_count=node_count,
        max_depth_seen=max_depth_seen,
        total_size_bytes=total_size,
        elapsed_seconds=elapsed,
        paths=paths if collect_paths else None,
    )
