"""
P0.1 — Runner-side glob expansion re-validation (PROBE_013_EDGE).

Eliminates governance/runner filesystem divergence for glob-expanded paths.

Governance returns an explicit approved expansion set (canonical paths).
Runner re-expands (or resolves) and aborts if any candidate path is not
in the approved set.

This prevents attacks where overlay/bind mount divergence causes the runner
to see different files than governance approved.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, FrozenSet, List, Optional, Set


# Deny reason codes (stable contract for telemetry)
GLOB_DIVERGENCE_DETECTED = "GLOB_DIVERGENCE_DETECTED"
GLOB_EXPANSION_EMPTY = "GLOB_EXPANSION_EMPTY"
GLOB_PATH_NOT_CANONICAL = "GLOB_PATH_NOT_CANONICAL"
GLOB_SYMLINK_ESCAPE = "GLOB_SYMLINK_ESCAPE"


@dataclass(frozen=True)
class GlobExpansionResult:
    """Result from governance-side glob expansion."""
    approved: bool
    canonical_paths: FrozenSet[str] = field(default_factory=frozenset)
    pattern: str = ""
    base_dir: str = ""
    deny_reason: Optional[str] = None
    deny_code: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "approved": self.approved,
            "canonical_paths": sorted(self.canonical_paths),
            "pattern": self.pattern,
            "base_dir": self.base_dir,
            "deny_reason": self.deny_reason,
            "deny_code": self.deny_code,
        }


@dataclass(frozen=True)
class GlobRevalidationResult:
    """Result from runner-side glob re-validation."""
    valid: bool
    divergent_paths: FrozenSet[str] = field(default_factory=frozenset)
    missing_paths: FrozenSet[str] = field(default_factory=frozenset)
    extra_paths: FrozenSet[str] = field(default_factory=frozenset)
    error: Optional[str] = None
    deny_code: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "valid": self.valid,
            "divergent_paths": sorted(self.divergent_paths),
            "missing_paths": sorted(self.missing_paths),
            "extra_paths": sorted(self.extra_paths),
            "error": self.error,
            "deny_code": self.deny_code,
        }


def canonicalize_path(path: str, base_dir: str = "/") -> Optional[str]:
    """
    Resolve a path to its canonical (realpath) form.

    Returns None if the path cannot be resolved or escapes base_dir
    via symlinks.
    """
    try:
        resolved = os.path.realpath(path)
    except (OSError, ValueError):
        return None

    # Verify the resolved path is under base_dir (symlink escape check)
    canonical_base = os.path.realpath(base_dir)
    if not resolved.startswith(canonical_base + os.sep) and resolved != canonical_base:
        return None

    return resolved


def governance_expand_glob(
    pattern: str,
    base_dir: str,
    *,
    allowed_base_dirs: Optional[Set[str]] = None,
) -> GlobExpansionResult:
    """
    Governance-side glob expansion.

    Expands a glob pattern to a set of canonical (realpath) paths.
    Returns the approved expansion set that the runner must re-validate.

    Args:
        pattern: The glob pattern to expand
        base_dir: The base directory for expansion
        allowed_base_dirs: Optional set of allowed base directories

    Returns:
        GlobExpansionResult with approved canonical paths
    """
    # Validate base_dir
    if allowed_base_dirs:
        canonical_base = os.path.realpath(base_dir)
        if not any(
            canonical_base.startswith(os.path.realpath(d))
            for d in allowed_base_dirs
        ):
            return GlobExpansionResult(
                approved=False,
                pattern=pattern,
                base_dir=base_dir,
                deny_reason=f"Base directory {base_dir} not in allowed set",
                deny_code=GLOB_PATH_NOT_CANONICAL,
            )

    # Expand the glob
    base = Path(base_dir)
    try:
        expanded = list(base.glob(pattern))
    except (OSError, ValueError) as e:
        return GlobExpansionResult(
            approved=False,
            pattern=pattern,
            base_dir=base_dir,
            deny_reason=f"Glob expansion failed: {e}",
            deny_code=GLOB_EXPANSION_EMPTY,
        )

    # Canonicalize all paths
    canonical: Set[str] = set()
    for p in expanded:
        cp = canonicalize_path(str(p), base_dir)
        if cp is None:
            return GlobExpansionResult(
                approved=False,
                pattern=pattern,
                base_dir=base_dir,
                deny_reason=f"Path {p} escapes base_dir via symlink",
                deny_code=GLOB_SYMLINK_ESCAPE,
            )
        canonical.add(cp)

    return GlobExpansionResult(
        approved=True,
        canonical_paths=frozenset(canonical),
        pattern=pattern,
        base_dir=base_dir,
    )


def runner_revalidate_glob(
    approved_paths: FrozenSet[str],
    pattern: str,
    base_dir: str,
) -> GlobRevalidationResult:
    """
    Runner-side re-validation of glob expansion.

    Re-expands the glob pattern and compares against the governance-approved
    set. Aborts if any candidate path is not in the approved set (divergence).

    This catches overlay/bind mount divergence where the runner's filesystem
    view differs from governance's view.

    Args:
        approved_paths: The set of canonical paths approved by governance
        pattern: The original glob pattern
        base_dir: The base directory for re-expansion

    Returns:
        GlobRevalidationResult with validation outcome
    """
    # Re-expand on runner's filesystem view
    base = Path(base_dir)
    try:
        runner_expanded = list(base.glob(pattern))
    except (OSError, ValueError) as e:
        return GlobRevalidationResult(
            valid=False,
            error=f"Runner glob expansion failed: {e}",
            deny_code=GLOB_DIVERGENCE_DETECTED,
        )

    # Canonicalize runner's view
    runner_canonical: Set[str] = set()
    for p in runner_expanded:
        cp = canonicalize_path(str(p), base_dir)
        if cp is None:
            return GlobRevalidationResult(
                valid=False,
                error=f"Runner path {p} escapes base_dir via symlink",
                deny_code=GLOB_SYMLINK_ESCAPE,
            )
        runner_canonical.add(cp)

    # Compare sets
    approved_set = set(approved_paths)
    extra = runner_canonical - approved_set
    missing = approved_set - runner_canonical

    if extra:
        return GlobRevalidationResult(
            valid=False,
            divergent_paths=frozenset(extra | missing),
            extra_paths=frozenset(extra),
            missing_paths=frozenset(missing),
            error=(
                f"Runner sees {len(extra)} path(s) not approved by governance. "
                f"Possible overlay/bind mount divergence."
            ),
            deny_code=GLOB_DIVERGENCE_DETECTED,
        )

    # Missing paths are acceptable (files may have been deleted between
    # governance check and runner execution) — but extra paths are not.
    return GlobRevalidationResult(
        valid=True,
        missing_paths=frozenset(missing),
    )
