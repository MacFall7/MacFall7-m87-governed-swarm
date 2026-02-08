"""
P1.1 — Semantic truncation defense (PROBE_002_PARTIAL).
P1.2 — Deny on empty args (PROBE_020_EDGE).

P1.1: Denies "empty overwrite" semantics — if source content size = 0 AND
destination is non-empty or critical, the operation is denied. This catches
both /dev/null and user-created 0-byte files used as truncation weapons.

P1.2: Removes sanitize-and-continue behavior for anomalous args. Any empty
string argument in a tool invocation is denied with an explicit reason.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional


# Deny reason codes (stable contract for telemetry)
EMPTY_OVERWRITE_DENIED = "EMPTY_OVERWRITE_DENIED"
EMPTY_ARG_DENIED = "EMPTY_ARG_DENIED"
DEVNULL_SOURCE_DENIED = "DEVNULL_SOURCE_DENIED"


@dataclass(frozen=True)
class InputValidationResult:
    """Result from input validation checks."""
    allowed: bool
    deny_reason: Optional[str] = None
    deny_code: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "allowed": self.allowed,
            "deny_reason": self.deny_reason,
            "deny_code": self.deny_code,
        }


# Known zero-content sources (explicit deny list)
ZERO_CONTENT_SOURCES = frozenset({
    "/dev/null",
    "/dev/zero",
})


def check_semantic_truncation(
    source_path: Optional[str] = None,
    source_content_size: Optional[int] = None,
    destination_path: Optional[str] = None,
    destination_is_nonempty: bool = False,
    destination_is_critical: bool = False,
    operation: str = "write",
) -> InputValidationResult:
    """
    P1.1: Check for semantic truncation attacks.

    Denies operations where:
    1. Source is a known zero-content device (/dev/null, /dev/zero)
    2. Source content size is 0 AND destination is non-empty or critical
    3. The operation would overwrite existing content with nothing

    This catches both explicit /dev/null redirections AND user-created
    0-byte files used as truncation weapons.

    Args:
        source_path: Path of the source file (if applicable)
        source_content_size: Size of source content in bytes
        destination_path: Path of the destination file
        destination_is_nonempty: Whether destination currently has content
        destination_is_critical: Whether destination is a critical file
        operation: The operation type (write, cp, mv, etc.)

    Returns:
        InputValidationResult with the validation outcome
    """
    # Check 1: Explicit /dev/null-like sources
    if source_path and source_path in ZERO_CONTENT_SOURCES:
        return InputValidationResult(
            allowed=False,
            deny_reason=(
                f"Operation '{operation}' denied: source '{source_path}' is a "
                f"zero-content device. This would truncate destination "
                f"'{destination_path or 'unknown'}'."
            ),
            deny_code=DEVNULL_SOURCE_DENIED,
        )

    # Check 2: Zero-length source overwriting non-empty or critical destination
    if source_content_size is not None and source_content_size == 0:
        if destination_is_nonempty or destination_is_critical:
            return InputValidationResult(
                allowed=False,
                deny_reason=(
                    f"Operation '{operation}' denied: source has 0 bytes but "
                    f"destination '{destination_path or 'unknown'}' is "
                    f"{'critical' if destination_is_critical else 'non-empty'}. "
                    f"This appears to be a semantic truncation attack."
                ),
                deny_code=EMPTY_OVERWRITE_DENIED,
            )

    return InputValidationResult(allowed=True)


def check_empty_args(
    tool_name: str,
    args: Dict[str, Any],
) -> InputValidationResult:
    """
    P1.2: Deny any empty string arguments.

    Removes sanitize-and-continue behavior. Any empty string argument
    is denied with an explicit reason code.

    This prevents:
    - Command injection via empty string placeholders
    - Argument confusion attacks
    - Silent parameter elision

    Args:
        tool_name: Name of the tool being invoked
        args: Dictionary of argument name → value pairs

    Returns:
        InputValidationResult with the validation outcome
    """
    empty_args: List[str] = []

    for key, value in args.items():
        if isinstance(value, str) and value == "":
            empty_args.append(key)

    if empty_args:
        return InputValidationResult(
            allowed=False,
            deny_reason=(
                f"Tool '{tool_name}' denied: empty string argument(s) "
                f"detected: {sorted(empty_args)}. Empty arguments are not "
                f"permitted (fail-closed policy)."
            ),
            deny_code=EMPTY_ARG_DENIED,
        )

    return InputValidationResult(allowed=True)


def validate_tool_inputs(
    tool_name: str,
    args: Dict[str, Any],
    source_path: Optional[str] = None,
    source_content_size: Optional[int] = None,
    destination_path: Optional[str] = None,
    destination_is_nonempty: bool = False,
    destination_is_critical: bool = False,
    operation: str = "write",
) -> InputValidationResult:
    """
    Combined input validation: runs all P1 checks.

    Checks (in order, fail-fast):
    1. Empty args check (P1.2)
    2. Semantic truncation check (P1.1)

    Returns the first failing result, or allowed if all pass.
    """
    # P1.2: Empty args
    result = check_empty_args(tool_name, args)
    if not result.allowed:
        return result

    # P1.1: Semantic truncation
    result = check_semantic_truncation(
        source_path=source_path,
        source_content_size=source_content_size,
        destination_path=destination_path,
        destination_is_nonempty=destination_is_nonempty,
        destination_is_critical=destination_is_critical,
        operation=operation,
    )
    if not result.allowed:
        return result

    return InputValidationResult(allowed=True)
