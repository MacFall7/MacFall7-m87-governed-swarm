"""
Phase 4 Airlocked runner gate: verify isolation + sanitize env + truncate output.

Standardizes the "airlock contract" for any exec-like tool (pytest, lint, build, etc.).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Tuple


@dataclass(frozen=True)
class AirlockPolicy:
    """Policy for environment sanitization and output handling."""
    # Only env vars with these prefixes are allowed through
    allowed_env_prefixes: Tuple[str, ...] = ("M87_", "PYTHONPATH", "PATH", "HOME", "USER")
    # These env vars are always denied (secrets)
    deny_env_keys: Tuple[str, ...] = (
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "GEMINI_API_KEY",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_ACCESS_KEY_ID",
        "GITHUB_TOKEN",
        "GH_TOKEN",
        "SLACK_TOKEN",
        "DATABASE_URL",
        "REDIS_URL",
    )
    # Output size limits
    max_output_bytes: int = 80_000
    max_stderr_bytes: int = 40_000


DEFAULT_AIRLOCK_POLICY = AirlockPolicy()


def sanitize_env(
    base_env: Dict[str, str],
    policy: AirlockPolicy = DEFAULT_AIRLOCK_POLICY
) -> Dict[str, str]:
    """
    Sanitize environment variables for tool execution.

    - Removes all denied keys (secrets)
    - Only passes through allowed prefixes
    - Ensures minimal safe env vars are present
    """
    out: Dict[str, str] = {}

    for k, v in base_env.items():
        # Always deny secret keys
        if k in policy.deny_env_keys:
            continue

        # Only allow whitelisted prefixes
        if any(k.startswith(p) for p in policy.allowed_env_prefixes):
            out[k] = v

    # Always ensure minimal safe env
    out["PATH"] = base_env.get("PATH", "/usr/bin:/bin")
    out["HOME"] = base_env.get("HOME", "/tmp")
    out["LANG"] = "C.UTF-8"

    return out


def truncate_output(
    stdout: bytes,
    stderr: bytes,
    policy: AirlockPolicy = DEFAULT_AIRLOCK_POLICY
) -> Tuple[bytes, bytes]:
    """
    Truncate stdout/stderr to prevent output bombs.

    Returns (truncated_stdout, truncated_stderr).
    """
    return (
        stdout[: policy.max_output_bytes],
        stderr[: policy.max_stderr_bytes]
    )


def require_airgap_attestation(runner_network_mode: str) -> None:
    """
    Enforce a hard claim so config drift is caught early.

    Raises RuntimeError if runner is not airgapped.
    """
    if runner_network_mode != "none":
        raise RuntimeError(
            f"Runner is not airgapped. Expected network_mode=none, got: {runner_network_mode}"
        )


class AirlockViolation(Exception):
    """Raised when airlock policy is violated."""
    pass


def validate_tool_input(
    tool_name: str,
    inputs: Dict,
    max_input_size: int = 100_000
) -> None:
    """
    Validate tool inputs don't exceed size limits.

    Raises AirlockViolation if inputs are too large.
    """
    import json
    serialized = json.dumps(inputs, default=str)
    if len(serialized) > max_input_size:
        raise AirlockViolation(
            f"Tool '{tool_name}' inputs exceed max size ({max_input_size} bytes)"
        )
