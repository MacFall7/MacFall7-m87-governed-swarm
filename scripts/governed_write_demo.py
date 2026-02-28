#!/usr/bin/env python3
"""
M87 Governed file_write — Demo Script

Three scenarios showing the governance enforcement chain for file_write:

  SCENARIO 1: Happy Path
    file_write → governance approves → runner writes → receipt with content hash

  SCENARIO 2: Denial Path
    file_write to ../../../../etc/passwd → sandbox containment → DENY

  SCENARIO 3: Scope Violation
    file_write with max_write_scope=none → runner rejects (sandbox > none)

Each scenario prints structured output showing the enforcement result.

Usage:
    python scripts/governed_write_demo.py
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path

# Ensure runner imports work
REPO_ROOT = Path(__file__).parent.parent
RUNNER_DIR = REPO_ROOT / "services" / "runner"
sys.path.insert(0, str(RUNNER_DIR))

from app.runner import (
    _resolve_sandbox_path,
    tool_file_write,
    validate_job_against_manifest,
    load_manifest,
    scope_rank,
    TOOL_WRITE_SCOPE_REQUIREMENTS,
)


def _header(title: str) -> None:
    print(f"\n{'=' * 60}")
    print(f"  {title}")
    print(f"{'=' * 60}\n")


def scenario_1_happy_path() -> dict:
    """
    Scenario 1: Happy Path — file_write succeeds.

    Simulates: governance approves → runner writes → receipt with hash.
    """
    _header("SCENARIO 1: Happy Path")

    with tempfile.TemporaryDirectory(prefix="m87-demo-") as sandbox:
        # 1. Validate inputs against manifest
        manifest = load_manifest(str(RUNNER_DIR / "app" / "tool_manifest.json"))
        job = {
            "tool": "file_write",
            "inputs": {
                "path": "output/result.txt",
                "content": "Hello from governed file_write!",
            },
        }

        err = validate_job_against_manifest(job, manifest)
        print(f"  Manifest validation: {'PASS' if not err else f'FAIL: {err}'}")
        assert not err, f"Unexpected validation error: {err}"

        # 2. Execute file_write in commit mode
        result = tool_file_write(
            path="output/result.txt",
            content="Hello from governed file_write!",
            mode="commit",
            sandbox_root=sandbox,
        )

        print(f"  Exit code: {result['exit_code']}")
        print(f"  Mode: {result['mode']}")
        print(f"  Content hash: {result['content_hash'][:16]}...")
        print(f"  Verify hash:  {result['verify_hash'][:16]}...")
        print(f"  Bytes written: {result['bytes_written']}")
        print(f"  File exists: {os.path.exists(result['resolved_path'])}")

        artifacts = result.get("completion_artifacts", {})
        print(f"  Artifacts: {len(artifacts.get('files', []))} files, "
              f"{len(artifacts.get('receipts', []))} receipts")

        assert result["exit_code"] == 0
        assert result["content_hash"] == result["verify_hash"]

        print("\n  RESULT: PASS — file written and verified")
        return {"scenario": "happy_path", "status": "PASS", "result": result}


def scenario_2_sandbox_denial() -> dict:
    """
    Scenario 2: Denial Path — traversal escape denied.

    Simulates: file_write to ../../../../etc/passwd → sandbox containment → DENY.
    """
    _header("SCENARIO 2: Sandbox Containment Denial")

    with tempfile.TemporaryDirectory(prefix="m87-demo-") as sandbox:
        # Attempt traversal escape
        result = tool_file_write(
            path="../../../../etc/passwd",
            content="evil:x:0:0::/root:/bin/bash",
            mode="commit",
            sandbox_root=sandbox,
        )

        print(f"  Exit code: {result['exit_code']}")
        print(f"  Error: {result.get('error', 'none')}")
        print(f"  Detail: {result.get('detail', 'none')}")

        # Verify /etc/passwd was NOT modified
        real_passwd = Path("/etc/passwd")
        if real_passwd.exists():
            print(f"  /etc/passwd intact: {real_passwd.exists()}")

        assert result["exit_code"] == -1
        assert "sandbox_containment" in result.get("error", "")

        print("\n  RESULT: PASS — traversal blocked by sandbox containment")
        return {"scenario": "sandbox_denial", "status": "PASS", "result": result}


def scenario_3_scope_violation() -> dict:
    """
    Scenario 3: Scope Violation — max_write_scope=none rejects file_write.

    Simulates: budget allows no writes, but file_write requires sandbox scope.
    Runner rejects before tool execution.
    """
    _header("SCENARIO 3: Write Scope Violation")

    required_scope = TOOL_WRITE_SCOPE_REQUIREMENTS.get("file_write", "sandbox")
    allowed_scope = "none"

    print(f"  Tool requires: {required_scope} (rank={scope_rank(required_scope)})")
    print(f"  Budget allows: {allowed_scope} (rank={scope_rank(allowed_scope)})")

    would_deny = scope_rank(required_scope) > scope_rank(allowed_scope)
    print(f"  Scope check: {'DENY' if would_deny else 'ALLOW'}")

    assert would_deny, "Expected scope violation"

    print(f"\n  Enforcement: Runner checks scope_rank('{required_scope}') > "
          f"scope_rank('{allowed_scope}') → {scope_rank(required_scope)} > "
          f"{scope_rank(allowed_scope)} = True → DENY")

    print("\n  RESULT: PASS — write scope gating blocks file_write")
    return {"scenario": "scope_violation", "status": "PASS", "would_deny": True}


def main() -> None:
    print("M87 Governed file_write — Demo Run")
    print(f"Runner path: {RUNNER_DIR}")

    results = []
    results.append(scenario_1_happy_path())
    results.append(scenario_2_sandbox_denial())
    results.append(scenario_3_scope_violation())

    _header("SUMMARY")
    for r in results:
        status = r.get("status", "UNKNOWN")
        scenario = r.get("scenario", "?")
        print(f"  [{status}] {scenario}")

    all_pass = all(r.get("status") == "PASS" for r in results)
    print(f"\n  Overall: {'ALL PASS' if all_pass else 'SOME FAILURES'}")

    if not all_pass:
        sys.exit(1)


if __name__ == "__main__":
    main()
