#!/usr/bin/env python3
"""
M87 Layer 0 — Traceable Demo Run

Provable artifact showing all three Layer 0 enforcement paths:

  PATH A: Governance-level denial
    Proposal with /dev/shm artifact → DENY at governance (check_virtual_fs_access)

  PATH B: Runner-level pathset mismatch
    Glob approves {a.txt, b.txt}. File c.txt injected.
    Runner detects extra path → RUNNER_PATHSET_MISMATCH / GLOB_DIVERGENCE_DETECTED.

  PATH C: Runner boot refusal
    Runner launched with non-loopback network interface → RUNNER_NAMESPACE_VIOLATION.
    Runner launched with CAP_SYS_ADMIN → RUNNER_CAPABILITY_VIOLATION.

  PATH D: TOCTOU symlink swap
    Governance approves /workspace/data.txt → safe file.
    Attacker swaps symlink → /etc/passwd.
    Runner detects symlink escape → abort.

Each path prints a structured trace (JSON) so operators can verify the
enforcement chain end-to-end.

Usage:
    python scripts/layer0_demo.py          # Run all paths
    python scripts/layer0_demo.py --json   # Machine-readable output
"""
from __future__ import annotations

import json
import os
import platform
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

# Resolve project root
SCRIPT_DIR = Path(__file__).parent.resolve()
PROJECT_ROOT = SCRIPT_DIR.parent
API_DIR = PROJECT_ROOT / "apps" / "api"
sys.path.insert(0, str(API_DIR))
sys.path.insert(0, str(PROJECT_ROOT))

# ---- Build provenance (anti-fake-green)

def _get_git_sha() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=str(PROJECT_ROOT),
            stderr=subprocess.DEVNULL,
        ).decode().strip()
    except Exception:
        return "unknown"


def _get_git_branch() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            cwd=str(PROJECT_ROOT),
            stderr=subprocess.DEVNULL,
        ).decode().strip()
    except Exception:
        return "unknown"


def _build_provenance() -> dict:
    return {
        "repo_commit": _get_git_sha(),
        "branch": _get_git_branch(),
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "runner_build_id": os.getenv("M87_BUILD_ID", "local"),
    }


# ---- Trace record helpers

_traces: list = []
_log_dest = sys.stdout  # switched to stderr in --json mode so stdout is pure JSON


def _log(msg: str):
    """Print to the current log destination (stdout or stderr)."""
    print(msg, file=_log_dest)


def trace(path: str, step: str, result: str, detail: dict | None = None):
    """Append a structured trace record."""
    record = {
        "path": path,
        "step": step,
        "result": result,
        "detail": detail or {},
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    _traces.append(record)
    icon = "\u2713" if result == "PASS" else "\u2717"
    _log(f"  [{icon}] {path} / {step}: {result}")
    if detail:
        for k, v in detail.items():
            _log(f"      {k}: {v}")


# ===========================================================================
# PATH A: Governance-level denial (virtual FS deny)
# ===========================================================================

def demo_path_a():
    _log("\n" + "=" * 70)
    _log("PATH A: Governance-level virtual FS denial")
    _log("=" * 70)

    from app.governance.virtual_fs_deny import check_virtual_fs_access

    # A.1: /dev/shm must be denied
    result = check_virtual_fs_access("/dev/shm/exploit_payload")
    assert not result.allowed
    trace("A", "deny /dev/shm", "PASS", {
        "path": "/dev/shm/exploit_payload",
        "deny_code": result.deny_code,
        "deny_reason": result.deny_reason,
    })

    # A.2: /proc/self/fd must be denied (not in allowlist)
    result = check_virtual_fs_access("/proc/self/fd/3")
    assert not result.allowed
    trace("A", "deny /proc/self/fd (not in allowlist)", "PASS", {
        "path": "/proc/self/fd/3",
        "deny_code": result.deny_code,
    })

    # A.3: /proc/cpuinfo IS in allowlist — must be allowed
    result = check_virtual_fs_access("/proc/cpuinfo")
    assert result.allowed
    trace("A", "allow /proc/cpuinfo (in allowlist)", "PASS", {
        "path": "/proc/cpuinfo",
    })

    # A.4: /sys must be denied
    result = check_virtual_fs_access("/sys/kernel/debug")
    assert not result.allowed
    trace("A", "deny /sys", "PASS", {
        "path": "/sys/kernel/debug",
        "deny_code": result.deny_code,
    })

    # A.5: Traversal bypass attempt
    result = check_virtual_fs_access("/workspace/../dev/shm/bypass")
    assert not result.allowed
    trace("A", "deny traversal bypass ../dev/shm", "PASS", {
        "path": "/workspace/../dev/shm/bypass",
        "deny_code": result.deny_code,
    })

    # A.6: Normal path must be allowed
    result = check_virtual_fs_access("/home/user/code/main.py")
    assert result.allowed
    trace("A", "allow normal path", "PASS", {
        "path": "/home/user/code/main.py",
    })

    _log("  Path A: ALL CHECKS PASSED")


# ===========================================================================
# PATH B: Runner-level pathset mismatch (TOCTOU detection)
# ===========================================================================

def demo_path_b():
    _log("\n" + "=" * 70)
    _log("PATH B: Runner-level pathset mismatch")
    _log("=" * 70)

    from app.governance.glob_validation import (
        governance_expand_glob,
        runner_revalidate_glob,
    )
    from services.runner.app.runner import _runner_revalidate_paths

    with tempfile.TemporaryDirectory(prefix="m87_demo_") as tmpdir:
        workspace = Path(tmpdir) / "workspace"
        workspace.mkdir()

        # B.1: Glob divergence — file injected after approval
        (workspace / "a.txt").write_text("file a")
        (workspace / "b.txt").write_text("file b")

        gov_result = governance_expand_glob("*.txt", str(workspace))
        assert gov_result.approved
        approved_count = len(gov_result.canonical_paths)
        trace("B", "governance glob *.txt", "PASS", {
            "approved_paths": sorted(gov_result.canonical_paths),
            "count": approved_count,
        })

        # Attacker injects c.txt
        (workspace / "c.txt").write_text("injected!")

        runner_result = runner_revalidate_glob(
            approved_paths=gov_result.canonical_paths,
            pattern="*.txt",
            base_dir=str(workspace),
        )
        assert not runner_result.valid
        trace("B", "runner detects glob divergence", "PASS", {
            "deny_code": runner_result.deny_code,
            "extra_paths": sorted(runner_result.extra_paths),
        })

        # B.2: Extra path in job input
        clean = workspace / "approved.dat"
        clean.write_text("clean")
        injected = workspace / "injected.dat"
        injected.write_text("evil")

        evidence = _runner_revalidate_paths(
            approved_paths=[str(clean)],
            job_inputs={"target": str(injected)},
            base_dir=str(workspace),
        )
        assert not evidence["pathset_valid"]
        trace("B", "runner detects extra input path", "PASS", {
            "error": evidence["error"],
            "extra_paths": evidence["extra_paths"],
        })

    _log("  Path B: ALL CHECKS PASSED")


# ===========================================================================
# PATH C: Runner boot refusal
# ===========================================================================

def demo_path_c():
    _log("\n" + "=" * 70)
    _log("PATH C: Runner boot refusal (namespace + capability)")
    _log("=" * 70)

    from services.runner.app.runner import (
        _verify_network_namespace,
        _verify_capabilities_dropped,
    )

    # C.1: Non-loopback interface → RuntimeError
    with patch.dict(os.environ, {"M87_NETWORK_CHECK_ENABLED": "1"}):
        with patch("services.runner.app.runner.os.path.exists", return_value=True):
            with patch("services.runner.app.runner.os.listdir", return_value=["lo", "eth0"]):
                try:
                    _verify_network_namespace()
                    trace("C", "network namespace (eth0 present)", "FAIL",
                          {"expected": "RuntimeError"})
                except RuntimeError as e:
                    assert "RUNNER_NAMESPACE_VIOLATION" in str(e)
                    trace("C", "network namespace (eth0 present)", "PASS", {
                        "error": str(e)[:120],
                    })

    # C.2: loopback only → passes
    with patch.dict(os.environ, {"M87_NETWORK_CHECK_ENABLED": "1"}):
        with patch("services.runner.app.runner.os.path.exists", return_value=True):
            with patch("services.runner.app.runner.os.listdir", return_value=["lo"]):
                _verify_network_namespace()
                trace("C", "network namespace (lo only)", "PASS", {
                    "interfaces": ["lo"],
                })

    # C.3: CAP_SYS_ADMIN → RuntimeError
    cap_status = (
        "Name:\trunner\nUmask:\t0022\nState:\tS (sleeping)\n"
        "CapInh:\t0000000000000000\nCapPrm:\t0000000000200000\n"
        "CapEff:\t0000000000200000\nCapBnd:\t0000000000200000\n"
    )
    with patch.dict(os.environ, {"M87_CAP_CHECK_ENABLED": "1"}):
        with patch("builtins.open", create=True) as mock_open:
            mock_open.return_value.__enter__ = lambda s: s
            mock_open.return_value.__exit__ = MagicMock(return_value=False)
            mock_open.return_value.read.return_value = cap_status
            try:
                _verify_capabilities_dropped()
                trace("C", "capability check (CAP_SYS_ADMIN)", "FAIL",
                      {"expected": "RuntimeError"})
            except RuntimeError as e:
                assert "RUNNER_CAPABILITY_VIOLATION" in str(e)
                trace("C", "capability check (CAP_SYS_ADMIN)", "PASS", {
                    "error": str(e)[:120],
                })

    # C.4: zero capabilities → passes
    clean_status = cap_status.replace("0000000000200000", "0000000000000000")
    with patch.dict(os.environ, {"M87_CAP_CHECK_ENABLED": "1"}):
        with patch("builtins.open", create=True) as mock_open:
            mock_open.return_value.__enter__ = lambda s: s
            mock_open.return_value.__exit__ = MagicMock(return_value=False)
            mock_open.return_value.read.return_value = clean_status
            _verify_capabilities_dropped()
            trace("C", "capability check (zero caps)", "PASS", {
                "cap_eff": "0x0",
            })

    _log("  Path C: ALL CHECKS PASSED")


# ===========================================================================
# PATH D: TOCTOU symlink swap
# ===========================================================================

def demo_path_d():
    _log("\n" + "=" * 70)
    _log("PATH D: TOCTOU symlink swap after approval")
    _log("=" * 70)

    from services.runner.app.runner import _runner_revalidate_paths

    with tempfile.TemporaryDirectory(prefix="m87_demo_") as tmpdir:
        workspace = Path(tmpdir) / "workspace"
        workspace.mkdir()

        # D.1: Symlink initially points to safe file
        safe_file = workspace / "real_data.txt"
        safe_file.write_text("safe content — governance approved this")
        link = workspace / "data.txt"
        link.symlink_to(str(safe_file))

        approved = [str(safe_file)]
        trace("D", "governance approves symlink target", "PASS", {
            "link": str(link),
            "target": str(safe_file),
            "approved_paths": approved,
        })

        # D.2: Attacker swaps symlink → /etc/passwd
        link.unlink()
        link.symlink_to("/etc/passwd")

        evidence = _runner_revalidate_paths(
            approved_paths=approved,
            job_inputs={"target": str(link)},
            base_dir=str(workspace),
        )
        assert not evidence["pathset_valid"]
        trace("D", "runner detects symlink swap", "PASS", {
            "link_now_points_to": os.path.realpath(str(link)),
            "symlink_escapes": evidence["symlink_escapes"],
            "error": evidence.get("error", ""),
        })

        # D.3: Symlink to virtual FS
        link.unlink()
        link.symlink_to("/dev/shm/covert_channel")

        evidence = _runner_revalidate_paths(
            approved_paths=approved,
            job_inputs={"target": str(link)},
            base_dir=str(workspace),
        )
        assert not evidence["pathset_valid"]
        trace("D", "runner detects symlink to /dev/shm", "PASS", {
            "symlink_escapes": evidence["symlink_escapes"],
        })

    _log("  Path D: ALL CHECKS PASSED")


# ===========================================================================
# Main
# ===========================================================================

def main():
    global _log_dest
    json_mode = "--json" in sys.argv
    if json_mode:
        _log_dest = sys.stderr  # human-readable → stderr, JSON → stdout
    provenance = _build_provenance()

    _log("=" * 70)
    _log("M87 Layer 0 — Traceable Demo Run")
    _log(f"  Timestamp: {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}")
    _log(f"  Commit:    {provenance['repo_commit'][:12]}")
    _log(f"  Branch:    {provenance['branch']}")
    _log(f"  Python:    {provenance['python_version']}")
    _log(f"  Platform:  {provenance['platform']}")
    _log(f"  Build ID:  {provenance['runner_build_id']}")
    _log("=" * 70)

    all_passed = True
    try:
        demo_path_a()
        demo_path_b()
        demo_path_c()
        demo_path_d()
    except (AssertionError, Exception) as e:
        all_passed = False
        trace("ERROR", "unexpected failure", "FAIL", {"exception": str(e)})
        import traceback
        traceback.print_exc()

    # Summary
    pass_count = sum(1 for t in _traces if t["result"] == "PASS")
    fail_count = sum(1 for t in _traces if t["result"] == "FAIL")

    _log("\n" + "=" * 70)
    _log("SUMMARY")
    _log("=" * 70)
    _log(f"  Total checks: {len(_traces)}")
    _log(f"  Passed:       {pass_count}")
    _log(f"  Failed:       {fail_count}")
    _log(f"  Verdict:      {'LAYER 0 ENFORCED' if all_passed else 'LAYER 0 BROKEN'}")
    _log("=" * 70)

    if json_mode:
        output = {
            "demo": "M87 Layer 0 Traceable Demo Run",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "provenance": provenance,
            "total_checks": len(_traces),
            "passed": pass_count,
            "failed": fail_count,
            "verdict": "LAYER_0_ENFORCED" if all_passed else "LAYER_0_BROKEN",
            "traces": _traces,
        }
        # JSON goes to stdout (clean for piping), human output already on stderr
        print(json.dumps(output, indent=2))

    sys.exit(0 if all_passed else 1)


if __name__ == "__main__":
    main()
