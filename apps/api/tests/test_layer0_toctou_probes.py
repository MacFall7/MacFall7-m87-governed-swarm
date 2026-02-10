"""
M87 Layer 0 — TOCTOU Red-Team Probes

These tests stress the *time dimension* of Layer 0 enforcement.  They simulate
attacks where the filesystem changes between governance approval and runner
execution (Time-of-Check to Time-of-Use):

PROBE 1: Symlink swap after approval
    Governance sees /workspace/data.txt → safe file.
    Attacker swaps symlink so /workspace/data.txt → /etc/shadow.
    Runner MUST detect the escape and abort.

PROBE 2: File injection between approval and execution
    Governance approves {file_a.txt}.
    Attacker creates file_b.txt before runner executes.
    Runner resolves extra path → RUNNER_PATHSET_MISMATCH.

PROBE 3: Glob expansion divergence (file created after glob)
    Governance globs *.txt and approves {a.txt, b.txt}.
    Attacker creates c.txt before runner re-globs.
    runner_revalidate_glob detects the extra path → GLOB_DIVERGENCE_DETECTED.

PROBE 4: Directory symlink swap escaping base_dir
    Governance approves /workspace/subdir/file.txt (subdir is a real dir).
    Attacker replaces subdir with a symlink → /etc/
    Runner's realpath resolves to /etc/file.txt (outside base_dir) → abort.

PROBE 5: Symlink-to-virtual-FS pivot
    Governance approves /workspace/output.log.
    Attacker replaces output.log with a symlink → /dev/shm/exfil.
    Runner MUST catch this via both symlink escape AND virtual FS deny.

PROBE 6: Double-fetch race (governance path vs runner path)
    Two paths resolve identically at governance time but diverge at runner time.
    Runner detects the divergence via approved_paths ⊆ check.

These probes are "laws of physics" — if they fail, TOCTOU attacks succeed.
"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

# Add repo root to path
_REPO_ROOT = str(Path(__file__).parent.parent.parent.parent)
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)


# ===========================================================================
# PROBE 1: Symlink swap after approval
# ===========================================================================

class TestSymlinkSwapAfterApproval:
    """
    Attacker swaps a symlink between governance approval and runner execution.

    Governance approved the *original* target; after the swap the symlink
    points somewhere the runner was never authorized to access.
    """

    def test_symlink_swap_to_outside_base_dir(self, tmp_path):
        """Symlink initially points inside base_dir, then swapped to /etc/passwd."""
        from services.runner.app.runner import _runner_revalidate_paths

        workspace = tmp_path / "workspace"
        workspace.mkdir()

        # Phase 1: governance time — symlink points to a safe file
        safe_file = workspace / "real_data.txt"
        safe_file.write_text("safe content")
        link = workspace / "data.txt"
        link.symlink_to(str(safe_file))

        # Governance approves the resolved path
        approved = [str(safe_file)]

        # Phase 2: attacker swaps the symlink
        link.unlink()
        link.symlink_to("/etc/passwd")

        # Phase 3: runner re-validates — MUST detect escape
        evidence = _runner_revalidate_paths(
            approved_paths=approved,
            job_inputs={"target": str(link)},
            base_dir=str(workspace),
        )
        assert evidence["pathset_valid"] is False
        assert len(evidence["symlink_escapes"]) > 0, \
            "Runner must detect symlink escape outside base_dir"

    def test_symlink_swap_to_different_file_inside_base(self, tmp_path):
        """Symlink swapped to a different file INSIDE base_dir but NOT in approved set."""
        from services.runner.app.runner import _runner_revalidate_paths

        workspace = tmp_path / "workspace"
        workspace.mkdir()

        # Governance time: link → file_a (approved)
        file_a = workspace / "file_a.txt"
        file_a.write_text("approved content")
        file_b = workspace / "file_b.txt"
        file_b.write_text("secret content")
        link = workspace / "data.txt"
        link.symlink_to(str(file_a))

        approved = [str(file_a)]

        # Attacker swaps link → file_b (not approved)
        link.unlink()
        link.symlink_to(str(file_b))

        # Runner detects: resolved path (file_b) not in approved set
        evidence = _runner_revalidate_paths(
            approved_paths=approved,
            job_inputs={"target": str(link)},
            base_dir=str(workspace),
        )
        assert evidence["pathset_valid"] is False
        assert len(evidence["extra_paths"]) > 0, \
            "Runner must detect swapped symlink resolving to unapproved path"
        assert str(file_b) in evidence["extra_paths"]


# ===========================================================================
# PROBE 2: File injection between approval and execution
# ===========================================================================

class TestFileInjectionAfterApproval:
    """
    Attacker creates new files between governance approval and runner execution.

    If the runner's inputs reference the new file (or glob catches it),
    the extra path must trigger RUNNER_PATHSET_MISMATCH.
    """

    def test_extra_file_in_input_path(self, tmp_path):
        """Runner input references a file that didn't exist at governance time."""
        from services.runner.app.runner import _runner_revalidate_paths

        workspace = tmp_path / "workspace"
        workspace.mkdir()

        # Governance approved only file_a
        file_a = workspace / "file_a.txt"
        file_a.write_text("approved")
        approved = [str(file_a)]

        # Attacker creates file_b after approval
        file_b = workspace / "file_b.txt"
        file_b.write_text("injected")

        # Job input references the injected file
        evidence = _runner_revalidate_paths(
            approved_paths=approved,
            job_inputs={"source": str(file_a), "target": str(file_b)},
            base_dir=str(workspace),
        )
        assert evidence["pathset_valid"] is False
        assert "RUNNER_PATHSET_MISMATCH" in evidence["error"]

    def test_approved_file_replaced_by_different_content(self, tmp_path):
        """
        File exists at same path but runner can't detect content changes
        (that's a Layer 2 concern). This test documents the boundary:
        path revalidation passes because the *path* is unchanged.
        """
        from services.runner.app.runner import _runner_revalidate_paths

        workspace = tmp_path / "workspace"
        workspace.mkdir()

        target = workspace / "config.json"
        target.write_text('{"safe": true}')
        approved = [str(target)]

        # Attacker overwrites content (same path)
        target.write_text('{"safe": false, "exfil": "data"}')

        # Path revalidation passes — content integrity is Layer 2
        evidence = _runner_revalidate_paths(
            approved_paths=approved,
            job_inputs={"target": str(target)},
            base_dir=str(workspace),
        )
        assert evidence["pathset_valid"] is True, \
            "Path revalidation should pass (content integrity is Layer 2)"


# ===========================================================================
# PROBE 3: Glob expansion divergence
# ===========================================================================

class TestGlobExpansionDivergence:
    """
    Filesystem changes between governance glob expansion and runner re-expansion.

    runner_revalidate_glob must detect extra paths that weren't in the
    governance-approved set.
    """

    def test_file_added_between_glob_expansions(self, tmp_path):
        """
        Governance globs *.txt → {a.txt, b.txt}.
        File c.txt is created before runner re-globs.
        Runner detects c.txt as an extra (unapproved) path.
        """
        from app.governance.glob_validation import (
            governance_expand_glob,
            runner_revalidate_glob,
            GLOB_DIVERGENCE_DETECTED,
        )

        workspace = tmp_path / "workspace"
        workspace.mkdir()
        (workspace / "a.txt").write_text("a")
        (workspace / "b.txt").write_text("b")

        # Governance expands
        gov_result = governance_expand_glob("*.txt", str(workspace))
        assert gov_result.approved is True
        assert len(gov_result.canonical_paths) == 2

        # Attacker injects c.txt
        (workspace / "c.txt").write_text("injected")

        # Runner re-validates
        runner_result = runner_revalidate_glob(
            approved_paths=gov_result.canonical_paths,
            pattern="*.txt",
            base_dir=str(workspace),
        )
        assert runner_result.valid is False
        assert runner_result.deny_code == GLOB_DIVERGENCE_DETECTED
        assert len(runner_result.extra_paths) == 1

    def test_file_removed_between_glob_expansions_is_ok(self, tmp_path):
        """
        File removal between approval and execution is acceptable
        (file may have been legitimately cleaned up). Only extra files
        are dangerous.
        """
        from app.governance.glob_validation import (
            governance_expand_glob,
            runner_revalidate_glob,
        )

        workspace = tmp_path / "workspace"
        workspace.mkdir()
        (workspace / "a.txt").write_text("a")
        (workspace / "b.txt").write_text("b")

        gov_result = governance_expand_glob("*.txt", str(workspace))
        assert gov_result.approved is True

        # File removed before runner re-globs
        (workspace / "b.txt").unlink()

        runner_result = runner_revalidate_glob(
            approved_paths=gov_result.canonical_paths,
            pattern="*.txt",
            base_dir=str(workspace),
        )
        # Valid because extra_paths is empty (missing is OK)
        assert runner_result.valid is True
        assert len(runner_result.missing_paths) == 1

    def test_glob_symlink_injection(self, tmp_path):
        """
        Attacker creates a symlink in the glob directory that escapes base_dir.
        Runner's re-expansion must detect the escape.
        """
        from app.governance.glob_validation import (
            governance_expand_glob,
            runner_revalidate_glob,
            GLOB_SYMLINK_ESCAPE,
        )

        workspace = tmp_path / "workspace"
        workspace.mkdir()
        (workspace / "safe.txt").write_text("safe")

        gov_result = governance_expand_glob("*.txt", str(workspace))
        assert gov_result.approved is True

        # Attacker creates a symlink that matches *.txt but escapes
        (workspace / "escape.txt").symlink_to("/etc/passwd")

        runner_result = runner_revalidate_glob(
            approved_paths=gov_result.canonical_paths,
            pattern="*.txt",
            base_dir=str(workspace),
        )
        assert runner_result.valid is False
        assert runner_result.deny_code == GLOB_SYMLINK_ESCAPE


# ===========================================================================
# PROBE 4: Directory symlink swap escaping base_dir
# ===========================================================================

class TestDirectorySymlinkEscape:
    """
    Attacker replaces a directory with a symlink to escape base_dir.

    The path looks the same textually but realpath now resolves outside
    the approved workspace.
    """

    def test_directory_replaced_by_symlink(self, tmp_path):
        """subdir/ replaced by symlink → /tmp/evil/"""
        from services.runner.app.runner import _runner_revalidate_paths

        workspace = tmp_path / "workspace"
        subdir = workspace / "subdir"
        subdir.mkdir(parents=True)

        target = subdir / "data.txt"
        target.write_text("safe")

        approved = [str(target)]

        # Attacker replaces subdir with symlink
        evil_dir = tmp_path / "evil"
        evil_dir.mkdir()
        (evil_dir / "data.txt").write_text("malicious")

        import shutil
        shutil.rmtree(str(subdir))
        subdir.symlink_to(str(evil_dir))

        # Runner resolves the path — now points outside workspace
        evidence = _runner_revalidate_paths(
            approved_paths=approved,
            job_inputs={"target": str(workspace / "subdir" / "data.txt")},
            base_dir=str(workspace),
        )
        # Should detect: resolved path is under evil_dir, not workspace
        assert evidence["pathset_valid"] is False
        has_escape = len(evidence["symlink_escapes"]) > 0
        has_extra = len(evidence["extra_paths"]) > 0
        assert has_escape or has_extra, \
            "Runner must detect directory symlink escape"


# ===========================================================================
# PROBE 5: Symlink-to-virtual-FS pivot
# ===========================================================================

class TestSymlinkToVirtualFSPivot:
    """
    Attacker creates a symlink from an approved path to a virtual FS path.

    Even if path revalidation somehow missed this, the runner-side virtual
    FS deny must catch it as a second line of defense.
    """

    def test_symlink_to_dev_shm(self, tmp_path):
        """output.log swapped to symlink → /dev/shm/exfil"""
        from services.runner.app.runner import _runner_check_virtual_fs

        workspace = tmp_path / "workspace"
        workspace.mkdir()

        # Create symlink to /dev/shm
        link = workspace / "output.log"
        link.symlink_to("/dev/shm/exfil")

        # Virtual FS check on the resolved path
        resolved = os.path.realpath(str(link))
        result = _runner_check_virtual_fs(resolved)
        assert result is not None
        assert "RUNNER_VIRTUAL_FS_DENIED" in result

    def test_symlink_to_proc_fd(self, tmp_path):
        """Symlink to /proc/self/fd/3 (not in allowlist)."""
        from services.runner.app.runner import _runner_check_virtual_fs

        result = _runner_check_virtual_fs("/proc/self/fd/3")
        assert result is not None
        assert "RUNNER_VIRTUAL_FS_DENIED" in result

    def test_symlink_chain_to_sys(self, tmp_path):
        """Multi-hop symlink chain ending at /sys."""
        from services.runner.app.runner import _runner_check_virtual_fs

        # Even through intermediate symlinks, the resolved path is /sys/...
        result = _runner_check_virtual_fs("/sys/class/net/lo/address")
        assert result is not None
        assert "RUNNER_VIRTUAL_FS_DENIED" in result

    def test_path_revalidation_plus_vfs_double_catch(self, tmp_path):
        """
        Both defenses fire: symlink escape to /dev/shm is caught by
        path revalidation (escape) AND virtual FS deny (deny prefix).
        """
        from services.runner.app.runner import (
            _runner_revalidate_paths,
            _runner_check_virtual_fs,
        )

        workspace = tmp_path / "workspace"
        workspace.mkdir()

        link = workspace / "data.bin"
        link.symlink_to("/dev/shm/covert_channel")

        # Defense 1: path revalidation detects escape
        evidence = _runner_revalidate_paths(
            approved_paths=[],
            job_inputs={"target": str(link)},
            base_dir=str(workspace),
        )
        assert evidence["pathset_valid"] is False, \
            "Path revalidation must catch symlink to /dev/shm"

        # Defense 2: virtual FS deny also catches it
        resolved = os.path.realpath(str(link))
        vfs_result = _runner_check_virtual_fs(resolved)
        assert vfs_result is not None, \
            "Virtual FS deny must also catch /dev/shm"


# ===========================================================================
# PROBE 6: Double-fetch race simulation
# ===========================================================================

class TestDoubleFetchRace:
    """
    Simulate a race condition where two path resolutions yield different
    results. The first resolution (governance) is safe; the second
    (runner) is dangerous.

    In practice this happens with bind mounts or overlayfs changes.
    We simulate it by mocking os.path.realpath to return different values.
    """

    def test_realpath_divergence_between_governance_and_runner(self, tmp_path):
        """
        Governance resolves path → /workspace/safe.txt
        Runner resolves same path → /etc/shadow (overlay changed)
        Runner must detect the mismatch.
        """
        from services.runner.app.runner import _runner_revalidate_paths

        workspace = tmp_path / "workspace"
        workspace.mkdir()
        safe = workspace / "safe.txt"
        safe.write_text("safe")

        # Governance approved the safe resolution
        approved = [str(safe)]

        # Simulate overlay divergence: runner's realpath returns /etc/shadow
        original_realpath = os.path.realpath

        def divergent_realpath(p, *args, **kwargs):
            if str(p).endswith("safe.txt") and str(workspace) in str(p):
                return "/etc/shadow"
            return original_realpath(p, *args, **kwargs)

        with patch("services.runner.app.runner.os.path.realpath", side_effect=divergent_realpath):
            evidence = _runner_revalidate_paths(
                approved_paths=approved,
                job_inputs={"target": str(safe)},
                base_dir=str(workspace),
            )

        assert evidence["pathset_valid"] is False, \
            "Runner must detect realpath divergence (overlay/bind mount change)"

    def test_concurrent_path_operations_all_caught(self, tmp_path):
        """
        Multiple inputs, one of which diverges. The divergent one must
        be caught even if others are clean.
        """
        from services.runner.app.runner import _runner_revalidate_paths

        workspace = tmp_path / "workspace"
        workspace.mkdir()

        clean = workspace / "clean.txt"
        clean.write_text("ok")
        dirty = workspace / "dirty.txt"
        dirty.write_text("ok")

        approved = [str(clean), str(dirty)]

        # Simulate: dirty.txt resolves to outside workspace
        original_realpath = os.path.realpath

        def divergent_realpath(p, *args, **kwargs):
            if str(p).endswith("dirty.txt") and str(workspace) in str(p):
                return "/tmp/attacker_controlled"
            return original_realpath(p, *args, **kwargs)

        with patch("services.runner.app.runner.os.path.realpath", side_effect=divergent_realpath):
            evidence = _runner_revalidate_paths(
                approved_paths=approved,
                job_inputs={
                    "source": str(clean),
                    "target": str(dirty),
                },
                base_dir=str(workspace),
            )

        assert evidence["pathset_valid"] is False


# ===========================================================================
# PROBE 7: Virtual FS traversal bypass attempts
# ===========================================================================

class TestVirtualFSBypassAttempts:
    """
    Attempts to bypass virtual FS deny rules using path traversal,
    case variations, and encoding tricks.
    """

    def test_dot_dot_traversal_to_dev_shm(self):
        """Path traversal /workspace/../dev/shm must be caught."""
        from services.runner.app.runner import _runner_check_virtual_fs

        result = _runner_check_virtual_fs("/workspace/../dev/shm/exfil")
        assert result is not None
        assert "RUNNER_VIRTUAL_FS_DENIED" in result

    def test_double_slash_normalization(self):
        """/dev//shm must normalize to /dev/shm and be caught."""
        from services.runner.app.runner import _runner_check_virtual_fs

        result = _runner_check_virtual_fs("/dev//shm/test")
        assert result is not None
        assert "RUNNER_VIRTUAL_FS_DENIED" in result

    def test_trailing_slash_normalization(self):
        """/sys/ must be caught same as /sys."""
        from services.runner.app.runner import _runner_check_virtual_fs

        result = _runner_check_virtual_fs("/sys/")
        assert result is not None
        assert "RUNNER_VIRTUAL_FS_DENIED" in result

    def test_dot_in_path(self):
        """/dev/./shm must normalize and be caught."""
        from services.runner.app.runner import _runner_check_virtual_fs

        result = _runner_check_virtual_fs("/dev/./shm/test")
        assert result is not None
        assert "RUNNER_VIRTUAL_FS_DENIED" in result

    def test_proc_traversal_escape_allowlist(self):
        """/proc/self/status/../fd must resolve to /proc/self/fd (not in allowlist)."""
        from services.runner.app.runner import _runner_check_virtual_fs

        result = _runner_check_virtual_fs("/proc/self/status/../fd/3")
        assert result is not None
        assert "RUNNER_VIRTUAL_FS_DENIED" in result

    def test_governance_side_traversal(self):
        """Same traversal bypasses tested against governance-side check."""
        from app.governance.virtual_fs_deny import check_virtual_fs_access

        # All of these must be caught by governance
        bypass_attempts = [
            "/workspace/../dev/shm/exfil",
            "/dev//shm/test",
            "/sys/",
            "/dev/./shm/test",
            "/proc/self/status/../fd/3",
            "/run/./secrets/../docker.sock",
        ]
        for path in bypass_attempts:
            result = check_virtual_fs_access(path)
            assert not result.allowed, \
                f"Governance must deny traversal bypass: {path}"
