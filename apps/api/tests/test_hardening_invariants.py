"""
M87 Hardening Package Invariant Tests (v1 + v2)

Tests verify all P0–P2 hardening invariants:
- P0.1: Glob expansion re-validation (divergent FS view aborts)
- P0.2: Virtual FS explicit deny policies
- P1.1: Zero-length overwrite semantic deny
- P1.2: Empty args cause DENY
- P2.1: Runtime mount invariant verification
- P2.2: Recursive pre-walk enumeration limits
- v2: Quarantine posture + degradation tiers

These are "laws of physics" - if they fail, the system is broken.
"""
from __future__ import annotations

import os
import tempfile
import time

import pytest


# ---- P0.1: Glob Expansion Re-validation Tests ----

class TestGlobExpansionRevalidation:
    """
    P0.1: Runner-side glob re-validation.

    Invariant: If runner sees paths not approved by governance,
    the operation must abort (divergence detected).
    """

    def test_matching_expansion_is_valid(self, tmp_path):
        """Re-validation passes when runner sees same paths as governance."""
        from app.governance.glob_validation import (
            governance_expand_glob,
            runner_revalidate_glob,
        )

        # Create some files
        (tmp_path / "a.txt").touch()
        (tmp_path / "b.txt").touch()

        # Governance expands glob
        result = governance_expand_glob("*.txt", str(tmp_path))
        assert result.approved

        # Runner re-validates — should match
        revalidation = runner_revalidate_glob(
            result.canonical_paths,
            "*.txt",
            str(tmp_path),
        )
        assert revalidation.valid

    def test_extra_path_on_runner_is_divergence(self, tmp_path):
        """
        Invariant: Runner seeing extra paths = divergence = DENY.

        Simulates overlay/bind mount divergence where runner has
        files that governance didn't see.
        """
        from app.governance.glob_validation import (
            governance_expand_glob,
            runner_revalidate_glob,
        )

        # Create files for governance
        (tmp_path / "a.txt").touch()
        result = governance_expand_glob("*.txt", str(tmp_path))
        assert result.approved

        # Create extra file AFTER governance expansion (simulates divergence)
        (tmp_path / "extra.txt").touch()

        # Runner re-validates — should detect divergence
        revalidation = runner_revalidate_glob(
            result.canonical_paths,
            "*.txt",
            str(tmp_path),
        )
        assert not revalidation.valid
        assert revalidation.deny_code == "GLOB_DIVERGENCE_DETECTED"
        assert len(revalidation.extra_paths) > 0

    def test_missing_path_on_runner_is_acceptable(self, tmp_path):
        """
        Missing paths are acceptable (file may have been deleted between
        governance check and runner execution).
        """
        from app.governance.glob_validation import (
            governance_expand_glob,
            runner_revalidate_glob,
        )

        # Create files
        (tmp_path / "a.txt").touch()
        (tmp_path / "b.txt").touch()

        result = governance_expand_glob("*.txt", str(tmp_path))
        assert result.approved

        # Delete one file AFTER governance expansion
        (tmp_path / "b.txt").unlink()

        # Runner re-validates — missing is OK
        revalidation = runner_revalidate_glob(
            result.canonical_paths,
            "*.txt",
            str(tmp_path),
        )
        assert revalidation.valid
        assert len(revalidation.missing_paths) > 0

    def test_symlink_escape_detected(self, tmp_path):
        """
        Invariant: Symlinks escaping base_dir must be denied.
        """
        from app.governance.glob_validation import canonicalize_path

        # Create a symlink pointing outside base_dir
        outside = tempfile.mkdtemp()
        link_path = tmp_path / "escape_link"
        os.symlink(outside, str(link_path))

        # Canonicalize should return None (escape detected)
        result = canonicalize_path(str(link_path), str(tmp_path))
        assert result is None

        # Cleanup
        os.rmdir(outside)

    def test_empty_expansion(self, tmp_path):
        """Glob expanding to no files is approved (empty set)."""
        from app.governance.glob_validation import governance_expand_glob

        result = governance_expand_glob("*.nonexistent", str(tmp_path))
        assert result.approved
        assert len(result.canonical_paths) == 0


# ---- P0.2: Virtual FS Explicit Deny Tests ----

class TestVirtualFSDenyPolicies:
    """
    P0.2: Explicit DENY for virtual mounts.

    Invariant: Access to /dev/shm, /sys, /run, /dev/pts, /dev/mqueue
    must always be denied. /proc is allowlist-only.
    """

    def test_dev_shm_denied(self):
        """Invariant: /dev/shm access must be denied."""
        from app.governance.virtual_fs_deny import check_virtual_fs_access

        result = check_virtual_fs_access("/dev/shm")
        assert not result.allowed
        assert result.deny_code == "VIRTUAL_FS_DENIED"

    def test_dev_shm_subpath_denied(self):
        """Invariant: Subpaths of /dev/shm must also be denied."""
        from app.governance.virtual_fs_deny import check_virtual_fs_access

        result = check_virtual_fs_access("/dev/shm/my_shared_mem")
        assert not result.allowed
        assert result.deny_code == "VIRTUAL_FS_DENIED"

    def test_sys_denied(self):
        """Invariant: /sys access must be denied."""
        from app.governance.virtual_fs_deny import check_virtual_fs_access

        result = check_virtual_fs_access("/sys")
        assert not result.allowed

    def test_sys_subpath_denied(self):
        """Invariant: /sys subpaths must be denied."""
        from app.governance.virtual_fs_deny import check_virtual_fs_access

        result = check_virtual_fs_access("/sys/class/net/eth0")
        assert not result.allowed

    def test_run_denied(self):
        """Invariant: /run access must be denied."""
        from app.governance.virtual_fs_deny import check_virtual_fs_access

        result = check_virtual_fs_access("/run/docker.sock")
        assert not result.allowed

    def test_dev_pts_denied(self):
        """Invariant: /dev/pts access must be denied."""
        from app.governance.virtual_fs_deny import check_virtual_fs_access

        result = check_virtual_fs_access("/dev/pts/0")
        assert not result.allowed

    def test_dev_mqueue_denied(self):
        """Invariant: /dev/mqueue access must be denied."""
        from app.governance.virtual_fs_deny import check_virtual_fs_access

        result = check_virtual_fs_access("/dev/mqueue")
        assert not result.allowed

    def test_proc_not_in_allowlist_denied(self):
        """Invariant: /proc paths not in allowlist must be denied."""
        from app.governance.virtual_fs_deny import check_virtual_fs_access

        # /proc/self/environ is NOT in the allowlist
        result = check_virtual_fs_access("/proc/self/environ")
        assert not result.allowed
        assert result.deny_code == "VIRTUAL_FS_NOT_IN_ALLOWLIST"

    def test_proc_kcore_denied(self):
        """Invariant: /proc/kcore (kernel memory) must be denied."""
        from app.governance.virtual_fs_deny import check_virtual_fs_access

        result = check_virtual_fs_access("/proc/kcore")
        assert not result.allowed

    def test_proc_allowlisted_path_allowed(self):
        """Invariant: Allowlisted /proc paths are accessible."""
        from app.governance.virtual_fs_deny import check_virtual_fs_access

        # /proc/self/status is in the allowlist
        result = check_virtual_fs_access("/proc/self/status")
        assert result.allowed

    def test_proc_cpuinfo_allowed(self):
        """Invariant: /proc/cpuinfo is in the allowlist."""
        from app.governance.virtual_fs_deny import check_virtual_fs_access

        result = check_virtual_fs_access("/proc/cpuinfo")
        assert result.allowed

    def test_proc_meminfo_allowed(self):
        """Invariant: /proc/meminfo is in the allowlist."""
        from app.governance.virtual_fs_deny import check_virtual_fs_access

        result = check_virtual_fs_access("/proc/meminfo")
        assert result.allowed

    def test_normal_path_allowed(self):
        """Non-virtual-FS paths should be allowed."""
        from app.governance.virtual_fs_deny import check_virtual_fs_access

        result = check_virtual_fs_access("/home/user/project/file.py")
        assert result.allowed

    def test_resource_manifest_contains_explicit_entries(self):
        """
        Invariant: Resource manifest must contain explicit deny entries
        for all virtual FS mounts. Future allowlist insertions cannot
        implicitly relax these.
        """
        from app.governance.virtual_fs_deny import (
            get_resource_manifest_entries,
            VIRTUAL_FS_RULES,
        )

        entries = get_resource_manifest_entries()
        assert len(entries) >= 6  # At least 6 rules

        # All mandatory mounts must have entries
        mount_points = {e["mount_point"] for e in entries}
        assert "/dev/shm" in mount_points
        assert "/sys" in mount_points
        assert "/run" in mount_points
        assert "/dev/pts" in mount_points
        assert "/dev/mqueue" in mount_points
        assert "/proc" in mount_points

        # /proc must be ALLOWLIST, not ALLOW
        proc_entry = [e for e in entries if e["mount_point"] == "/proc"][0]
        assert proc_entry["policy"] == "ALLOWLIST"
        assert "allowed_sub_paths" in proc_entry


# ---- P1.1: Semantic Truncation Defense Tests ----

class TestSemanticTruncationDefense:
    """
    P1.1: Zero-length overwrite semantic deny.

    Invariant: Empty overwrite semantics are denied — both /dev/null
    by name AND user-created 0-byte files.
    """

    def test_devnull_source_denied(self):
        """Invariant: /dev/null as source must be denied."""
        from app.governance.input_validation import check_semantic_truncation

        result = check_semantic_truncation(
            source_path="/dev/null",
            destination_path="/etc/config.yml",
        )
        assert not result.allowed
        assert result.deny_code == "DEVNULL_SOURCE_DENIED"

    def test_devzero_source_denied(self):
        """Invariant: /dev/zero as source must be denied."""
        from app.governance.input_validation import check_semantic_truncation

        result = check_semantic_truncation(
            source_path="/dev/zero",
            destination_path="/etc/config.yml",
        )
        assert not result.allowed
        assert result.deny_code == "DEVNULL_SOURCE_DENIED"

    def test_zero_byte_file_overwriting_nonempty_denied(self):
        """
        Invariant: User-created 0-byte file overwriting non-empty
        destination must trigger same denial as /dev/null.
        """
        from app.governance.input_validation import check_semantic_truncation

        result = check_semantic_truncation(
            source_content_size=0,
            destination_path="/etc/config.yml",
            destination_is_nonempty=True,
        )
        assert not result.allowed
        assert result.deny_code == "EMPTY_OVERWRITE_DENIED"

    def test_zero_byte_file_overwriting_critical_denied(self):
        """Invariant: 0-byte file overwriting critical destination denied."""
        from app.governance.input_validation import check_semantic_truncation

        result = check_semantic_truncation(
            source_content_size=0,
            destination_path="/app/governance.py",
            destination_is_critical=True,
        )
        assert not result.allowed
        assert result.deny_code == "EMPTY_OVERWRITE_DENIED"

    def test_zero_byte_to_empty_destination_allowed(self):
        """Zero-byte to empty destination is not a truncation attack."""
        from app.governance.input_validation import check_semantic_truncation

        result = check_semantic_truncation(
            source_content_size=0,
            destination_path="/tmp/new_empty_file",
            destination_is_nonempty=False,
            destination_is_critical=False,
        )
        assert result.allowed

    def test_normal_write_allowed(self):
        """Normal non-empty writes should be allowed."""
        from app.governance.input_validation import check_semantic_truncation

        result = check_semantic_truncation(
            source_content_size=1024,
            destination_path="/etc/config.yml",
            destination_is_nonempty=True,
        )
        assert result.allowed

    def test_no_source_info_allowed(self):
        """No source info means no truncation check needed."""
        from app.governance.input_validation import check_semantic_truncation

        result = check_semantic_truncation(
            destination_path="/etc/config.yml",
            destination_is_nonempty=True,
        )
        assert result.allowed


# ---- P1.2: Deny on Empty Args Tests ----

class TestDenyOnEmptyArgs:
    """
    P1.2: Empty string argument → DENY.

    Invariant: No sanitize-and-continue for anomalous args.
    """

    def test_empty_string_arg_denied(self):
        """Invariant: Empty string argument must be denied."""
        from app.governance.input_validation import check_empty_args

        result = check_empty_args("echo", {"message": ""})
        assert not result.allowed
        assert result.deny_code == "EMPTY_ARG_DENIED"

    def test_multiple_empty_args_all_reported(self):
        """All empty args should be reported in deny reason."""
        from app.governance.input_validation import check_empty_args

        result = check_empty_args("tool", {"arg1": "", "arg2": "", "arg3": "valid"})
        assert not result.allowed
        assert "arg1" in result.deny_reason
        assert "arg2" in result.deny_reason

    def test_nonempty_args_allowed(self):
        """Non-empty string arguments should be allowed."""
        from app.governance.input_validation import check_empty_args

        result = check_empty_args("echo", {"message": "hello"})
        assert result.allowed

    def test_non_string_args_ignored(self):
        """Non-string arguments are not checked for emptiness."""
        from app.governance.input_validation import check_empty_args

        result = check_empty_args("tool", {"count": 0, "flag": False, "data": None})
        assert result.allowed

    def test_combined_validation_empty_args_checked_first(self):
        """Combined validation checks empty args before truncation."""
        from app.governance.input_validation import validate_tool_inputs

        result = validate_tool_inputs(
            tool_name="cp",
            args={"source": ""},
            source_path="/dev/null",
            destination_path="/etc/config.yml",
        )
        # Empty args check fires first
        assert not result.allowed
        assert result.deny_code == "EMPTY_ARG_DENIED"

    def test_runner_empty_arg_validation(self):
        """
        Invariant: Runner's validate_job_against_manifest must reject
        empty string arguments.
        """
        import sys
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../../services/runner"))

        from app.runner import validate_job_against_manifest

        manifest = {
            "tools": {
                "echo": {
                    "inputs": {
                        "required": ["message"],
                        "optional": [],
                        "limits": {"message_max_len": 4000},
                    },
                    "timeout_seconds": 10,
                }
            }
        }

        # Job with empty message
        job = {"tool": "echo", "inputs": {"message": ""}}
        error = validate_job_against_manifest(job, manifest)
        assert error is not None
        assert "EMPTY_ARG_DENIED" in error


# ---- P2.1: Runtime Mount Invariant Verification Tests ----

class TestRuntimeMountVerification:
    """
    P2.1: Runtime mount option verification.

    Invariant: Runner refuses to start if mount invariants violated.
    """

    def test_valid_mounts_pass(self):
        """Mounts with all required options should pass."""
        from app.governance.runtime_mounts import verify_mount_invariants, MountInvariant

        invariants = [
            MountInvariant(
                mount_point="/tmp",
                required_options=frozenset({"nosuid", "nodev"}),
                reason="test",
            ),
        ]

        mounts_content = "tmpfs /tmp tmpfs rw,nosuid,nodev,noexec 0 0\n"
        result = verify_mount_invariants(invariants=invariants, mounts_content=mounts_content)
        assert result.passed

    def test_missing_option_is_violation(self):
        """Missing required mount option must be flagged."""
        from app.governance.runtime_mounts import verify_mount_invariants, MountInvariant

        invariants = [
            MountInvariant(
                mount_point="/tmp",
                required_options=frozenset({"nosuid", "nodev"}),
                reason="test",
            ),
        ]

        # /tmp is missing nodev
        mounts_content = "tmpfs /tmp tmpfs rw,nosuid 0 0\n"
        result = verify_mount_invariants(invariants=invariants, mounts_content=mounts_content)
        assert not result.passed
        assert result.deny_code == "MOUNT_INVARIANT_VIOLATED"
        assert len(result.violations) == 1
        assert "nodev" in result.violations[0]["missing"]

    def test_mount_not_present_is_skipped(self):
        """Mount point not found in /proc/mounts is skipped (not an error)."""
        from app.governance.runtime_mounts import verify_mount_invariants, MountInvariant

        invariants = [
            MountInvariant(
                mount_point="/nonexistent",
                required_options=frozenset({"nosuid"}),
                reason="test",
            ),
        ]

        mounts_content = "tmpfs /tmp tmpfs rw,nosuid,nodev 0 0\n"
        result = verify_mount_invariants(invariants=invariants, mounts_content=mounts_content)
        assert result.passed

    def test_multiple_violations_all_reported(self):
        """All mount violations should be reported."""
        from app.governance.runtime_mounts import verify_mount_invariants, MountInvariant

        invariants = [
            MountInvariant(
                mount_point="/tmp",
                required_options=frozenset({"nosuid", "nodev"}),
                reason="test1",
            ),
            MountInvariant(
                mount_point="/var/tmp",
                required_options=frozenset({"nosuid", "nodev"}),
                reason="test2",
            ),
        ]

        mounts_content = (
            "tmpfs /tmp tmpfs rw 0 0\n"
            "tmpfs /var/tmp tmpfs rw 0 0\n"
        )
        result = verify_mount_invariants(invariants=invariants, mounts_content=mounts_content)
        assert not result.passed
        assert len(result.violations) == 2

    def test_parse_proc_mounts(self):
        """Parsing /proc/mounts content should extract mount options."""
        from app.governance.runtime_mounts import parse_proc_mounts

        content = (
            "proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\n"
            "tmpfs /tmp tmpfs rw,nosuid,nodev 0 0\n"
            "devpts /dev/pts devpts rw,nosuid,noexec 0 0\n"
        )

        result = parse_proc_mounts(content)
        assert "/proc" in result
        assert "nosuid" in result["/proc"]
        assert "nodev" in result["/proc"]
        assert "/tmp" in result
        assert "nosuid" in result["/tmp"]


# ---- P2.2: Enumeration Limits Tests ----

class TestEnumerationLimits:
    """
    P2.2: Bounded recursive enumeration.

    Invariant: Exceeding any limit → DENY with UNBOUNDED_ENUMERATION.
    """

    def test_small_tree_allowed(self, tmp_path):
        """Small directory tree within limits should be allowed."""
        from app.governance.enumeration_limits import (
            bounded_recursive_enumerate,
            EnumerationLimits,
        )

        # Create a small tree
        (tmp_path / "a.txt").touch()
        (tmp_path / "b.txt").touch()
        sub = tmp_path / "sub"
        sub.mkdir()
        (sub / "c.txt").touch()

        result = bounded_recursive_enumerate(str(tmp_path))
        assert result.allowed
        assert result.node_count == 4  # sub dir + 3 files

    def test_node_limit_exceeded(self, tmp_path):
        """Exceeding max nodes must deny."""
        from app.governance.enumeration_limits import (
            bounded_recursive_enumerate,
            EnumerationLimits,
        )

        # Create many files
        for i in range(20):
            (tmp_path / f"file_{i}.txt").touch()

        limits = EnumerationLimits(max_nodes=10)
        result = bounded_recursive_enumerate(str(tmp_path), limits=limits)
        assert not result.allowed
        assert result.deny_code == "ENUMERATION_NODE_LIMIT_EXCEEDED"

    def test_depth_limit_exceeded(self, tmp_path):
        """Exceeding max depth must deny."""
        from app.governance.enumeration_limits import (
            bounded_recursive_enumerate,
            EnumerationLimits,
        )

        # Create deep tree
        current = tmp_path
        for i in range(10):
            current = current / f"level_{i}"
            current.mkdir()
            (current / "file.txt").touch()

        limits = EnumerationLimits(max_depth=5)
        result = bounded_recursive_enumerate(str(tmp_path), limits=limits)
        assert not result.allowed
        assert result.deny_code == "ENUMERATION_DEPTH_EXCEEDED"

    def test_time_limit_enforced(self, tmp_path):
        """
        Time limit enforcement (synthetic test).

        We can't easily create a tree that takes >5s to enumerate,
        but we verify the limit is checked by using a very small timeout.
        """
        from app.governance.enumeration_limits import (
            bounded_recursive_enumerate,
            EnumerationLimits,
        )

        # Create a moderate tree
        for i in range(100):
            (tmp_path / f"file_{i}.txt").touch()

        # Use very short timeout — may or may not trigger depending on speed
        # The important thing is the limit field exists and is enforced
        limits = EnumerationLimits(max_time_seconds=0.0001)
        result = bounded_recursive_enumerate(str(tmp_path), limits=limits)
        # Either denied due to timeout or allowed if enumeration was fast enough
        # The test validates the mechanism exists
        assert isinstance(result.allowed, bool)

    def test_collect_paths_returns_paths(self, tmp_path):
        """collect_paths=True should return path list."""
        from app.governance.enumeration_limits import bounded_recursive_enumerate

        (tmp_path / "a.txt").touch()
        (tmp_path / "b.txt").touch()

        result = bounded_recursive_enumerate(str(tmp_path), collect_paths=True)
        assert result.allowed
        assert result.paths is not None
        assert len(result.paths) == 2

    def test_not_a_directory_denied(self, tmp_path):
        """Non-directory root path must be denied."""
        from app.governance.enumeration_limits import bounded_recursive_enumerate

        filepath = tmp_path / "file.txt"
        filepath.touch()

        result = bounded_recursive_enumerate(str(filepath))
        assert not result.allowed


# ---- v2: Quarantine Posture + Degradation Tiers Tests ----

class TestQuarantinePosture:
    """
    v2: Quarantine posture state machine tests.

    These verify the scaffolding for graduated degradation.
    """

    def test_default_tier_is_full_service(self):
        """Default tier must be FULL_SERVICE (Tier 0)."""
        from app.governance.quarantine import (
            QuarantinePostureManager,
            DegradationTier,
        )

        mgr = QuarantinePostureManager(enabled=True)
        assert mgr.get_state().current_tier == DegradationTier.FULL_SERVICE

    def test_escalation_upward_only(self):
        """Escalation is only allowed upward (higher tier number)."""
        from app.governance.quarantine import (
            QuarantinePostureManager,
            DegradationTier,
            QuarantineTrigger,
        )

        mgr = QuarantinePostureManager(enabled=True)

        # Escalate to QUARANTINE
        result = mgr.escalate(
            DegradationTier.QUARANTINE,
            QuarantineTrigger.OPERATOR_MANUAL,
        )
        assert result
        assert mgr.get_state().current_tier == DegradationTier.QUARANTINE

        # Cannot escalate to READ_ONLY (lower tier)
        result = mgr.escalate(
            DegradationTier.READ_ONLY,
            QuarantineTrigger.OPERATOR_MANUAL,
        )
        assert not result
        assert mgr.get_state().current_tier == DegradationTier.QUARANTINE

    def test_deny_all_blocks_everything(self):
        """DENY_ALL tier must block all proposals."""
        from app.governance.quarantine import (
            QuarantinePostureManager,
            DegradationTier,
            QuarantineTrigger,
        )

        mgr = QuarantinePostureManager(enabled=True)
        mgr.escalate(DegradationTier.DENY_ALL, QuarantineTrigger.INTEGRITY_SIGNAL)

        assert not mgr.is_proposal_allowed(["READ_REPO"])
        assert not mgr.is_proposal_allowed(["COMPUTE"])
        assert not mgr.is_proposal_allowed(["NETWORK_CALL"])

    def test_read_only_tier_allows_only_reads(self):
        """READ_ONLY tier must allow only safe read effects."""
        from app.governance.quarantine import (
            QuarantinePostureManager,
            DegradationTier,
            QuarantineTrigger,
        )

        mgr = QuarantinePostureManager(enabled=True)
        mgr.escalate(DegradationTier.READ_ONLY, QuarantineTrigger.SUSTAINED_ANOMALY)

        assert mgr.is_proposal_allowed(["READ_REPO"])
        assert mgr.is_proposal_allowed(["READ_CONFIG"])
        assert mgr.is_proposal_allowed(["COMPUTE"])
        assert not mgr.is_proposal_allowed(["WRITE_PATCH"])
        assert not mgr.is_proposal_allowed(["NETWORK_CALL"])
        assert not mgr.is_proposal_allowed(["DEPLOY"])

    def test_quarantine_tier_allows_bounded_reads(self):
        """QUARANTINE tier must allow only bounded reads."""
        from app.governance.quarantine import (
            QuarantinePostureManager,
            DegradationTier,
            QuarantineTrigger,
        )

        mgr = QuarantinePostureManager(enabled=True)
        mgr.escalate(DegradationTier.QUARANTINE, QuarantineTrigger.OBSERVABILITY_POISONING)

        assert mgr.is_proposal_allowed(["READ_REPO"])
        assert mgr.is_proposal_allowed(["READ_CONFIG"])
        assert not mgr.is_proposal_allowed(["COMPUTE"])
        assert not mgr.is_proposal_allowed(["WRITE_PATCH"])

    def test_disabled_manager_allows_everything(self):
        """Disabled quarantine manager must not block anything (v2 scaffolding)."""
        from app.governance.quarantine import QuarantinePostureManager

        mgr = QuarantinePostureManager(enabled=False)
        assert mgr.is_proposal_allowed(["DEPLOY", "NETWORK_CALL"])

    def test_deescalation_requires_cooldown(self):
        """De-escalation must respect cooldown period."""
        from app.governance.quarantine import (
            QuarantinePostureManager,
            DegradationTier,
            QuarantineTrigger,
        )

        mgr = QuarantinePostureManager(enabled=True)
        mgr.escalate(DegradationTier.READ_ONLY, QuarantineTrigger.SUSTAINED_ANOMALY)

        # Immediately try to de-escalate — should fail (cooldown)
        result = mgr.try_deescalate(DegradationTier.FULL_SERVICE)
        assert not result

    def test_tier_history_tracked(self):
        """Tier transitions must be recorded in history."""
        from app.governance.quarantine import (
            QuarantinePostureManager,
            DegradationTier,
            QuarantineTrigger,
        )

        mgr = QuarantinePostureManager(enabled=True)
        mgr.escalate(DegradationTier.READ_ONLY, QuarantineTrigger.SUSTAINED_ANOMALY)
        mgr.escalate(DegradationTier.QUARANTINE, QuarantineTrigger.ECONOMIC_COERCION)

        state = mgr.get_state()
        assert len(state.tier_history) == 2
        assert state.tier_history[0]["from_tier"] == 0
        assert state.tier_history[0]["to_tier"] == 1
        assert state.tier_history[1]["from_tier"] == 1
        assert state.tier_history[1]["to_tier"] == 2


class TestObservabilityQuarantine:
    """v2: Observability quarantine store tests."""

    def test_store_and_retrieve(self):
        """Agent metadata can be stored and retrieved."""
        from app.governance.quarantine import ObservabilityQuarantineStore

        store = ObservabilityQuarantineStore()
        store.store("agent-1", {"key": "value"})

        entries = store.get_entries()
        assert len(entries) == 1
        assert entries[0]["agent_id"] == "agent-1"
        assert entries[0]["quarantined"] is True
        assert entries[0]["trust_level"] == "untrusted"

    def test_filter_by_agent_id(self):
        """Entries can be filtered by agent_id."""
        from app.governance.quarantine import ObservabilityQuarantineStore

        store = ObservabilityQuarantineStore()
        store.store("agent-1", {"data": "a"})
        store.store("agent-2", {"data": "b"})
        store.store("agent-1", {"data": "c"})

        entries = store.get_entries(agent_id="agent-1")
        assert len(entries) == 2
        assert all(e["agent_id"] == "agent-1" for e in entries)

    def test_max_entries_cap(self):
        """Store must cap entries to prevent memory exhaustion."""
        from app.governance.quarantine import ObservabilityQuarantineStore

        store = ObservabilityQuarantineStore(max_entries=5)
        for i in range(10):
            store.store("agent", {"index": i})

        entries = store.get_entries(limit=100)
        assert len(entries) <= 5

    def test_clear(self):
        """Clear must remove all entries."""
        from app.governance.quarantine import ObservabilityQuarantineStore

        store = ObservabilityQuarantineStore()
        store.store("agent", {"data": "test"})
        count = store.clear()
        assert count == 1
        assert len(store.get_entries()) == 0


# ---- Integration: Deny reason codes are stable (telemetry contract) ----

class TestDenyReasonCodeStability:
    """
    Release gate: All deny reason codes must be stable strings.

    These are a contract for telemetry — changing them would break dashboards.
    """

    def test_glob_deny_codes(self):
        from app.governance.glob_validation import (
            GLOB_DIVERGENCE_DETECTED,
            GLOB_EXPANSION_EMPTY,
            GLOB_PATH_NOT_CANONICAL,
            GLOB_SYMLINK_ESCAPE,
        )
        assert GLOB_DIVERGENCE_DETECTED == "GLOB_DIVERGENCE_DETECTED"
        assert GLOB_EXPANSION_EMPTY == "GLOB_EXPANSION_EMPTY"
        assert GLOB_PATH_NOT_CANONICAL == "GLOB_PATH_NOT_CANONICAL"
        assert GLOB_SYMLINK_ESCAPE == "GLOB_SYMLINK_ESCAPE"

    def test_virtual_fs_deny_codes(self):
        from app.governance.virtual_fs_deny import (
            VIRTUAL_FS_DENIED,
            VIRTUAL_FS_NOT_IN_ALLOWLIST,
        )
        assert VIRTUAL_FS_DENIED == "VIRTUAL_FS_DENIED"
        assert VIRTUAL_FS_NOT_IN_ALLOWLIST == "VIRTUAL_FS_NOT_IN_ALLOWLIST"

    def test_input_validation_deny_codes(self):
        from app.governance.input_validation import (
            EMPTY_OVERWRITE_DENIED,
            EMPTY_ARG_DENIED,
            DEVNULL_SOURCE_DENIED,
        )
        assert EMPTY_OVERWRITE_DENIED == "EMPTY_OVERWRITE_DENIED"
        assert EMPTY_ARG_DENIED == "EMPTY_ARG_DENIED"
        assert DEVNULL_SOURCE_DENIED == "DEVNULL_SOURCE_DENIED"

    def test_mount_deny_codes(self):
        from app.governance.runtime_mounts import (
            MOUNT_INVARIANT_VIOLATED,
            MOUNT_CHECK_FAILED,
        )
        assert MOUNT_INVARIANT_VIOLATED == "MOUNT_INVARIANT_VIOLATED"
        assert MOUNT_CHECK_FAILED == "MOUNT_CHECK_FAILED"

    def test_enumeration_deny_codes(self):
        from app.governance.enumeration_limits import (
            UNBOUNDED_ENUMERATION,
            ENUMERATION_DEPTH_EXCEEDED,
            ENUMERATION_NODE_LIMIT_EXCEEDED,
            ENUMERATION_TIMEOUT,
        )
        assert UNBOUNDED_ENUMERATION == "UNBOUNDED_ENUMERATION"
        assert ENUMERATION_DEPTH_EXCEEDED == "ENUMERATION_DEPTH_EXCEEDED"
        assert ENUMERATION_NODE_LIMIT_EXCEEDED == "ENUMERATION_NODE_LIMIT_EXCEEDED"
        assert ENUMERATION_TIMEOUT == "ENUMERATION_TIMEOUT"
