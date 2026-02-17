"""
M87 Layer 0 Closure Tests — Unauthorized Execution Prevention

These tests prove that Layer 0 gaps identified in the audit are now closed:

1. Virtual FS deny is enforced in govern_proposal (not just defined)
2. Runner-side path revalidation catches TOCTOU divergence
3. Runner-side virtual FS deny blocks dangerous paths at execution
4. Runner boot checks refuse start on namespace/capability violations

Red team probes:
- Proposal targeting /dev/shm → DENY at governance level
- Proposal targeting /proc/self/fd → DENY at governance level
- Runner resolves extra path not in approved set → RUNNER_PATHSET_MISMATCH
- Runner blocks /sys input → RUNNER_VIRTUAL_FS_DENIED
- Runner refuses boot with non-loopback interfaces
- Runner refuses boot with dangerous capabilities

These are "laws of physics" — if they fail, Layer 0 is broken.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Add repo root to path so we can import runner code
_REPO_ROOT = str(Path(__file__).parent.parent.parent.parent)
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)


# ===========================================================================
# FIX 1: Virtual FS deny enforced at API governance level
# ===========================================================================

class TestVirtualFSDenyInGovernance:
    """Prove check_virtual_fs_access() is called during proposal evaluation."""

    @pytest.fixture
    def mock_redis(self):
        mock = MagicMock()
        mock.ping.return_value = True
        mock.xadd.return_value = "mock-event-id"
        mock.hgetall.return_value = {}
        mock.get.return_value = None
        mock.set.return_value = True
        mock.zrangebyscore.return_value = []
        mock.zadd.return_value = 1
        mock.expire.return_value = True
        return mock

    @pytest.fixture
    def client(self, mock_redis):
        from app.auth import AuthDecision, AuthReasonCode
        from fastapi.testclient import TestClient

        mock_key_store = MagicMock()
        mock_rate_limiter = MagicMock()
        mock_rl_result = MagicMock()
        mock_rl_result.allowed = True
        mock_rate_limiter.check_rate_limit.return_value = mock_rl_result

        with patch("app.main.rdb", mock_redis), \
             patch("app.main.key_store", mock_key_store), \
             patch("app.main.key_verifier") as mock_verifier, \
             patch("app.main.rate_limiter", mock_rate_limiter), \
             patch("app.main._db_available", True), \
             patch("app.main.persist_proposal"), \
             patch("app.main.persist_decision"), \
             patch("app.main.persist_job"), \
             patch("app.main.enqueue_job") as mock_enqueue:

            mock_enqueue.return_value = "mock-job-id"

            def mock_verify(plaintext_key, endpoint_scope, requested_effects=None, risk_score=None):
                if plaintext_key == "test-key":
                    return AuthDecision(
                        allowed=True,
                        key_id="key_bootstrap",
                        principal_type="admin",
                        principal_id="bootstrap",
                        reason="Authorized",
                        reason_code=AuthReasonCode.ALLOWED,
                    )
                return AuthDecision(
                    allowed=False,
                    key_id=None,
                    principal_type=None,
                    principal_id=None,
                    reason="Invalid key",
                    reason_code=AuthReasonCode.INVALID_KEY,
                )

            mock_verifier.verify.side_effect = mock_verify

            from app.main import app
            yield TestClient(app)

    def _make_proposal(self, artifacts, effects=None):
        return {
            "proposal_id": "test-vfs-proposal",
            "intent_id": "test-intent",
            "agent": "Casey",
            "summary": "Test proposal",
            "effects": effects or ["READ_REPO"],
            "truth_account": {
                "observations": ["unit test observation"],
                "claims": [{"claim": "testing", "confidence": 0.9}],
            },
            "risk_score": 0.1,
            "artifacts": artifacts,
        }

    def test_proposal_with_dev_shm_path_denied(self, client):
        """Proposal targeting /dev/shm MUST be denied at governance level."""
        response = client.post(
            "/v1/govern/proposal",
            headers={"X-M87-Key": "test-key"},
            json=self._make_proposal([{"path": "/dev/shm/exploit"}]),
        )
        assert response.status_code == 200
        data = response.json()
        assert data["decision"] == "DENY"
        assert any("VIRTUAL_FS" in r for r in data["reasons"])

    def test_proposal_with_proc_self_fd_denied(self, client):
        """Proposal targeting /proc/self/fd MUST be denied (not in allowlist)."""
        response = client.post(
            "/v1/govern/proposal",
            headers={"X-M87-Key": "test-key"},
            json=self._make_proposal([{"path": "/proc/self/fd/3"}]),
        )
        assert response.status_code == 200
        data = response.json()
        assert data["decision"] == "DENY"
        assert any("VIRTUAL_FS" in r for r in data["reasons"])

    def test_proposal_with_sys_path_denied(self, client):
        """/sys is explicitly denied — no sysfs access."""
        response = client.post(
            "/v1/govern/proposal",
            headers={"X-M87-Key": "test-key"},
            json=self._make_proposal([{"path": "/sys/kernel/debug"}]),
        )
        assert response.status_code == 200
        data = response.json()
        assert data["decision"] == "DENY"

    def test_proposal_with_dev_mqueue_denied(self, client):
        """/dev/mqueue is explicitly denied."""
        response = client.post(
            "/v1/govern/proposal",
            headers={"X-M87-Key": "test-key"},
            json=self._make_proposal([{"source": "/dev/mqueue/covert"}]),
        )
        assert response.status_code == 200
        data = response.json()
        assert data["decision"] == "DENY"

    def test_proposal_with_safe_path_not_denied(self, client):
        """Normal paths should pass virtual FS check."""
        response = client.post(
            "/v1/govern/proposal",
            headers={"X-M87-Key": "test-key"},
            json=self._make_proposal([{"path": "/home/user/code/main.py"}]),
        )
        assert response.status_code == 200
        data = response.json()
        # May be APPROVE or REQUIRE_HUMAN, but NOT denied by virtual FS
        assert data["decision"] != "DENY" or not any("VIRTUAL_FS" in r for r in data["reasons"])

    def test_proposal_with_proc_allowlisted_path_passes(self, client):
        """/proc/cpuinfo is in the allowlist — should pass FS check."""
        response = client.post(
            "/v1/govern/proposal",
            headers={"X-M87-Key": "test-key"},
            json=self._make_proposal([{"path": "/proc/cpuinfo"}]),
        )
        data = response.json()
        # Should not be denied by virtual FS (may be denied by other rules)
        if data["decision"] == "DENY":
            assert not any("VIRTUAL_FS" in r for r in data["reasons"])

    def test_proposal_artifact_destination_checked(self, client):
        """Destination paths in artifacts are also checked."""
        response = client.post(
            "/v1/govern/proposal",
            headers={"X-M87-Key": "test-key"},
            json=self._make_proposal([{"destination": "/dev/shm/write_here"}]),
        )
        assert response.status_code == 200
        data = response.json()
        assert data["decision"] == "DENY"
        assert any("VIRTUAL_FS" in r for r in data["reasons"])

    def test_proposal_with_no_artifacts_passes_fs_check(self, client):
        """Proposals without artifacts skip FS check (nothing to check)."""
        response = client.post(
            "/v1/govern/proposal",
            headers={"X-M87-Key": "test-key"},
            json=self._make_proposal(None),
        )
        data = response.json()
        # Should not be denied by virtual FS
        if data["decision"] == "DENY":
            assert not any("VIRTUAL_FS" in r for r in data["reasons"])


# ===========================================================================
# FIX 2: Runner-side path revalidation
# ===========================================================================

class TestRunnerPathRevalidation:
    """Prove runner catches TOCTOU divergence via path revalidation."""

    def test_no_approved_paths_passes(self):
        """Jobs without approved_paths skip revalidation (no paths to check)."""
        from services.runner.app.runner import _runner_revalidate_paths

        evidence = _runner_revalidate_paths(
            approved_paths=[],
            job_inputs={"message": "hello"},
        )
        assert evidence["pathset_valid"] is True

    def test_matching_paths_pass(self, tmp_path):
        """When resolved paths match approved set, revalidation passes."""
        from services.runner.app.runner import _runner_revalidate_paths

        test_file = tmp_path / "safe.txt"
        test_file.touch()

        evidence = _runner_revalidate_paths(
            approved_paths=[str(test_file)],
            job_inputs={"target": str(test_file)},
            base_dir=str(tmp_path),
        )
        assert evidence["pathset_valid"] is True

    def test_extra_path_detected(self, tmp_path):
        """Runner resolves a path not in approved set → MISMATCH."""
        from services.runner.app.runner import _runner_revalidate_paths

        approved = tmp_path / "approved.txt"
        approved.touch()
        extra = tmp_path / "secret.txt"
        extra.touch()

        evidence = _runner_revalidate_paths(
            approved_paths=[str(approved)],
            job_inputs={"target": str(extra)},
            base_dir=str(tmp_path),
        )
        assert evidence["pathset_valid"] is False
        assert len(evidence["extra_paths"]) > 0
        assert "RUNNER_PATHSET_MISMATCH" in evidence["error"]

    def test_symlink_escape_detected(self, tmp_path):
        """Symlink pointing outside base_dir → abort."""
        from services.runner.app.runner import _runner_revalidate_paths

        # Create symlink escaping base_dir
        escape_link = tmp_path / "escape"
        escape_link.symlink_to("/etc/passwd")

        evidence = _runner_revalidate_paths(
            approved_paths=[],
            job_inputs={"target": str(escape_link)},
            base_dir=str(tmp_path),
        )
        assert evidence["pathset_valid"] is False
        assert len(evidence["symlink_escapes"]) > 0

    def test_non_path_inputs_ignored(self):
        """Non-path inputs (no slashes) are not checked."""
        from services.runner.app.runner import _runner_revalidate_paths

        evidence = _runner_revalidate_paths(
            approved_paths=[],
            job_inputs={"message": "hello world", "count": "42"},
        )
        assert evidence["pathset_valid"] is True


# ===========================================================================
# FIX 2 cont: Runner-side virtual FS deny
# ===========================================================================

class TestRunnerVirtualFSDeny:
    """Prove runner independently blocks virtual FS paths."""

    def test_runner_denies_dev_shm(self):
        """Runner blocks /dev/shm at execution level."""
        from services.runner.app.runner import _runner_check_virtual_fs

        result = _runner_check_virtual_fs("/dev/shm/exploit")
        assert result is not None
        assert "RUNNER_VIRTUAL_FS_DENIED" in result

    def test_runner_denies_sys(self):
        """Runner blocks /sys at execution level."""
        from services.runner.app.runner import _runner_check_virtual_fs

        result = _runner_check_virtual_fs("/sys/kernel/debug")
        assert result is not None
        assert "RUNNER_VIRTUAL_FS_DENIED" in result

    def test_runner_denies_proc_not_in_allowlist(self):
        """Runner blocks /proc paths not in allowlist."""
        from services.runner.app.runner import _runner_check_virtual_fs

        result = _runner_check_virtual_fs("/proc/self/fd/3")
        assert result is not None
        assert "RUNNER_VIRTUAL_FS_DENIED" in result

    def test_runner_allows_proc_mounts(self):
        """Runner allows /proc/mounts (in allowlist for mount checks)."""
        from services.runner.app.runner import _runner_check_virtual_fs

        result = _runner_check_virtual_fs("/proc/mounts")
        assert result is None

    def test_runner_allows_normal_path(self):
        """Runner allows normal filesystem paths."""
        from services.runner.app.runner import _runner_check_virtual_fs

        result = _runner_check_virtual_fs("/home/user/code/main.py")
        assert result is None

    def test_runner_denies_run(self):
        """Runner blocks /run at execution level."""
        from services.runner.app.runner import _runner_check_virtual_fs

        result = _runner_check_virtual_fs("/run/secrets/key")
        assert result is not None


# ===========================================================================
# FIX 3: Runner boot invariant checks
# ===========================================================================

class TestRunnerNetworkNamespaceCheck:
    """Prove runner refuses boot with non-loopback interfaces."""

    def test_only_loopback_passes(self, tmp_path):
        """Only 'lo' interface → passes."""
        from services.runner.app.runner import _verify_network_namespace

        net_dir = tmp_path / "sys" / "class" / "net" / "lo"
        net_dir.mkdir(parents=True)

        with patch.dict(os.environ, {"M87_NETWORK_CHECK_ENABLED": "1"}):
            with patch("services.runner.app.runner.os.path.exists", return_value=True):
                with patch("services.runner.app.runner.os.listdir", return_value=["lo"]):
                    _verify_network_namespace()  # Should not raise

    def test_extra_interface_crashes(self):
        """Non-loopback interface (eth0) → RuntimeError."""
        from services.runner.app.runner import _verify_network_namespace

        with patch.dict(os.environ, {"M87_NETWORK_CHECK_ENABLED": "1"}):
            with patch("services.runner.app.runner.os.path.exists", return_value=True):
                with patch("services.runner.app.runner.os.listdir", return_value=["lo", "eth0"]):
                    with pytest.raises(RuntimeError, match="RUNNER_NAMESPACE_VIOLATION"):
                        _verify_network_namespace()

    def test_disabled_by_default(self):
        """Check is disabled by default (M87_NETWORK_CHECK_ENABLED != 1)."""
        from services.runner.app.runner import _verify_network_namespace

        with patch.dict(os.environ, {"M87_NETWORK_CHECK_ENABLED": "0"}):
            _verify_network_namespace()  # Should not raise


class TestRunnerCapabilityCheck:
    """Prove runner refuses boot with dangerous capabilities."""

    def _make_status(self, cap_eff_hex):
        return (
            f"Name:\trunner\n"
            f"Umask:\t0022\n"
            f"State:\tS (sleeping)\n"
            f"CapInh:\t0000000000000000\n"
            f"CapPrm:\t{cap_eff_hex}\n"
            f"CapEff:\t{cap_eff_hex}\n"
            f"CapBnd:\t{cap_eff_hex}\n"
        )

    def test_no_dangerous_caps_passes(self):
        """Zero effective caps → passes."""
        from services.runner.app.runner import _verify_capabilities_dropped

        with patch.dict(os.environ, {"M87_CAP_CHECK_ENABLED": "1"}):
            with patch("builtins.open", create=True) as mock_open:
                mock_open.return_value.__enter__ = lambda s: s
                mock_open.return_value.__exit__ = MagicMock(return_value=False)
                mock_open.return_value.read.return_value = self._make_status("0000000000000000")
                _verify_capabilities_dropped()  # Should not raise

    def test_cap_sys_admin_crashes(self):
        """CAP_SYS_ADMIN (bit 21) present → RuntimeError."""
        from services.runner.app.runner import _verify_capabilities_dropped

        # Bit 21 = 0x200000
        with patch.dict(os.environ, {"M87_CAP_CHECK_ENABLED": "1"}):
            with patch("builtins.open", create=True) as mock_open:
                mock_open.return_value.__enter__ = lambda s: s
                mock_open.return_value.__exit__ = MagicMock(return_value=False)
                mock_open.return_value.read.return_value = self._make_status("0000000000200000")
                with pytest.raises(RuntimeError, match="RUNNER_CAPABILITY_VIOLATION"):
                    _verify_capabilities_dropped()

    def test_cap_net_raw_crashes(self):
        """CAP_NET_RAW (bit 13) present → RuntimeError."""
        from services.runner.app.runner import _verify_capabilities_dropped

        # Bit 13 = 0x2000
        with patch.dict(os.environ, {"M87_CAP_CHECK_ENABLED": "1"}):
            with patch("builtins.open", create=True) as mock_open:
                mock_open.return_value.__enter__ = lambda s: s
                mock_open.return_value.__exit__ = MagicMock(return_value=False)
                mock_open.return_value.read.return_value = self._make_status("0000000000002000")
                with pytest.raises(RuntimeError, match="RUNNER_CAPABILITY_VIOLATION"):
                    _verify_capabilities_dropped()

    def test_disabled_by_default(self):
        """Check is disabled by default."""
        from services.runner.app.runner import _verify_capabilities_dropped

        with patch.dict(os.environ, {"M87_CAP_CHECK_ENABLED": "0"}):
            _verify_capabilities_dropped()  # Should not raise

    def test_multiple_dangerous_caps(self):
        """Multiple dangerous caps listed in violation."""
        from services.runner.app.runner import _verify_capabilities_dropped

        # CAP_SYS_ADMIN (21) + CAP_NET_RAW (13) = 0x202000
        with patch.dict(os.environ, {"M87_CAP_CHECK_ENABLED": "1"}):
            with patch("builtins.open", create=True) as mock_open:
                mock_open.return_value.__enter__ = lambda s: s
                mock_open.return_value.__exit__ = MagicMock(return_value=False)
                mock_open.return_value.read.return_value = self._make_status("0000000000202000")
                with pytest.raises(RuntimeError, match="RUNNER_CAPABILITY_VIOLATION"):
                    _verify_capabilities_dropped()
