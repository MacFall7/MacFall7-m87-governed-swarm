"""
Offline Bundle Verification — Phase 2 Tests

Tests OV_01 through OV_10 verify the offline bundle verifier produces
correct binary PASS/FAIL results for various bundle states.

These tests create synthetic bundles (tar.gz) with controlled content
and verify the OfflineVerifier produces the expected results.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import sys
import tarfile
import tempfile
from pathlib import Path

import pytest

# Ensure imports work from test directory
API_DIR = Path(__file__).parent.parent
if str(API_DIR) not in sys.path:
    sys.path.insert(0, str(API_DIR))

from app.governance.verify.offline import OfflineVerifier, VerificationReport


# ── Test Bundle Builder ──

class BundleBuilder:
    """
    Builds synthetic governance bundles (tar.gz) for testing.

    Creates a minimal valid bundle with all required artifacts,
    then allows modifications for specific test scenarios.
    """

    def __init__(self):
        self._files: dict[str, bytes] = {}
        self._receipts: list[dict] = []
        self._autonomy_budget = {
            "max_runtime_seconds": 300,
            "max_tool_calls": 50,
        }

    def with_defaults(self) -> "BundleBuilder":
        """Populate all required artifacts with valid defaults."""
        self._files["project_profile.json"] = json.dumps({
            "name": "test-project",
            "version": "1.0.0",
        }).encode()

        self._files["snapshot_manifest.json"] = json.dumps({
            "version": "1.0.0",
            "files": [
                {"path": "src/main.py", "sha256": "a" * 64},
                {"path": "src/lib.py", "sha256": "b" * 64},
            ],
        }).encode()

        self._files["skill_manifest.lock"] = json.dumps({
            "version": "1.0.0",
            "skills": {
                "code_review": {"trust_level": "TRUSTED", "version": "1.0"},
                "test_runner": {"trust_level": "TRUSTED", "version": "1.0"},
            },
        }).encode()

        self._files["context_graph.json"] = json.dumps({
            "nodes": [],
            "edges": [],
            "execution_path": [
                {"skill_id": "code_review", "step": 1},
                {"skill_id": "test_runner", "step": 2},
            ],
        }).encode()

        self._files["integration_plan.yaml"] = b"plan:\n  version: 1.0\n  steps: []\n"

        self._files["tool_contracts.json"] = json.dumps({
            "contracts": {},
        }).encode()

        self._files["patch_registry.jsonl"] = b""

        self._files["mutation_policy.yaml"] = b"policy:\n  mode: strict\n"

        self._files["bootstrap_execution_contract_v1.md"] = (
            b"# Execution Contract\n\n"
            b"## Assumptions\nNo external state.\n\n"
            b"## Constraints\nSandbox only.\n\n"
            b"## Interfaces\nCLI + API.\n\n"
            b"## Failure Modes\nHalt on error.\n\n"
            b"## Artifact Definition\nSHA-256 hashes.\n\n"
            b"## Receipt\nJSON receipt per call.\n"
        )

        return self

    def with_receipt(
        self,
        sequence: int,
        tool: str = "echo",
        outcome: str = "APPROVE",
        execution_ms: float = 10.0,
        previous_hash: str = None,
        receipt_hash: str = None,
    ) -> "BundleBuilder":
        """Add a call receipt."""
        r = {
            "receipt_version": "1.0.0",
            "sequence_number": sequence,
            "session_id": "test-session",
            "timestamp_utc": "2025-01-01T00:00:00+00:00",
            "previous_receipt_hash": previous_hash,
            "proposal": {
                "proposal_hash": hashlib.sha256(f"proposal-{sequence}".encode()).hexdigest(),
                "tool": tool,
                "operation": f"test op {sequence}",
                "args_hash": hashlib.sha256(f"args-{sequence}".encode()).hexdigest(),
                "args_redacted": False,
                "resource_paths": [],
                "effect_class": "READ_ONLY",
                "reversibility_class": None,
            },
            "decision": {
                "outcome": outcome,
                "posture_at_decision": "NORMAL",
                "risk_delta": 0.05,
                "cumulative_risk": 0.05 * (sequence + 1),
                "reason": None,
                "policy_path": "governance_gate",
            },
            "execution": {
                "result_hash": hashlib.sha256(f"result-{sequence}".encode()).hexdigest(),
                "result_size_bytes": 100,
                "execution_ms": execution_ms,
                "exit_code": 0,
                "truncated": False,
            } if outcome == "APPROVE" else None,
            "receipt_hash": receipt_hash or hashlib.sha256(
                f"receipt-{sequence}".encode()
            ).hexdigest(),
        }
        self._receipts.append(r)
        return self

    def with_valid_receipt_chain(self, count: int = 3) -> "BundleBuilder":
        """Add a chain of receipts with correct hash links."""
        prev_hash = None
        for i in range(count):
            receipt_hash = hashlib.sha256(f"receipt-{i}".encode()).hexdigest()
            self.with_receipt(
                sequence=i,
                tool="echo",
                execution_ms=10.0,
                previous_hash=prev_hash,
                receipt_hash=receipt_hash,
            )
            prev_hash = receipt_hash
        return self

    def set_budget(self, max_runtime: int = 300, max_tool_calls: int = 50) -> "BundleBuilder":
        """Set the autonomy budget in the bundle receipt."""
        self._autonomy_budget = {
            "max_runtime_seconds": max_runtime,
            "max_tool_calls": max_tool_calls,
        }
        return self

    def remove_file(self, name: str) -> "BundleBuilder":
        """Remove a file from the bundle."""
        self._files.pop(name, None)
        return self

    def remove_receipt(self, sequence: int) -> "BundleBuilder":
        """Remove a specific receipt by sequence number."""
        self._receipts = [
            r for r in self._receipts if r["sequence_number"] != sequence
        ]
        return self

    def alter_receipt(self, sequence: int, field: str, value) -> "BundleBuilder":
        """Alter a field in a specific receipt."""
        for r in self._receipts:
            if r["sequence_number"] == sequence:
                # Support nested fields like "execution.execution_ms"
                parts = field.split(".")
                target = r
                for p in parts[:-1]:
                    target = target[p]
                target[parts[-1]] = value
        return self

    def set_contract_text(self, text: str) -> "BundleBuilder":
        """Override execution contract content."""
        self._files["bootstrap_execution_contract_v1.md"] = text.encode()
        return self

    def set_skill_manifest(self, data: dict) -> "BundleBuilder":
        """Override skill manifest content."""
        self._files["skill_manifest.lock"] = json.dumps(data).encode()
        return self

    def set_context_graph(self, data: dict) -> "BundleBuilder":
        """Override context graph content."""
        self._files["context_graph.json"] = json.dumps(data).encode()
        return self

    def build(self, keyring_path: str = None) -> tuple[str, str]:
        """
        Build the bundle tar.gz and keyring. Returns (bundle_path, keyring_path).

        The signature uses a content hash (all files except bundle_signature.sig
        itself) to avoid the circular dependency of signing a bundle that
        contains its own signature.
        """
        tmpdir = tempfile.mkdtemp()

        # Add receipts to files
        for r in self._receipts:
            seq = r["sequence_number"]
            tool = r.get("proposal", {}).get("tool", "unknown")
            filename = f"call_receipts/{seq:04d}_{tool}.json"
            self._files[filename] = json.dumps(r, sort_keys=True).encode()

        # Build bundle receipt
        bundle_receipt = {
            "version": "1.0.0",
            "session_id": "test-session",
            "call_receipts_count": len(self._receipts),
            "call_receipts_hash": hashlib.sha256(
                "".join(r.get("receipt_hash", "") for r in self._receipts).encode()
            ).hexdigest() if self._receipts else None,
            "autonomy_budget": self._autonomy_budget,
        }

        # Create keyring
        if keyring_path is None:
            keyring_path = os.path.join(tmpdir, "keyring.pub")
            Path(keyring_path).write_bytes(b"test-public-key-ed25519")

        keyring_fp = hashlib.sha256(Path(keyring_path).read_bytes()).hexdigest()[:16]

        # Compute content hash (excludes bundle_receipt.json and bundle_signature.sig
        # to break the circular dependency — both reference the content hash).
        # KEEP IN SYNC: governance/verify/offline.py OfflineVerifier._HASH_EXCLUDED_FILES
        h = hashlib.sha256()
        for key in sorted(self._files.keys()):
            h.update(key.encode("utf-8"))
            h.update(self._files[key])
        content_hash = h.hexdigest()

        # Store content hash in receipt for BUNDLE_HASH_MATCH check
        bundle_receipt["bundle_sha256"] = content_hash

        # Build all contents for the tar
        all_contents: dict[str, bytes] = dict(self._files)

        # Create signature referencing the content hash
        sig = {
            "bundle_sha256": content_hash,
            "keyring_fingerprint": keyring_fp,
            "signed_at": "2025-01-01T00:00:00Z",
        }

        # Build final tar.gz
        bundle_path = os.path.join(tmpdir, "bundle.tar.gz")
        with tarfile.open(bundle_path, "w:gz") as tar:
            for name, content in all_contents.items():
                info = tarfile.TarInfo(name=name)
                info.size = len(content)
                tar.addfile(info, io.BytesIO(content))

            # Add bundle receipt
            receipt_bytes = json.dumps(bundle_receipt, sort_keys=True).encode()
            info = tarfile.TarInfo(name="bundle_receipt.json")
            info.size = len(receipt_bytes)
            tar.addfile(info, io.BytesIO(receipt_bytes))

            # Add signature
            sig_bytes = json.dumps(sig, sort_keys=True).encode()
            info = tarfile.TarInfo(name="bundle_signature.sig")
            info.size = len(sig_bytes)
            tar.addfile(info, io.BytesIO(sig_bytes))

        return bundle_path, keyring_path


# ═══════════════════════════════════════════════════════════════
# OV_01: Valid bundle passes
# ═══════════════════════════════════════════════════════════════

class TestOV01ValidBundlePasses:
    """Complete bundle with valid signature and all artifacts passes."""

    def test_valid_bundle_overall_pass(self):
        """overall == PASS. All checks status == PASS."""
        bundle_path, keyring_path = (
            BundleBuilder()
            .with_defaults()
            .with_valid_receipt_chain(3)
            .build()
        )

        verifier = OfflineVerifier()
        report = verifier.verify(bundle_path, keyring_path)

        assert report.overall == "PASS"
        assert report.report_version == "1.0.0"
        assert report.bundle_file == bundle_path
        assert len(report.bundle_hash) == 64
        assert report.duration_ms is not None
        assert report.duration_ms >= 0

        # All checks pass
        for check in report.checks:
            assert check.status == "PASS", f"Check {check.check_id} failed: {check.detail}"


# ═══════════════════════════════════════════════════════════════
# OV_02: Tampered artifact
# ═══════════════════════════════════════════════════════════════

class TestOV02TamperedArtifact:
    """Modifying context_graph.json after signing causes FAIL."""

    def test_tampered_bundle_fails(self):
        """overall == FAIL due to hash mismatch."""
        bundle_path, keyring_path = (
            BundleBuilder()
            .with_defaults()
            .with_valid_receipt_chain(2)
            .build()
        )

        # Tamper: rewrite the tar.gz with modified context_graph
        # The signature will reference the old hash
        with tarfile.open(bundle_path, "r:gz") as tar:
            members = {}
            for m in tar.getmembers():
                if m.isfile():
                    f = tar.extractfile(m)
                    if f:
                        members[m.name] = f.read()

        # Modify context_graph
        members["context_graph.json"] = json.dumps({"tampered": True}).encode()

        # Rebuild without updating signature
        with tarfile.open(bundle_path, "w:gz") as tar:
            for name, content in members.items():
                info = tarfile.TarInfo(name=name)
                info.size = len(content)
                tar.addfile(info, io.BytesIO(content))

        verifier = OfflineVerifier()
        report = verifier.verify(bundle_path, keyring_path)

        assert report.overall == "FAIL"
        # Either SIG_VALID or BUNDLE_HASH_MATCH should fail
        sig_or_hash_failed = any(
            c.check_id in ("SIG_VALID", "BUNDLE_HASH_MATCH") and c.status == "FAIL"
            for c in report.checks
        )
        assert sig_or_hash_failed


# ═══════════════════════════════════════════════════════════════
# OV_03: Missing artifact
# ═══════════════════════════════════════════════════════════════

class TestOV03MissingArtifact:
    """Missing integration_plan.yaml causes ARTIFACTS_COMPLETE to fail."""

    def test_missing_artifact_fails(self):
        """overall == FAIL. ARTIFACTS_COMPLETE fails with missing file."""
        bundle_path, keyring_path = (
            BundleBuilder()
            .with_defaults()
            .remove_file("integration_plan.yaml")
            .with_valid_receipt_chain(2)
            .build()
        )

        verifier = OfflineVerifier()
        report = verifier.verify(bundle_path, keyring_path)

        assert report.overall == "FAIL"
        artifacts_check = next(
            c for c in report.checks if c.check_id == "ARTIFACTS_COMPLETE"
        )
        assert artifacts_check.status == "FAIL"
        assert "integration_plan.yaml" in artifacts_check.detail


# ═══════════════════════════════════════════════════════════════
# OV_04: Receipt chain gap
# ═══════════════════════════════════════════════════════════════

class TestOV04ReceiptChainGap:
    """Deleting receipt for sequence 2 causes RECEIPTS_NO_GAPS to fail."""

    def test_receipt_gap_fails(self):
        """overall == FAIL. RECEIPTS_NO_GAPS fails at sequence 2."""
        builder = BundleBuilder().with_defaults().with_valid_receipt_chain(4)
        # Remove sequence 2
        builder.remove_receipt(2)
        bundle_path, keyring_path = builder.build()

        verifier = OfflineVerifier()
        report = verifier.verify(bundle_path, keyring_path)

        assert report.overall == "FAIL"
        gaps_check = next(
            c for c in report.checks if c.check_id == "RECEIPTS_NO_GAPS"
        )
        assert gaps_check.status == "FAIL"
        assert "2" in gaps_check.detail  # Reports gap at sequence 2


# ═══════════════════════════════════════════════════════════════
# OV_05: Receipt hash chain break
# ═══════════════════════════════════════════════════════════════

class TestOV05ReceiptHashChainBreak:
    """Altering previous_receipt_hash in receipt 3 breaks chain."""

    def test_chain_break_fails(self):
        """overall == FAIL. RECEIPTS_CHAIN_VALID fails."""
        builder = BundleBuilder().with_defaults().with_valid_receipt_chain(4)
        # Alter previous_receipt_hash in receipt 3
        builder.alter_receipt(3, "previous_receipt_hash", "deadbeef" * 8)
        bundle_path, keyring_path = builder.build()

        verifier = OfflineVerifier()
        report = verifier.verify(bundle_path, keyring_path)

        assert report.overall == "FAIL"
        chain_check = next(
            c for c in report.checks if c.check_id == "RECEIPTS_CHAIN_VALID"
        )
        assert chain_check.status == "FAIL"


# ═══════════════════════════════════════════════════════════════
# OV_06: Budget overflow
# ═══════════════════════════════════════════════════════════════

class TestOV06BudgetOverflow:
    """Receipts totaling 90s against 60s budget causes FAIL."""

    def test_budget_overflow_fails(self):
        """overall == FAIL. BUDGET_COMPLIANCE fails."""
        builder = BundleBuilder().with_defaults().set_budget(max_runtime=60)

        # Add receipts totaling 90s (3 x 30s)
        prev_hash = None
        for i in range(3):
            receipt_hash = hashlib.sha256(f"budget-receipt-{i}".encode()).hexdigest()
            builder.with_receipt(
                sequence=i,
                execution_ms=30000.0,  # 30 seconds each = 90s total
                previous_hash=prev_hash,
                receipt_hash=receipt_hash,
            )
            prev_hash = receipt_hash

        bundle_path, keyring_path = builder.build()

        verifier = OfflineVerifier()
        report = verifier.verify(bundle_path, keyring_path)

        assert report.overall == "FAIL"
        budget_check = next(
            c for c in report.checks if c.check_id == "BUDGET_COMPLIANCE"
        )
        assert budget_check.status == "FAIL"
        assert "90" in budget_check.detail or "exceeded" in budget_check.detail.lower()


# ═══════════════════════════════════════════════════════════════
# OV_07: Missing keyring
# ═══════════════════════════════════════════════════════════════

class TestOV07MissingKeyring:
    """Missing keyring causes SIG_VALID to FAIL (not skip)."""

    def test_missing_keyring_fails(self):
        """overall == FAIL. SIG_VALID fails. Does NOT skip."""
        bundle_path, _ = (
            BundleBuilder()
            .with_defaults()
            .with_valid_receipt_chain(2)
            .build()
        )

        verifier = OfflineVerifier()
        report = verifier.verify(bundle_path, "/nonexistent/keyring.pub")

        assert report.overall == "FAIL"
        sig_check = next(
            c for c in report.checks if c.check_id == "SIG_VALID"
        )
        assert sig_check.status == "FAIL"  # FAIL, not SKIPPED
        assert "not found" in sig_check.detail.lower() or "keyring" in sig_check.detail.lower()


# ═══════════════════════════════════════════════════════════════
# OV_08: Known limitations listed
# ═══════════════════════════════════════════════════════════════

class TestOV08KnownLimitationsListed:
    """Report includes known limitations."""

    def test_known_limitations_present(self):
        """known_limitations is non-empty and contains expected entries."""
        bundle_path, keyring_path = (
            BundleBuilder()
            .with_defaults()
            .with_valid_receipt_chain(2)
            .build()
        )

        verifier = OfflineVerifier()
        report = verifier.verify(bundle_path, keyring_path)

        assert len(report.known_limitations) > 0

        limitations_text = " ".join(report.known_limitations).lower()
        assert "nonce monotonicity" in limitations_text
        assert "snapshot freshness" in limitations_text
        assert "governance service" in limitations_text


# ═══════════════════════════════════════════════════════════════
# OV_09: UNTRUSTED skill in execution path
# ═══════════════════════════════════════════════════════════════

class TestOV09UntrustedSkillInExecution:
    """UNTRUSTED skill in execution path causes NO_UNTRUSTED_EXEC to fail."""

    def test_untrusted_skill_fails(self):
        """overall == FAIL. NO_UNTRUSTED_EXEC fails."""
        builder = BundleBuilder().with_defaults().with_valid_receipt_chain(2)

        # Add untrusted skill to manifest
        builder.set_skill_manifest({
            "version": "1.0.0",
            "skills": {
                "code_review": {"trust_level": "TRUSTED", "version": "1.0"},
                "evil_plugin": {"trust_level": "UNTRUSTED", "version": "0.1"},
            },
        })

        # Use untrusted skill in execution path
        builder.set_context_graph({
            "nodes": [],
            "edges": [],
            "execution_path": [
                {"skill_id": "code_review", "step": 1},
                {"skill_id": "evil_plugin", "step": 2},  # UNTRUSTED!
            ],
        })

        bundle_path, keyring_path = builder.build()

        verifier = OfflineVerifier()
        report = verifier.verify(bundle_path, keyring_path)

        assert report.overall == "FAIL"
        untrusted_check = next(
            c for c in report.checks if c.check_id == "NO_UNTRUSTED_EXEC"
        )
        assert untrusted_check.status == "FAIL"
        assert "evil_plugin" in untrusted_check.detail


# ═══════════════════════════════════════════════════════════════
# OV_10: Contract incomplete
# ═══════════════════════════════════════════════════════════════

class TestOV10ContractIncomplete:
    """Missing failure_modes section causes CONTRACT_COMPLETE to fail."""

    def test_incomplete_contract_fails(self):
        """overall == FAIL. CONTRACT_COMPLETE fails with missing section."""
        builder = BundleBuilder().with_defaults().with_valid_receipt_chain(2)

        # Contract missing "failure_modes" section
        builder.set_contract_text(
            "# Execution Contract\n\n"
            "## Assumptions\nNo external state.\n\n"
            "## Constraints\nSandbox only.\n\n"
            "## Interfaces\nCLI + API.\n\n"
            # "## Failure Modes\n" — deliberately missing
            "## Artifact Definition\nSHA-256 hashes.\n\n"
            "## Receipt\nJSON receipt per call.\n"
        )

        bundle_path, keyring_path = builder.build()

        verifier = OfflineVerifier()
        report = verifier.verify(bundle_path, keyring_path)

        assert report.overall == "FAIL"
        contract_check = next(
            c for c in report.checks if c.check_id == "CONTRACT_COMPLETE"
        )
        assert contract_check.status == "FAIL"
        assert "failure_modes" in contract_check.detail
