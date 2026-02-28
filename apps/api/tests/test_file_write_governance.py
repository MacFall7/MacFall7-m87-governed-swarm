"""
Governed file_write Tool — Invariant Tests

Tests for the first effectful tool in the M87 runner:
- Sandbox containment (traversal, absolute paths, null bytes, dot paths)
- Input validation (manifest enforcement, required/optional/limits)
- Execution modes (draft, preview, commit)
- Artifacts (receipts, file hashes)
- Write scope gating
- Reversibility gate interaction
- Mode manifest enforcement

These tests validate that file_write respects all governance invariants
independently of the governance API.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

# Ensure imports work from test directory
RUNNER_DIR = Path(__file__).parent.parent.parent.parent / "services" / "runner"
if str(RUNNER_DIR) not in sys.path:
    sys.path.insert(0, str(RUNNER_DIR))

from app.runner import (
    _resolve_sandbox_path,
    tool_file_write,
    validate_job_against_manifest,
    execute_job,
    load_manifest,
    TOOL_WRITE_SCOPE_REQUIREMENTS,
    scope_rank,
    verify_reversibility_gate,
    verify_execution_mode,
    REVERSIBILITY_REVERSIBLE,
    REVERSIBILITY_PARTIAL,
    REVERSIBILITY_IRREVERSIBLE,
)


# ═══════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════

def _load_test_manifest():
    """Load the actual tool_manifest.json for validation tests."""
    manifest_path = RUNNER_DIR / "app" / "tool_manifest.json"
    return load_manifest(str(manifest_path))


def _make_file_write_job(
    path="hello.txt",
    content="hello world",
    mode=None,
    execution_mode="commit",
    manifest_hash=None,
    envelope_hash=None,
    deployment_envelope=None,
    max_write_scope="sandbox",
    reversibility_class=None,
    rollback_proof=None,
    human_approved=False,
):
    """Build a minimal file_write job for testing."""
    inputs = {"path": path, "content": content}
    if mode is not None:
        inputs["mode"] = mode

    job = {
        "job_id": "test-fw-001",
        "proposal_id": "prop-fw-001",
        "tool": "file_write",
        "inputs": inputs,
        "execution_mode": execution_mode,
        "manifest_hash": manifest_hash,
        "effect_schema_version": "1.0.0",
    }

    if reversibility_class is not None:
        job["reversibility_class"] = reversibility_class
    if rollback_proof is not None:
        job["rollback_proof"] = rollback_proof
    if human_approved:
        job["human_approved"] = True

    # Build deployment envelope
    envelope = deployment_envelope or {
        "model_source": "closed",
        "safety_mode": "safe_default",
        "autonomy_budget": {
            "max_steps": 100,
            "max_tool_calls": 50,
            "max_runtime_seconds": 300,
            "max_external_io": 10,
            "max_write_scope": max_write_scope,
        },
    }
    job["deployment_envelope"] = envelope

    # Compute envelope hash
    from app.runner import compute_envelope_hash, _exclude_none_recursive
    clean = _exclude_none_recursive(envelope)
    job["envelope_hash"] = compute_envelope_hash(envelope)

    return job


# ═══════════════════════════════════════════════════════════════
# TestSandboxContainment (8 tests)
# ═══════════════════════════════════════════════════════════════

class TestSandboxContainment:
    """Sandbox path resolution rejects escapes and dangerous paths."""

    def test_simple_relative_path(self, tmp_path):
        """Simple relative path resolves inside sandbox."""
        result = _resolve_sandbox_path("hello.txt", str(tmp_path))
        assert result.startswith(str(tmp_path))
        assert result.endswith("hello.txt")

    def test_subdirectory_path(self, tmp_path):
        """Nested path resolves inside sandbox."""
        result = _resolve_sandbox_path("sub/dir/file.txt", str(tmp_path))
        assert result.startswith(str(tmp_path))
        assert "sub/dir/file.txt" in result

    def test_traversal_escape_denied(self, tmp_path):
        """Path traversal (../) is detected and rejected."""
        with pytest.raises(ValueError, match="SANDBOX_ESCAPE"):
            _resolve_sandbox_path("../../etc/passwd", str(tmp_path))

    def test_double_traversal_denied(self, tmp_path):
        """Deep traversal (../../../../) is detected and rejected."""
        with pytest.raises(ValueError, match="SANDBOX_ESCAPE"):
            _resolve_sandbox_path("../../../../etc/shadow", str(tmp_path))

    def test_absolute_path_denied(self, tmp_path):
        """Absolute paths are rejected."""
        with pytest.raises(ValueError, match="SANDBOX_ABSOLUTE_PATH"):
            _resolve_sandbox_path("/etc/passwd", str(tmp_path))

    def test_null_byte_denied(self, tmp_path):
        """Null byte injection is detected and rejected."""
        with pytest.raises(ValueError, match="SANDBOX_NULL_BYTE"):
            _resolve_sandbox_path("hello\x00.txt", str(tmp_path))

    def test_dot_path_stays_in_sandbox(self, tmp_path):
        """Single dot (.) resolves to sandbox root."""
        result = _resolve_sandbox_path(".", str(tmp_path))
        assert os.path.realpath(result) == os.path.realpath(str(tmp_path))

    def test_dot_dot_at_root_denied(self, tmp_path):
        """../file at sandbox root escapes."""
        with pytest.raises(ValueError, match="SANDBOX_ESCAPE"):
            _resolve_sandbox_path("../outside.txt", str(tmp_path))


# ═══════════════════════════════════════════════════════════════
# TestFileWriteInputValidation (11 tests)
# ═══════════════════════════════════════════════════════════════

class TestFileWriteInputValidation:
    """Manifest-based input validation for file_write tool."""

    def test_file_write_in_manifest(self):
        """file_write is declared in tool_manifest.json."""
        manifest = _load_test_manifest()
        assert "file_write" in manifest.get("tools", {})

    def test_required_inputs_path_and_content(self):
        """path and content are required inputs."""
        manifest = _load_test_manifest()
        spec = manifest["tools"]["file_write"]["inputs"]
        assert "path" in spec["required"]
        assert "content" in spec["required"]

    def test_mode_is_optional(self):
        """mode is an optional input."""
        manifest = _load_test_manifest()
        spec = manifest["tools"]["file_write"]["inputs"]
        assert "mode" in spec["optional"]

    def test_missing_path_rejected(self):
        """Missing required 'path' input is rejected."""
        manifest = _load_test_manifest()
        job = {"tool": "file_write", "inputs": {"content": "hello"}}
        err = validate_job_against_manifest(job, manifest)
        assert err is not None
        assert "path" in err

    def test_missing_content_rejected(self):
        """Missing required 'content' input is rejected."""
        manifest = _load_test_manifest()
        job = {"tool": "file_write", "inputs": {"path": "test.txt"}}
        err = validate_job_against_manifest(job, manifest)
        assert err is not None
        assert "content" in err

    def test_unexpected_key_rejected(self):
        """Unexpected input key is rejected (strict)."""
        manifest = _load_test_manifest()
        job = {"tool": "file_write", "inputs": {"path": "t.txt", "content": "x", "evil": "y"}}
        err = validate_job_against_manifest(job, manifest)
        assert err is not None
        assert "Unexpected" in err

    def test_empty_path_rejected(self):
        """Empty string path is rejected (P1.2 empty arg deny)."""
        manifest = _load_test_manifest()
        job = {"tool": "file_write", "inputs": {"path": "", "content": "hello"}}
        err = validate_job_against_manifest(job, manifest)
        assert err is not None
        assert "EMPTY_ARG" in err

    def test_empty_content_rejected(self):
        """Empty string content is rejected (P1.2 empty arg deny)."""
        manifest = _load_test_manifest()
        job = {"tool": "file_write", "inputs": {"path": "test.txt", "content": ""}}
        err = validate_job_against_manifest(job, manifest)
        assert err is not None
        assert "EMPTY_ARG" in err

    def test_path_exceeds_max_length(self):
        """Path exceeding limit is rejected."""
        manifest = _load_test_manifest()
        long_path = "a" * 600
        job = {"tool": "file_write", "inputs": {"path": long_path, "content": "x"}}
        err = validate_job_against_manifest(job, manifest)
        assert err is not None
        assert "max length" in err

    def test_content_exceeds_max_length(self):
        """Content exceeding limit is rejected."""
        manifest = _load_test_manifest()
        big_content = "x" * 70000
        job = {"tool": "file_write", "inputs": {"path": "t.txt", "content": big_content}}
        err = validate_job_against_manifest(job, manifest)
        assert err is not None
        assert "max length" in err

    def test_invalid_mode_rejected(self):
        """Invalid mode value is rejected."""
        manifest = _load_test_manifest()
        job = {"tool": "file_write", "inputs": {"path": "t.txt", "content": "x", "mode": "destroy"}}
        err = validate_job_against_manifest(job, manifest)
        assert err is not None
        assert "mode" in err


# ═══════════════════════════════════════════════════════════════
# TestFileWriteExecutionModes (6 tests)
# ═══════════════════════════════════════════════════════════════

class TestFileWriteExecutionModes:
    """Three execution modes: draft, preview, commit."""

    def test_draft_writes_nothing(self, tmp_path):
        """Draft mode validates but does not write any file."""
        result = tool_file_write("test.txt", "hello", mode="draft", sandbox_root=str(tmp_path))
        assert result["exit_code"] == 0
        assert result["mode"] == "draft"
        assert not (tmp_path / "test.txt").exists()
        assert result["content_hash"] == hashlib.sha256(b"hello").hexdigest()

    def test_preview_writes_preview_suffix(self, tmp_path):
        """Preview mode writes to {path}.preview."""
        result = tool_file_write("test.txt", "hello", mode="preview", sandbox_root=str(tmp_path))
        assert result["exit_code"] == 0
        assert result["mode"] == "preview"
        assert not (tmp_path / "test.txt").exists()
        preview_path = tmp_path / "test.txt.preview"
        assert preview_path.exists()
        assert preview_path.read_text() == "hello"

    def test_commit_writes_and_verifies(self, tmp_path):
        """Commit mode writes file and verifies content hash."""
        result = tool_file_write("test.txt", "hello world", mode="commit", sandbox_root=str(tmp_path))
        assert result["exit_code"] == 0
        assert result["mode"] == "commit"
        assert (tmp_path / "test.txt").exists()
        assert (tmp_path / "test.txt").read_text() == "hello world"
        assert result["content_hash"] == result["verify_hash"]

    def test_commit_creates_subdirectories(self, tmp_path):
        """Commit mode creates intermediate directories."""
        result = tool_file_write("sub/dir/file.txt", "content", mode="commit", sandbox_root=str(tmp_path))
        assert result["exit_code"] == 0
        assert (tmp_path / "sub" / "dir" / "file.txt").exists()
        assert (tmp_path / "sub" / "dir" / "file.txt").read_text() == "content"

    def test_traversal_denied_at_execution(self, tmp_path):
        """Path traversal is caught at execution time."""
        result = tool_file_write("../../escape.txt", "evil", mode="commit", sandbox_root=str(tmp_path))
        assert result["exit_code"] == -1
        assert "sandbox_containment" in result.get("error", "")

    def test_default_mode_is_commit(self, tmp_path):
        """Default mode (when not specified) is commit."""
        result = tool_file_write("default.txt", "test", sandbox_root=str(tmp_path))
        assert result["exit_code"] == 0
        assert result["mode"] == "commit"
        assert (tmp_path / "default.txt").exists()


# ═══════════════════════════════════════════════════════════════
# TestFileWriteArtifacts (3 tests)
# ═══════════════════════════════════════════════════════════════

class TestFileWriteArtifacts:
    """Every mode produces verifiable artifacts."""

    def test_draft_produces_receipt(self, tmp_path):
        """Draft mode produces a receipt artifact."""
        result = tool_file_write("f.txt", "x", mode="draft", sandbox_root=str(tmp_path))
        artifacts = result.get("completion_artifacts", {})
        assert len(artifacts.get("receipts", [])) >= 1
        assert artifacts["receipts"][0]["action"] == "file_write:draft"

    def test_commit_produces_file_artifact(self, tmp_path):
        """Commit mode produces a file artifact with sha256."""
        result = tool_file_write("f.txt", "hello", mode="commit", sandbox_root=str(tmp_path))
        artifacts = result.get("completion_artifacts", {})
        files = artifacts.get("files", [])
        assert len(files) == 1
        assert files[0]["sha256"] == hashlib.sha256(b"hello").hexdigest()

    def test_preview_produces_file_artifact(self, tmp_path):
        """Preview mode produces a file artifact for the .preview file."""
        result = tool_file_write("f.txt", "data", mode="preview", sandbox_root=str(tmp_path))
        artifacts = result.get("completion_artifacts", {})
        files = artifacts.get("files", [])
        assert len(files) == 1
        assert files[0]["path"].endswith(".preview")


# ═══════════════════════════════════════════════════════════════
# TestFileWriteScope (4 tests)
# ═══════════════════════════════════════════════════════════════

class TestFileWriteScope:
    """Write scope gating for file_write tool."""

    def test_file_write_requires_sandbox_scope(self):
        """file_write declares sandbox write scope requirement."""
        assert TOOL_WRITE_SCOPE_REQUIREMENTS.get("file_write") == "sandbox"

    def test_none_scope_denies_file_write(self):
        """max_write_scope=none denies file_write (sandbox > none)."""
        assert scope_rank("sandbox") > scope_rank("none")

    def test_sandbox_scope_allows_file_write(self):
        """max_write_scope=sandbox allows file_write (sandbox == sandbox)."""
        assert scope_rank("sandbox") <= scope_rank("sandbox")

    def test_prod_scope_allows_file_write(self):
        """max_write_scope=prod allows file_write (sandbox < prod)."""
        assert scope_rank("sandbox") <= scope_rank("prod")


# ═══════════════════════════════════════════════════════════════
# TestFileWriteReversibility (3 tests)
# ═══════════════════════════════════════════════════════════════

class TestFileWriteReversibility:
    """Reversibility gate interaction with file_write."""

    def test_reversible_requires_rollback_proof(self):
        """REVERSIBLE file_write without rollback_proof is denied."""
        job = {"reversibility_class": REVERSIBILITY_REVERSIBLE, "execution_mode": "commit"}
        evidence = verify_reversibility_gate(job, "file_write")
        assert not evidence["reversibility_verified"]
        assert "rollback_proof" in evidence.get("error", "")

    def test_partial_commit_requires_rollback_proof(self):
        """PARTIALLY_REVERSIBLE commit without rollback_proof is denied."""
        job = {"reversibility_class": REVERSIBILITY_PARTIAL, "execution_mode": "commit"}
        evidence = verify_reversibility_gate(job, "file_write")
        assert not evidence["reversibility_verified"]

    def test_irreversible_requires_human(self):
        """IRREVERSIBLE file_write without human approval is denied."""
        job = {"reversibility_class": REVERSIBILITY_IRREVERSIBLE, "execution_mode": "commit"}
        evidence = verify_reversibility_gate(job, "file_write")
        assert not evidence["reversibility_verified"]
        assert "human approval" in evidence.get("error", "")


# ═══════════════════════════════════════════════════════════════
# TestFileWriteModeManifest (3 tests)
# ═══════════════════════════════════════════════════════════════

class TestFileWriteModeManifest:
    """Execution mode enforcement from manifest."""

    def test_commit_mode_supported(self):
        """file_write supports commit mode."""
        manifest = _load_test_manifest()
        spec = manifest["tools"]["file_write"]
        job = {"execution_mode": "commit"}
        evidence = verify_execution_mode(job, spec)
        assert evidence["mode_verified"]

    def test_draft_mode_supported(self):
        """file_write supports draft mode."""
        manifest = _load_test_manifest()
        spec = manifest["tools"]["file_write"]
        job = {"execution_mode": "draft"}
        evidence = verify_execution_mode(job, spec)
        assert evidence["mode_verified"]

    def test_unsupported_mode_denied(self):
        """Unsupported mode is denied."""
        manifest = _load_test_manifest()
        spec = manifest["tools"]["file_write"]
        job = {"execution_mode": "yolo"}
        evidence = verify_execution_mode(job, spec)
        assert not evidence["mode_verified"]
        assert "yolo" in evidence.get("error", "")
