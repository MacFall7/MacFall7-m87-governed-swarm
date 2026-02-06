"""
Reversibility Gate Invariant Tests for M87 Governance.

These tests prove the Reversibility Gate catches:
1. REVERSIBLE actions without rollback_proof
2. PARTIALLY_REVERSIBLE commits without rollback_proof
3. IRREVERSIBLE actions without human approval
4. READ actions bypass the gate

All tests assert NO EXECUTION occurs when blocked.
"""
from __future__ import annotations

import pytest
from unittest.mock import MagicMock, patch

from app.governance.reversibility import (
    ReversibilityClass,
    ExecutionMode,
    CleanupCost,
    RollbackProof,
    ReversibilityGateResult,
    evaluate_reversibility_gate,
    create_downgrade_response,
    is_read_only_action,
    CLEANUP_COST_BUDGET_MULTIPLIERS,
    CLEANUP_COST_RETRY_LIMITS,
)


class TestReversibilityGateLogic:
    """Tests for core reversibility gate evaluation logic."""

    # ----------------------------------------------------------------
    # INVARIANT 1: REVERSIBLE requires rollback_proof
    # ----------------------------------------------------------------
    def test_reversible_without_rollback_proof_blocked(self):
        """
        Given a write action marked REVERSIBLE without rollback_proof,
        Gate must refuse execution and return proposal-only downgrade.
        """
        result = evaluate_reversibility_gate(
            effects=["WRITE_PATCH"],
            reversibility_class="REVERSIBLE",
            rollback_proof=None,  # Missing!
            execution_mode="commit",
            human_approved=False,
        )

        assert result.allowed is False
        assert "rollback_proof" in result.reason.lower()
        assert result.downgrade_to_proposal is True

    def test_reversible_with_rollback_proof_allowed(self):
        """
        Given a REVERSIBLE action with valid rollback_proof,
        Gate should allow execution.
        """
        result = evaluate_reversibility_gate(
            effects=["WRITE_PATCH"],
            reversibility_class="REVERSIBLE",
            rollback_proof={"description": "git revert", "rollback_tool": "git"},
            execution_mode="commit",
            human_approved=False,
        )

        assert result.allowed is True
        assert "rollback_proof" in result.reason.lower()

    # ----------------------------------------------------------------
    # INVARIANT 2: PARTIALLY_REVERSIBLE commit blocked without proof
    # ----------------------------------------------------------------
    def test_partially_reversible_commit_without_proof_blocked(self):
        """
        Given a PARTIALLY_REVERSIBLE action in commit mode without rollback_proof,
        Gate must block and suggest draft mode.
        """
        result = evaluate_reversibility_gate(
            effects=["BUILD_ARTIFACT"],
            reversibility_class="PARTIALLY_REVERSIBLE",
            rollback_proof=None,  # Missing!
            execution_mode="commit",
            human_approved=False,
        )

        assert result.allowed is False
        assert result.safe_alternative == "draft"
        assert result.downgrade_to_proposal is True

    def test_partially_reversible_draft_without_proof_allowed(self):
        """
        Given a PARTIALLY_REVERSIBLE action in draft mode,
        Gate should allow even without rollback_proof.
        """
        result = evaluate_reversibility_gate(
            effects=["BUILD_ARTIFACT"],
            reversibility_class="PARTIALLY_REVERSIBLE",
            rollback_proof=None,
            execution_mode="draft",  # Safe mode
            human_approved=False,
        )

        assert result.allowed is True
        assert "draft" in result.reason.lower()

    def test_partially_reversible_commit_with_proof_allowed(self):
        """
        Given a PARTIALLY_REVERSIBLE action with rollback_proof,
        Gate should allow commit mode.
        """
        result = evaluate_reversibility_gate(
            effects=["BUILD_ARTIFACT"],
            reversibility_class="PARTIALLY_REVERSIBLE",
            rollback_proof={"description": "Delete artifact from registry"},
            execution_mode="commit",
            human_approved=False,
        )

        assert result.allowed is True

    # ----------------------------------------------------------------
    # INVARIANT 3: IRREVERSIBLE blocked without human approval
    # ----------------------------------------------------------------
    def test_irreversible_without_approval_blocked(self):
        """
        Given an IRREVERSIBLE action without human approval,
        Gate must never allow execution.
        """
        result = evaluate_reversibility_gate(
            effects=["SEND_NOTIFICATION"],
            reversibility_class="IRREVERSIBLE",
            rollback_proof=None,
            execution_mode="commit",
            human_approved=False,  # Not approved!
        )

        assert result.allowed is False
        assert "human approval" in result.reason.lower()
        assert result.safe_alternative == "approval_required"

    # ----------------------------------------------------------------
    # INVARIANT 4: IRREVERSIBLE allowed with human approval
    # ----------------------------------------------------------------
    def test_irreversible_with_approval_allowed(self):
        """
        Given an IRREVERSIBLE action with explicit human approval,
        Gate should allow execution.
        """
        result = evaluate_reversibility_gate(
            effects=["SEND_NOTIFICATION"],
            reversibility_class="IRREVERSIBLE",
            rollback_proof=None,
            execution_mode="commit",
            human_approved=True,  # Approved!
        )

        assert result.allowed is True
        assert "approved" in result.reason.lower()

    # ----------------------------------------------------------------
    # INVARIANT 5: READ action bypasses gate
    # ----------------------------------------------------------------
    def test_read_action_bypasses_gate(self):
        """
        Given a read-only action (READ_REPO, READ_CONFIG, COMPUTE),
        Gate must allow without reversibility fields.
        """
        for effect in ["READ_REPO", "READ_CONFIG", "COMPUTE"]:
            result = evaluate_reversibility_gate(
                effects=[effect],
                reversibility_class=None,  # Not required for read
                rollback_proof=None,
                execution_mode="commit",
                human_approved=False,
            )

            assert result.allowed is True, f"Failed for effect: {effect}"
            assert "read-only" in result.reason.lower()

    def test_mixed_read_write_requires_reversibility(self):
        """
        Given a proposal with both read and write effects,
        Gate should require reversibility declaration.
        """
        result = evaluate_reversibility_gate(
            effects=["READ_REPO", "WRITE_PATCH"],  # Mixed
            reversibility_class=None,
            rollback_proof=None,
            execution_mode="commit",
            human_approved=False,
        )

        assert result.allowed is False
        assert "reversibility_class" in result.reason.lower()

    # ----------------------------------------------------------------
    # INVARIANT 6: Missing reversibility_class → blocked
    # ----------------------------------------------------------------
    def test_missing_reversibility_class_blocked(self):
        """
        Given a non-read action without reversibility_class,
        Gate must block execution.
        """
        result = evaluate_reversibility_gate(
            effects=["WRITE_PATCH"],
            reversibility_class=None,  # Missing!
            rollback_proof=None,
            execution_mode="commit",
            human_approved=False,
        )

        assert result.allowed is False
        assert "reversibility_class" in result.reason.lower()
        assert result.downgrade_to_proposal is True

    # ----------------------------------------------------------------
    # INVARIANT 7: Invalid reversibility_class → blocked
    # ----------------------------------------------------------------
    def test_invalid_reversibility_class_blocked(self):
        """
        Given an invalid reversibility_class value,
        Gate must block execution.
        """
        result = evaluate_reversibility_gate(
            effects=["WRITE_PATCH"],
            reversibility_class="INVALID_CLASS",
            rollback_proof=None,
            execution_mode="commit",
            human_approved=False,
        )

        assert result.allowed is False
        assert "invalid" in result.reason.lower()


class TestCleanupCostBudgetAdjustments:
    """Tests for V2 Cleanup Cost → Budget Adjustment feature."""

    # ----------------------------------------------------------------
    # INVARIANT 8: LOW cleanup_cost → full budget, unlimited retries
    # ----------------------------------------------------------------
    def test_low_cleanup_cost_full_budget(self):
        """
        Given cleanup_cost=LOW,
        Gate must return budget_multiplier=1.0 and retry_limit=None.
        """
        result = evaluate_reversibility_gate(
            effects=["WRITE_PATCH"],
            reversibility_class="REVERSIBLE",
            rollback_proof={"description": "git revert"},
            execution_mode="commit",
            human_approved=False,
            cleanup_cost="LOW",
        )

        assert result.allowed is True
        assert result.budget_multiplier == 1.0
        assert result.retry_limit is None  # Unlimited

    # ----------------------------------------------------------------
    # INVARIANT 9: MEDIUM cleanup_cost → reduced budget, limited retries
    # ----------------------------------------------------------------
    def test_medium_cleanup_cost_reduced_budget(self):
        """
        Given cleanup_cost=MEDIUM,
        Gate must return budget_multiplier=0.8 and retry_limit=3.
        """
        result = evaluate_reversibility_gate(
            effects=["WRITE_PATCH"],
            reversibility_class="REVERSIBLE",
            rollback_proof={"description": "git revert"},
            execution_mode="commit",
            human_approved=False,
            cleanup_cost="MEDIUM",
        )

        assert result.allowed is True
        assert result.budget_multiplier == 0.8
        assert result.retry_limit == 3

    # ----------------------------------------------------------------
    # INVARIANT 10: HIGH cleanup_cost → minimal budget, single attempt
    # ----------------------------------------------------------------
    def test_high_cleanup_cost_minimal_budget(self):
        """
        Given cleanup_cost=HIGH,
        Gate must return budget_multiplier=0.5 and retry_limit=1.
        """
        result = evaluate_reversibility_gate(
            effects=["WRITE_PATCH"],
            reversibility_class="REVERSIBLE",
            rollback_proof={"description": "git revert"},
            execution_mode="commit",
            human_approved=False,
            cleanup_cost="HIGH",
        )

        assert result.allowed is True
        assert result.budget_multiplier == 0.5
        assert result.retry_limit == 1

    # ----------------------------------------------------------------
    # INVARIANT 11: Unknown cleanup_cost → conservative default (MEDIUM)
    # ----------------------------------------------------------------
    def test_unknown_cleanup_cost_defaults_to_medium(self):
        """
        Given an invalid cleanup_cost value,
        Gate must default to MEDIUM budget adjustments (fail-conservative).
        """
        result = evaluate_reversibility_gate(
            effects=["WRITE_PATCH"],
            reversibility_class="REVERSIBLE",
            rollback_proof={"description": "git revert"},
            execution_mode="commit",
            human_approved=False,
            cleanup_cost="INVALID_COST",
        )

        assert result.allowed is True
        assert result.budget_multiplier == 0.8  # MEDIUM default
        assert result.retry_limit == 3  # MEDIUM default

    # ----------------------------------------------------------------
    # INVARIANT 12: None cleanup_cost → full budget (backward compat)
    # ----------------------------------------------------------------
    def test_none_cleanup_cost_full_budget(self):
        """
        Given cleanup_cost=None (not specified),
        Gate must return full budget (backward compatibility).
        """
        result = evaluate_reversibility_gate(
            effects=["WRITE_PATCH"],
            reversibility_class="REVERSIBLE",
            rollback_proof={"description": "git revert"},
            execution_mode="commit",
            human_approved=False,
            cleanup_cost=None,
        )

        assert result.allowed is True
        assert result.budget_multiplier == 1.0
        assert result.retry_limit is None

    # ----------------------------------------------------------------
    # INVARIANT 13: Budget adjustments included in to_dict()
    # ----------------------------------------------------------------
    def test_budget_adjustments_in_to_dict(self):
        """
        Budget adjustments must be serialized in to_dict() output.
        """
        result = evaluate_reversibility_gate(
            effects=["WRITE_PATCH"],
            reversibility_class="REVERSIBLE",
            rollback_proof={"description": "git revert"},
            execution_mode="commit",
            human_approved=False,
            cleanup_cost="HIGH",
        )

        d = result.to_dict()
        assert d["budget_multiplier"] == 0.5
        assert d["retry_limit"] == 1


class TestReversibilityGateHelpers:
    """Tests for helper functions."""

    def test_is_read_only_action_true(self):
        """Test read-only effect detection."""
        assert is_read_only_action(["READ_REPO"]) is True
        assert is_read_only_action(["READ_CONFIG"]) is True
        assert is_read_only_action(["COMPUTE"]) is True
        assert is_read_only_action(["READ_REPO", "COMPUTE"]) is True

    def test_is_read_only_action_false(self):
        """Test non-read-only effect detection."""
        assert is_read_only_action(["WRITE_PATCH"]) is False
        assert is_read_only_action(["READ_REPO", "WRITE_PATCH"]) is False
        assert is_read_only_action(["DEPLOY"]) is False

    def test_rollback_proof_from_dict(self):
        """Test RollbackProof parsing."""
        data = {
            "description": "git revert HEAD",
            "rollback_tool": "git",
            "rollback_args": {"commit": "HEAD"},
        }
        proof = RollbackProof.from_dict(data)

        assert proof is not None
        assert proof.description == "git revert HEAD"
        assert proof.rollback_tool == "git"
        assert proof.rollback_args == {"commit": "HEAD"}

    def test_rollback_proof_from_none(self):
        """Test RollbackProof handles None."""
        proof = RollbackProof.from_dict(None)
        assert proof is None

    def test_create_downgrade_response(self):
        """Test downgrade response structure."""
        gate_result = ReversibilityGateResult(
            allowed=False,
            reason="Missing rollback_proof",
            safe_alternative="proposal",
            downgrade_to_proposal=True,
        )
        original_action = {
            "effects": ["WRITE_PATCH"],
            "summary": "Fix bug",
            "reversibility_class": "REVERSIBLE",
        }

        response = create_downgrade_response(original_action, gate_result)

        assert response["status"] == "blocked_by_reversibility_gate"
        assert response["original_action"]["effects"] == ["WRITE_PATCH"]
        assert response["safe_alternative"] == "proposal"
        assert len(response["next_steps"]) > 0


class TestReversibilityGateAPIIntegration:
    """
    Integration tests verifying gate is enforced at the API level.
    These tests mock the database and verify no job is minted when blocked.
    """

    @pytest.fixture
    def mock_redis(self):
        """Create mock Redis."""
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
    def mock_key_store(self, mock_redis):
        """Create mock key store."""
        from app.auth import KeyStore, hash_key, KeyRecord
        from datetime import datetime

        store = MagicMock(spec=KeyStore)
        bootstrap_record = KeyRecord(
            key_id="key_bootstrap",
            key_hash=hash_key("test-bootstrap-key"),
            principal_type="admin",
            principal_id="bootstrap",
            endpoint_scopes={"proposal:create", "proposal:approve"},
            effect_scopes={"READ_REPO", "WRITE_PATCH", "SEND_NOTIFICATION"},
            max_risk=1.0,
            enabled=True,
            created_at=datetime.utcnow(),
            description="Test key",
        )
        store.get_by_plaintext.return_value = bootstrap_record
        return store

    @pytest.fixture
    def client(self, mock_redis, mock_key_store):
        """Create test client."""
        from app.auth import AuthDecision, AuthReasonCode
        from fastapi.testclient import TestClient

        with patch("app.main.rdb", mock_redis), \
             patch("app.main.key_store", mock_key_store), \
             patch("app.main.key_verifier") as mock_verifier, \
             patch("app.main._db_available", True), \
             patch("app.main.persist_proposal"), \
             patch("app.main.persist_decision"), \
             patch("app.main.persist_job"), \
             patch("app.main.enqueue_job") as mock_enqueue:

            mock_enqueue.return_value = "mock-job-id"

            def mock_verify(plaintext_key, endpoint_scope, requested_effects=None, risk_score=None):
                if plaintext_key == "test-bootstrap-key":
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
            yield TestClient(app), mock_enqueue

    def test_api_blocks_reversible_without_proof(self, client):
        """
        API must block REVERSIBLE action without rollback_proof.
        No job should be minted.
        """
        test_client, mock_enqueue = client

        response = test_client.post(
            "/v1/govern/proposal",
            headers={"X-M87-Key": "test-bootstrap-key"},
            json={
                "proposal_id": "test-rev-1",
                "intent_id": "test-intent",
                "agent": "Casey",
                "summary": "Write code",
                "effects": ["WRITE_PATCH"],
                "truth_account": {"observations": ["test"], "claims": []},
                "reversibility_class": "REVERSIBLE",
                "rollback_proof": None,  # Missing!
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert data["decision"] == "DENY"
        assert "Reversibility Gate" in str(data["reasons"])
        mock_enqueue.assert_not_called()

    def test_api_blocks_irreversible_without_approval(self, client):
        """
        API must escalate IRREVERSIBLE action to REQUIRE_HUMAN.
        No job should be minted until approved.
        """
        test_client, mock_enqueue = client

        response = test_client.post(
            "/v1/govern/proposal",
            headers={"X-M87-Key": "test-bootstrap-key"},
            json={
                "proposal_id": "test-irrev-1",
                "intent_id": "test-intent",
                "agent": "Jordan",
                "summary": "Send notification",
                "effects": ["SEND_NOTIFICATION"],
                "truth_account": {"observations": ["test"], "claims": []},
                "reversibility_class": "IRREVERSIBLE",
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert data["decision"] == "REQUIRE_HUMAN"
        assert "Reversibility Gate" in str(data["reasons"])
        mock_enqueue.assert_not_called()

    def test_api_allows_read_without_reversibility(self, client):
        """
        API must allow read-only action without reversibility fields.
        """
        test_client, mock_enqueue = client

        response = test_client.post(
            "/v1/govern/proposal",
            headers={"X-M87-Key": "test-bootstrap-key"},
            json={
                "proposal_id": "test-read-1",
                "intent_id": "test-intent",
                "agent": "Casey",
                "summary": "Read repo",
                "effects": ["READ_REPO"],
                "truth_account": {"observations": ["test"], "claims": []},
                # No reversibility fields - should be fine for read
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert data["decision"] == "ALLOW"
        mock_enqueue.assert_called_once()

    def test_api_allows_reversible_with_proof(self, client):
        """
        API must allow REVERSIBLE action with valid rollback_proof.
        """
        test_client, mock_enqueue = client

        response = test_client.post(
            "/v1/govern/proposal",
            headers={"X-M87-Key": "test-bootstrap-key"},
            json={
                "proposal_id": "test-rev-valid",
                "intent_id": "test-intent",
                "agent": "Casey",
                "summary": "Write code with rollback",
                "effects": ["WRITE_PATCH"],
                "truth_account": {"observations": ["test"], "claims": []},
                "reversibility_class": "REVERSIBLE",
                "rollback_proof": {
                    "description": "git revert HEAD",
                    "rollback_tool": "git",
                },
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert data["decision"] == "ALLOW"
        mock_enqueue.assert_called_once()
