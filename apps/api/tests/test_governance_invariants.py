"""
M87 Governance Invariant Tests

These tests verify the fundamental governance invariants:
- READ_SECRETS → DENY (absolute)
- Agent effect scope violation → DENY
- No decision → No job (job minting requires decision)
- DEPLOY → REQUIRE_HUMAN

These are "laws of physics" - if they fail, the system is broken.
"""

import pytest
from unittest.mock import MagicMock, patch
from fastapi.testclient import TestClient

# We need to patch before importing the app
import sys
import os

# Set up test environment
os.environ["M87_API_KEY"] = "test-bootstrap-key"
os.environ["DATABASE_URL"] = ""
os.environ["REDIS_URL"] = "redis://localhost:6379/0"
os.environ["M87_TOOL_MANIFEST_PATH"] = "/nonexistent/manifest.json"  # Will be mocked


class TestGovernanceInvariants:
    """Governance invariant tests - these MUST pass for system integrity."""

    @pytest.fixture
    def mock_redis(self):
        """Create a comprehensive mock Redis."""
        mock = MagicMock()
        mock.ping.return_value = True
        mock.xadd.return_value = "mock-event-id"
        mock.hgetall.return_value = {}
        mock.get.return_value = None
        mock.set.return_value = True
        # Phase 3-6 governance: SessionRiskTracker uses sorted sets
        mock.zrangebyscore.return_value = []  # Empty history
        mock.zadd.return_value = 1
        mock.expire.return_value = True
        return mock

    @pytest.fixture
    def mock_key_store(self, mock_redis):
        """Create a mock key store with bootstrap key."""
        from app.auth import KeyStore, hash_key, KeyRecord
        from datetime import datetime

        store = MagicMock(spec=KeyStore)

        # Bootstrap key record
        bootstrap_record = KeyRecord(
            key_id="key_bootstrap",
            key_hash=hash_key("test-bootstrap-key"),
            principal_type="admin",
            principal_id="bootstrap",
            endpoint_scopes={
                "proposal:create", "proposal:approve", "proposal:deny",
                "runner:result", "admin:emit", "admin:keys",
            },
            effect_scopes={
                "READ_REPO", "WRITE_PATCH", "RUN_TESTS", "BUILD_ARTIFACT",
                "NETWORK_CALL", "SEND_NOTIFICATION", "CREATE_PR", "MERGE", "DEPLOY"
            },
            max_risk=1.0,
            enabled=True,
            created_at=datetime.utcnow(),
            description="Test bootstrap key",
        )

        store.get_by_plaintext.return_value = bootstrap_record
        store.seed_bootstrap_key.return_value = bootstrap_record

        return store

    @pytest.fixture
    def client(self, mock_redis, mock_key_store):
        """Create test client with mocked dependencies."""
        # P2.A: Mock rate limiter to always allow
        mock_rate_limiter = MagicMock()
        mock_rl_result = MagicMock()
        mock_rl_result.allowed = True
        mock_rl_result.current = 1
        mock_rl_result.limit = 30
        mock_rl_result.remaining = 29
        mock_rate_limiter.check_rate_limit.return_value = mock_rl_result

        with patch("app.main.rdb", mock_redis), \
             patch("app.main.key_store", mock_key_store), \
             patch("app.main.key_verifier") as mock_verifier, \
             patch("app.main.rate_limiter", mock_rate_limiter), \
             patch("app.main._db_available", True), \
             patch("app.main.persist_proposal") as mock_persist_proposal, \
             patch("app.main.persist_decision") as mock_persist_decision, \
             patch("app.main.persist_job") as mock_persist_job, \
             patch("app.main.enqueue_job") as mock_enqueue_job:
            # Mock enqueue_job to return a fake job_id
            mock_enqueue_job.return_value = "mock-job-id-12345"

            # Configure mock verifier to allow bootstrap key
            from app.auth import AuthDecision, AuthReasonCode

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
            yield TestClient(app)

    # ----------------------------------------------------------------
    # INVARIANT: READ_SECRETS → DENY (absolute)
    # ----------------------------------------------------------------
    def test_read_secrets_always_denied(self, client):
        """READ_SECRETS must ALWAYS be denied, regardless of who proposes it."""
        response = client.post(
            "/v1/govern/proposal",
            headers={"X-M87-Key": "test-bootstrap-key"},
            json={
                "proposal_id": "test-secrets-proposal",
                "intent_id": "test-intent",
                "agent": "Human",  # Even humans can't read secrets
                "summary": "Try to read secrets",
                "effects": ["READ_SECRETS"],
                "truth_account": {
                    "observations": ["test"],
                    "claims": [],
                },
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert data["decision"] == "DENY"
        assert "READ_SECRETS" in str(data["reasons"])

    def test_read_secrets_denied_even_with_other_effects(self, client):
        """READ_SECRETS must be denied even when mixed with allowed effects."""
        response = client.post(
            "/v1/govern/proposal",
            headers={"X-M87-Key": "test-bootstrap-key"},
            json={
                "proposal_id": "test-mixed-secrets",
                "intent_id": "test-intent",
                "agent": "Human",
                "summary": "Try to mix secrets with allowed effects",
                "effects": ["READ_REPO", "READ_SECRETS"],
                "truth_account": {
                    "observations": ["test"],
                    "claims": [],
                },
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert data["decision"] == "DENY"

    # ----------------------------------------------------------------
    # INVARIANT: Agent effect scope violation → DENY
    # ----------------------------------------------------------------
    def test_agent_effect_scope_violation_denied(self, client):
        """Agent proposing effects outside their scope must be denied."""
        # Casey can only do: READ_REPO, WRITE_PATCH, RUN_TESTS
        response = client.post(
            "/v1/govern/proposal",
            headers={"X-M87-Key": "test-bootstrap-key"},
            json={
                "proposal_id": "test-casey-deploy",
                "intent_id": "test-intent",
                "agent": "Casey",
                "summary": "Casey tries to deploy",
                "effects": ["DEPLOY"],  # Not in Casey's allowed effects
                "truth_account": {
                    "observations": ["test"],
                    "claims": [],
                },
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert data["decision"] == "DENY"
        assert "not allowed effects" in str(data["reasons"])

    def test_unknown_agent_restricted_to_read_repo(self, client):
        """Unknown agents should only be allowed READ_REPO."""
        response = client.post(
            "/v1/govern/proposal",
            headers={"X-M87-Key": "test-bootstrap-key"},
            json={
                "proposal_id": "test-unknown-agent",
                "intent_id": "test-intent",
                "agent": "MysteryAgent",  # Not a known agent
                "summary": "Unknown agent tries to write",
                "effects": ["WRITE_PATCH"],  # Unknown agents can't write
                "truth_account": {
                    "observations": ["test"],
                    "claims": [],
                },
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert data["decision"] == "DENY"

    # ----------------------------------------------------------------
    # INVARIANT: DEPLOY → REQUIRE_HUMAN
    # ----------------------------------------------------------------
    def test_deploy_requires_human_approval(self, client):
        """DEPLOY must always require human approval."""
        # Human agent proposing DEPLOY
        response = client.post(
            "/v1/govern/proposal",
            headers={"X-M87-Key": "test-bootstrap-key"},
            json={
                "proposal_id": "test-deploy-human",
                "intent_id": "test-intent",
                "agent": "Human",  # Only Human can propose DEPLOY
                "summary": "Deploy to production",
                "effects": ["DEPLOY"],
                "truth_account": {
                    "observations": ["test"],
                    "claims": [],
                },
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert data["decision"] == "REQUIRE_HUMAN"
        assert "required_approvals" in data
        assert "DEPLOY" in str(data["reasons"])

    # ----------------------------------------------------------------
    # INVARIANT: Valid proposal within scope → ALLOW
    # ----------------------------------------------------------------
    def test_valid_proposal_within_scope_allowed(self, client):
        """Valid proposal within agent scope should be allowed."""
        # Casey proposing READ_REPO (within Casey's scope)
        response = client.post(
            "/v1/govern/proposal",
            headers={"X-M87-Key": "test-bootstrap-key"},
            json={
                "proposal_id": "test-casey-read",
                "intent_id": "test-intent",
                "agent": "Casey",
                "summary": "Casey reads repo",
                "effects": ["READ_REPO"],
                "truth_account": {
                    "observations": ["test"],
                    "claims": [],
                },
                "risk_score": 0.3,
            },
        )

        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"
        data = response.json()
        assert data["decision"] == "ALLOW"

    # ----------------------------------------------------------------
    # INVARIANT: Risk threshold exceeded → REQUIRE_HUMAN
    # ----------------------------------------------------------------
    def test_risk_threshold_exceeded_requires_human(self, client):
        """Risk score exceeding agent threshold requires human approval."""
        # Casey has max_risk=0.6, proposing with risk=0.8
        response = client.post(
            "/v1/govern/proposal",
            headers={"X-M87-Key": "test-bootstrap-key"},
            json={
                "proposal_id": "test-casey-high-risk",
                "intent_id": "test-intent",
                "agent": "Casey",
                "summary": "High risk operation",
                "effects": ["READ_REPO"],  # Within scope
                "truth_account": {
                    "observations": ["test"],
                    "claims": [],
                },
                "risk_score": 0.8,  # Exceeds Casey's max_risk of 0.6
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert data["decision"] == "REQUIRE_HUMAN"
        assert "risk" in str(data["reasons"]).lower()


class TestFailSafeInvariants:
    """Test hard fail-safe behavior."""

    @pytest.fixture
    def mock_redis(self):
        mock = MagicMock()
        mock.ping.return_value = True
        return mock

    @pytest.fixture
    def client_db_unavailable(self, mock_redis):
        """Create test client with DB unavailable."""
        with patch("app.main.rdb", mock_redis), \
             patch("app.main._db_available", False):

            from app.main import app
            yield TestClient(app)

    def test_proposal_denied_when_db_unavailable(self, client_db_unavailable):
        """Proposals must be denied with 503 when DB is unavailable."""
        response = client_db_unavailable.post(
            "/v1/govern/proposal",
            headers={"X-M87-Key": "test-bootstrap-key"},
            json={
                "proposal_id": "test-no-db",
                "intent_id": "test-intent",
                "agent": "Casey",
                "summary": "Test without DB",
                "effects": ["READ_REPO"],
                "truth_account": {
                    "observations": ["test"],
                    "claims": [],
                },
            },
        )

        assert response.status_code == 503
        data = response.json()
        assert data["detail"]["error"] == "DB_UNAVAILABLE"
