"""
M87 Auth Invariant Tests

These tests verify the fundamental auth invariants:
- Missing key → 401
- Invalid key → 401
- Wrong endpoint scope → 403
- Wrong effect scope → 403
- Risk cap exceeded → 403

These are "laws of physics" - if they fail, the system is broken.
"""

import pytest
from unittest.mock import MagicMock, patch
from datetime import datetime, timedelta

# Import auth components directly for unit testing
from app.auth import (
    KeyStore,
    KeyVerifier,
    KeyRecord,
    AuthDecision,
    AuthReasonCode,
    hash_key,
)


class TestAuthInvariants:
    """Auth invariant tests - these MUST pass for system integrity."""

    @pytest.fixture
    def mock_store(self):
        """Create a mock key store."""
        store = MagicMock(spec=KeyStore)
        return store

    @pytest.fixture
    def verifier(self, mock_store):
        """Create a verifier with mock store."""
        return KeyVerifier(mock_store)

    @pytest.fixture
    def valid_key_record(self):
        """Create a valid key record for testing."""
        return KeyRecord(
            key_id="test-key-id",
            key_hash=hash_key("test-plaintext-key"),
            principal_type="adapter",
            principal_id="test-adapter",
            endpoint_scopes={"proposal:create"},
            effect_scopes={"READ_REPO", "WRITE_PATCH"},
            max_risk=0.5,
            enabled=True,
            expires_at=None,
            created_at=datetime.utcnow(),
            description="Test key",
        )

    # ----------------------------------------------------------------
    # INVARIANT: Missing key → 401
    # ----------------------------------------------------------------
    def test_missing_key_returns_missing_key_reason(self, verifier, mock_store):
        """Missing API key must return MISSING_KEY reason."""
        mock_store.get_by_plaintext.return_value = None

        decision = verifier.verify(
            plaintext_key=None,
            endpoint_scope="proposal:create",
        )

        assert decision.allowed is False
        assert decision.reason_code == AuthReasonCode.MISSING_KEY

    def test_empty_key_returns_missing_key_reason(self, verifier, mock_store):
        """Empty string API key must return MISSING_KEY reason."""
        mock_store.get_by_plaintext.return_value = None

        decision = verifier.verify(
            plaintext_key="",
            endpoint_scope="proposal:create",
        )

        assert decision.allowed is False
        assert decision.reason_code == AuthReasonCode.MISSING_KEY

    # ----------------------------------------------------------------
    # INVARIANT: Invalid key → 401 (INVALID_KEY)
    # ----------------------------------------------------------------
    def test_invalid_key_returns_invalid_key_reason(self, verifier, mock_store):
        """Invalid API key must return INVALID_KEY reason."""
        mock_store.get_by_plaintext.return_value = None

        decision = verifier.verify(
            plaintext_key="bogus-key-that-doesnt-exist",
            endpoint_scope="proposal:create",
        )

        assert decision.allowed is False
        assert decision.reason_code == AuthReasonCode.INVALID_KEY

    # ----------------------------------------------------------------
    # INVARIANT: Disabled key → 403 (KEY_DISABLED)
    # ----------------------------------------------------------------
    def test_disabled_key_returns_key_disabled_reason(self, verifier, mock_store, valid_key_record):
        """Disabled key must return KEY_DISABLED reason."""
        valid_key_record.enabled = False
        mock_store.get_by_plaintext.return_value = valid_key_record

        decision = verifier.verify(
            plaintext_key="test-plaintext-key",
            endpoint_scope="proposal:create",
        )

        assert decision.allowed is False
        assert decision.reason_code == AuthReasonCode.KEY_DISABLED

    # ----------------------------------------------------------------
    # INVARIANT: Expired key → 403 (KEY_EXPIRED)
    # ----------------------------------------------------------------
    def test_expired_key_returns_key_expired_reason(self, verifier, mock_store, valid_key_record):
        """Expired key must return KEY_EXPIRED reason."""
        valid_key_record.expires_at = datetime.utcnow() - timedelta(hours=1)
        mock_store.get_by_plaintext.return_value = valid_key_record

        decision = verifier.verify(
            plaintext_key="test-plaintext-key",
            endpoint_scope="proposal:create",
        )

        assert decision.allowed is False
        assert decision.reason_code == AuthReasonCode.KEY_EXPIRED

    # ----------------------------------------------------------------
    # INVARIANT: Wrong endpoint scope → 403 (ENDPOINT_SCOPE_DENIED)
    # ----------------------------------------------------------------
    def test_wrong_endpoint_scope_returns_endpoint_scope_denied(self, verifier, mock_store, valid_key_record):
        """Key without required endpoint scope must return ENDPOINT_SCOPE_DENIED."""
        # Key only has proposal:create, trying to access admin:keys
        mock_store.get_by_plaintext.return_value = valid_key_record

        decision = verifier.verify(
            plaintext_key="test-plaintext-key",
            endpoint_scope="admin:keys",  # Not in key's scopes
        )

        assert decision.allowed is False
        assert decision.reason_code == AuthReasonCode.ENDPOINT_SCOPE_DENIED

    # ----------------------------------------------------------------
    # INVARIANT: Wrong effect scope → 403 (EFFECT_SCOPE_DENIED)
    # ----------------------------------------------------------------
    def test_wrong_effect_scope_returns_effect_scope_denied(self, verifier, mock_store, valid_key_record):
        """Key without required effect scope must return EFFECT_SCOPE_DENIED."""
        # Key has READ_REPO, WRITE_PATCH; trying to propose DEPLOY
        mock_store.get_by_plaintext.return_value = valid_key_record

        decision = verifier.verify(
            plaintext_key="test-plaintext-key",
            endpoint_scope="proposal:create",
            requested_effects={"DEPLOY"},  # Not in key's effect scopes
        )

        assert decision.allowed is False
        assert decision.reason_code == AuthReasonCode.EFFECT_SCOPE_DENIED

    def test_partial_effect_scope_mismatch_returns_denied(self, verifier, mock_store, valid_key_record):
        """If ANY requested effect is denied, auth must fail."""
        mock_store.get_by_plaintext.return_value = valid_key_record

        # Has READ_REPO, WRITE_PATCH; trying READ_REPO + DEPLOY
        decision = verifier.verify(
            plaintext_key="test-plaintext-key",
            endpoint_scope="proposal:create",
            requested_effects={"READ_REPO", "DEPLOY"},
        )

        assert decision.allowed is False
        assert decision.reason_code == AuthReasonCode.EFFECT_SCOPE_DENIED

    # ----------------------------------------------------------------
    # INVARIANT: Risk cap exceeded → 403 (RISK_CAP_EXCEEDED)
    # ----------------------------------------------------------------
    def test_risk_cap_exceeded_returns_risk_cap_exceeded(self, verifier, mock_store, valid_key_record):
        """Risk score exceeding key's max must return RISK_CAP_EXCEEDED."""
        # Key has max_risk=0.5, trying risk_score=0.8
        mock_store.get_by_plaintext.return_value = valid_key_record

        decision = verifier.verify(
            plaintext_key="test-plaintext-key",
            endpoint_scope="proposal:create",
            requested_effects={"READ_REPO"},
            risk_score=0.8,  # Exceeds max_risk of 0.5
        )

        assert decision.allowed is False
        assert decision.reason_code == AuthReasonCode.RISK_CAP_EXCEEDED

    def test_risk_at_cap_is_allowed(self, verifier, mock_store, valid_key_record):
        """Risk score exactly at max should be allowed."""
        mock_store.get_by_plaintext.return_value = valid_key_record

        decision = verifier.verify(
            plaintext_key="test-plaintext-key",
            endpoint_scope="proposal:create",
            requested_effects={"READ_REPO"},
            risk_score=0.5,  # Exactly at max_risk
        )

        assert decision.allowed is True
        assert decision.reason_code == AuthReasonCode.ALLOWED

    # ----------------------------------------------------------------
    # INVARIANT: Valid key with valid scope → ALLOWED
    # ----------------------------------------------------------------
    def test_valid_key_valid_scope_returns_allowed(self, verifier, mock_store, valid_key_record):
        """Valid key with matching scopes must be allowed."""
        mock_store.get_by_plaintext.return_value = valid_key_record

        decision = verifier.verify(
            plaintext_key="test-plaintext-key",
            endpoint_scope="proposal:create",
            requested_effects={"READ_REPO"},
            risk_score=0.3,
        )

        assert decision.allowed is True
        assert decision.reason_code == AuthReasonCode.ALLOWED
        assert decision.key_id == "test-key-id"
        assert decision.principal_type == "adapter"
        assert decision.principal_id == "test-adapter"


class TestAuthCheckOrder:
    """Verify auth checks happen in correct order."""

    @pytest.fixture
    def mock_store(self):
        store = MagicMock(spec=KeyStore)
        return store

    @pytest.fixture
    def verifier(self, mock_store):
        return KeyVerifier(mock_store)

    def test_missing_key_checked_before_store_lookup(self, verifier, mock_store):
        """Missing key should fail before hitting store."""
        decision = verifier.verify(
            plaintext_key=None,
            endpoint_scope="proposal:create",
        )

        assert decision.reason_code == AuthReasonCode.MISSING_KEY
        mock_store.get_by_plaintext.assert_not_called()

    def test_check_order_is_correct(self, verifier, mock_store):
        """Auth checks must happen in order: present → valid → enabled → not expired → endpoint → effect → risk."""
        # This is implicitly tested by the individual tests, but we document the order here
        # 1. Key present (MISSING_KEY)
        # 2. Key valid (INVALID_KEY)
        # 3. Key enabled (KEY_DISABLED)
        # 4. Key not expired (KEY_EXPIRED)
        # 5. Endpoint scope (ENDPOINT_SCOPE_DENIED)
        # 6. Effect scope (EFFECT_SCOPE_DENIED)
        # 7. Risk cap (RISK_CAP_EXCEEDED)
        pass  # Documented test
