"""
M87 API Key Verifier

Performs authentication and authorization checks with detailed reason codes.
"""

import logging
from datetime import datetime
from typing import Optional, List, Set

from .models import (
    KeyRecord,
    AuthDecision,
    AuthReasonCode,
    EndpointScope,
    EffectScope,
)
from .store import KeyStore


logger = logging.getLogger(__name__)


class KeyVerifier:
    """
    Verifies API keys and enforces scoped permissions.

    Checks (in order):
    1. Key present
    2. Key valid (exists in store)
    3. Key enabled
    4. Key not expired
    5. Endpoint scope allowed
    6. Effect scope allowed (for proposals)
    7. Risk cap not exceeded (for proposals)
    """

    def __init__(self, store: KeyStore):
        self.store = store

    def verify(
        self,
        plaintext_key: Optional[str],
        endpoint_scope: EndpointScope,
        requested_effects: Optional[Set[str]] = None,
        risk_score: Optional[float] = None,
    ) -> AuthDecision:
        """
        Verify a key for a specific operation.

        Args:
            plaintext_key: The API key from request header
            endpoint_scope: The endpoint being accessed
            requested_effects: Effects being proposed (for proposal:create)
            risk_score: Risk score being proposed (for proposal:create)

        Returns:
            AuthDecision with allowed status and reason
        """
        # Check 1: Key present
        if not plaintext_key:
            return self._deny(
                AuthReasonCode.MISSING_KEY,
                "API key required"
            )

        # Check 2: Key valid
        record = self.store.get_by_plaintext(plaintext_key)
        if not record:
            logger.warning(f"Invalid key attempted")
            return self._deny(
                AuthReasonCode.INVALID_KEY,
                "Invalid API key"
            )

        # Check 3: Key enabled
        if not record.enabled:
            logger.warning(f"Disabled key attempted: {record.key_id}")
            return self._deny(
                AuthReasonCode.KEY_DISABLED,
                "API key is disabled",
                record
            )

        # Check 4: Key not expired
        if record.expires_at and datetime.utcnow() > record.expires_at:
            logger.warning(f"Expired key attempted: {record.key_id}")
            return self._deny(
                AuthReasonCode.KEY_EXPIRED,
                "API key has expired",
                record
            )

        # Check 5: Endpoint scope
        if endpoint_scope not in record.endpoint_scopes:
            logger.warning(
                f"Endpoint scope denied: {record.key_id} tried {endpoint_scope}, "
                f"has {record.endpoint_scopes}"
            )
            return self._deny(
                AuthReasonCode.ENDPOINT_SCOPE_DENIED,
                f"Key not authorized for endpoint: {endpoint_scope}",
                record
            )

        # Check 6: Effect scope (only for proposal:create)
        if endpoint_scope == "proposal:create" and requested_effects:
            denied_effects = set(requested_effects) - record.effect_scopes
            if denied_effects:
                logger.warning(
                    f"Effect scope denied: {record.key_id} tried {denied_effects}, "
                    f"has {record.effect_scopes}"
                )
                return self._deny(
                    AuthReasonCode.EFFECT_SCOPE_DENIED,
                    f"Key not authorized for effects: {sorted(denied_effects)}",
                    record
                )

        # Check 7: Risk cap (only for proposal:create)
        if endpoint_scope == "proposal:create" and risk_score is not None:
            if risk_score > record.max_risk:
                logger.warning(
                    f"Risk cap exceeded: {record.key_id} tried {risk_score}, "
                    f"max {record.max_risk}"
                )
                return self._deny(
                    AuthReasonCode.RISK_CAP_EXCEEDED,
                    f"Risk {risk_score} exceeds key max {record.max_risk}",
                    record
                )

        # All checks passed
        logger.debug(
            f"Auth allowed: {record.key_id} ({record.principal_type}:{record.principal_id}) "
            f"for {endpoint_scope}"
        )
        return self._allow(record)

    def _allow(self, record: KeyRecord) -> AuthDecision:
        """Create an allow decision."""
        return AuthDecision(
            allowed=True,
            key_id=record.key_id,
            principal_type=record.principal_type,
            principal_id=record.principal_id,
            reason="Authorized",
            reason_code=AuthReasonCode.ALLOWED,
        )

    def _deny(
        self,
        reason_code: str,
        reason: str,
        record: Optional[KeyRecord] = None,
    ) -> AuthDecision:
        """Create a deny decision."""
        return AuthDecision(
            allowed=False,
            key_id=record.key_id if record else None,
            principal_type=record.principal_type if record else None,
            principal_id=record.principal_id if record else None,
            reason=reason,
            reason_code=reason_code,
        )


def emit_auth_event(
    decision: AuthDecision,
    endpoint: str,
    emit_fn,
):
    """
    Emit an auth decision event for audit logging.

    Args:
        decision: The auth decision
        endpoint: The endpoint that was accessed
        emit_fn: Function to emit events
    """
    event_type = "auth.allowed" if decision.allowed else "auth.denied"
    payload = {
        "allowed": decision.allowed,
        "endpoint": endpoint,
        "key_id": decision.key_id,
        "principal_type": decision.principal_type,
        "principal_id": decision.principal_id,
        "reason": decision.reason,
        "reason_code": decision.reason_code,
    }
    emit_fn(event_type, payload)
