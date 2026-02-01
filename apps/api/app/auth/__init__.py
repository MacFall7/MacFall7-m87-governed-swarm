"""
M87 API Authentication Module

Provides scoped API key management with:
- Principal identification (adapter, runner, human, admin)
- Endpoint scopes (what endpoints can be accessed)
- Effect scopes (what effects can be proposed)
- Risk caps (maximum risk score allowed)
- Expiration and enable/disable
"""

from .models import (
    KeyRecord,
    AuthDecision,
    AuthReasonCode,
    PrincipalType,
    EndpointScope,
    EffectScope,
    generate_key,
    generate_key_id,
    hash_key,
)

from .store import KeyStore

from .verifier import KeyVerifier, emit_auth_event

__all__ = [
    # Models
    "KeyRecord",
    "AuthDecision",
    "AuthReasonCode",
    "PrincipalType",
    "EndpointScope",
    "EffectScope",
    "generate_key",
    "generate_key_id",
    "hash_key",
    # Store
    "KeyStore",
    # Verifier
    "KeyVerifier",
    "emit_auth_event",
]
