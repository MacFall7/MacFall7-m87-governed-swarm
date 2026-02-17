"""
M87 API Key Authentication Models

Scoped keys with principal, effect, and risk constraints.
Keys are hashed with Argon2id (passlib) for storage security.
Legacy SHA-256 hashes are accepted and transparently rehashed on verify.
"""

from pydantic import BaseModel, Field
from typing import Optional, Set, Literal
from datetime import datetime
import hashlib
import hmac
import secrets
import logging

_logger = logging.getLogger(__name__)

# Argon2id via passlib (preferred)
try:
    from passlib.hash import argon2 as _argon2_base
    _ARGON2_HASHER = _argon2_base.using(type="ID", memory_cost=65536, time_cost=3, parallelism=1)
    _ARGON2_AVAILABLE = True
except ImportError:
    _ARGON2_HASHER = None
    _ARGON2_AVAILABLE = False
    _logger.warning("passlib[argon2] not installed — falling back to SHA-256 only")


# Principal types
PrincipalType = Literal["adapter", "runner", "human", "admin", "service"]

# Endpoint scopes
EndpointScope = Literal[
    "proposal:create",
    "proposal:approve",
    "proposal:deny",
    "runner:result",
    "admin:emit",
    "admin:keys",
]

# Effect scopes (what effects this key can propose)
EffectScope = Literal[
    "READ_REPO",
    "WRITE_PATCH",
    "RUN_TESTS",
    "BUILD_ARTIFACT",
    "NETWORK_CALL",
    "SEND_NOTIFICATION",
    "CREATE_PR",
    "MERGE",
    "DEPLOY",
]


class KeyRecord(BaseModel):
    """
    API key record with scoped permissions.

    Fields:
    - key_id: Unique identifier for the key
    - key_hash: SHA-256 hash of the actual key
    - principal_type: Type of principal (adapter, runner, human, admin)
    - principal_id: Identifier for the specific principal (e.g., "Casey")
    - endpoint_scopes: What endpoints this key can access
    - effect_scopes: What effects this key can propose (for proposal:create)
    - max_risk: Maximum risk score this key can submit
    - enabled: Whether the key is active
    - expires_at: Optional expiration timestamp
    - created_at: When the key was created
    - description: Human-readable description
    """
    key_id: str
    key_hash: str
    principal_type: PrincipalType
    principal_id: str
    endpoint_scopes: Set[EndpointScope]
    effect_scopes: Set[EffectScope] = Field(default_factory=set)
    max_risk: float = Field(default=1.0, ge=0.0, le=1.0)
    enabled: bool = True
    expires_at: Optional[datetime] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    description: Optional[str] = None

    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat() if v else None,
            set: lambda v: sorted(list(v)),
        }


class AuthDecision(BaseModel):
    """
    Result of an authentication/authorization decision.
    """
    allowed: bool
    key_id: Optional[str] = None
    principal_type: Optional[PrincipalType] = None
    principal_id: Optional[str] = None
    reason: str
    reason_code: str  # Machine-readable code


# Reason codes for auth decisions
class AuthReasonCode:
    # Allow codes
    ALLOWED = "allowed"

    # Deny codes (4xx)
    MISSING_KEY = "missing_key"
    INVALID_KEY = "invalid_key"
    KEY_DISABLED = "key_disabled"
    KEY_EXPIRED = "key_expired"
    ENDPOINT_SCOPE_DENIED = "endpoint_scope_denied"
    EFFECT_SCOPE_DENIED = "effect_scope_denied"
    RISK_CAP_EXCEEDED = "risk_cap_exceeded"


def generate_key() -> tuple[str, str]:
    """
    Generate a new API key and its hash.

    Returns:
        Tuple of (plaintext_key, key_hash)
    """
    # Generate 32-byte random key
    plaintext = f"m87_{secrets.token_hex(32)}"
    key_hash = hash_key(plaintext)
    return plaintext, key_hash


def _sha256_hash(plaintext: str) -> str:
    """Legacy SHA-256 hash (deterministic, used for lookup + migration)."""
    return hashlib.sha256(plaintext.encode()).hexdigest()


def _is_legacy_sha256(h: str) -> bool:
    """Check if a stored hash is legacy SHA-256 (64-char hex)."""
    return len(h) == 64 and all(c in "0123456789abcdef" for c in h)


def hash_key(plaintext: str) -> str:
    """
    Hash an API key using Argon2id (preferred) or SHA-256 (fallback).

    Argon2id provides:
    - Timing-attack resistance (constant-time comparison)
    - Memory-hard hashing (GPU/ASIC resistant)
    - Salt per hash (no rainbow tables)

    Falls back to SHA-256 if passlib[argon2] is not installed.
    """
    if _ARGON2_AVAILABLE:
        return _ARGON2_HASHER.hash(plaintext)
    return _sha256_hash(plaintext)


def verify_key_hash(plaintext: str, stored_hash: str) -> bool:
    """
    Verify a plaintext key against a stored hash.

    Supports both Argon2id and legacy SHA-256 hashes.
    Returns True if the key matches.
    """
    if _is_legacy_sha256(stored_hash):
        return hmac.compare_digest(stored_hash, _sha256_hash(plaintext))
    if _ARGON2_AVAILABLE:
        try:
            return _ARGON2_HASHER.verify(plaintext, stored_hash)
        except Exception:
            return False
    return False


def needs_rehash(stored_hash: str) -> bool:
    """Check if a stored hash should be rehashed to Argon2id."""
    if not _ARGON2_AVAILABLE:
        return False
    if _is_legacy_sha256(stored_hash):
        return True
    try:
        return _ARGON2_HASHER.needs_update(stored_hash)
    except Exception:
        return False


def generate_key_id() -> str:
    """Generate a unique key ID."""
    return f"key_{secrets.token_hex(8)}"
