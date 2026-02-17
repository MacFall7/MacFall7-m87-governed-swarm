"""
M87 API Key Store

Manages key storage and retrieval using Redis.
Keys are stored hashed; plaintext is never persisted.
"""

import json
from typing import Optional, List
from datetime import datetime
from redis import Redis

from .models import (
    KeyRecord,
    generate_key,
    generate_key_id,
    hash_key,
    verify_key_hash,
    needs_rehash,
    _sha256_hash,
)


class KeyStore:
    """
    Redis-backed key storage.

    Keys are stored in Redis hash: m87:keys:{key_hash}
    Index by key_id: m87:keys:id:{key_id} -> key_hash
    """

    KEY_PREFIX = "m87:keys:"
    ID_INDEX_PREFIX = "m87:keys:id:"

    def __init__(self, redis: Redis):
        self.redis = redis

    @staticmethod
    def _deserialize_record(data: dict) -> KeyRecord:
        """Deserialize a Redis-stored dict into a KeyRecord."""
        data["endpoint_scopes"] = set(data["endpoint_scopes"])
        data["effect_scopes"] = set(data["effect_scopes"])
        if data.get("expires_at"):
            data["expires_at"] = datetime.fromisoformat(data["expires_at"])
        if data.get("created_at"):
            data["created_at"] = datetime.fromisoformat(data["created_at"])
        return KeyRecord(**data)

    def _key_path(self, key_hash: str) -> str:
        return f"{self.KEY_PREFIX}{key_hash}"

    def _id_path(self, key_id: str) -> str:
        return f"{self.ID_INDEX_PREFIX}{key_id}"

    def create_key(
        self,
        principal_type: str,
        principal_id: str,
        endpoint_scopes: set,
        effect_scopes: set = None,
        max_risk: float = 1.0,
        description: str = None,
        expires_at: datetime = None,
    ) -> tuple[str, KeyRecord]:
        """
        Create a new API key.

        Returns:
            Tuple of (plaintext_key, KeyRecord)
        """
        plaintext, key_hash = generate_key()
        key_id = generate_key_id()

        record = KeyRecord(
            key_id=key_id,
            key_hash=key_hash,
            principal_type=principal_type,
            principal_id=principal_id,
            endpoint_scopes=endpoint_scopes,
            effect_scopes=effect_scopes or set(),
            max_risk=max_risk,
            enabled=True,
            expires_at=expires_at,
            created_at=datetime.utcnow(),
            description=description,
        )

        self._save_record(record)

        return plaintext, record

    def _save_record(self, record: KeyRecord):
        """Save key record to Redis."""
        data = record.model_dump(mode="json")
        # Convert sets to lists for JSON
        data["endpoint_scopes"] = list(data["endpoint_scopes"])
        data["effect_scopes"] = list(data["effect_scopes"])

        self.redis.set(
            self._key_path(record.key_hash),
            json.dumps(data)
        )
        # Index by key_id
        self.redis.set(
            self._id_path(record.key_id),
            record.key_hash
        )

    def get_by_plaintext(self, plaintext: str) -> Optional[KeyRecord]:
        """
        Look up key by plaintext.

        P1.A dual-verify migration:
        1. Try Argon2id lookup via key_id index scan (for non-deterministic hashes)
        2. Try legacy SHA-256 lookup (for backward compat)
        3. On successful legacy match, transparently rehash to Argon2id

        For seeded keys (bootstrap, service keys), lookup goes through key_id,
        so this method is mainly for dynamically-created keys.
        """
        # Fast path: try legacy SHA-256 lookup (deterministic → O(1))
        legacy_hash = _sha256_hash(plaintext)
        record = self.get_by_hash(legacy_hash)
        if record:
            # Transparent rehash: upgrade to Argon2id on next save
            if needs_rehash(record.key_hash):
                new_hash = hash_key(plaintext)
                old_hash = record.key_hash
                record.key_hash = new_hash
                self._save_record(record)
                # Clean up old hash key
                self.redis.delete(self._key_path(old_hash))
            return record

        # Slow path: scan all keys and verify against Argon2id hashes
        # This only triggers for Argon2id-hashed keys (non-deterministic)
        cursor = 0
        while True:
            cursor, found = self.redis.scan(cursor, match=f"{self.KEY_PREFIX}*", count=100)
            for key_path in found:
                if isinstance(key_path, bytes):
                    key_path = key_path.decode("utf-8")
                if "id:" in key_path:
                    continue
                data = self.redis.get(key_path)
                if not data:
                    continue
                record_data = json.loads(data)
                stored_hash = record_data.get("key_hash", "")
                if verify_key_hash(plaintext, stored_hash):
                    return self._deserialize_record(record_data)
            if cursor == 0:
                break

        return None

    def get_by_hash(self, key_hash: str) -> Optional[KeyRecord]:
        """Look up key by hash."""
        data = self.redis.get(self._key_path(key_hash))
        if not data:
            return None
        return self._deserialize_record(json.loads(data))

    def get_by_id(self, key_id: str) -> Optional[KeyRecord]:
        """Look up key by key_id."""
        key_hash = self.redis.get(self._id_path(key_id))
        if not key_hash:
            return None
        return self.get_by_hash(key_hash)

    def disable_key(self, key_id: str) -> bool:
        """Disable a key by ID."""
        record = self.get_by_id(key_id)
        if not record:
            return False

        record.enabled = False
        self._save_record(record)
        return True

    def enable_key(self, key_id: str) -> bool:
        """Enable a key by ID."""
        record = self.get_by_id(key_id)
        if not record:
            return False

        record.enabled = True
        self._save_record(record)
        return True

    def delete_key(self, key_id: str) -> bool:
        """Delete a key by ID."""
        key_hash = self.redis.get(self._id_path(key_id))
        if not key_hash:
            return False

        self.redis.delete(self._key_path(key_hash))
        self.redis.delete(self._id_path(key_id))
        return True

    def list_keys(self) -> List[KeyRecord]:
        """List all keys (for admin)."""
        # Scan for all key hashes
        keys = []
        cursor = 0
        while True:
            cursor, found = self.redis.scan(cursor, match=f"{self.KEY_PREFIX}*", count=100)
            for key_path in found:
                # Skip index entries
                if "id:" in key_path:
                    continue
                data = self.redis.get(key_path)
                if data:
                    keys.append(self._deserialize_record(json.loads(data)))
            if cursor == 0:
                break
        return keys

    def seed_bootstrap_key(self, bootstrap_key: str) -> KeyRecord:
        """
        Create the initial admin bootstrap key.
        This key has full access and is used to create other keys.

        Args:
            bootstrap_key: The plaintext key to use (from environment)

        Returns:
            The created KeyRecord
        """
        key_id = "key_bootstrap"

        # Clean up old hash entry (same orphan-prevention as seed_service_key)
        old_hash = self.redis.get(self._id_path(key_id))
        if old_hash:
            self.redis.delete(self._key_path(old_hash))

        key_hash = hash_key(bootstrap_key)

        record = KeyRecord(
            key_id=key_id,
            key_hash=key_hash,
            principal_type="admin",
            principal_id="bootstrap",
            endpoint_scopes={
                "proposal:create",
                "proposal:approve",
                "proposal:deny",
                "runner:result",
                "admin:emit",
                "admin:keys",
            },
            effect_scopes={
                "READ_REPO", "WRITE_PATCH", "RUN_TESTS", "BUILD_ARTIFACT",
                "NETWORK_CALL", "SEND_NOTIFICATION", "CREATE_PR", "MERGE", "DEPLOY"
            },
            max_risk=1.0,
            enabled=True,
            description="Bootstrap admin key (from M87_BOOTSTRAP_KEY env)",
        )

        self._save_record(record)
        return record

    def seed_service_key(
        self,
        plaintext_key: str,
        key_id: str,
        principal_type: str,
        principal_id: str,
        endpoint_scopes: set,
        effect_scopes: set = None,
        max_risk: float = 1.0,
        description: str = None,
    ) -> KeyRecord:
        """
        Seed a scoped service key (idempotent).

        If a key with the same key_id already exists, it is overwritten
        to ensure scopes stay current with the codebase definition.

        Args:
            plaintext_key: The plaintext key (from environment)
            key_id: Stable identifier for this service key
            principal_type: Type of principal (adapter, runner, service)
            principal_id: Identifier for the principal (e.g., "Casey")
            endpoint_scopes: Allowed endpoints
            effect_scopes: Allowed effects (for proposals)
            max_risk: Maximum risk score
            description: Human-readable description

        Returns:
            The created/updated KeyRecord
        """
        # Delete any previous hash entry for this key_id before saving.
        # Argon2id is non-deterministic, so each call to hash_key() produces
        # a different hash string. Without cleanup, _save_record() writes a
        # new m87:keys:{new_hash} entry while the old m87:keys:{old_hash}
        # entry remains orphaned — growing Redis and confusing scan-based
        # lookups.
        old_hash = self.redis.get(self._id_path(key_id))
        if old_hash:
            self.redis.delete(self._key_path(old_hash))

        key_hash = hash_key(plaintext_key)

        record = KeyRecord(
            key_id=key_id,
            key_hash=key_hash,
            principal_type=principal_type,
            principal_id=principal_id,
            endpoint_scopes=endpoint_scopes,
            effect_scopes=effect_scopes or set(),
            max_risk=max_risk,
            enabled=True,
            description=description,
        )

        self._save_record(record)
        return record
