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
        """Look up key by plaintext (hashes and queries)."""
        key_hash = hash_key(plaintext)
        return self.get_by_hash(key_hash)

    def get_by_hash(self, key_hash: str) -> Optional[KeyRecord]:
        """Look up key by hash."""
        data = self.redis.get(self._key_path(key_hash))
        if not data:
            return None

        record_data = json.loads(data)
        # Convert lists back to sets
        record_data["endpoint_scopes"] = set(record_data["endpoint_scopes"])
        record_data["effect_scopes"] = set(record_data["effect_scopes"])
        # Parse datetime
        if record_data.get("expires_at"):
            record_data["expires_at"] = datetime.fromisoformat(record_data["expires_at"])
        if record_data.get("created_at"):
            record_data["created_at"] = datetime.fromisoformat(record_data["created_at"])

        return KeyRecord(**record_data)

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
                    record_data = json.loads(data)
                    record_data["endpoint_scopes"] = set(record_data["endpoint_scopes"])
                    record_data["effect_scopes"] = set(record_data["effect_scopes"])
                    if record_data.get("expires_at"):
                        record_data["expires_at"] = datetime.fromisoformat(record_data["expires_at"])
                    if record_data.get("created_at"):
                        record_data["created_at"] = datetime.fromisoformat(record_data["created_at"])
                    keys.append(KeyRecord(**record_data))
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
        key_hash = hash_key(bootstrap_key)
        key_id = "key_bootstrap"

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
            description="Bootstrap admin key (from M87_API_KEY env)",
        )

        self._save_record(record)
        return record
