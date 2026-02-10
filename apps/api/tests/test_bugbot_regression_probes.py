"""
M87 — Bugbot Regression Probes

One probe per bug from the Bugbot audit.  These are structural regression
tests — if they fail, the fixed bug has been re-introduced.

PROBE 1: Enumeration depth bypass via dirpath.replace()
    Construct /workspace/workspace/deep and verify depth is counted correctly.
    The old code used dirpath.replace(root_path, "") which collapsed
    /workspace/workspace → workspace (stripping the root twice), undercounting.

PROBE 2: Rate limiter ZSET member collision
    Simulate two concurrent calls producing the same timestamp + count.
    With uuid nonce, both should be counted as distinct requests.

PROBE 3: Service key reseed orphaned entries
    Call seed_service_key() twice.  Assert only one m87:keys:{hash} entry
    exists for that key_id, and lookup returns the newest scope.

PROBE 4: allowed_base_dirs prefix bypass (/opt/data → /opt/dataexfil)
    base_dir "/opt/dataexfil" must be rejected when only "/opt/data" is allowed.

PROBE 5: Result file deleted before delivery ack
    Simulate failed post_result_to_api.  Assert result file is rolled back
    and still available for retry.
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

# Resolve project root
TEST_DIR = Path(__file__).parent.resolve()
API_DIR = TEST_DIR.parent
PROJECT_ROOT = API_DIR.parent.parent
sys.path.insert(0, str(API_DIR))
sys.path.insert(0, str(PROJECT_ROOT))


# ---------------------------------------------------------------------------
# PROBE 1: Enumeration depth bypass via dirpath.replace()
# ---------------------------------------------------------------------------

class TestEnumerationDepthBypass:
    """dirpath.replace(root_path, "") strips ALL occurrences, not just the prefix."""

    def test_workspace_inside_workspace_counted_correctly(self, tmp_path):
        """
        /workspace/workspace/deep should be depth=2, not depth=0.

        Old code: "/workspace/workspace/deep".replace("/workspace", "")
                 → "/deep"  (count(sep) = 1, should be 2)
        """
        from app.governance.enumeration_limits import (
            bounded_recursive_enumerate,
            EnumerationLimits,
        )

        # Create: tmp/workspace/workspace/deep/file.txt
        root = tmp_path / "workspace"
        nested = root / "workspace" / "deep"
        nested.mkdir(parents=True)
        (nested / "file.txt").write_text("x")

        # Enumerate with max_depth=1 — should be DENIED because
        # workspace/workspace/deep is depth=2
        limits = EnumerationLimits(max_depth=1, max_nodes=1000, max_time_seconds=5)
        result = bounded_recursive_enumerate(str(root), limits)
        assert not result.allowed, (
            f"Depth bypass: workspace/workspace/deep should exceed max_depth=1 "
            f"but was counted as depth {result.max_depth_seen}"
        )
        assert result.deny_code == "ENUMERATION_DEPTH_EXCEEDED"

    def test_root_depth_is_zero(self, tmp_path):
        """Root directory itself should be depth 0."""
        from app.governance.enumeration_limits import (
            bounded_recursive_enumerate,
            EnumerationLimits,
        )
        root = tmp_path / "data"
        root.mkdir()
        (root / "file.txt").write_text("x")

        limits = EnumerationLimits(max_depth=0, max_nodes=1000, max_time_seconds=5)
        result = bounded_recursive_enumerate(str(root), limits)
        # depth=0 means only root-level files, no subdirectories traversed
        assert result.allowed

    def test_single_level_is_depth_one(self, tmp_path):
        """One level of nesting should be depth 1."""
        from app.governance.enumeration_limits import (
            bounded_recursive_enumerate,
            EnumerationLimits,
        )
        root = tmp_path / "data"
        sub = root / "sub"
        sub.mkdir(parents=True)
        (sub / "file.txt").write_text("x")

        limits = EnumerationLimits(max_depth=0, max_nodes=1000, max_time_seconds=5)
        result = bounded_recursive_enumerate(str(root), limits)
        assert not result.allowed
        assert result.deny_code == "ENUMERATION_DEPTH_EXCEEDED"


# ---------------------------------------------------------------------------
# PROBE 2: Rate limiter ZSET member collision
# ---------------------------------------------------------------------------

class TestRateLimiterMemberCollision:
    """Concurrent requests with same timestamp must not collide."""

    def _make_limiter(self):
        """Create rate limiter with dict-backed fake Redis."""
        from app.governance.rate_limiter import KeyRateLimiter

        sorted_sets = {}

        class FakePipeline:
            def __init__(self, data):
                self.data = data
                self.commands = []

            def zremrangebyscore(self, key, min_s, max_s):
                self.commands.append(("zremrangebyscore", key, min_s, max_s))
                return self

            def zcard(self, key):
                self.commands.append(("zcard", key))
                return self

            def zadd(self, key, mapping):
                self.commands.append(("zadd", key, mapping))
                return self

            def expire(self, key, seconds):
                self.commands.append(("expire", key, seconds))
                return self

            def execute(self):
                results = []
                for cmd in self.commands:
                    if cmd[0] == "zremrangebyscore":
                        key, min_s, max_s = cmd[1], cmd[2], cmd[3]
                        if key not in self.data:
                            results.append(0)
                            continue
                        min_v = float("-inf") if min_s == "-inf" else float(min_s)
                        max_v = float("inf") if max_s == "+inf" else float(max_s)
                        before = len(self.data[key])
                        self.data[key] = [
                            (m, s) for m, s in self.data[key]
                            if not (min_v <= s <= max_v)
                        ]
                        results.append(before - len(self.data[key]))
                    elif cmd[0] == "zcard":
                        results.append(len(self.data.get(cmd[1], [])))
                    elif cmd[0] == "zadd":
                        key, mapping = cmd[1], cmd[2]
                        if key not in self.data:
                            self.data[key] = []
                        for member, score in mapping.items():
                            self.data[key].append((member, score))
                        results.append(len(mapping))
                    elif cmd[0] == "expire":
                        results.append(True)
                self.commands = []
                return results

        class FakeRedis:
            def pipeline(self):
                return FakePipeline(sorted_sets)

            def zadd(self, key, mapping):
                if key not in sorted_sets:
                    sorted_sets[key] = []
                for member, score in mapping.items():
                    sorted_sets[key].append((member, score))

            def zcard(self, key):
                return len(sorted_sets.get(key, []))

            def zrange(self, key, start, stop, withscores=False):
                items = sorted_sets.get(key, [])
                items.sort(key=lambda x: x[1])
                sliced = items[start:stop + 1] if stop >= 0 else items[start:]
                return sliced if withscores else [m for m, s in sliced]

            def expire(self, key, seconds):
                pass

        return KeyRateLimiter(FakeRedis()), sorted_sets

    def test_same_timestamp_same_count_distinct_members(self):
        """Two zadd calls at the exact same time with same count must both register."""
        limiter, _ = self._make_limiter()

        fixed_time = 1700000000.0
        with patch("app.governance.rate_limiter.time") as mock_time:
            mock_time.time.return_value = fixed_time

            r1 = limiter.check_rate_limit("test-user", max_per_minute=10)
            r2 = limiter.check_rate_limit("test-user", max_per_minute=10)

        assert r1.allowed
        assert r2.allowed
        assert r2.current == 2, (
            f"Second request should show count=2 but got {r2.current} — "
            f"ZSET member collision caused undercount"
        )

    def test_rapid_fire_all_counted(self):
        """5 rapid requests must all be counted distinctly."""
        limiter, _ = self._make_limiter()

        fixed_time = 1700000000.0
        with patch("app.governance.rate_limiter.time") as mock_time:
            mock_time.time.return_value = fixed_time
            for i in range(5):
                r = limiter.check_rate_limit("rapid-user", max_per_minute=10)
                assert r.allowed
                assert r.current == i + 1


# ---------------------------------------------------------------------------
# PROBE 3: Service key reseed orphaned entries
# ---------------------------------------------------------------------------

class TestServiceKeyReseedOrphans:
    """seed_service_key() twice must not leave orphaned hash entries."""

    def _make_store(self):
        """Create KeyStore with dict-backed FakeRedis."""
        from app.auth.store import KeyStore
        import fnmatch

        store_data = {}

        class FakeRedis:
            def get(self, key):
                return store_data.get(key)

            def set(self, key, value):
                store_data[key] = value

            def delete(self, *keys):
                for k in keys:
                    store_data.pop(k, None)

            def scan(self, cursor, match=None, count=100):
                results = []
                for k in list(store_data.keys()):
                    if match and fnmatch.fnmatch(k, match):
                        results.append(k)
                return (0, results)

        return KeyStore(FakeRedis()), store_data

    def test_reseed_cleans_old_hash_entry(self):
        """After two seeds, only one m87:keys:{hash} entry should exist for key_id."""
        store, store_data = self._make_store()

        key_id = "key_test_service"
        plaintext = "test-key-value"

        # First seed
        record1 = store.seed_service_key(
            plaintext_key=plaintext,
            key_id=key_id,
            principal_type="service",
            principal_id="test-svc",
            endpoint_scopes={"runner:result"},
            effect_scopes=set(),
            max_risk=0.0,
            description="Test service v1",
        )
        hash1 = record1.key_hash

        # Second seed (Argon2id produces different hash)
        record2 = store.seed_service_key(
            plaintext_key=plaintext,
            key_id=key_id,
            principal_type="service",
            principal_id="test-svc",
            endpoint_scopes={"runner:result", "proposal:create"},
            effect_scopes=set(),
            max_risk=0.5,
            description="Test service v2",
        )
        hash2 = record2.key_hash

        # The old hash entry must be gone
        if hash1 != hash2:
            assert store_data.get(f"m87:keys:{hash1}") is None, (
                f"Orphaned entry m87:keys:{hash1[:16]}... still exists after reseed"
            )

        # The key_id index must point to the new hash
        assert store_data.get(f"m87:keys:id:{key_id}") == hash2

        # Lookup by ID must return the newest record
        looked_up = store.get_by_id(key_id)
        assert looked_up is not None
        assert looked_up.max_risk == 0.5
        assert "proposal:create" in looked_up.endpoint_scopes

        # Count total m87:keys:{hash} entries (excluding id: entries)
        hash_entries = [k for k in store_data if k.startswith("m87:keys:") and ":id:" not in k]
        assert len(hash_entries) == 1, (
            f"Expected 1 hash entry, found {len(hash_entries)}: {hash_entries}"
        )

    def test_bootstrap_reseed_cleans_old_hash(self):
        """seed_bootstrap_key() twice must not leave orphaned entries."""
        store, store_data = self._make_store()

        record1 = store.seed_bootstrap_key("bootstrap-secret")
        hash1 = record1.key_hash

        record2 = store.seed_bootstrap_key("bootstrap-secret")
        hash2 = record2.key_hash

        if hash1 != hash2:
            assert store_data.get(f"m87:keys:{hash1}") is None, (
                "Orphaned bootstrap hash entry after reseed"
            )

        assert store_data.get(f"m87:keys:id:key_bootstrap") == hash2

        hash_entries = [k for k in store_data if k.startswith("m87:keys:") and ":id:" not in k]
        assert len(hash_entries) == 1


# ---------------------------------------------------------------------------
# PROBE 4: allowed_base_dirs prefix bypass
# ---------------------------------------------------------------------------

class TestAllowedBaseDirsPrefixBypass:
    """startswith("/opt/data") must NOT accept "/opt/dataexfil"."""

    def test_prefix_collision_rejected(self, tmp_path):
        """
        /opt/dataexfil must be rejected when only /opt/data is allowed.

        Old code: canonical_base.startswith(os.path.realpath("/opt/data"))
        would match "/opt/dataexfil" because it starts with "/opt/data".
        """
        from app.governance.glob_validation import governance_expand_glob

        # Create both directories
        allowed_dir = tmp_path / "opt" / "data"
        allowed_dir.mkdir(parents=True)
        evil_dir = tmp_path / "opt" / "dataexfil"
        evil_dir.mkdir(parents=True)
        (evil_dir / "secrets.txt").write_text("exfiltrated")

        result = governance_expand_glob(
            pattern="*",
            base_dir=str(evil_dir),
            allowed_base_dirs={str(allowed_dir)},
        )
        assert not result.approved, (
            f"/opt/dataexfil was accepted when only /opt/data is allowed — "
            f"prefix boundary check missing"
        )
        assert result.deny_code == "GLOB_BASE_DIR_NOT_ALLOWED"

    def test_exact_match_accepted(self, tmp_path):
        """Exact match of base_dir and allowed dir should be accepted."""
        from app.governance.glob_validation import governance_expand_glob

        allowed_dir = tmp_path / "workspace"
        allowed_dir.mkdir()
        (allowed_dir / "file.txt").write_text("ok")

        result = governance_expand_glob(
            pattern="*",
            base_dir=str(allowed_dir),
            allowed_base_dirs={str(allowed_dir)},
        )
        assert result.approved

    def test_subdirectory_accepted(self, tmp_path):
        """A subdirectory of an allowed dir should be accepted."""
        from app.governance.glob_validation import governance_expand_glob

        allowed_dir = tmp_path / "workspace"
        sub_dir = allowed_dir / "project"
        sub_dir.mkdir(parents=True)
        (sub_dir / "file.txt").write_text("ok")

        result = governance_expand_glob(
            pattern="*",
            base_dir=str(sub_dir),
            allowed_base_dirs={str(allowed_dir)},
        )
        assert result.approved


# ---------------------------------------------------------------------------
# PROBE 5: Result file deleted before delivery ack
# ---------------------------------------------------------------------------

class TestResultFileAckOnSuccess:
    """Result file must survive failed delivery and be available for retry."""

    def test_failed_post_preserves_result_file(self, tmp_path):
        """
        If post_result_to_api() fails, the result file must be rolled back
        from inflight to its original location for retry.
        """
        from app.job_dispatcher import claim_result, nack_result
        import app.job_dispatcher as jd

        jd.RESULT_QUEUE_PATH = tmp_path
        job_id = "job-delivery-fail"
        result_file = tmp_path / f"{job_id}.result.json"
        result_file.write_text(json.dumps({"status": "completed", "job_id": job_id}))

        # Claim the result (moves to inflight)
        claimed = claim_result(job_id)
        assert claimed is not None
        data, inflight_path = claimed

        # Simulate delivery failure
        assert not result_file.exists()  # Original is gone
        assert inflight_path.exists()    # Inflight exists

        # Nack — roll back
        nack_result(inflight_path, job_id)

        # Result file must be back in original location for retry
        assert result_file.exists(), (
            "Result file was lost after failed delivery — "
            "nack_result did not roll back the inflight file"
        )
        assert not inflight_path.exists()

        # Verify data is intact
        recovered = json.loads(result_file.read_text())
        assert recovered["job_id"] == job_id

    def test_successful_post_deletes_result(self, tmp_path):
        """After successful delivery, ack_result removes the inflight file."""
        from app.job_dispatcher import claim_result, ack_result
        import app.job_dispatcher as jd

        jd.RESULT_QUEUE_PATH = tmp_path
        job_id = "job-delivery-ok"
        result_file = tmp_path / f"{job_id}.result.json"
        result_file.write_text(json.dumps({"status": "completed", "job_id": job_id}))

        claimed = claim_result(job_id)
        assert claimed is not None
        data, inflight_path = claimed

        # Simulate successful delivery
        ack_result(inflight_path)

        # Both files should be gone
        assert not result_file.exists()
        assert not inflight_path.exists()

    def test_claim_is_atomic_against_double_read(self, tmp_path):
        """Two concurrent claim_result calls: only one should succeed."""
        from app.job_dispatcher import claim_result
        import app.job_dispatcher as jd

        jd.RESULT_QUEUE_PATH = tmp_path
        job_id = "job-double-claim"
        result_file = tmp_path / f"{job_id}.result.json"
        result_file.write_text(json.dumps({"status": "completed"}))

        claim1 = claim_result(job_id)
        claim2 = claim_result(job_id)

        # Exactly one should succeed
        assert claim1 is not None
        assert claim2 is None, "Double-claim succeeded — atomic rename failed"
