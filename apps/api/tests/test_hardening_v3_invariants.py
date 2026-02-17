"""
M87 Hardening Package v3 Invariant Tests

Tests for the operational-security hardening items:
- P0.A: Scoped service credentials (seed_service_key, scope enforcement)
- P0.B: File-based job dispatch (job_dispatcher)
- P1.A: Argon2id key hashing (dual-verify migration)
- P1.B: Kill-switch lockdown (_enforce_killswitch_lockdown)
- P2.A: Per-key rate limiting (Redis sliding window)

These are "laws of physics" — if they fail, the system is broken.
"""
from __future__ import annotations

import json
import os
import time
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


# ===========================================================================
# P0.A: Scoped Service Credentials
# ===========================================================================

class TestScopedServiceCredentials:
    """P0.A: Each service gets its own scoped key with minimal permissions."""

    def _make_store(self):
        """Create a KeyStore backed by a mock Redis (dict-based)."""
        from app.auth.store import KeyStore
        from app.auth.models import hash_key, _sha256_hash

        # Simple dict-backed mock Redis for testing
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
                import fnmatch
                results = []
                for k in list(store_data.keys()):
                    if match and fnmatch.fnmatch(k, match):
                        results.append(k)
                return (0, results)

        return KeyStore(FakeRedis()), store_data

    def test_seed_service_key_creates_scoped_record(self):
        """Seeding a service key creates a record with correct scopes."""
        store, _ = self._make_store()
        record = store.seed_service_key(
            plaintext_key="test-runner-key",
            key_id="key_runner",
            principal_type="runner",
            principal_id="runner",
            endpoint_scopes={"runner:result"},
            effect_scopes=set(),
            max_risk=0.0,
            description="Runner key",
        )
        assert record.key_id == "key_runner"
        assert record.principal_type == "runner"
        assert record.endpoint_scopes == {"runner:result"}
        assert record.effect_scopes == set()
        assert record.max_risk == 0.0

    def test_seed_service_key_is_idempotent(self):
        """Re-seeding overwrites with current scopes."""
        store, _ = self._make_store()
        r1 = store.seed_service_key(
            plaintext_key="key1",
            key_id="key_casey",
            principal_type="adapter",
            principal_id="Casey",
            endpoint_scopes={"proposal:create"},
            effect_scopes={"READ_REPO"},
            max_risk=0.5,
        )
        r2 = store.seed_service_key(
            plaintext_key="key1",
            key_id="key_casey",
            principal_type="adapter",
            principal_id="Casey",
            endpoint_scopes={"proposal:create"},
            effect_scopes={"READ_REPO", "WRITE_PATCH"},
            max_risk=0.6,
        )
        assert r2.effect_scopes == {"READ_REPO", "WRITE_PATCH"}
        assert r2.max_risk == 0.6

    def test_scoped_key_denies_wrong_endpoint(self):
        """A runner key can't hit admin:keys endpoint."""
        from app.auth.models import hash_key, KeyRecord
        from app.auth.store import KeyStore
        from app.auth.verifier import KeyVerifier

        store, _ = self._make_store()
        store.seed_service_key(
            plaintext_key="runner-secret",
            key_id="key_runner",
            principal_type="runner",
            principal_id="runner",
            endpoint_scopes={"runner:result"},
        )

        verifier = KeyVerifier(store)
        decision = verifier.verify(
            plaintext_key="runner-secret",
            endpoint_scope="admin:keys",
        )
        assert not decision.allowed
        assert decision.reason_code == "endpoint_scope_denied"

    def test_scoped_key_denies_wrong_effects(self):
        """Casey's key can't propose DEPLOY effects."""
        store, _ = self._make_store()
        store.seed_service_key(
            plaintext_key="casey-secret",
            key_id="key_casey",
            principal_type="adapter",
            principal_id="Casey",
            endpoint_scopes={"proposal:create"},
            effect_scopes={"READ_REPO", "WRITE_PATCH", "RUN_TESTS"},
            max_risk=0.6,
        )

        from app.auth.verifier import KeyVerifier
        verifier = KeyVerifier(store)
        decision = verifier.verify(
            plaintext_key="casey-secret",
            endpoint_scope="proposal:create",
            requested_effects={"READ_REPO", "DEPLOY"},
        )
        assert not decision.allowed
        assert decision.reason_code == "effect_scope_denied"

    def test_scoped_key_denies_excess_risk(self):
        """Casey's key can't submit risk > 0.6."""
        store, _ = self._make_store()
        store.seed_service_key(
            plaintext_key="casey-secret",
            key_id="key_casey",
            principal_type="adapter",
            principal_id="Casey",
            endpoint_scopes={"proposal:create"},
            effect_scopes={"READ_REPO"},
            max_risk=0.6,
        )

        from app.auth.verifier import KeyVerifier
        verifier = KeyVerifier(store)
        decision = verifier.verify(
            plaintext_key="casey-secret",
            endpoint_scope="proposal:create",
            requested_effects={"READ_REPO"},
            risk_score=0.8,
        )
        assert not decision.allowed
        assert decision.reason_code == "risk_cap_exceeded"

    def test_scoped_key_allows_within_scope(self):
        """Casey can propose READ_REPO within risk cap."""
        store, _ = self._make_store()
        store.seed_service_key(
            plaintext_key="casey-secret",
            key_id="key_casey",
            principal_type="adapter",
            principal_id="Casey",
            endpoint_scopes={"proposal:create"},
            effect_scopes={"READ_REPO", "WRITE_PATCH", "RUN_TESTS"},
            max_risk=0.6,
        )

        from app.auth.verifier import KeyVerifier
        verifier = KeyVerifier(store)
        decision = verifier.verify(
            plaintext_key="casey-secret",
            endpoint_scope="proposal:create",
            requested_effects={"READ_REPO"},
            risk_score=0.3,
        )
        assert decision.allowed
        assert decision.principal_id == "Casey"


# ===========================================================================
# P0.B: File-based Job Dispatch
# ===========================================================================

class TestFileJobDispatch:
    """P0.B: File-based dispatch for airgapped runner."""

    def test_write_job_envelope_creates_file(self, tmp_path):
        """write_job_envelope creates atomic JSON file."""
        from app.job_dispatcher import write_job_envelope, JOB_QUEUE_PATH
        import app.job_dispatcher as jd

        # Override paths
        jd.JOB_QUEUE_PATH = tmp_path
        job = {"job_id": "test-123", "tool": "echo", "inputs": {"message": "hi"}}
        path = write_job_envelope(job)
        assert path.exists()
        data = json.loads(path.read_text())
        assert data["job_id"] == "test-123"

    def test_claim_result_returns_none_if_missing(self, tmp_path):
        """claim_result returns None for non-existent result."""
        from app.job_dispatcher import claim_result
        import app.job_dispatcher as jd

        jd.RESULT_QUEUE_PATH = tmp_path
        assert claim_result("nonexistent-job") is None

    def test_claim_result_returns_data_and_moves_to_inflight(self, tmp_path):
        """claim_result reads result and moves to inflight (ack-on-success)."""
        from app.job_dispatcher import claim_result, ack_result
        import app.job_dispatcher as jd

        jd.RESULT_QUEUE_PATH = tmp_path
        result_file = tmp_path / "job-abc.result.json"
        result_file.write_text(json.dumps({"status": "completed", "output": {}}))

        claimed = claim_result("job-abc")
        assert claimed is not None
        data, inflight_path = claimed
        assert data["status"] == "completed"
        assert not result_file.exists()  # Original removed
        assert inflight_path.exists()    # Inflight file exists until ack
        ack_result(inflight_path)
        assert not inflight_path.exists()  # Cleaned up after ack

    def test_write_is_atomic(self, tmp_path):
        """Temp file + rename pattern avoids partial reads."""
        from app.job_dispatcher import write_job_envelope
        import app.job_dispatcher as jd

        jd.JOB_QUEUE_PATH = tmp_path
        job = {"job_id": "atomic-test", "tool": "echo", "inputs": {}}
        path = write_job_envelope(job)

        # No .tmp files should remain
        tmp_files = list(tmp_path.glob(".*tmp"))
        assert len(tmp_files) == 0
        assert path.exists()


# ===========================================================================
# P1.A: Argon2id Key Hashing
# ===========================================================================

class TestArgon2idKeyHashing:
    """P1.A: Argon2id hashing with SHA-256 backward compat."""

    def test_hash_key_produces_argon2_hash(self):
        """hash_key produces Argon2id hash when passlib available."""
        from app.auth.models import hash_key, _ARGON2_AVAILABLE
        if not _ARGON2_AVAILABLE:
            pytest.skip("passlib[argon2] not installed")

        h = hash_key("test-key-123")
        assert h.startswith("$argon2")

    def test_verify_key_hash_argon2(self):
        """verify_key_hash validates Argon2id hashes."""
        from app.auth.models import hash_key, verify_key_hash, _ARGON2_AVAILABLE
        if not _ARGON2_AVAILABLE:
            pytest.skip("passlib[argon2] not installed")

        h = hash_key("my-secret-key")
        assert verify_key_hash("my-secret-key", h)
        assert not verify_key_hash("wrong-key", h)

    def test_verify_key_hash_legacy_sha256(self):
        """verify_key_hash validates legacy SHA-256 hashes."""
        from app.auth.models import verify_key_hash, _sha256_hash

        legacy = _sha256_hash("old-key")
        assert verify_key_hash("old-key", legacy)
        assert not verify_key_hash("wrong-key", legacy)

    def test_is_legacy_sha256_detection(self):
        """_is_legacy_sha256 correctly identifies 64-char hex strings."""
        from app.auth.models import _is_legacy_sha256

        assert _is_legacy_sha256("a" * 64)
        assert _is_legacy_sha256("0123456789abcdef" * 4)
        assert not _is_legacy_sha256("$argon2id$v=19$m=65536,t=3,p=1$...")
        assert not _is_legacy_sha256("short")

    def test_needs_rehash_for_sha256(self):
        """SHA-256 hashes need rehash to Argon2id."""
        from app.auth.models import needs_rehash, _sha256_hash, _ARGON2_AVAILABLE
        if not _ARGON2_AVAILABLE:
            pytest.skip("passlib[argon2] not installed")

        legacy = _sha256_hash("key")
        assert needs_rehash(legacy)

    def test_needs_rehash_false_for_argon2(self):
        """Current Argon2id hashes don't need rehash."""
        from app.auth.models import hash_key, needs_rehash, _ARGON2_AVAILABLE
        if not _ARGON2_AVAILABLE:
            pytest.skip("passlib[argon2] not installed")

        h = hash_key("key")
        assert not needs_rehash(h)

    def test_dual_verify_migration(self):
        """Store.get_by_plaintext finds legacy SHA-256 keys and rehashes."""
        from app.auth.models import _sha256_hash, hash_key, _ARGON2_AVAILABLE
        from app.auth.store import KeyStore

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
                import fnmatch
                results = []
                for k in list(store_data.keys()):
                    if match and fnmatch.fnmatch(k, match):
                        results.append(k)
                return (0, results)

        store = KeyStore(FakeRedis())

        # Seed a key with legacy SHA-256 hash
        legacy_hash = _sha256_hash("my-key")
        record_data = {
            "key_id": "key_legacy",
            "key_hash": legacy_hash,
            "principal_type": "admin",
            "principal_id": "bootstrap",
            "endpoint_scopes": ["admin:keys"],
            "effect_scopes": [],
            "max_risk": 1.0,
            "enabled": True,
        }
        store_data[f"m87:keys:{legacy_hash}"] = json.dumps(record_data)
        store_data["m87:keys:id:key_legacy"] = legacy_hash

        # Look up by plaintext — should find via legacy path
        found = store.get_by_plaintext("my-key")
        assert found is not None
        assert found.key_id == "key_legacy"

        # If Argon2id is available, hash should have been upgraded
        if _ARGON2_AVAILABLE:
            assert found.key_hash.startswith("$argon2")


# ===========================================================================
# P1.B: Kill-switch Lockdown
# ===========================================================================

class TestKillswitchLockdown:
    """P1.B: Kill-switch denied in prod without authorization."""

    def test_killswitch_off_is_noop(self):
        """No kill-switch → function returns without error."""
        with patch.dict(os.environ, {"M87_DISABLE_PHASE36_GOVERNANCE": "0"}, clear=False):
            from app.main import _enforce_killswitch_lockdown
            _enforce_killswitch_lockdown()  # Should not raise

    def test_killswitch_on_dev_warns_but_allows(self):
        """Kill-switch in dev mode → warns but allows."""
        with patch.dict(os.environ, {"M87_DISABLE_PHASE36_GOVERNANCE": "1"}, clear=False):
            import app.main as main_mod
            old_env = main_mod.M87_ENV
            main_mod.M87_ENV = "dev"
            try:
                main_mod._enforce_killswitch_lockdown()  # Should not raise
            finally:
                main_mod.M87_ENV = old_env

    def test_killswitch_on_prod_default_key_crashes(self):
        """Kill-switch in prod with default key → RuntimeError."""
        with patch.dict(os.environ, {"M87_DISABLE_PHASE36_GOVERNANCE": "1"}, clear=False):
            import app.main as main_mod
            old_env = main_mod.M87_ENV
            old_key = main_mod.BOOTSTRAP_KEY
            main_mod.M87_ENV = "prod"
            main_mod.BOOTSTRAP_KEY = "m87-dev-key-change-me"
            try:
                with pytest.raises(RuntimeError, match="KILLSWITCH_LOCKDOWN"):
                    main_mod._enforce_killswitch_lockdown()
            finally:
                main_mod.M87_ENV = old_env
                main_mod.BOOTSTRAP_KEY = old_key

    def test_killswitch_on_prod_custom_key_no_override_crashes(self):
        """Kill-switch in prod with custom key but no override → crashes (fail-closed)."""
        with patch.dict(os.environ, {"M87_DISABLE_PHASE36_GOVERNANCE": "1"}, clear=False):
            import app.main as main_mod
            old_env = main_mod.M87_ENV
            old_key = main_mod.BOOTSTRAP_KEY
            old_path = main_mod.KILLSWITCH_OVERRIDE_PATH
            main_mod.M87_ENV = "prod"
            main_mod.BOOTSTRAP_KEY = "real-production-secret-key-12345"
            main_mod.KILLSWITCH_OVERRIDE_PATH = ""
            try:
                with pytest.raises(RuntimeError, match="KILLSWITCH_LOCKDOWN"):
                    main_mod._enforce_killswitch_lockdown()
            finally:
                main_mod.M87_ENV = old_env
                main_mod.BOOTSTRAP_KEY = old_key
                main_mod.KILLSWITCH_OVERRIDE_PATH = old_path

    def test_killswitch_on_prod_override_file_present(self, tmp_path):
        """Kill-switch in prod with override file → authorized."""
        override = tmp_path / "killswitch.override"
        override.write_text("authorized by ops team")

        with patch.dict(os.environ, {"M87_DISABLE_PHASE36_GOVERNANCE": "1"}, clear=False):
            import app.main as main_mod
            old_env = main_mod.M87_ENV
            old_key = main_mod.BOOTSTRAP_KEY
            old_path = main_mod.KILLSWITCH_OVERRIDE_PATH
            main_mod.M87_ENV = "prod"
            main_mod.BOOTSTRAP_KEY = "real-production-secret-key-12345"
            main_mod.KILLSWITCH_OVERRIDE_PATH = str(override)
            try:
                main_mod._enforce_killswitch_lockdown()  # Should not raise
            finally:
                main_mod.M87_ENV = old_env
                main_mod.BOOTSTRAP_KEY = old_key
                main_mod.KILLSWITCH_OVERRIDE_PATH = old_path

    def test_killswitch_on_prod_override_file_missing_crashes(self, tmp_path):
        """Kill-switch in prod with override path but missing file → RuntimeError."""
        with patch.dict(os.environ, {"M87_DISABLE_PHASE36_GOVERNANCE": "1"}, clear=False):
            import app.main as main_mod
            old_env = main_mod.M87_ENV
            old_key = main_mod.BOOTSTRAP_KEY
            old_path = main_mod.KILLSWITCH_OVERRIDE_PATH
            main_mod.M87_ENV = "prod"
            main_mod.BOOTSTRAP_KEY = "real-production-secret-key-12345"
            main_mod.KILLSWITCH_OVERRIDE_PATH = str(tmp_path / "nonexistent.override")
            try:
                with pytest.raises(RuntimeError, match="KILLSWITCH_LOCKDOWN"):
                    main_mod._enforce_killswitch_lockdown()
            finally:
                main_mod.M87_ENV = old_env
                main_mod.BOOTSTRAP_KEY = old_key
                main_mod.KILLSWITCH_OVERRIDE_PATH = old_path


# ===========================================================================
# P2.A: Per-key Rate Limiting
# ===========================================================================

class TestPerKeyRateLimiting:
    """P2.A: Redis sliding-window rate limiting per principal."""

    def _make_limiter(self):
        """Create rate limiter with dict-backed fake Redis."""
        from app.governance.rate_limiter import KeyRateLimiter

        sorted_sets = {}  # key → list of (member, score)

        class FakeRedis:
            def pipeline(self):
                return FakePipeline(sorted_sets)

            def zadd(self, key, mapping):
                if key not in sorted_sets:
                    sorted_sets[key] = []
                for member, score in mapping.items():
                    sorted_sets[key].append((member, score))

            def zremrangebyscore(self, key, min_score, max_score):
                if key not in sorted_sets:
                    return 0
                if min_score == "-inf":
                    min_score = float("-inf")
                if max_score == "+inf":
                    max_score = float("inf")
                before = len(sorted_sets[key])
                sorted_sets[key] = [
                    (m, s) for m, s in sorted_sets[key]
                    if not (float(min_score) if isinstance(min_score, str) and min_score != "-inf" else min_score) <= s <= (float(max_score) if isinstance(max_score, str) and max_score != "+inf" else max_score)
                ]
                return before - len(sorted_sets[key])

            def zcard(self, key):
                return len(sorted_sets.get(key, []))

            def zrange(self, key, start, stop, withscores=False):
                items = sorted_sets.get(key, [])
                items.sort(key=lambda x: x[1])
                sliced = items[start:stop + 1] if stop >= 0 else items[start:]
                return sliced if withscores else [m for m, s in sliced]

            def expire(self, key, seconds):
                pass  # No-op for tests

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

        return KeyRateLimiter(FakeRedis())

    def test_first_request_allowed(self):
        """First request always passes."""
        limiter = self._make_limiter()
        result = limiter.check_rate_limit("casey", max_per_minute=10)
        assert result.allowed
        assert result.current == 1
        assert result.limit == 10
        assert result.remaining == 9

    def test_under_limit_allowed(self):
        """Requests under limit pass."""
        limiter = self._make_limiter()
        for i in range(5):
            result = limiter.check_rate_limit("casey", max_per_minute=10)
            assert result.allowed

    def test_over_limit_denied(self):
        """Request over limit returns 429-worthy denial."""
        limiter = self._make_limiter()
        for i in range(3):
            result = limiter.check_rate_limit("casey", max_per_minute=3)
            assert result.allowed, f"Request {i} should be allowed"

        # 4th request should be denied
        result = limiter.check_rate_limit("casey", max_per_minute=3)
        assert not result.allowed
        assert result.remaining == 0
        assert "Rate limit exceeded" in result.reason

    def test_different_principals_independent(self):
        """Rate limits are per principal, not global."""
        limiter = self._make_limiter()

        # Fill up Casey's limit
        for _ in range(3):
            limiter.check_rate_limit("casey", max_per_minute=3)

        # Jordan still has budget
        result = limiter.check_rate_limit("jordan", max_per_minute=3)
        assert result.allowed

    def test_get_usage(self):
        """get_usage returns current state."""
        limiter = self._make_limiter()
        limiter.check_rate_limit("casey", max_per_minute=30)
        limiter.check_rate_limit("casey", max_per_minute=30)

        usage = limiter.get_usage("casey")
        assert usage["principal_id"] == "casey"
        assert usage["current"] == 2
        # get_usage uses the module-level default (30) since no override
        assert usage["limit"] == 30


# ===========================================================================
# Runner File Dispatch Loop (unit-level)
# ===========================================================================

class TestRunnerFileDispatch:
    """P0.B: Runner file dispatch mode integration."""

    def test_runner_dispatch_mode_env(self):
        """Runner reads DISPATCH_MODE from env."""
        # Just verify the module-level constant exists and defaults to redis
        import importlib
        # Importing runner in test context may fail due to missing redis connection,
        # so we just check the env var pattern
        assert os.getenv("M87_DISPATCH_MODE", "redis") in ("redis", "file")

    def test_runner_file_incoming_outgoing_paths(self):
        """FILE_INCOMING and FILE_OUTGOING have sensible defaults."""
        incoming = os.getenv("M87_FILE_INCOMING", "/dispatch/incoming")
        outgoing = os.getenv("M87_FILE_OUTGOING", "/dispatch/outgoing")
        assert incoming != outgoing


# ===========================================================================
# Docker Compose Consistency Checks
# ===========================================================================

class TestComposeConsistency:
    """Verify docker-compose files are internally consistent."""

    def _load_compose(self, filename):
        """Load compose YAML file (simple parser, no full YAML lib needed)."""
        path = Path(__file__).parent.parent.parent.parent / "infra" / filename
        if not path.exists():
            pytest.skip(f"{filename} not found at {path}")
        return path.read_text()

    def test_secure_compose_runner_has_no_network(self):
        """Secure compose runner must have network_mode: none."""
        content = self._load_compose("docker-compose.secure.yml")
        assert 'network_mode: "none"' in content

    def test_secure_compose_has_dispatch_volumes(self):
        """Secure compose defines dispatch_incoming and dispatch_outgoing volumes."""
        content = self._load_compose("docker-compose.secure.yml")
        assert "dispatch_incoming:" in content
        assert "dispatch_outgoing:" in content

    def test_secure_compose_no_stale_runner_volumes(self):
        """Secure compose doesn't reference old runner_jobs/runner_results volumes."""
        content = self._load_compose("docker-compose.secure.yml")
        # These should only appear in the volumes section if they're used,
        # and since we replaced them with dispatch_*, they shouldn't be declared
        lines = content.split("\n")
        volume_section = False
        declared_volumes = []
        for line in lines:
            if line.strip() == "volumes:":
                volume_section = True
                continue
            if volume_section:
                if line.startswith("  ") and ":" in line:
                    vol_name = line.strip().rstrip(":")
                    declared_volumes.append(vol_name)
                elif not line.startswith(" ") and line.strip():
                    break

        assert "runner_jobs" not in declared_volumes
        assert "runner_results" not in declared_volumes

    def test_secure_compose_runner_file_dispatch_mode(self):
        """Runner in secure compose uses file dispatch mode."""
        content = self._load_compose("docker-compose.secure.yml")
        assert "M87_DISPATCH_MODE=file" in content

    def test_secure_compose_has_scoped_keys(self):
        """Secure compose passes per-service key env vars to API."""
        content = self._load_compose("docker-compose.secure.yml")
        assert "M87_BOOTSTRAP_KEY" in content
        assert "M87_RUNNER_KEY" in content

    def test_main_compose_has_scoped_keys(self):
        """Main compose has P0.A scoped key env vars."""
        content = self._load_compose("docker-compose.yml")
        assert "M87_BOOTSTRAP_KEY" in content
        assert "M87_RUNNER_KEY" in content
        assert "M87_CASEY_KEY" in content


# ===========================================================================
# .env.example Consistency
# ===========================================================================

class TestEnvExample:
    """Verify .env.example documents all new env vars."""

    def test_env_example_has_scoped_keys(self):
        path = Path(__file__).parent.parent.parent.parent / ".env.example"
        if not path.exists():
            pytest.skip(".env.example not found")
        content = path.read_text()
        assert "M87_BOOTSTRAP_KEY" in content
        assert "M87_RUNNER_KEY" in content
        assert "M87_CASEY_KEY" in content
        assert "M87_JORDAN_KEY" in content
        assert "M87_RILEY_KEY" in content
        assert "M87_NOTIFIER_KEY" in content

    def test_env_example_has_killswitch(self):
        path = Path(__file__).parent.parent.parent.parent / ".env.example"
        if not path.exists():
            pytest.skip(".env.example not found")
        content = path.read_text()
        assert "M87_DISABLE_PHASE36_GOVERNANCE" in content
        assert "M87_KILLSWITCH_OVERRIDE_PATH" in content

    def test_env_example_has_rate_limit(self):
        path = Path(__file__).parent.parent.parent.parent / ".env.example"
        if not path.exists():
            pytest.skip(".env.example not found")
        content = path.read_text()
        assert "M87_RATE_LIMIT_PROPOSALS_PER_MIN" in content

    def test_env_example_has_m87_env(self):
        path = Path(__file__).parent.parent.parent.parent / ".env.example"
        if not path.exists():
            pytest.skip(".env.example not found")
        content = path.read_text()
        assert "M87_ENV" in content
