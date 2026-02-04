"""
Red team invariant tests for M87 governance.

These tests prove the governance chain catches salami-slicing attacks,
confused deputy patterns, and sensor blindness scenarios.
"""
from __future__ import annotations

import pytest

from app.session_risk import SessionRiskTracker
from app.governance.effects import EffectTag, parse_effects
from app.governance.resource_limits import (
    bounded_python_tripwire_scan,
    GovernanceTimeout,
    GovernanceLimitExceeded,
    enforce_size_limit,
    Limits,
)
from app.governance.adversarial_review import (
    stable_proposal_hash,
    generate_challenge,
    verify_challenge,
)


# ---- Fake Redis for testing ----

class FakeRedis:
    """In-memory Redis mock for testing."""

    def __init__(self):
        self.data = {}
        self._should_fail = False

    def set_should_fail(self, should_fail: bool):
        """Make Redis operations fail (simulates network issues)."""
        self._should_fail = should_fail

    def zrangebyscore(self, key, a, b):
        if self._should_fail:
            raise ConnectionError("Redis unavailable")
        return list(self.data.get(key, []))

    def pipeline(self):
        return FakePipeline(self)

    def delete(self, key):
        if key in self.data:
            del self.data[key]


class FakePipeline:
    def __init__(self, redis_instance):
        self.redis = redis_instance
        self.ops = []

    def zadd(self, key, mapping):
        for k in mapping.keys():
            self.redis.data.setdefault(key, set()).add(k.encode("utf-8"))
        return self

    def expire(self, key, ttl):
        return self

    def execute(self):
        return True


# ---- Session Risk Tests ----

class TestSessionRiskTracker:
    """Tests for cumulative risk tracking and toxic topology detection."""

    def test_salami_slicing_repo_read_then_network_escalates(self):
        """
        Invariant: READ_REPO followed by NETWORK_CALL must escalate.

        This is the classic salami-slicing exfiltration pattern.
        """
        r = FakeRedis()
        t = SessionRiskTracker(r=r, window_seconds=300, ttl_seconds=1800)

        principal, agent = "p1", "a1"

        # Step 1: benign repo read is allowed and committed
        d1, _ = t.evaluate(principal, agent, ["READ_REPO"])
        assert d1 == "ALLOW"
        t.commit(principal, agent, ["READ_REPO"])

        # Step 2: now propose a network call -> toxic topology becomes satisfied
        d2, reason = t.evaluate(principal, agent, ["NETWORK_CALL"])
        assert d2 in ("REQUIRE_HUMAN", "DENY")
        assert "Toxic topology" in reason

    def test_secrets_then_network_is_hard_deny(self):
        """
        Invariant: READ_SECRETS followed by NETWORK_CALL must be DENY, not just escalate.
        """
        r = FakeRedis()
        t = SessionRiskTracker(r=r)

        principal, agent = "p1", "a1"

        # Read secrets
        d1, _ = t.evaluate(principal, agent, ["READ_SECRETS"])
        # Note: READ_SECRETS alone might be allowed (org-dependent)
        t.commit(principal, agent, ["READ_SECRETS"])

        # Network call after secrets must be DENY
        d2, reason = t.evaluate(principal, agent, ["NETWORK_CALL"])
        assert d2 == "DENY"
        assert "secrets_then_network" in reason

    def test_redis_blind_escalates_exfil_adjacent(self):
        """
        Invariant: When Redis is unavailable, exfil-adjacent effects must escalate.

        Fail-closed when the sensor is blind.
        """
        r = FakeRedis()
        r.set_should_fail(True)
        t = SessionRiskTracker(r=r)

        # Network call when blind must escalate
        d, reason = t.evaluate("p1", "a1", ["NETWORK_CALL"])
        assert d == "REQUIRE_HUMAN"
        assert "sensor unavailable" in reason.lower()

    def test_redis_blind_allows_readonly(self):
        """
        Invariant: When Redis is unavailable, read-only effects may proceed.

        Don't block all work just because history is unavailable.
        """
        r = FakeRedis()
        r.set_should_fail(True)
        t = SessionRiskTracker(r=r)

        # Read-only when blind is allowed
        d, reason = t.evaluate("p1", "a1", ["READ_REPO"])
        assert d == "ALLOW"

    def test_unknown_effect_escalates(self):
        """
        Invariant: Unknown effect tags must escalate.

        Unknown effects map to OTHER which is inherently suspicious.
        """
        r = FakeRedis()
        t = SessionRiskTracker(r=r)

        d, reason = t.evaluate("p1", "a1", ["TOTALLY_UNKNOWN_EFFECT"])
        assert d == "REQUIRE_HUMAN"
        assert "Unknown effect" in reason

    def test_topology_only_triggers_once(self):
        """
        Invariant: Toxic topology only triggers when newly satisfied.

        If both effects were already committed, re-proposing shouldn't re-trigger.
        """
        r = FakeRedis()
        t = SessionRiskTracker(r=r)

        principal, agent = "p1", "a1"

        # Commit both effects (maybe via two separate approved proposals)
        t.commit(principal, agent, ["READ_REPO"])
        t.commit(principal, agent, ["NETWORK_CALL"])

        # Now propose something else - shouldn't re-trigger topology
        d, reason = t.evaluate(principal, agent, ["COMPUTE"])
        assert d == "ALLOW"


# ---- Tripwire Scan Tests ----

class TestTripwireScan:
    """Tests for code artifact scanning."""

    def test_detects_socket_import(self):
        """Invariant: import socket must be flagged."""
        code = "import socket\ns = socket.socket()"
        result = bounded_python_tripwire_scan(code)
        assert not result["ok"]
        assert "import_socket" in result["flags"]

    def test_detects_requests_import(self):
        """Invariant: import requests must be flagged."""
        code = "import requests\nrequests.get('http://evil.com')"
        result = bounded_python_tripwire_scan(code)
        assert not result["ok"]
        assert "import_requests" in result["flags"]

    def test_detects_subprocess(self):
        """Invariant: subprocess usage must be flagged."""
        code = "import subprocess\nsubprocess.run(['rm', '-rf', '/'])"
        result = bounded_python_tripwire_scan(code)
        assert not result["ok"]
        assert "subprocess" in result["flags"]

    def test_detects_environ_access(self):
        """Invariant: os.environ access must be flagged."""
        code = "import os\nsecret = os.environ['API_KEY']"
        result = bounded_python_tripwire_scan(code)
        assert not result["ok"]
        assert "os_environ" in result["flags"]

    def test_detects_eval(self):
        """Invariant: eval() must be flagged."""
        code = "evil = 'print(1)'\neval(evil)"
        result = bounded_python_tripwire_scan(code)
        assert not result["ok"]
        assert "eval" in result["flags"]

    def test_clean_code_passes(self):
        """Invariant: Clean code should pass."""
        code = "def add(a, b):\n    return a + b\nprint(add(1, 2))"
        result = bounded_python_tripwire_scan(code)
        assert result["ok"]
        assert result["flags"] == []

    def test_size_limit_enforced(self):
        """Invariant: Oversized code must be rejected."""
        limits = Limits(max_code_bytes=100)
        code = "x" * 200
        with pytest.raises(GovernanceLimitExceeded):
            enforce_size_limit(code, limits)


# ---- Challenge-Response Tests ----

class TestChallengeResponse:
    """Tests for adversarial review challenge-response."""

    def test_correct_answer_passes(self):
        """Invariant: Correct answer with valid binding passes."""
        proposal_hash = stable_proposal_hash('{"test": "proposal"}')
        ch = generate_challenge(proposal_hash, "repo_read_then_network")

        result = verify_challenge(ch, "repo_read_then_network")
        assert result["ok"] == "true"

    def test_wrong_answer_fails(self):
        """Invariant: Wrong answer fails."""
        proposal_hash = stable_proposal_hash('{"test": "proposal"}')
        ch = generate_challenge(proposal_hash, "repo_read_then_network")

        result = verify_challenge(ch, "wrong_answer")
        assert result["ok"] == "false"
        assert result["reason"] == "challenge_failed"

    def test_tampered_binding_fails(self):
        """Invariant: Tampered challenge binding fails."""
        proposal_hash = stable_proposal_hash('{"test": "proposal"}')
        ch = generate_challenge(proposal_hash, "repo_read_then_network")

        # Create a tampered challenge with wrong proposal hash
        from app.governance.adversarial_review import Challenge
        tampered = Challenge(
            challenge_id=ch.challenge_id,
            prompt=ch.prompt,
            expected=ch.expected,
            proposal_hash="tampered_hash",
        )

        result = verify_challenge(tampered, "repo_read_then_network")
        assert result["ok"] == "false"
        assert result["reason"] == "challenge_binding_failed"

    def test_different_proposals_different_challenges(self):
        """Invariant: Different proposals produce different challenge IDs."""
        hash1 = stable_proposal_hash('{"proposal": 1}')
        hash2 = stable_proposal_hash('{"proposal": 2}')

        ch1 = generate_challenge(hash1, "topology")
        ch2 = generate_challenge(hash2, "topology")

        assert ch1.challenge_id != ch2.challenge_id


# ---- Effect Taxonomy Tests ----

class TestEffectTaxonomy:
    """Tests for effect parsing and classification."""

    def test_parse_valid_effects(self):
        """Invariant: Valid effects parse correctly."""
        effects = parse_effects(["READ_REPO", "NETWORK_CALL"])
        assert EffectTag.READ_REPO in effects
        assert EffectTag.NETWORK_CALL in effects

    def test_parse_unknown_maps_to_other(self):
        """Invariant: Unknown effects map to OTHER."""
        effects = parse_effects(["UNKNOWN_EFFECT"])
        assert EffectTag.OTHER in effects

    def test_parse_mixed(self):
        """Invariant: Mix of valid and unknown works correctly."""
        effects = parse_effects(["READ_REPO", "TOTALLY_FAKE"])
        assert EffectTag.READ_REPO in effects
        assert EffectTag.OTHER in effects
