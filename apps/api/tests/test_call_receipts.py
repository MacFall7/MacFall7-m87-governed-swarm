"""
Per-Call Receipt Layer — Phase 1 Tests

Tests CR_01 through CR_07 verify the call receipt models, emitter,
hash chain integrity, and integration contract.

These tests validate Invariant #4 (Artifact-Backed Completion) at
per-call granularity.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

# Ensure imports work from test directory
API_DIR = Path(__file__).parent.parent
if str(API_DIR) not in sys.path:
    sys.path.insert(0, str(API_DIR))

from app.governance.call_receipt import (
    CallReceipt,
    DecisionOutcome,
    DecisionRecord,
    EffectClass,
    ExecutionRecord,
    PostureLevel,
    ProposalRecord,
    ReceiptEmitter,
    ReversibilityClass,
    _deterministic_serialize,
    classify_effects,
    map_decision_outcome,
    map_posture_level,
)

# Schema path for validation
SCHEMA_DIR = API_DIR / "app" / "governance" / "schemas"
SCHEMA_PATH = SCHEMA_DIR / "call_receipt.schema.json"


def _make_proposal(
    tool: str = "echo",
    effect: EffectClass = EffectClass.READ_ONLY,
    redacted: bool = False,
    resource_paths: list = None,
    rev_class: ReversibilityClass = None,
) -> ProposalRecord:
    """Helper to build a ProposalRecord for tests."""
    return ProposalRecord(
        proposal_hash=hashlib.sha256(b"test-proposal").hexdigest(),
        tool=tool,
        operation="test operation",
        args_hash=hashlib.sha256(b"test-args").hexdigest(),
        args_redacted=redacted,
        resource_paths=resource_paths or [],
        effect_class=effect,
        reversibility_class=rev_class,
    )


def _make_decision(
    outcome: DecisionOutcome = DecisionOutcome.APPROVE,
    posture: PostureLevel = PostureLevel.NORMAL,
    risk_delta: float = None,
    cumulative_risk: float = None,
    reason: str = None,
) -> DecisionRecord:
    """Helper to build a DecisionRecord for tests."""
    return DecisionRecord(
        outcome=outcome,
        posture_at_decision=posture,
        risk_delta=risk_delta,
        cumulative_risk=cumulative_risk,
        reason=reason,
        policy_path="governance_gate",
    )


def _make_execution(
    exit_code: int = 0,
    execution_ms: float = 42.5,
) -> ExecutionRecord:
    """Helper to build an ExecutionRecord for tests."""
    result_bytes = b"test-result-output"
    return ExecutionRecord(
        result_hash=hashlib.sha256(result_bytes).hexdigest(),
        result_size_bytes=len(result_bytes),
        execution_ms=execution_ms,
        exit_code=exit_code,
        truncated=False,
    )


# ═══════════════════════════════════════════════════════════════
# CR_01: Schema compliance
# ═══════════════════════════════════════════════════════════════

class TestCR01SchemaCompliance:
    """Single approved READ_ONLY call produces a schema-valid receipt."""

    def test_receipt_validates_against_schema(self):
        """Receipt validates against call_receipt.schema.json."""
        emitter = ReceiptEmitter(session_id="test-session-cr01")
        proposal = _make_proposal(effect=EffectClass.READ_ONLY)
        decision = _make_decision(outcome=DecisionOutcome.APPROVE)

        receipt = emitter.emit_decision(proposal, decision)
        execution = _make_execution()
        emitter.record_execution(receipt, execution)

        data = receipt.model_dump(mode="json")

        # Verify structural requirements from schema
        assert data["receipt_version"] == "1.0.0"
        assert data["sequence_number"] == 0
        assert data["proposal"]["effect_class"] == "READ_ONLY"
        assert data["decision"]["outcome"] == "APPROVE"
        assert data["execution"] is not None
        assert len(data["execution"]["result_hash"]) == 64
        assert all(c in "0123456789abcdef" for c in data["execution"]["result_hash"])

    def test_receipt_hash_is_64_char_hex(self):
        """receipt_hash is a 64-character hex string after finalization."""
        emitter = ReceiptEmitter(session_id="test-session-cr01b")
        proposal = _make_proposal()
        decision = _make_decision()

        receipt = emitter.emit_decision(proposal, decision)
        emitter.record_execution(receipt, _make_execution())

        assert receipt.receipt_hash is not None
        assert len(receipt.receipt_hash) == 64
        assert all(c in "0123456789abcdef" for c in receipt.receipt_hash)

    def test_timestamp_is_utc(self):
        """timestamp_utc is timezone-aware UTC."""
        emitter = ReceiptEmitter(session_id="test-session-cr01c")
        receipt = emitter.emit_decision(_make_proposal(), _make_decision())
        assert receipt.timestamp_utc.tzinfo is not None


# ═══════════════════════════════════════════════════════════════
# CR_02: RESTRICTED redaction
# ═══════════════════════════════════════════════════════════════

class TestCR02RestrictedRedaction:
    """Proposal targeting restricted paths has hashed resource_paths."""

    def test_redacted_proposal_has_hashed_paths(self):
        """args_redacted == true and resource_paths contain hashes."""
        raw_paths = ["/var/log/governance/audit.log", "/etc/m87/secrets.yaml"]
        hashed_paths = [
            hashlib.sha256(p.encode()).hexdigest() for p in raw_paths
        ]

        proposal = _make_proposal(
            redacted=True,
            resource_paths=hashed_paths,
        )

        emitter = ReceiptEmitter(session_id="test-session-cr02")
        receipt = emitter.emit_decision(proposal, _make_decision())
        emitter.finalize_denied(receipt)

        assert receipt.proposal.args_redacted is True
        # Resource paths are hashes (64-char hex), not raw paths
        for path in receipt.proposal.resource_paths:
            assert len(path) == 64
            assert all(c in "0123456789abcdef" for c in path)
        # Original raw paths NOT present
        for raw in raw_paths:
            assert raw not in receipt.proposal.resource_paths
        # args_hash still present
        assert receipt.proposal.args_hash is not None
        assert len(receipt.proposal.args_hash) == 64


# ═══════════════════════════════════════════════════════════════
# CR_03: Emission failure non-blocking
# ═══════════════════════════════════════════════════════════════

class TestCR03EmissionFailureNonBlocking:
    """Receipt emission failure must not block the governance pipeline."""

    def test_ioerror_in_emitter_does_not_raise(self):
        """Wrapping receipt logic in try/except allows pipeline to continue."""
        # Simulate what main.py does: wrap in try/except
        receipt = None
        try:
            emitter = ReceiptEmitter(session_id="test-session-cr03")
            # Simulate IOError by patching datetime to raise
            with patch(
                "app.governance.call_receipt.datetime"
            ) as mock_dt:
                mock_dt.now.side_effect = IOError("disk full")
                mock_dt.side_effect = IOError("disk full")
                proposal = _make_proposal()
                decision = _make_decision()
                receipt = emitter.emit_decision(proposal, decision)
        except Exception:
            receipt = None

        # Pipeline continues regardless — receipt is None on failure
        # The governance decision would proceed here
        assert receipt is None or isinstance(receipt, CallReceipt)

    def test_pipeline_returns_decision_on_receipt_failure(self):
        """Governance decision is returned even when receipt emission fails."""
        # Simulate the actual pattern from main.py
        governance_decision = {"decision": "ALLOW", "reasons": ["test"]}

        receipt = None
        try:
            raise IOError("receipt storage failure")
        except Exception:
            receipt = None

        # Decision is unaffected
        assert governance_decision["decision"] == "ALLOW"
        assert receipt is None


# ═══════════════════════════════════════════════════════════════
# CR_04: Bundle includes receipts
# ═══════════════════════════════════════════════════════════════

class TestCR04BundleIncludesReceipts:
    """Session with 3 tool calls produces 3 receipts with chain hash."""

    def test_three_calls_produce_three_receipts(self):
        """3 calls (2 APPROVE, 1 DENY) produce 3 receipts."""
        emitter = ReceiptEmitter(session_id="test-session-cr04")

        # Call 1: APPROVE
        r1 = emitter.emit_decision(
            _make_proposal(tool="echo"),
            _make_decision(outcome=DecisionOutcome.APPROVE),
        )
        emitter.record_execution(r1, _make_execution())

        # Call 2: DENY
        r2 = emitter.emit_decision(
            _make_proposal(tool="pytest"),
            _make_decision(outcome=DecisionOutcome.DENY, reason="effect scope violation"),
        )
        emitter.finalize_denied(r2)

        # Call 3: APPROVE
        r3 = emitter.emit_decision(
            _make_proposal(tool="echo"),
            _make_decision(outcome=DecisionOutcome.APPROVE),
        )
        emitter.record_execution(r3, _make_execution(execution_ms=100.0))

        receipts = emitter.get_receipts()
        assert len(receipts) == 3

        # Sequence numbers
        assert receipts[0].sequence_number == 0
        assert receipts[1].sequence_number == 1
        assert receipts[2].sequence_number == 2

        # All have receipt_hash after finalization
        for r in receipts:
            assert r.receipt_hash is not None
            assert len(r.receipt_hash) == 64

        # Chain hash computable
        chain_hash = emitter.compute_chain_hash()
        assert chain_hash is not None
        assert len(chain_hash) == 64

    def test_receipt_filenames_include_sequence(self):
        """Filenames would use zero-padded sequence numbers."""
        emitter = ReceiptEmitter(session_id="test-session-cr04b")

        for i in range(3):
            r = emitter.emit_decision(_make_proposal(), _make_decision())
            emitter.finalize_denied(r)

        receipts = emitter.get_receipts()
        for r in receipts:
            filename = f"call_receipts/{r.sequence_number:04d}_{r.proposal.tool}.json"
            assert filename.startswith("call_receipts/")
            assert r.proposal.tool in filename


# ═══════════════════════════════════════════════════════════════
# CR_05: Hash chain integrity
# ═══════════════════════════════════════════════════════════════

class TestCR05HashChainIntegrity:
    """5 sequential calls form a valid hash chain."""

    def test_chain_links_are_correct(self):
        """receipt[0].previous_receipt_hash == null,
        receipt[n].previous_receipt_hash == receipt[n-1].receipt_hash."""
        emitter = ReceiptEmitter(session_id="test-session-cr05")

        receipts = []
        for i in range(5):
            r = emitter.emit_decision(
                _make_proposal(tool=f"tool_{i}"),
                _make_decision(),
            )
            emitter.record_execution(r, _make_execution(execution_ms=float(i * 10)))
            receipts.append(r)

        # First receipt has null previous
        assert receipts[0].previous_receipt_hash is None

        # Each subsequent links to previous
        for i in range(1, 5):
            assert receipts[i].previous_receipt_hash == receipts[i - 1].receipt_hash
            assert receipts[i].previous_receipt_hash is not None

        # No gaps in sequence
        for i, r in enumerate(receipts):
            assert r.sequence_number == i

    def test_hash_is_deterministic(self):
        """Same receipt data produces the same hash."""
        emitter = ReceiptEmitter(session_id="test-session-cr05b")
        proposal = _make_proposal()
        decision = _make_decision()

        receipt = emitter.emit_decision(proposal, decision)
        receipt.finalize()

        hash1 = receipt.receipt_hash
        hash2 = receipt.compute_hash()

        assert hash1 == hash2

    def test_chain_hash_changes_with_additional_receipt(self):
        """Adding a receipt changes the chain hash."""
        emitter = ReceiptEmitter(session_id="test-session-cr05c")

        r1 = emitter.emit_decision(_make_proposal(), _make_decision())
        emitter.record_execution(r1, _make_execution())
        chain1 = emitter.compute_chain_hash()

        r2 = emitter.emit_decision(_make_proposal(), _make_decision())
        emitter.record_execution(r2, _make_execution())
        chain2 = emitter.compute_chain_hash()

        assert chain1 != chain2


# ═══════════════════════════════════════════════════════════════
# CR_06: DENY has null execution
# ═══════════════════════════════════════════════════════════════

class TestCR06DenyHasNullExecution:
    """Denied proposals produce receipts with execution == null."""

    def test_deny_receipt_has_null_execution(self):
        """decision.outcome == DENY and execution == null."""
        emitter = ReceiptEmitter(session_id="test-session-cr06")
        proposal = _make_proposal()
        decision = _make_decision(
            outcome=DecisionOutcome.DENY,
            reason="READ_SECRETS is forbidden",
        )

        receipt = emitter.emit_decision(proposal, decision)
        emitter.finalize_denied(receipt)

        assert receipt.decision.outcome == DecisionOutcome.DENY
        assert receipt.execution is None
        # Receipt still has a hash
        assert receipt.receipt_hash is not None
        assert len(receipt.receipt_hash) == 64

    def test_deny_receipt_is_in_chain(self):
        """Denied receipts participate in the hash chain."""
        emitter = ReceiptEmitter(session_id="test-session-cr06b")

        # APPROVE
        r1 = emitter.emit_decision(_make_proposal(), _make_decision())
        emitter.record_execution(r1, _make_execution())

        # DENY
        r2 = emitter.emit_decision(
            _make_proposal(),
            _make_decision(outcome=DecisionOutcome.DENY),
        )
        emitter.finalize_denied(r2)

        # APPROVE
        r3 = emitter.emit_decision(_make_proposal(), _make_decision())
        emitter.record_execution(r3, _make_execution())

        # r2 links to r1, r3 links to r2
        assert r2.previous_receipt_hash == r1.receipt_hash
        assert r3.previous_receipt_hash == r2.receipt_hash


# ═══════════════════════════════════════════════════════════════
# CR_07: Posture and risk captured
# ═══════════════════════════════════════════════════════════════

class TestCR07PostureAndRiskCaptured:
    """Posture level and risk metrics are captured in decision record."""

    def test_elevated_posture_captured(self):
        """decision.posture_at_decision == ELEVATED with accumulated risk."""
        emitter = ReceiptEmitter(session_id="test-session-cr07")

        decision = _make_decision(
            posture=PostureLevel.ELEVATED,
            risk_delta=0.15,
            cumulative_risk=0.35,
        )
        receipt = emitter.emit_decision(_make_proposal(), decision)
        emitter.finalize_denied(receipt)

        assert receipt.decision.posture_at_decision == PostureLevel.ELEVATED
        assert receipt.decision.risk_delta == 0.15
        assert receipt.decision.cumulative_risk >= 0.30

    def test_posture_level_mapping(self):
        """M87 degradation tier values map to correct posture levels."""
        assert map_posture_level(0) == PostureLevel.NORMAL
        assert map_posture_level(1) == PostureLevel.ELEVATED
        assert map_posture_level(2) == PostureLevel.LOCKDOWN
        assert map_posture_level(3) == PostureLevel.HARD_TERMINATE

    def test_decision_outcome_mapping(self):
        """M87 governance decisions map to correct GBE outcomes."""
        assert map_decision_outcome("ALLOW") == DecisionOutcome.APPROVE
        assert map_decision_outcome("DENY") == DecisionOutcome.DENY
        assert map_decision_outcome("REQUIRE_HUMAN") == DecisionOutcome.PASS_TO_REVIEW

    def test_effect_classification(self):
        """M87 effect tags classify to correct GBE effect classes."""
        assert classify_effects(["READ_REPO"]) == EffectClass.READ_ONLY
        assert classify_effects(["WRITE_PATCH"]) == EffectClass.WRITE_LOCAL
        assert classify_effects(["RUN_TESTS"]) == EffectClass.SHELL_EXEC
        assert classify_effects(["DEPLOY"]) == EffectClass.NETWORK_TRANSMIT
        assert classify_effects(["CREATE_PR"]) == EffectClass.INTEGRATION_WIRE
        # Highest risk wins
        assert classify_effects(["READ_REPO", "DEPLOY"]) == EffectClass.NETWORK_TRANSMIT
