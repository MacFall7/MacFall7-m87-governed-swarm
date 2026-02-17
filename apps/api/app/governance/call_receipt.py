"""
M87 Governed Swarm — Per-Call Receipt Layer

Sealed artifact for each tool invocation through the governance pipeline.
Receipts are hash-chained, monotonic, and schema-validated.

Integration points:
- main.py: call emit_decision() after policy evaluation
- runner.py: call record_execution() after tool execution

MUST NOT block the governance pipeline. Failures are logged and swallowed.
"""
from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field

logger = logging.getLogger("m87.call_receipt")


# ── Canonical Enums (must match GBE spec v2.1.1 effect taxonomy) ──

class EffectClass(str, Enum):
    READ_ONLY = "READ_ONLY"
    WRITE_LOCAL = "WRITE_LOCAL"
    MODEL_INFERENCE = "MODEL_INFERENCE"
    EXTERNAL_READ = "EXTERNAL_READ"
    NETWORK_TRANSMIT = "NETWORK_TRANSMIT"
    PERMISSION_CHANGE = "PERMISSION_CHANGE"
    INTEGRATION_WIRE = "INTEGRATION_WIRE"
    SHELL_EXEC = "SHELL_EXEC"
    SCHEMA_MODIFY = "SCHEMA_MODIFY"


class ReversibilityClass(str, Enum):
    REVERSIBLE = "REVERSIBLE"
    PARTIALLY_REVERSIBLE = "PARTIALLY_REVERSIBLE"
    IRREVERSIBLE = "IRREVERSIBLE"


class DecisionOutcome(str, Enum):
    DENY = "DENY"
    PASS_TO_REVIEW = "PASS_TO_REVIEW"
    SKIP_FILE = "SKIP_FILE"
    FLAG_FOR_REVIEW = "FLAG_FOR_REVIEW"
    TRUNCATE_AND_FLAG = "TRUNCATE_AND_FLAG"
    INVALIDATE_BUNDLE = "INVALIDATE_BUNDLE"
    ESCALATE_TO_LOCKDOWN = "ESCALATE_TO_LOCKDOWN"
    FREEZE = "FREEZE"
    APPROVE = "APPROVE"


class PostureLevel(str, Enum):
    NORMAL = "NORMAL"
    ELEVATED = "ELEVATED"
    LOCKDOWN = "LOCKDOWN"
    HARD_TERMINATE = "HARD_TERMINATE"


# ── Receipt Models ──

class ProposalRecord(BaseModel):
    """What was proposed."""
    proposal_hash: str
    tool: str
    operation: Optional[str] = None
    args_hash: str
    args_redacted: bool = False
    resource_paths: list[str] = Field(default_factory=list)
    effect_class: EffectClass
    reversibility_class: Optional[ReversibilityClass] = None


class DecisionRecord(BaseModel):
    """What governance decided."""
    outcome: DecisionOutcome
    posture_at_decision: PostureLevel
    risk_delta: Optional[float] = None
    cumulative_risk: Optional[float] = None
    reason: Optional[str] = None
    policy_path: Optional[str] = None


class ExecutionRecord(BaseModel):
    """What the runner produced. Null if decision was not APPROVE."""
    result_hash: str
    result_size_bytes: int
    execution_ms: float
    exit_code: Optional[int] = None
    truncated: bool = False


class CallReceipt(BaseModel):
    """Sealed artifact for a single tool invocation."""
    receipt_version: str = "1.0.0"
    sequence_number: int
    session_id: str
    timestamp_utc: datetime
    previous_receipt_hash: Optional[str] = None
    proposal: ProposalRecord
    decision: DecisionRecord
    execution: Optional[ExecutionRecord] = None
    receipt_hash: Optional[str] = None

    def compute_hash(self) -> str:
        """Hash everything except receipt_hash itself."""
        data = self.model_dump(exclude={"receipt_hash"})
        serialized = _deterministic_serialize(data)
        return hashlib.sha256(serialized).hexdigest()

    def finalize(self) -> "CallReceipt":
        """Compute and set receipt_hash. Returns self for chaining."""
        self.receipt_hash = self.compute_hash()
        return self


# ── Receipt Emitter ──

class ReceiptEmitter:
    """
    Emits call receipts during a governance session.

    MUST NOT block the governance pipeline.
    All public methods must be wrapped in try/except at the call site.
    """

    def __init__(self, session_id: str):
        self._session_id = session_id
        self._sequence = 0
        self._receipts: list[CallReceipt] = []
        self._last_hash: Optional[str] = None

    def emit_decision(
        self,
        proposal: ProposalRecord,
        decision: DecisionRecord,
    ) -> CallReceipt:
        """
        Called AFTER governance decision, BEFORE runner dispatch.
        Returns receipt with execution=None.
        """
        receipt = CallReceipt(
            sequence_number=self._sequence,
            session_id=self._session_id,
            timestamp_utc=datetime.now(timezone.utc),
            previous_receipt_hash=self._last_hash,
            proposal=proposal,
            decision=decision,
            execution=None,
        )
        self._sequence += 1
        self._receipts.append(receipt)
        return receipt

    def record_execution(
        self,
        receipt: CallReceipt,
        execution: ExecutionRecord,
    ) -> CallReceipt:
        """
        Called AFTER runner execution, BEFORE result return.
        Updates receipt with execution data and finalizes hash chain.
        """
        receipt.execution = execution
        receipt.finalize()
        self._last_hash = receipt.receipt_hash
        return receipt

    def finalize_denied(self, receipt: CallReceipt) -> CallReceipt:
        """
        Called for non-APPROVE decisions (no execution).
        Finalizes hash chain without execution data.
        """
        receipt.finalize()
        self._last_hash = receipt.receipt_hash
        return receipt

    def get_receipts(self) -> list[CallReceipt]:
        """All receipts emitted in this session, in order."""
        return list(self._receipts)

    def compute_chain_hash(self) -> Optional[str]:
        """SHA-256 of all receipt hashes concatenated. For bundle receipt."""
        if not self._receipts:
            return None
        combined = "".join(
            r.receipt_hash for r in self._receipts if r.receipt_hash
        )
        return hashlib.sha256(combined.encode()).hexdigest()


# ── Utility ──

def _deterministic_serialize(data: dict) -> bytes:
    """Deterministic JSON bytes for hashing. Sorted keys, no whitespace."""
    return json.dumps(
        data,
        sort_keys=True,
        default=str,
        separators=(",", ":"),
    ).encode("utf-8")


# ── Effect mapping helper ──

# Maps M87 EffectTag values to GBE EffectClass for receipt generation.
EFFECT_TAG_TO_CLASS = {
    "READ_REPO": EffectClass.READ_ONLY,
    "READ_CONFIG": EffectClass.READ_ONLY,
    "READ_SECRETS": EffectClass.READ_ONLY,
    "COMPUTE": EffectClass.MODEL_INFERENCE,
    "WRITE_PATCH": EffectClass.WRITE_LOCAL,
    "RUN_TESTS": EffectClass.SHELL_EXEC,
    "BUILD_ARTIFACT": EffectClass.SHELL_EXEC,
    "CREATE_PR": EffectClass.INTEGRATION_WIRE,
    "MERGE": EffectClass.INTEGRATION_WIRE,
    "DEPLOY": EffectClass.NETWORK_TRANSMIT,
    "NETWORK_CALL": EffectClass.NETWORK_TRANSMIT,
    "SEND_NOTIFICATION": EffectClass.NETWORK_TRANSMIT,
    "OTHER": EffectClass.SHELL_EXEC,
}


def classify_effects(effects: list[str]) -> EffectClass:
    """
    Map M87 effect tags to the highest-risk GBE EffectClass.

    Priority order (highest risk first):
    NETWORK_TRANSMIT > INTEGRATION_WIRE > SHELL_EXEC > WRITE_LOCAL
    > MODEL_INFERENCE > EXTERNAL_READ > READ_ONLY
    """
    priority = [
        EffectClass.NETWORK_TRANSMIT,
        EffectClass.PERMISSION_CHANGE,
        EffectClass.INTEGRATION_WIRE,
        EffectClass.SHELL_EXEC,
        EffectClass.SCHEMA_MODIFY,
        EffectClass.WRITE_LOCAL,
        EffectClass.MODEL_INFERENCE,
        EffectClass.EXTERNAL_READ,
        EffectClass.READ_ONLY,
    ]
    classes = {EFFECT_TAG_TO_CLASS.get(e, EffectClass.SHELL_EXEC) for e in effects}
    for p in priority:
        if p in classes:
            return p
    return EffectClass.READ_ONLY


def map_decision_outcome(decision: str) -> DecisionOutcome:
    """Map M87 governance decision string to GBE DecisionOutcome."""
    mapping = {
        "ALLOW": DecisionOutcome.APPROVE,
        "DENY": DecisionOutcome.DENY,
        "REQUIRE_HUMAN": DecisionOutcome.PASS_TO_REVIEW,
        "NEED_MORE_EVIDENCE": DecisionOutcome.FLAG_FOR_REVIEW,
    }
    return mapping.get(decision, DecisionOutcome.DENY)


def map_posture_level(tier_value: int) -> PostureLevel:
    """Map M87 DegradationTier value to GBE PostureLevel."""
    mapping = {
        0: PostureLevel.NORMAL,
        1: PostureLevel.ELEVATED,
        2: PostureLevel.LOCKDOWN,
        3: PostureLevel.HARD_TERMINATE,
    }
    return mapping.get(tier_value, PostureLevel.NORMAL)
