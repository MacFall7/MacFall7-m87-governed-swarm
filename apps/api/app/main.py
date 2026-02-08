from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import List, Optional, Literal, Dict, Any, Set
import os
import json
import uuid
import logging
import hashlib
import re
from pathlib import Path
from datetime import datetime
from redis import Redis

from .auth import (
    KeyStore,
    KeyVerifier,
    AuthDecision,
    AuthReasonCode,
    emit_auth_event,
)

from .db import (
    init_db,
    check_db_health,
    PersistenceUnavailable,
    persist_api_key,
    persist_proposal,
    persist_decision,
    persist_job,
    persist_execution,
    update_api_key_enabled,
    delete_api_key as db_delete_key,
)

# V1 Governance: Phase 3-6 unified governance route
from .routes.govern_proposal import router as govern_router
from .routes.govern_proposal import evaluate_governance_proposal

# V1.1 Reversibility Gate
from .governance.reversibility import (
    evaluate_reversibility_gate,
    create_downgrade_response,
    is_read_only_action,
)

# V2 Hardening: P0–P2 modules
from .governance.input_validation import (
    check_empty_args,
    check_semantic_truncation,
    validate_tool_inputs,
)
from .governance.virtual_fs_deny import (
    check_virtual_fs_access,
    VIRTUAL_FS_DENIED,
    VIRTUAL_FS_NOT_IN_ALLOWLIST,
)
from .governance.glob_validation import (
    governance_expand_glob,
    runner_revalidate_glob,
)
from .governance.enumeration_limits import (
    bounded_recursive_enumerate,
    EnumerationLimits,
)
from .governance.quarantine import (
    quarantine_manager,
    observability_quarantine,
    DegradationTier,
)
from .governance.rate_limiter import KeyRateLimiter, RateLimitResult

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="m87-governed-swarm-api", version="0.3.0")

# ---- Config
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
DATABASE_URL = os.getenv("DATABASE_URL", "")
# Auth keys: bootstrap (admin) + per-service scoped keys
# M87_BOOTSTRAP_KEY is the admin-only key. Services MUST NOT use it.
# Falls back to M87_API_KEY for backward compatibility.
BOOTSTRAP_KEY = os.getenv("M87_BOOTSTRAP_KEY", os.getenv("M87_API_KEY", "m87-dev-key-change-me"))

# Per-service keys (each service gets its own scoped key)
SERVICE_KEY_RUNNER = os.getenv("M87_RUNNER_KEY", "")
SERVICE_KEY_CASEY = os.getenv("M87_CASEY_KEY", "")
SERVICE_KEY_JORDAN = os.getenv("M87_JORDAN_KEY", "")
SERVICE_KEY_RILEY = os.getenv("M87_RILEY_KEY", "")
SERVICE_KEY_NOTIFIER = os.getenv("M87_NOTIFIER_KEY", "")

ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000").split(",")
ENABLE_TEST_ENDPOINTS = os.getenv("M87_ENABLE_TEST_ENDPOINTS", "false").lower() == "true"
M87_ENV = os.getenv("M87_ENV", "dev")  # dev | staging | prod


def load_tool_manifest() -> Dict[str, Any]:
    """Load and hash the tool manifest file."""
    path = os.getenv("M87_TOOL_MANIFEST_PATH", "")
    if not path:
        return {"ok": False, "error": "M87_TOOL_MANIFEST_PATH not set"}

    p = Path(path)
    if not p.exists():
        return {"ok": False, "error": f"Manifest not found at {path}"}

    raw = p.read_bytes()
    manifest_hash = hashlib.sha256(raw).hexdigest()
    data = json.loads(raw.decode("utf-8"))

    return {"ok": True, "manifest": data, "manifest_hash": manifest_hash, "path": str(p)}


def current_manifest_hash_or_die() -> str:
    """Get current manifest hash, or raise 500 if unavailable."""
    loaded = load_tool_manifest()
    if not loaded.get("ok"):
        raise HTTPException(status_code=500, detail=loaded.get("error"))
    return loaded["manifest_hash"]


# ---- Manifest lock verification (supply-chain integrity)
MANIFEST_LOCK_PATH = os.getenv("M87_MANIFEST_LOCK_PATH", "/app/manifest.lock.json")


def verify_manifest_lock() -> Dict[str, Any]:
    """
    Verify that tool_manifest.json matches manifest.lock.json.
    Returns verification result dict. Raises on critical mismatch.
    """
    lock_path = Path(MANIFEST_LOCK_PATH)
    if not lock_path.exists():
        return {"ok": False, "error": f"Lock file not found: {MANIFEST_LOCK_PATH}", "critical": False}

    try:
        lock_data = json.loads(lock_path.read_text())
    except Exception as e:
        return {"ok": False, "error": f"Failed to parse lock file: {e}", "critical": True}

    locked_hash = lock_data.get("sha256")
    if not locked_hash:
        return {"ok": False, "error": "Lock file missing sha256 field", "critical": True}

    # Load and hash the manifest
    manifest_result = load_tool_manifest()
    if not manifest_result.get("ok"):
        return {"ok": False, "error": f"Manifest load failed: {manifest_result.get('error')}", "critical": True}

    current_hash = manifest_result["manifest_hash"]

    if current_hash != locked_hash:
        return {
            "ok": False,
            "error": "MANIFEST_HASH_DRIFT",
            "detail": f"Lock expects {locked_hash[:16]}... but manifest is {current_hash[:16]}...",
            "locked_hash": locked_hash,
            "current_hash": current_hash,
            "critical": True,
        }

    return {
        "ok": True,
        "locked_hash": locked_hash,
        "manifest_version": lock_data.get("manifest_version"),
        "source_commit": lock_data.get("source_commit"),
    }


# ---- Phase 5 Step 3: Runner result caps + redaction
MAX_RUNNER_RESULT_BYTES = int(os.getenv("M87_MAX_RUNNER_RESULT_BYTES", "65536"))  # 64 KiB
MAX_RUNNER_TEXT_FIELD = int(os.getenv("M87_MAX_RUNNER_TEXT_FIELD", "8000"))       # per string field

_SECRET_PATTERNS = [
    # PEM blocks
    re.compile(r"-----BEGIN [A-Z ]+PRIVATE KEY-----.*?-----END [A-Z ]+PRIVATE KEY-----", re.DOTALL),
    # Common token-ish env assignments
    re.compile(r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*([^\s\"']+)", re.DOTALL),
    # AWS Access Key ID (heuristic)
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    # Generic long token blobs (heuristic)
    re.compile(r"\b[a-zA-Z0-9_\-]{32,}\b"),
]


def _truncate(s: str, limit: int = MAX_RUNNER_TEXT_FIELD) -> str:
    if s is None:
        return ""
    s = str(s)
    return s if len(s) <= limit else (s[:limit] + "…(truncated)")


def _redact_text(s: str) -> str:
    if not s:
        return s
    out = s
    for pat in _SECRET_PATTERNS:
        out = pat.sub("[REDACTED]", out)
    return out


def sanitize_output(obj: Any) -> Any:
    """
    Recursively redact + truncate strings inside runner output payloads.
    Keeps dict/list structure, only mutates string leaves.
    """
    if obj is None:
        return None
    if isinstance(obj, str):
        return _redact_text(_truncate(obj))
    if isinstance(obj, (int, float, bool)):
        return obj
    if isinstance(obj, list):
        return [sanitize_output(x) for x in obj[:200]]  # cap list length
    if isinstance(obj, dict):
        # cap number of keys to prevent payload bombs
        items = list(obj.items())[:200]
        return {str(k)[:128]: sanitize_output(v) for k, v in items}
    # fallback: stringify unknowns
    return _redact_text(_truncate(str(obj)))


# ---- Global state: persistence availability
_db_available = False

# CORS - tightened for V1.2
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["*"],
)

# ---- V1 Governance: Phase 3-6 unified governance route
app.include_router(govern_router)

# ---- Redis connection
rdb = Redis.from_url(REDIS_URL, decode_responses=True)

# ---- Auth system (V2.0 - scoped keys)
key_store = KeyStore(rdb)
key_verifier = KeyVerifier(key_store)

# ---- P2.A: Per-key rate limiter (Redis sliding window)
rate_limiter = KeyRateLimiter(rdb)

# Stream keys
EVENT_STREAM = "m87:events"
JOB_STREAM = "m87:jobs"

# Runner tool allowlist
ALLOWED_TOOLS = {"echo", "pytest", "git", "build"}


# ---- V1.3: Agent Profiles (effect scopes + risk thresholds)
AGENT_PROFILES: Dict[str, Dict[str, Any]] = {
    "Casey": {
        "allowed_effects": {"READ_REPO", "WRITE_PATCH", "RUN_TESTS"},
        "max_risk": 0.6,
        "description": "Code changes and testing",
    },
    "Jordan": {
        "allowed_effects": {"SEND_NOTIFICATION", "BUILD_ARTIFACT", "CREATE_PR", "READ_REPO"},
        "max_risk": 0.5,
        "description": "Artifacts, notifications, PRs",
    },
    "Riley": {
        "allowed_effects": {"READ_REPO", "BUILD_ARTIFACT", "SEND_NOTIFICATION"},
        "max_risk": 0.4,
        "description": "Analysis and reporting",
    },
    "Human": {
        "allowed_effects": {
            "READ_REPO", "WRITE_PATCH", "RUN_TESTS", "BUILD_ARTIFACT",
            "NETWORK_CALL", "SEND_NOTIFICATION", "CREATE_PR", "MERGE", "DEPLOY"
        },
        "max_risk": 1.0,
        "description": "Manual human proposals",
    },
}

DEFAULT_AGENT_PROFILE = {
    "allowed_effects": {"READ_REPO"},
    "max_risk": 0.3,
    "description": "Unknown agent (restricted)",
}


# ---- Event + Job emission (defined early for use in auth)
def emit(event_type: str, payload: Dict[str, Any]) -> str:
    """Emit event to Redis stream, returns event ID."""
    event_id = rdb.xadd(EVENT_STREAM, {"type": event_type, "payload": json.dumps(payload)})
    return event_id


# ---- P1.B: Kill-switch lockdown
# In prod, M87_DISABLE_PHASE36_GOVERNANCE=1 is a dangerous emergency-only escape hatch.
# If enabled in prod, the API refuses to start unless the bootstrap key is explicitly set
# (not the default) — proving a human operator authorized the override.
KILLSWITCH_OVERRIDE_PATH = os.getenv("M87_KILLSWITCH_OVERRIDE_PATH", "")


def _enforce_killswitch_lockdown() -> None:
    """
    P1.B — Refuse to boot in prod if kill-switch is enabled without authorization.

    Rules:
    - dev/staging: kill-switch allowed (with warning)
    - prod + kill-switch OFF: no action needed
    - prod + kill-switch ON: refuse boot UNLESS:
        1. M87_BOOTSTRAP_KEY is set to a non-default value (proves human set it), AND
        2. Either M87_KILLSWITCH_OVERRIDE_PATH points to an existing file (signed override)
           OR M87_ENV is not "prod"
    """
    killswitch_on = os.environ.get("M87_DISABLE_PHASE36_GOVERNANCE", "0") == "1"

    if not killswitch_on:
        return  # Nothing to do

    if M87_ENV != "prod":
        logger.warning(
            "KILLSWITCH ACTIVE: M87_DISABLE_PHASE36_GOVERNANCE=1 in %s mode. "
            "Phase 3-6 governance is BYPASSED.", M87_ENV
        )
        return

    # Prod + kill-switch ON: require authorization
    default_keys = {"m87-dev-key-change-me", "change-this-to-a-long-random-secret", ""}
    if BOOTSTRAP_KEY in default_keys:
        raise RuntimeError(
            "KILLSWITCH_LOCKDOWN: Cannot disable Phase 3-6 governance in prod "
            "with a default bootstrap key. Set M87_BOOTSTRAP_KEY to a unique secret."
        )

    if KILLSWITCH_OVERRIDE_PATH:
        override_path = Path(KILLSWITCH_OVERRIDE_PATH)
        if override_path.exists():
            logger.warning(
                "KILLSWITCH AUTHORIZED: Override file present at %s. "
                "Phase 3-6 governance is BYPASSED in prod. THIS IS AN EMERGENCY MEASURE.",
                KILLSWITCH_OVERRIDE_PATH,
            )
            return
        else:
            raise RuntimeError(
                f"KILLSWITCH_LOCKDOWN: Override file not found at {KILLSWITCH_OVERRIDE_PATH}. "
                "Cannot disable Phase 3-6 governance in prod without signed override."
            )

    # Bootstrap key is non-default but no override file configured
    logger.warning(
        "KILLSWITCH AUTHORIZED (key-only): Phase 3-6 governance BYPASSED in prod. "
        "Configure M87_KILLSWITCH_OVERRIDE_PATH for stronger authorization."
    )


# ---- Startup: Initialize database and seed bootstrap key
@app.on_event("startup")
async def startup_event():
    """Initialize the system on startup."""
    global _db_available
    logger.info("M87 API starting up (v0.4.0 - Manifest lock verification)...")

    # Verify manifest lock (supply-chain integrity)
    lock_result = verify_manifest_lock()
    if lock_result.get("ok"):
        logger.info(f"Manifest lock verified: {lock_result.get('locked_hash', '')[:16]}... (commit: {lock_result.get('source_commit', 'unknown')})")
    elif lock_result.get("critical"):
        logger.error(f"CRITICAL: Manifest lock verification failed: {lock_result.get('error')} - {lock_result.get('detail', '')}")
        raise RuntimeError(f"Manifest lock verification failed: {lock_result.get('error')}")
    else:
        logger.warning(f"Manifest lock not enforced: {lock_result.get('error')}")

    # Check Redis connection
    try:
        rdb.ping()
        logger.info("Redis connection OK")
    except Exception as e:
        logger.error(f"Redis connection failed: {e}")
        raise

    # Initialize database (Phase 2)
    if DATABASE_URL:
        try:
            if init_db():
                _db_available = True
                logger.info("Postgres connection OK - tables initialized")

                # Verify connectivity
                health = check_db_health()
                if not health["connected"]:
                    logger.error(f"Postgres health check failed: {health['error']}")
                    _db_available = False
            else:
                logger.error("Failed to initialize database tables")
                _db_available = False
        except Exception as e:
            logger.error(f"Postgres initialization failed: {e}")
            _db_available = False
    else:
        logger.warning("DATABASE_URL not configured - running without persistence")
        _db_available = False

    # Seed bootstrap key if it doesn't exist
    existing = key_store.get_by_plaintext(BOOTSTRAP_KEY)
    if not existing:
        record = key_store.seed_bootstrap_key(BOOTSTRAP_KEY)
        logger.info(f"Bootstrap key seeded: {record.key_id}")

        # Persist bootstrap key to Postgres if available
        if _db_available:
            try:
                persist_api_key(
                    key_id=record.key_id,
                    key_hash=record.key_hash,
                    principal_type=record.principal_type,
                    principal_id=record.principal_id,
                    endpoint_scopes=list(record.endpoint_scopes),
                    effect_scopes=list(record.effect_scopes),
                    max_risk=record.max_risk,
                    enabled=record.enabled,
                    description=record.description,
                )
            except Exception as e:
                logger.error(f"Failed to persist bootstrap key: {e}")
    else:
        logger.info(f"Bootstrap key already exists: {existing.key_id}")

    # P0.A: Seed scoped service keys (idempotent)
    # Each service gets only the scopes it needs — no shared admin key.
    _SERVICE_KEY_PROFILES = [
        {
            "env_key": SERVICE_KEY_RUNNER,
            "key_id": "key_runner",
            "principal_type": "runner",
            "principal_id": "runner",
            "endpoint_scopes": {"runner:result"},
            "effect_scopes": set(),
            "max_risk": 0.0,
            "description": "Runner: can only report job results",
        },
        {
            "env_key": SERVICE_KEY_CASEY,
            "key_id": "key_casey",
            "principal_type": "adapter",
            "principal_id": "Casey",
            "endpoint_scopes": {"proposal:create"},
            "effect_scopes": {"READ_REPO", "WRITE_PATCH", "RUN_TESTS"},
            "max_risk": 0.6,
            "description": "Casey adapter: code changes and testing",
        },
        {
            "env_key": SERVICE_KEY_JORDAN,
            "key_id": "key_jordan",
            "principal_type": "adapter",
            "principal_id": "Jordan",
            "endpoint_scopes": {"proposal:create"},
            "effect_scopes": {"SEND_NOTIFICATION", "BUILD_ARTIFACT", "CREATE_PR", "READ_REPO"},
            "max_risk": 0.5,
            "description": "Jordan adapter: artifacts, notifications, PRs",
        },
        {
            "env_key": SERVICE_KEY_RILEY,
            "key_id": "key_riley",
            "principal_type": "adapter",
            "principal_id": "Riley",
            "endpoint_scopes": {"proposal:create"},
            "effect_scopes": {"READ_REPO", "BUILD_ARTIFACT", "SEND_NOTIFICATION"},
            "max_risk": 0.4,
            "description": "Riley adapter: analysis and reporting",
        },
        {
            "env_key": SERVICE_KEY_NOTIFIER,
            "key_id": "key_notifier",
            "principal_type": "service",
            "principal_id": "notifier",
            "endpoint_scopes": {"admin:emit"},
            "effect_scopes": set(),
            "max_risk": 0.0,
            "description": "Notifier: can only emit events",
        },
    ]

    seeded_count = 0
    for profile in _SERVICE_KEY_PROFILES:
        plaintext = profile["env_key"]
        if not plaintext:
            continue  # Not configured — skip (backward compat)
        record = key_store.seed_service_key(
            plaintext_key=plaintext,
            key_id=profile["key_id"],
            principal_type=profile["principal_type"],
            principal_id=profile["principal_id"],
            endpoint_scopes=profile["endpoint_scopes"],
            effect_scopes=profile["effect_scopes"],
            max_risk=profile["max_risk"],
            description=profile["description"],
        )
        seeded_count += 1
        logger.info(f"Service key seeded: {record.key_id} ({record.principal_id})")

    if seeded_count > 0:
        logger.info(f"Seeded {seeded_count} scoped service key(s)")
    else:
        logger.warning("No scoped service keys configured — services may be using bootstrap key")

    # P1.B: Kill-switch lockdown
    _enforce_killswitch_lockdown()

    logger.info(f"M87 API ready (db_available={_db_available}, env={M87_ENV}, killswitch_locked={'prod' if M87_ENV == 'prod' else 'off'})")


# ---- Hard fail-safe helper (Phase 2)
def require_persistence():
    """
    Hard fail-safe: deny mutations if Postgres is unavailable.

    Raises HTTPException 503 if persistence is not available.
    """
    if not _db_available:
        logger.warning("Mutation denied: persistence unavailable")
        raise HTTPException(
            status_code=503,
            detail={
                "error": "DB_UNAVAILABLE",
                "message": "Persistence layer unavailable - mutations denied",
            }
        )


# ---- Auth helper
def verify_auth(
    x_m87_key: Optional[str],
    endpoint_scope: str,
    requested_effects: Optional[Set[str]] = None,
    risk_score: Optional[float] = None,
) -> AuthDecision:
    """
    Verify authentication and authorization for an endpoint.

    Raises HTTPException on failure.
    Returns AuthDecision on success (for logging principal info).
    """
    decision = key_verifier.verify(
        plaintext_key=x_m87_key,
        endpoint_scope=endpoint_scope,
        requested_effects=requested_effects,
        risk_score=risk_score,
    )

    # Log the auth decision
    emit_auth_event(decision, endpoint_scope, emit)

    if not decision.allowed:
        # Map reason codes to HTTP status codes
        if decision.reason_code in (AuthReasonCode.MISSING_KEY, AuthReasonCode.INVALID_KEY):
            raise HTTPException(status_code=401, detail=decision.reason)
        else:
            # Scope/permission errors are 403
            raise HTTPException(status_code=403, detail=decision.reason)

    return decision


# ---- Minimal in-service models
EffectTag = Literal[
    "READ_REPO",
    "WRITE_PATCH",
    "RUN_TESTS",
    "BUILD_ARTIFACT",
    "NETWORK_CALL",
    "SEND_NOTIFICATION",
    "CREATE_PR",
    "MERGE",
    "DEPLOY",
    "READ_SECRETS",
]

Decision = Literal["ALLOW", "DENY", "REQUIRE_HUMAN", "NEED_MORE_EVIDENCE"]
RunnerTool = Literal["echo", "pytest", "git", "build"]


class Intent(BaseModel):
    intent_id: str
    from_: str = Field(alias="from")
    mode: str
    goal: str
    constraints: Optional[Dict[str, Any]] = None


class TruthAccount(BaseModel):
    observations: List[str]
    claims: List[Dict[str, Any]]


class Proposal(BaseModel):
    proposal_id: str
    intent_id: str
    agent: str
    summary: str
    effects: List[EffectTag]
    artifacts: Optional[List[Dict[str, str]]] = None
    truth_account: TruthAccount
    risk_score: Optional[float] = None
    # V1 Governance: Optional deployment envelope (defaults applied if not provided)
    deployment_envelope: Optional[Dict[str, Any]] = None
    # V1.1 Reversibility Gate: Required for non-read actions
    reversibility_class: Optional[str] = None  # REVERSIBLE | PARTIALLY_REVERSIBLE | IRREVERSIBLE
    rollback_proof: Optional[Dict[str, Any]] = None  # Required for REVERSIBLE
    execution_mode: Optional[str] = "commit"  # commit | draft | preview
    # V2 Cleanup Cost: Affects autonomy budget allocation
    cleanup_cost: Optional[str] = None  # LOW | MEDIUM | HIGH


class GovernanceDecision(BaseModel):
    proposal_id: str
    decision: Decision
    reasons: List[str]
    required_approvals: Optional[List[str]] = None
    allowed_effects: Optional[List[EffectTag]] = None
    job_id: Optional[str] = None  # V1: included when job is minted
    # V1.1 Reversibility Gate
    reversibility_gate: Optional[Dict[str, Any]] = None  # Gate evaluation result
    safe_alternative: Optional[str] = None  # draft | preview | approval_required


class JobSpec(BaseModel):
    job_id: str
    proposal_id: str
    tool: RunnerTool
    inputs: Dict[str, Any] = {}
    sandbox: Dict[str, str] = {"network": "deny", "fs": "ro"}
    timeout_seconds: int = 60
    # V1.1 Reversibility Gate: Passed to runner for enforcement
    reversibility_class: Optional[str] = None
    rollback_proof: Optional[Dict[str, Any]] = None
    execution_mode: str = "commit"
    human_approved: bool = False
    # V2 Cleanup Cost: Budget adjustments from gate
    cleanup_cost: Optional[str] = None
    budget_multiplier: float = 1.0
    retry_limit: Optional[int] = None


# Phase 5 Step 3: Strict runner result contract
RunnerStatus = Literal["completed", "failed", "manifest_reject"]


# V1 Governance: Artifact-Backed Completion
class FileArtifact(BaseModel):
    """Verifiable file artifact with hash."""
    path: str = Field(..., min_length=1, max_length=512)
    sha256: str = Field(..., min_length=64, max_length=64)


class DiffArtifact(BaseModel):
    """Verifiable diff artifact with hash."""
    target: str = Field(..., min_length=1, max_length=512)
    diff_hash: str = Field(..., min_length=64, max_length=64)


class LogArtifact(BaseModel):
    """Verifiable log artifact with hash."""
    source: str = Field(..., min_length=1, max_length=256)
    sha256: str = Field(..., min_length=64, max_length=64)


class ReceiptArtifact(BaseModel):
    """Action receipt with proof."""
    action: str = Field(..., min_length=1, max_length=256)
    timestamp: str
    proof: Optional[str] = None


class CompletionArtifacts(BaseModel):
    """
    Verifiable artifacts required for task completion.
    A task cannot be marked complete without returning artifacts.
    """
    files: List[FileArtifact] = Field(default_factory=list)
    diffs: List[DiffArtifact] = Field(default_factory=list)
    logs: List[LogArtifact] = Field(default_factory=list)
    receipts: List[ReceiptArtifact] = Field(default_factory=list)

    def has_artifacts(self) -> bool:
        """Check if any artifacts are present."""
        return bool(self.files or self.diffs or self.logs or self.receipts)


# V1 Governance: Continuous Shadow Evaluations (CSE)
class ShadowEvalConfig(BaseModel):
    """Configuration for shadow evaluations."""
    eval_suite_hash: str = Field(..., min_length=64, max_length=64)
    prompt_family_hash: str = Field(..., min_length=64, max_length=64)
    scoring_function_hash: str = Field(..., min_length=64, max_length=64)
    trigger_interval_jobs: int = Field(default=100, ge=1, le=10000)
    drift_threshold: float = Field(default=0.1, ge=0, le=1.0)


class ShadowEvalResult(BaseModel):
    """Result from a shadow evaluation run."""
    eval_id: str
    envelope_hash: str
    eval_suite_hash: str
    drift_score: float
    passed: bool
    details: Dict[str, Any] = Field(default_factory=dict)
    run_at: str


class ShadowEvalTrigger(BaseModel):
    """Trigger conditions for shadow evaluation."""
    reason: str  # "interval", "envelope_change", "anomaly", "manual"
    job_id: Optional[str] = None
    envelope_hash: Optional[str] = None


# Shadow eval state (in-memory for now, would be persisted in production)
_shadow_eval_state = {
    "jobs_since_last_eval": 0,
    "last_eval_at": None,
    "last_drift_score": 0.0,
    "eval_history": [],
}

# Default shadow eval config (placeholder hashes)
DEFAULT_SHADOW_EVAL_CONFIG = ShadowEvalConfig(
    eval_suite_hash="0" * 64,  # Placeholder
    prompt_family_hash="0" * 64,  # Placeholder
    scoring_function_hash="0" * 64,  # Placeholder
    trigger_interval_jobs=100,
    drift_threshold=0.1,
)


class RunnerResult(BaseModel):
    job_id: str = Field(..., min_length=8, max_length=128)
    proposal_id: str = Field(..., min_length=1, max_length=128)
    status: RunnerStatus
    output: Dict[str, Any] = Field(default_factory=dict)
    manifest_hash: Optional[str] = Field(None, min_length=64, max_length=64)
    manifest_version: Optional[str] = Field(None, max_length=32)
    # V1 Governance: Artifact-Backed Completion
    completion_artifacts: Optional[CompletionArtifacts] = None
    envelope_hash: Optional[str] = Field(None, min_length=64, max_length=64)
    # V1 Step 2: Autonomy Budget forensics
    autonomy_budget: Optional[Dict[str, Any]] = None  # What was allowed
    autonomy_usage: Optional[Dict[str, Any]] = None   # What was consumed
    # V1 Governance: DEH verification evidence (machine-verifiable proof)
    deh_evidence: Optional[Dict[str, Any]] = None


class CreateKeyRequest(BaseModel):
    principal_type: str
    principal_id: str
    endpoint_scopes: List[str]
    effect_scopes: Optional[List[str]] = None
    max_risk: float = 1.0
    description: Optional[str] = None


# ---- V1 Governance Hardening: Deployment Envelope + Autonomy Budget
WriteScope = Literal["none", "sandbox", "staging", "prod"]
SafetyMode = Literal["safe_default", "governed", "restricted"]
ModelSource = Literal["closed", "open"]


class AutonomyBudget(BaseModel):
    """Rate and magnitude limits on agent behavior."""
    max_steps: int = Field(default=100, ge=1, le=10000)
    max_tool_calls: int = Field(default=50, ge=1, le=1000)
    max_parallel_agents: int = Field(default=1, ge=1, le=10)
    max_runtime_seconds: int = Field(default=300, ge=1, le=3600)
    max_external_io: int = Field(default=10, ge=0, le=100)
    max_write_scope: WriteScope = "sandbox"


class InferencePolicy(BaseModel):
    """Runtime behavior constraints for model inference."""
    reasoning_mode: bool = False
    tool_access_profile: str = "default"
    max_compute_class: str = "standard"


class DeploymentEnvelope(BaseModel):
    """
    Chain of custody for model + runtime configuration.
    Extends governance beyond tool manifests to post-training + runtime behavior.
    """
    model_id: str = Field(..., min_length=1, max_length=256)
    model_source: ModelSource = "closed"
    weights_hash: Optional[str] = Field(None, min_length=64, max_length=64)
    post_training_recipe_hash: Optional[str] = Field(None, min_length=64, max_length=64)
    inference_policy: InferencePolicy = Field(default_factory=InferencePolicy)
    safety_mode: SafetyMode = "safe_default"
    autonomy_budget: AutonomyBudget = Field(default_factory=AutonomyBudget)


def compute_deployment_envelope_hash(envelope: DeploymentEnvelope) -> str:
    """
    Compute DEH = SHA256(canonical_json(deployment_envelope))

    Canonicalization rules (MUST match runner):
    - mode="json" ensures JSON-serializable types
    - exclude_none=True prevents None field mismatches
    - sort_keys=True for deterministic ordering
    - separators=(',', ':') removes whitespace
    """
    canonical = json.dumps(
        envelope.model_dump(mode="json", exclude_none=True),
        sort_keys=True,
        separators=(',', ':'),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# Default envelope for backward compatibility (open-weight safe defaults)
DEFAULT_ENVELOPE = DeploymentEnvelope(
    model_id="m87-runner-v1",
    model_source="closed",
    safety_mode="safe_default",
    autonomy_budget=AutonomyBudget(
        max_steps=100,
        max_tool_calls=50,
        max_parallel_agents=1,
        max_runtime_seconds=300,
        max_external_io=10,
        max_write_scope="sandbox",
    ),
)


# ---- Job minting
def enqueue_job(
    proposal_id: str,
    tool: str,
    inputs: Dict[str, Any] = None,
    envelope: Optional[DeploymentEnvelope] = None,
    # V1.1 Reversibility Gate
    reversibility_class: Optional[str] = None,
    rollback_proof: Optional[Dict[str, Any]] = None,
    execution_mode: str = "commit",
    human_approved: bool = False,
    # V2 Cleanup Cost
    cleanup_cost: Optional[str] = None,
    budget_multiplier: float = 1.0,
    retry_limit: Optional[int] = None,
) -> str:
    """
    Mint a JobSpec and add to jobs stream.
    This is the ONLY way jobs get created - after governance.

    V0.3.0: Persists job to Postgres (write-through).
    V0.4.0: Pins manifest_hash for drift detection.
    V1.0.0: Includes deployment envelope + DEH.
    """
    if tool not in ALLOWED_TOOLS:
        raise ValueError(f"Tool '{tool}' not in allowlist: {ALLOWED_TOOLS}")

    job_id = str(uuid.uuid4())
    job_inputs = inputs or {}

    # Phase 5: Pin manifest hash at job mint time
    manifest_hash = current_manifest_hash_or_die()

    # V1 Governance: Use provided envelope or default
    job_envelope = envelope or DEFAULT_ENVELOPE

    # Open-weight safety: force safe defaults
    if job_envelope.model_source == "open":
        job_envelope = DeploymentEnvelope(
            **{**job_envelope.model_dump(), "safety_mode": "safe_default"}
        )

    # Compute Deployment Envelope Hash
    envelope_hash = compute_deployment_envelope_hash(job_envelope)

    # Sandbox derived from envelope write scope
    write_scope = job_envelope.autonomy_budget.max_write_scope
    sandbox = {
        "network": "deny" if write_scope in ("none", "sandbox") else "allow",
        "fs": "ro" if write_scope == "none" else "rw",
        "write_scope": write_scope,
    }

    # Timeout from autonomy budget
    timeout_seconds = min(job_envelope.autonomy_budget.max_runtime_seconds, 3600)

    job = {
        "job_id": job_id,
        "proposal_id": proposal_id,
        "tool": tool,
        "inputs": job_inputs,
        "sandbox": sandbox,
        "timeout_seconds": timeout_seconds,
        "manifest_hash": manifest_hash,
        # V1 Governance fields
        "envelope_hash": envelope_hash,
        "deployment_envelope": job_envelope.model_dump(),  # Full envelope for runner verification
        "autonomy_budget": job_envelope.autonomy_budget.model_dump(),
        "safety_mode": job_envelope.safety_mode,
        "model_id": job_envelope.model_id,
        # V1.1 Reversibility Gate
        "reversibility_class": reversibility_class,
        "rollback_proof": rollback_proof,
        "execution_mode": execution_mode,
        "human_approved": human_approved,
        # V2 Cleanup Cost
        "cleanup_cost": cleanup_cost,
        "budget_multiplier": budget_multiplier,
        "retry_limit": retry_limit,
    }

    # Phase 2: Persist job to Postgres (write-through)
    if _db_available:
        try:
            persist_job(
                job_id=job_id,
                proposal_id=proposal_id,
                tool=tool,
                inputs=job_inputs,
                sandbox=sandbox,
                timeout_seconds=timeout_seconds,
            )
        except PersistenceUnavailable as e:
            logger.error(f"Failed to persist job: {e}")
            raise HTTPException(
                status_code=503,
                detail={"error": "DB_WRITE_FAILED", "message": str(e)}
            )

    rdb.xadd(JOB_STREAM, {"job": json.dumps(job)})

    # V1 Telemetry: JOB_ACCEPTED with envelope_hash
    emit("job.created", {
        "job_id": job_id,
        "proposal_id": proposal_id,
        "tool": tool,
        "envelope_hash": envelope_hash,
        "safety_mode": job_envelope.safety_mode,
    })

    return job_id


def get_agent_profile(agent: str) -> Dict[str, Any]:
    """Get agent profile, returns default for unknown agents."""
    return AGENT_PROFILES.get(agent, DEFAULT_AGENT_PROFILE)


def check_agent_effects(agent: str, effects: List[str]) -> tuple[bool, Set[str]]:
    """Check if agent is allowed to propose these effects."""
    profile = get_agent_profile(agent)
    allowed = profile["allowed_effects"]
    requested = set(effects)
    disallowed = requested - allowed
    return len(disallowed) == 0, disallowed


def check_agent_risk(agent: str, risk_score: Optional[float]) -> tuple[bool, float]:
    """Check if proposal risk is within agent's threshold."""
    profile = get_agent_profile(agent)
    max_risk = profile["max_risk"]
    if risk_score is None:
        return True, max_risk
    return risk_score <= max_risk, max_risk


# ---- V1 Governance: Shadow Eval endpoints

@app.post("/v1/shadow-eval/trigger")
def trigger_shadow_eval(
    trigger: ShadowEvalTrigger,
    x_m87_key: Optional[str] = Header(None, alias="X-M87-Key"),
):
    """
    Trigger a shadow evaluation run.
    V1 Governance: Continuous Shadow Evaluations for drift detection.
    """
    verify_auth(x_m87_key, "admin:shadow-eval")

    eval_id = str(uuid.uuid4())
    config = DEFAULT_SHADOW_EVAL_CONFIG

    # Stub: In production, this would run actual evaluations
    # For now, emit telemetry and return a placeholder result
    drift_score = 0.0  # Placeholder - would be computed from actual eval
    passed = drift_score < config.drift_threshold

    result = ShadowEvalResult(
        eval_id=eval_id,
        envelope_hash=trigger.envelope_hash or "unknown",
        eval_suite_hash=config.eval_suite_hash,
        drift_score=drift_score,
        passed=passed,
        details={
            "trigger_reason": trigger.reason,
            "job_id": trigger.job_id,
            "stub": True,  # Indicates this is a stub implementation
        },
        run_at=datetime.utcnow().isoformat() + "Z",
    )

    # Update state
    _shadow_eval_state["last_eval_at"] = result.run_at
    _shadow_eval_state["last_drift_score"] = drift_score
    _shadow_eval_state["jobs_since_last_eval"] = 0
    _shadow_eval_state["eval_history"].append(result.model_dump())
    if len(_shadow_eval_state["eval_history"]) > 100:
        _shadow_eval_state["eval_history"] = _shadow_eval_state["eval_history"][-100:]

    # Emit telemetry
    emit("shadow_eval.run", {
        "eval_id": eval_id,
        "envelope_hash": trigger.envelope_hash,
        "drift_score": drift_score,
        "passed": passed,
        "trigger_reason": trigger.reason,
    })

    if not passed:
        emit("shadow_eval.drift_detected", {
            "eval_id": eval_id,
            "envelope_hash": trigger.envelope_hash,
            "drift_score": drift_score,
            "threshold": config.drift_threshold,
        })

    return result


@app.get("/v1/shadow-eval/status")
def shadow_eval_status(x_m87_key: Optional[str] = Header(None, alias="X-M87-Key")):
    """Get current shadow evaluation status."""
    verify_auth(x_m87_key, "admin:shadow-eval")

    return {
        "jobs_since_last_eval": _shadow_eval_state["jobs_since_last_eval"],
        "last_eval_at": _shadow_eval_state["last_eval_at"],
        "last_drift_score": _shadow_eval_state["last_drift_score"],
        "trigger_interval": DEFAULT_SHADOW_EVAL_CONFIG.trigger_interval_jobs,
        "drift_threshold": DEFAULT_SHADOW_EVAL_CONFIG.drift_threshold,
        "recent_evals": _shadow_eval_state["eval_history"][-10:],
    }


def maybe_trigger_shadow_eval(job_id: str, envelope_hash: str) -> None:
    """Check if shadow eval should be triggered based on job count."""
    _shadow_eval_state["jobs_since_last_eval"] += 1

    if _shadow_eval_state["jobs_since_last_eval"] >= DEFAULT_SHADOW_EVAL_CONFIG.trigger_interval_jobs:
        # In production, this would actually trigger an eval
        # For now, just emit telemetry
        emit("shadow_eval.trigger_due", {
            "jobs_since_last": _shadow_eval_state["jobs_since_last_eval"],
            "trigger_threshold": DEFAULT_SHADOW_EVAL_CONFIG.trigger_interval_jobs,
            "envelope_hash": envelope_hash,
        })


# ---- Endpoints

@app.get("/health")
def health():
    """
    Health check endpoint.

    Returns health status for Redis and Postgres.
    System is "ok" only if all required services are available.
    """
    redis_ok = False
    try:
        rdb.ping()
        redis_ok = True
    except Exception:
        pass

    db_health = check_db_health() if DATABASE_URL else {"connected": False, "error": "Not configured"}

    # System is healthy if Redis is up and (DB is up or not configured)
    system_ok = redis_ok and (db_health["connected"] or not DATABASE_URL)

    return {
        "ok": system_ok,
        "version": "2.0.0",
        "redis": "connected" if redis_ok else "disconnected",
        "postgres": "connected" if db_health["connected"] else "disconnected",
        "persistence_available": _db_available,
        "quarantine_tier": quarantine_manager.get_state().current_tier.value,
    }


# ---- v2 Quarantine + Degradation Tier endpoints ----

@app.get("/v1/quarantine/status")
def quarantine_status(x_m87_key: Optional[str] = Header(None, alias="X-M87-Key")):
    """Get current quarantine posture and degradation tier."""
    verify_auth(x_m87_key, "admin:keys")
    state = quarantine_manager.get_state()
    return state.to_dict()


@app.get("/v1/quarantine/observability")
def quarantine_observability(
    agent_id: Optional[str] = None,
    limit: int = 100,
    x_m87_key: Optional[str] = Header(None, alias="X-M87-Key"),
):
    """Get quarantined agent-supplied metadata (untrusted)."""
    verify_auth(x_m87_key, "admin:keys")
    entries = observability_quarantine.get_entries(agent_id=agent_id, limit=limit)
    return {"entries": entries, "total": len(entries)}


@app.get("/v1/agents")
def list_agents():
    """List registered agent profiles and their effect scopes."""
    agents = []
    for name, profile in AGENT_PROFILES.items():
        agents.append({
            "name": name,
            "allowed_effects": sorted(profile["allowed_effects"]),
            "max_risk": profile["max_risk"],
            "description": profile["description"],
        })
    return {"agents": agents}


@app.get("/v1/tools")
def list_tools():
    """
    Source-of-truth view of what the runner can execute.
    Reads the same manifest artifact shipped in the runner container.
    """
    loaded = load_tool_manifest()
    if not loaded.get("ok"):
        raise HTTPException(status_code=500, detail=loaded.get("error"))

    manifest = loaded["manifest"]
    tools = manifest.get("tools", {})

    # Return a minimal, stable shape for dashboard + proof tests
    view = []
    for tool_name, spec in tools.items():
        view.append({
            "tool": tool_name,
            "description": spec.get("description", ""),
            "effects": spec.get("effects", []),
            "requires_human": spec.get("requires_human", False),
            "timeout_seconds": spec.get("timeout_seconds", 0),
        })

    view.sort(key=lambda x: x["tool"])

    return {
        "version": manifest.get("version", ""),
        "manifest_hash": loaded["manifest_hash"],
        "path": loaded["path"],
        "tools": view,
    }


@app.post("/v1/intent")
def create_intent(intent: Intent, _: bool = Header(None, alias="X-M87-Key")):
    emit("intent.created", intent.model_dump(by_alias=True))
    return {"accepted": True, "intent_id": intent.intent_id}


@app.post("/v1/govern/proposal", response_model=GovernanceDecision)
def govern_proposal(
    proposal: Proposal,
    x_m87_key: Optional[str] = Header(None, alias="X-M87-Key"),
):
    """
    Governance gate. Decides ALLOW/DENY/REQUIRE_HUMAN.
    Requires scoped API key with proposal:create scope.

    V2.0 Auth checks (in order):
    1. Key valid and enabled
    2. Key has proposal:create scope
    3. Key has effect scopes for requested effects
    4. Risk <= key's max_risk

    V1.3 Policy rules (after auth):
    1. READ_SECRETS → DENY (absolute)
    2. Agent effect scope violation → DENY
    3. Agent risk threshold exceeded → REQUIRE_HUMAN
    4. DEPLOY → REQUIRE_HUMAN
    5. Otherwise → ALLOW

    V0.3.0: Requires Postgres for write-through (hard fail-safe).
    """
    # Phase 2: Hard fail-safe - require persistence for mutations
    require_persistence()

    # V2.0: Scoped auth check
    auth = verify_auth(
        x_m87_key=x_m87_key,
        endpoint_scope="proposal:create",
        requested_effects=set(proposal.effects),
        risk_score=proposal.risk_score,
    )

    # P2.A: Per-key rate limiting (after auth, before expensive governance)
    rl = rate_limiter.check_rate_limit(auth.principal_id)
    if not rl.allowed:
        emit("rate_limit.exceeded", {
            "principal_id": auth.principal_id,
            "current": rl.current,
            "limit": rl.limit,
        })
        raise HTTPException(
            status_code=429,
            detail={
                "error": "RATE_LIMIT_EXCEEDED",
                "message": rl.reason,
                "retry_after": rl.retry_after,
                "current": rl.current,
                "limit": rl.limit,
            },
        )

    # Phase 2: Persist proposal to Postgres (write-through)
    try:
        persist_proposal(
            proposal_id=proposal.proposal_id,
            intent_id=proposal.intent_id,
            agent=proposal.agent,
            summary=proposal.summary,
            effects=list(proposal.effects),
            artifacts=proposal.artifacts,
            truth_account=proposal.truth_account.model_dump() if proposal.truth_account else None,
            risk_score=proposal.risk_score,
            principal_type=auth.principal_type,
            principal_id=auth.principal_id,
        )
    except PersistenceUnavailable as e:
        logger.error(f"Failed to persist proposal: {e}")
        raise HTTPException(
            status_code=503,
            detail={"error": "DB_WRITE_FAILED", "message": str(e)}
        )

    reasons: List[str] = []
    agent = proposal.agent

    # v2 Quarantine Posture: Check if current tier allows this proposal
    if not quarantine_manager.is_proposal_allowed(list(proposal.effects)):
        tier_state = quarantine_manager.get_state()
        reasons.append(
            f"Degradation Tier {tier_state.current_tier.value} "
            f"({tier_state.current_tier.name}): proposal effects not permitted."
        )
        decision = GovernanceDecision(
            proposal_id=proposal.proposal_id,
            decision="DENY",
            reasons=reasons,
        )
        persist_decision(
            proposal_id=proposal.proposal_id,
            outcome="DENY",
            reasons=reasons,
            decided_by="policy:quarantine_posture",
        )
        emit("proposal.denied", {
            **decision.model_dump(),
            "agent": agent,
            "principal_id": auth.principal_id,
            "quarantine_tier": tier_state.current_tier.value,
        })
        return decision

    # Rule 1: READ_SECRETS is absolutely forbidden
    if "READ_SECRETS" in proposal.effects:
        reasons.append("READ_SECRETS is forbidden.")
        decision = GovernanceDecision(
            proposal_id=proposal.proposal_id,
            decision="DENY",
            reasons=reasons,
        )
        # Phase 2: Persist decision
        persist_decision(
            proposal_id=proposal.proposal_id,
            outcome="DENY",
            reasons=reasons,
            decided_by="policy",
        )
        emit("proposal.denied", {
            **decision.model_dump(),
            "agent": agent,
            "principal_id": auth.principal_id,
        })
        return decision

    # Rule 2: Check agent effect scope
    effects_allowed, disallowed_effects = check_agent_effects(agent, proposal.effects)
    if not effects_allowed:
        reasons.append(f"Agent '{agent}' not allowed effects: {sorted(disallowed_effects)}")
        decision = GovernanceDecision(
            proposal_id=proposal.proposal_id,
            decision="DENY",
            reasons=reasons,
        )
        # Phase 2: Persist decision
        persist_decision(
            proposal_id=proposal.proposal_id,
            outcome="DENY",
            reasons=reasons,
            decided_by="policy",
        )
        emit("proposal.denied", {
            **decision.model_dump(),
            "agent": agent,
            "principal_id": auth.principal_id,
        })
        return decision

    # Rule 3: Check agent risk threshold
    risk_allowed, max_risk = check_agent_risk(agent, proposal.risk_score)
    if not risk_allowed:
        reasons.append(f"Risk {proposal.risk_score} exceeds agent '{agent}' max {max_risk}. Requires human review.")
        decision = GovernanceDecision(
            proposal_id=proposal.proposal_id,
            decision="REQUIRE_HUMAN",
            reasons=reasons,
            required_approvals=["mac"],
            allowed_effects=proposal.effects,
        )
        # Phase 2: Persist decision
        persist_decision(
            proposal_id=proposal.proposal_id,
            outcome="REQUIRE_HUMAN",
            reasons=reasons,
            decided_by="policy",
            required_approvals=["mac"],
            allowed_effects=list(proposal.effects),
        )
        emit("proposal.needs_approval", {
            **decision.model_dump(),
            "summary": proposal.summary,
            "agent": agent,
            "risk_score": proposal.risk_score,
            "principal_id": auth.principal_id,
        })
        rdb.hset(f"m87:pending:{proposal.proposal_id}", mapping={
            "proposal": json.dumps(proposal.model_dump()),
            "decision": json.dumps(decision.model_dump()),
        })
        return decision

    # Rule 4: DEPLOY requires human approval
    if "DEPLOY" in proposal.effects:
        reasons.append("DEPLOY requires human approval.")
        allowed = [e for e in proposal.effects if e != "DEPLOY"]
        decision = GovernanceDecision(
            proposal_id=proposal.proposal_id,
            decision="REQUIRE_HUMAN",
            reasons=reasons,
            required_approvals=["mac"],
            allowed_effects=allowed,
        )
        # Phase 2: Persist decision
        persist_decision(
            proposal_id=proposal.proposal_id,
            outcome="REQUIRE_HUMAN",
            reasons=reasons,
            decided_by="policy",
            required_approvals=["mac"],
            allowed_effects=allowed,
        )
        emit("proposal.needs_approval", {
            **decision.model_dump(),
            "summary": proposal.summary,
            "agent": agent,
            "principal_id": auth.principal_id,
        })
        rdb.hset(f"m87:pending:{proposal.proposal_id}", mapping={
            "proposal": json.dumps(proposal.model_dump()),
            "decision": json.dumps(decision.model_dump()),
        })
        return decision

    # Rule 5: ALLOW - but first check Phase 3-6 governance (no bypass)
    # V1.1: Delegate to Phase 3-6 SessionRiskTracker for toxic topology detection
    phase36_payload = {
        "principal_id": auth.principal_id,
        "agent_name": agent,
        "effects": list(proposal.effects),
        "artifacts": proposal.artifacts or [],
        "_proposal_json": proposal.model_dump_json() if hasattr(proposal, "model_dump_json") else json.dumps(proposal.model_dump()),
    }

    # Check kill-switch: if disabled, skip Phase 3-6 (for emergency rollback only)
    if os.environ.get("M87_DISABLE_PHASE36_GOVERNANCE", "0") != "1":
        phase36_result = evaluate_governance_proposal(phase36_payload, rdb)

        if phase36_result.get("decision") == "DENY":
            reasons.append(f"Phase 3-6 governance: {phase36_result.get('reason')}")
            decision = GovernanceDecision(
                proposal_id=proposal.proposal_id,
                decision="DENY",
                reasons=reasons,
            )
            persist_decision(
                proposal_id=proposal.proposal_id,
                outcome="DENY",
                reasons=reasons,
                decided_by="policy:phase36",
            )
            emit("proposal.denied", {
                **decision.model_dump(),
                "agent": agent,
                "principal_id": auth.principal_id,
                "phase36_reason": phase36_result.get("reason"),
            })
            return decision

        if phase36_result.get("decision") == "REQUIRE_HUMAN":
            reasons.append(f"Phase 3-6 governance: {phase36_result.get('reason')}")
            decision = GovernanceDecision(
                proposal_id=proposal.proposal_id,
                decision="REQUIRE_HUMAN",
                reasons=reasons,
                required_approvals=["mac"],
                allowed_effects=proposal.effects,
            )
            persist_decision(
                proposal_id=proposal.proposal_id,
                outcome="REQUIRE_HUMAN",
                reasons=reasons,
                decided_by="policy:phase36",
                required_approvals=["mac"],
                allowed_effects=list(proposal.effects),
            )
            emit("proposal.needs_approval", {
                **decision.model_dump(),
                "summary": proposal.summary,
                "agent": agent,
                "principal_id": auth.principal_id,
                "phase36_reason": phase36_result.get("reason"),
                "challenge": phase36_result.get("challenge"),
            })
            rdb.hset(f"m87:pending:{proposal.proposal_id}", mapping={
                "proposal": json.dumps(proposal.model_dump()),
                "decision": json.dumps(decision.model_dump()),
                "phase36_challenge": json.dumps(phase36_result.get("challenge") or {}),
            })
            return decision

    # Phase 3-6 passed (or disabled) - check V1.1 Reversibility Gate
    # Gate enforces: non-read actions must declare reversibility_class
    # V2: Gate also returns budget adjustments based on cleanup_cost
    rev_gate = evaluate_reversibility_gate(
        effects=[str(e) for e in proposal.effects],
        reversibility_class=proposal.reversibility_class,
        rollback_proof=proposal.rollback_proof,
        execution_mode=proposal.execution_mode or "commit",
        human_approved=False,  # Not yet approved
        cleanup_cost=proposal.cleanup_cost,
    )

    if not rev_gate.allowed:
        # Emit telemetry for blocked execution
        emit("reversibility_gate.blocked", {
            "proposal_id": proposal.proposal_id,
            "agent": agent,
            "principal_id": auth.principal_id,
            "reversibility_class": proposal.reversibility_class,
            "reason": rev_gate.reason,
            "safe_alternative": rev_gate.safe_alternative,
        })

        # Determine decision based on gate result
        if rev_gate.safe_alternative == "approval_required":
            # IRREVERSIBLE requires human approval
            reasons.append(f"Reversibility Gate: {rev_gate.reason}")
            decision = GovernanceDecision(
                proposal_id=proposal.proposal_id,
                decision="REQUIRE_HUMAN",
                reasons=reasons,
                required_approvals=["mac"],
                allowed_effects=proposal.effects,
                reversibility_gate=rev_gate.to_dict(),
                safe_alternative=rev_gate.safe_alternative,
            )
            persist_decision(
                proposal_id=proposal.proposal_id,
                outcome="REQUIRE_HUMAN",
                reasons=reasons,
                decided_by="policy:reversibility_gate",
                required_approvals=["mac"],
                allowed_effects=list(proposal.effects),
            )
            emit("proposal.needs_approval", {
                **decision.model_dump(),
                "summary": proposal.summary,
                "agent": agent,
                "principal_id": auth.principal_id,
                "reversibility_reason": rev_gate.reason,
            })
            rdb.hset(f"m87:pending:{proposal.proposal_id}", mapping={
                "proposal": json.dumps(proposal.model_dump()),
                "decision": json.dumps(decision.model_dump()),
                "reversibility_gate": json.dumps(rev_gate.to_dict()),
            })
            return decision
        else:
            # Missing reversibility declaration or proof - downgrade to proposal
            reasons.append(f"Reversibility Gate: {rev_gate.reason}")
            decision = GovernanceDecision(
                proposal_id=proposal.proposal_id,
                decision="DENY",
                reasons=reasons,
                reversibility_gate=rev_gate.to_dict(),
                safe_alternative=rev_gate.safe_alternative,
            )
            persist_decision(
                proposal_id=proposal.proposal_id,
                outcome="DENY",
                reasons=reasons,
                decided_by="policy:reversibility_gate",
            )
            emit("proposal.denied", {
                **decision.model_dump(),
                "agent": agent,
                "principal_id": auth.principal_id,
                "reversibility_reason": rev_gate.reason,
            })
            return decision

    # Reversibility Gate passed - proceed with ALLOW
    # Emit telemetry for allowed execution (enables ops dashboard analytics)
    emit("reversibility_gate.allowed", {
        "proposal_id": proposal.proposal_id,
        "agent": agent,
        "principal_id": auth.principal_id,
        "reversibility_class": proposal.reversibility_class,
        "cleanup_cost": proposal.cleanup_cost,
        "budget_multiplier": rev_gate.budget_multiplier,
        "retry_limit": rev_gate.retry_limit,
    })

    reasons.append(f"Allowed by policy. Agent '{agent}' within scope.")
    reasons.append(f"Reversibility Gate: {rev_gate.reason}")
    decision = GovernanceDecision(
        proposal_id=proposal.proposal_id,
        decision="ALLOW",
        reasons=reasons,
        allowed_effects=proposal.effects,
    )
    # Phase 2: Persist decision
    persist_decision(
        proposal_id=proposal.proposal_id,
        outcome="ALLOW",
        reasons=reasons,
        decided_by="policy",
        allowed_effects=list(proposal.effects),
    )

    # V1 Governance: Parse deployment envelope if provided
    job_envelope = None
    if proposal.deployment_envelope:
        try:
            job_envelope = DeploymentEnvelope(**proposal.deployment_envelope)
        except Exception as e:
            logger.warning(f"Invalid deployment envelope, using default: {e}")

    emit("proposal.allowed", {
        **decision.model_dump(),
        "agent": agent,
        "principal_id": auth.principal_id,
    })

    job_id = enqueue_job(
        proposal_id=proposal.proposal_id,
        tool="echo",
        inputs={"message": f"[{agent}] {proposal.summary}"},
        envelope=job_envelope,
        # V1.1 Reversibility fields
        reversibility_class=proposal.reversibility_class,
        rollback_proof=proposal.rollback_proof,
        execution_mode=proposal.execution_mode or "commit",
        human_approved=False,
        # V2 Cleanup Cost: Pass budget adjustments from gate
        cleanup_cost=proposal.cleanup_cost,
        budget_multiplier=rev_gate.budget_multiplier,
        retry_limit=rev_gate.retry_limit,
    )

    # Return decision with job_id for convenience
    return GovernanceDecision(
        proposal_id=proposal.proposal_id,
        decision="ALLOW",
        reasons=reasons,
        allowed_effects=proposal.effects,
        job_id=job_id,
    )


class ApproveRequest(BaseModel):
    """Request body for /v1/approve (optional for backward compatibility)."""
    challenge_answer: Optional[str] = None  # Required if proposal has phase36_challenge


@app.post("/v1/approve/{proposal_id}")
def approve(
    proposal_id: str,
    body: Optional[ApproveRequest] = None,
    x_m87_key: Optional[str] = Header(None, alias="X-M87-Key"),
):
    """
    Human approves a pending proposal. Requires proposal:approve scope.

    V1.1: If proposal was escalated by Phase 3-6, requires challenge_answer.
    """
    # Phase 2: Hard fail-safe
    require_persistence()

    auth = verify_auth(x_m87_key, "proposal:approve")

    pending_key = f"m87:pending:{proposal_id}"
    pending_data = rdb.hgetall(pending_key)

    if not pending_data:
        raise HTTPException(status_code=404, detail="No pending proposal found")

    # Decode Redis data (may be bytes)
    def decode_redis(val):
        if isinstance(val, bytes):
            return val.decode("utf-8")
        return val

    proposal_json = decode_redis(pending_data.get("proposal", b"{}"))
    phase36_challenge_json = decode_redis(pending_data.get("phase36_challenge", b"{}"))

    proposal_data = json.loads(proposal_json)
    phase36_challenge = json.loads(phase36_challenge_json)

    # V1.1: If Phase 3-6 challenge exists, verify it
    if phase36_challenge and phase36_challenge.get("challenge_id"):
        if not body or not body.challenge_answer:
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "CHALLENGE_REQUIRED",
                    "message": "This proposal requires challenge-response verification",
                    "challenge": phase36_challenge,
                }
            )

        # Verify challenge using the Phase 3-6 helper
        from .governance.adversarial_review import stable_proposal_hash, generate_challenge, verify_challenge, Challenge

        p_hash = stable_proposal_hash(proposal_json)

        # Extract topology from challenge or use generic
        topology_name = "unknown_topology"
        decision_data = json.loads(decode_redis(pending_data.get("decision", b"{}")))
        reason = " ".join(decision_data.get("reasons", []))
        if "Toxic topology detected:" in reason:
            try:
                topology_name = reason.split("Toxic topology detected:")[1].strip().split()[0]
            except Exception:
                pass

        ch = Challenge(
            challenge_id=phase36_challenge.get("challenge_id"),
            prompt="",
            expected=topology_name,
            proposal_hash=p_hash,
        )

        result = verify_challenge(ch, body.challenge_answer)
        if result.get("ok") != "true":
            raise HTTPException(
                status_code=403,
                detail=f"Challenge verification failed: {result.get('reason')}"
            )

    # Phase 2: Persist human approval decision
    persist_decision(
        proposal_id=proposal_id,
        outcome="ALLOW",
        reasons=["Human approved (challenge verified)" if phase36_challenge else "Human approved"],
        decided_by=f"human:{auth.principal_id}",
    )

    evt = {
        "proposal_id": proposal_id,
        "approved_by": auth.principal_id,
    }
    emit("proposal.approved", evt)

    # V2: Re-evaluate gate with human_approved=True to get budget adjustments
    from .governance.reversibility import evaluate_reversibility_gate
    approve_gate = evaluate_reversibility_gate(
        effects=proposal_data.get("effects", []),
        reversibility_class=proposal_data.get("reversibility_class"),
        rollback_proof=proposal_data.get("rollback_proof"),
        execution_mode=proposal_data.get("execution_mode", "commit"),
        human_approved=True,
        cleanup_cost=proposal_data.get("cleanup_cost"),
    )

    job_id = enqueue_job(
        proposal_id=proposal_id,
        tool="echo",
        inputs={"message": f"Approved: {proposal_data.get('summary', 'unknown')}"},
        # V1.1 Reversibility: Human approved, pass fields to runner
        reversibility_class=proposal_data.get("reversibility_class"),
        rollback_proof=proposal_data.get("rollback_proof"),
        execution_mode=proposal_data.get("execution_mode", "commit"),
        human_approved=True,  # Key: human has approved
        # V2 Cleanup Cost: Pass budget adjustments from gate
        cleanup_cost=proposal_data.get("cleanup_cost"),
        budget_multiplier=approve_gate.budget_multiplier,
        retry_limit=approve_gate.retry_limit,
    )

    rdb.delete(pending_key)

    return {"approved": True, "job_id": job_id, **evt}


@app.post("/v1/deny/{proposal_id}")
def deny(
    proposal_id: str,
    reason: str = "Denied by human",
    x_m87_key: Optional[str] = Header(None, alias="X-M87-Key"),
):
    """Human denies a pending proposal. Requires proposal:deny scope."""
    # Phase 2: Hard fail-safe
    require_persistence()

    auth = verify_auth(x_m87_key, "proposal:deny")

    pending_key = f"m87:pending:{proposal_id}"

    # Phase 2: Persist human denial decision
    persist_decision(
        proposal_id=proposal_id,
        outcome="DENY",
        reasons=[reason],
        decided_by=f"human:{auth.principal_id}",
    )

    evt = {
        "proposal_id": proposal_id,
        "denied_by": auth.principal_id,
        "reason": reason,
    }
    emit("proposal.denied_by_human", evt)

    rdb.delete(pending_key)

    return {"denied": True, **evt}


@app.get("/v1/events")
def list_events(limit: int = 200, after: Optional[str] = None):
    """Get events from stream."""
    if after:
        items = rdb.xrange(EVENT_STREAM, min=f"({after}", max="+", count=limit)
    else:
        items = rdb.xrevrange(EVENT_STREAM, max="+", min="-", count=limit)
        items = list(reversed(items))

    events = []
    for event_id, fields in items:
        events.append({
            "id": event_id,
            "type": fields.get("type"),
            "payload": json.loads(fields.get("payload") or "{}")
        })
    return {"events": events}


@app.get("/v1/jobs")
def list_jobs(limit: int = 100, status: Optional[str] = None):
    """Get jobs from stream with derived status."""
    job_items = rdb.xrevrange(JOB_STREAM, max="+", min="-", count=limit)
    event_items = rdb.xrevrange(EVENT_STREAM, max="+", min="-", count=500)

    job_status = {}
    for _, fields in event_items:
        event_type = fields.get("type", "")
        payload = json.loads(fields.get("payload") or "{}")
        job_id = payload.get("job_id")

        if not job_id:
            continue

        if event_type == "job.completed" and job_id not in job_status:
            job_status[job_id] = {"status": "completed", "output": payload.get("output")}
        elif event_type == "job.failed" and job_id not in job_status:
            job_status[job_id] = {"status": "failed", "error": payload.get("error")}
        elif event_type == "job.started" and job_id not in job_status:
            job_status[job_id] = {"status": "running"}

    jobs = []
    for job_stream_id, fields in reversed(list(job_items)):
        job_data = json.loads(fields.get("job", "{}"))
        job_id = job_data.get("job_id")

        derived = job_status.get(job_id, {"status": "pending"})
        job_entry = {
            "stream_id": job_stream_id,
            **job_data,
            **derived,
        }

        if status is None or job_entry.get("status") == status:
            jobs.append(job_entry)

    return {"jobs": jobs}


@app.get("/v1/pending-approvals")
def pending_approvals():
    """Get proposals awaiting human approval."""
    items = rdb.xrevrange(EVENT_STREAM, max="+", min="-", count=1000)

    needs_approval = {}
    resolved = set()

    for event_id, fields in items:
        event_type = fields.get("type")
        payload = json.loads(fields.get("payload") or "{}")
        proposal_id = payload.get("proposal_id")

        if not proposal_id:
            continue

        if event_type in ("proposal.approved", "proposal.denied_by_human"):
            resolved.add(proposal_id)
        elif event_type == "proposal.needs_approval" and proposal_id not in resolved:
            if proposal_id not in needs_approval:
                needs_approval[proposal_id] = {
                    "id": event_id,
                    "proposal_id": proposal_id,
                    "payload": payload
                }

    return {"pending": list(needs_approval.values())}


@app.post("/v1/runner/result")
def runner_result(result: RunnerResult, x_m87_key: Optional[str] = Header(None, alias="X-M87-Key")):
    """
    Runner reports job completion/failure.
    Phase 5 Step 3: Hardened with size caps, redaction, and strict schema.
    V1 Governance: Enforces Artifact-Backed Completion.
    """
    # Phase 2: Hard fail-safe
    require_persistence()

    auth = verify_auth(x_m87_key, "runner:result")

    # Byte-size hard cap (prevents output-as-exfil / memory bombs)
    raw_bytes = json.dumps(result.model_dump(), ensure_ascii=False).encode("utf-8")
    if len(raw_bytes) > MAX_RUNNER_RESULT_BYTES:
        raise HTTPException(status_code=413, detail=f"Result too large ({len(raw_bytes)} bytes)")

    # V1 Governance: Artifact-Backed Completion enforcement
    # "Completed: true" without artifacts → invalid
    effective_status = result.status
    artifact_rejection = None

    if result.status == "completed":
        has_artifacts = (
            result.completion_artifacts is not None
            and result.completion_artifacts.has_artifacts()
        )
        if not has_artifacts:
            effective_status = "failed"
            artifact_rejection = "TASK_INCOMPLETE: no completion artifacts provided"
            logger.warning(f"Job {result.job_id}: completion rejected - no artifacts")
            # Emit telemetry for artifact rejection
            emit("task.completion_rejected", {
                "job_id": result.job_id,
                "proposal_id": result.proposal_id,
                "reason": "NO_ARTIFACTS",
                "envelope_hash": result.envelope_hash,
            })

    # Sanitize output before anything else touches it
    safe_output = sanitize_output(result.output)

    # Add artifact rejection reason if applicable
    if artifact_rejection:
        if isinstance(safe_output, dict):
            safe_output["artifact_rejection"] = artifact_rejection
        else:
            safe_output = {"original": safe_output, "artifact_rejection": artifact_rejection}

    # Build payload with sanitized output
    payload = {
        "job_id": result.job_id,
        "proposal_id": result.proposal_id,
        "status": effective_status,
        "output": safe_output,
        "manifest_hash": result.manifest_hash,
        "manifest_version": result.manifest_version,
        "envelope_hash": result.envelope_hash,
        "autonomy_budget": result.autonomy_budget,  # Forensic: what was allowed
        "autonomy_usage": result.autonomy_usage,    # Forensic: what was consumed
        "has_artifacts": result.completion_artifacts.has_artifacts() if result.completion_artifacts else False,
        "deh_evidence": result.deh_evidence,  # Machine-verifiable DEH proof from runner
        "received_at": datetime.utcnow().isoformat() + "Z",
    }

    # Phase 2: Persist execution receipt (with sanitized output)
    try:
        persist_execution(
            job_id=result.job_id,
            status=effective_status,
            output=safe_output,
            error=safe_output.get("error") if isinstance(safe_output, dict) else artifact_rejection,
            runner_id=auth.principal_id,
        )
    except PersistenceUnavailable as e:
        logger.error(f"Failed to persist execution: {e}")
        raise HTTPException(
            status_code=503,
            detail={"error": "DB_WRITE_FAILED", "message": str(e)}
        )

    if effective_status == "completed":
        emit("job.completed", payload)
    else:
        emit("job.failed", payload)

    # V1 Governance: Check if shadow eval should be triggered
    maybe_trigger_shadow_eval(result.job_id, result.envelope_hash or "unknown")

    return {"ok": True, "effective_status": effective_status, "artifact_rejection": artifact_rejection}


# ---- Admin endpoints (key management)

@app.post("/v1/admin/keys")
def create_key(
    request: CreateKeyRequest,
    x_m87_key: Optional[str] = Header(None, alias="X-M87-Key"),
):
    """Create a new API key. Requires admin:keys scope."""
    # Phase 2: Hard fail-safe
    require_persistence()

    verify_auth(x_m87_key, "admin:keys")

    plaintext, record = key_store.create_key(
        principal_type=request.principal_type,
        principal_id=request.principal_id,
        endpoint_scopes=set(request.endpoint_scopes),
        effect_scopes=set(request.effect_scopes) if request.effect_scopes else set(),
        max_risk=request.max_risk,
        description=request.description,
    )

    # Phase 2: Persist key to Postgres
    try:
        persist_api_key(
            key_id=record.key_id,
            key_hash=record.key_hash,
            principal_type=record.principal_type,
            principal_id=record.principal_id,
            endpoint_scopes=list(record.endpoint_scopes),
            effect_scopes=list(record.effect_scopes),
            max_risk=record.max_risk,
            enabled=record.enabled,
            expires_at=record.expires_at,
            description=record.description,
        )
    except PersistenceUnavailable as e:
        logger.error(f"Failed to persist key: {e}")
        # Rollback Redis write
        key_store.delete_key(record.key_id)
        raise HTTPException(
            status_code=503,
            detail={"error": "DB_WRITE_FAILED", "message": str(e)}
        )

    logger.info(f"Key created: {record.key_id} for {record.principal_type}:{record.principal_id}")

    return {
        "key_id": record.key_id,
        "key": plaintext,  # Only returned once at creation
        "principal_type": record.principal_type,
        "principal_id": record.principal_id,
        "endpoint_scopes": sorted(record.endpoint_scopes),
        "effect_scopes": sorted(record.effect_scopes),
        "max_risk": record.max_risk,
    }


@app.get("/v1/admin/keys")
def list_keys(x_m87_key: Optional[str] = Header(None, alias="X-M87-Key")):
    """List all API keys. Requires admin:keys scope."""
    verify_auth(x_m87_key, "admin:keys")

    keys = key_store.list_keys()
    return {
        "keys": [
            {
                "key_id": k.key_id,
                "principal_type": k.principal_type,
                "principal_id": k.principal_id,
                "endpoint_scopes": sorted(k.endpoint_scopes),
                "effect_scopes": sorted(k.effect_scopes),
                "max_risk": k.max_risk,
                "enabled": k.enabled,
                "created_at": k.created_at.isoformat() if k.created_at else None,
                "description": k.description,
            }
            for k in keys
        ]
    }


@app.post("/v1/admin/keys/{key_id}/disable")
def disable_key(key_id: str, x_m87_key: Optional[str] = Header(None, alias="X-M87-Key")):
    """Disable an API key. Requires admin:keys scope."""
    # Phase 2: Hard fail-safe
    require_persistence()

    verify_auth(x_m87_key, "admin:keys")

    if key_store.disable_key(key_id):
        # Phase 2: Persist to Postgres
        update_api_key_enabled(key_id, False)
        logger.info(f"Key disabled: {key_id}")
        return {"disabled": True, "key_id": key_id}
    raise HTTPException(status_code=404, detail="Key not found")


@app.post("/v1/admin/keys/{key_id}/enable")
def enable_key(key_id: str, x_m87_key: Optional[str] = Header(None, alias="X-M87-Key")):
    """Enable an API key. Requires admin:keys scope."""
    # Phase 2: Hard fail-safe
    require_persistence()

    verify_auth(x_m87_key, "admin:keys")

    if key_store.enable_key(key_id):
        # Phase 2: Persist to Postgres
        update_api_key_enabled(key_id, True)
        logger.info(f"Key enabled: {key_id}")
        return {"enabled": True, "key_id": key_id}
    raise HTTPException(status_code=404, detail="Key not found")


@app.delete("/v1/admin/keys/{key_id}")
def delete_key(key_id: str, x_m87_key: Optional[str] = Header(None, alias="X-M87-Key")):
    """Delete an API key. Requires admin:keys scope."""
    # Phase 2: Hard fail-safe
    require_persistence()

    verify_auth(x_m87_key, "admin:keys")

    if key_id == "key_bootstrap":
        raise HTTPException(status_code=400, detail="Cannot delete bootstrap key")

    if key_store.delete_key(key_id):
        # Phase 2: Persist to Postgres
        db_delete_key(key_id)
        logger.info(f"Key deleted: {key_id}")
        return {"deleted": True, "key_id": key_id}
    raise HTTPException(status_code=404, detail="Key not found")


@app.post("/v1/admin/emit")
def admin_emit(payload: Dict[str, Any], x_m87_key: Optional[str] = Header(None, alias="X-M87-Key")):
    """Admin endpoint to emit arbitrary events (for testing)."""
    if not ENABLE_TEST_ENDPOINTS:
        raise HTTPException(status_code=404, detail="Not found")

    verify_auth(x_m87_key, "admin:emit")

    event_type = payload.get("type")
    data = payload.get("payload", {})

    if not event_type:
        raise HTTPException(status_code=400, detail="Missing event type")

    emit(event_type, data)
    return {"ok": True, "emitted": event_type}


# ---- Test endpoints (for verification scripts, gated by M87_ENABLE_TEST_ENDPOINTS)

@app.get("/v1/test/db/proposals/{proposal_id}")
def test_db_proposal_exists(
    proposal_id: str,
    x_m87_key: Optional[str] = Header(None, alias="X-M87-Key"),
):
    """
    Test endpoint: Check if proposal exists in Postgres.

    Used by verification scripts to prove DB durability without psql.
    Only available when M87_ENABLE_TEST_ENDPOINTS=true.
    """
    if not ENABLE_TEST_ENDPOINTS:
        raise HTTPException(status_code=404, detail="Not found")

    verify_auth(x_m87_key, "admin:keys")

    if not _db_available:
        return {"exists": False, "error": "DB_UNAVAILABLE"}

    from .db import get_db, Proposal
    try:
        with get_db(required=False) as db:
            if db is None:
                return {"exists": False, "error": "DB_UNAVAILABLE"}
            proposal = db.query(Proposal).filter(Proposal.proposal_id == proposal_id).first()
            return {
                "exists": proposal is not None,
                "proposal_id": proposal_id,
            }
    except Exception as e:
        return {"exists": False, "error": str(e)}


@app.get("/v1/test/db/decisions/{proposal_id}")
def test_db_decision_exists(
    proposal_id: str,
    x_m87_key: Optional[str] = Header(None, alias="X-M87-Key"),
):
    """
    Test endpoint: Check if decision exists for proposal in Postgres.

    Used by verification scripts to prove DB durability without psql.
    """
    if not ENABLE_TEST_ENDPOINTS:
        raise HTTPException(status_code=404, detail="Not found")

    verify_auth(x_m87_key, "admin:keys")

    if not _db_available:
        return {"exists": False, "error": "DB_UNAVAILABLE"}

    from .db import get_db, Decision
    try:
        with get_db(required=False) as db:
            if db is None:
                return {"exists": False, "error": "DB_UNAVAILABLE"}
            decision = db.query(Decision).filter(Decision.proposal_id == proposal_id).first()
            return {
                "exists": decision is not None,
                "proposal_id": proposal_id,
                "outcome": decision.outcome if decision else None,
            }
    except Exception as e:
        return {"exists": False, "error": str(e)}


@app.get("/v1/test/db/jobs/{proposal_id}")
def test_db_job_exists(
    proposal_id: str,
    x_m87_key: Optional[str] = Header(None, alias="X-M87-Key"),
):
    """
    Test endpoint: Check if job exists for proposal in Postgres.

    Used by verification scripts to prove DB durability without psql.
    """
    if not ENABLE_TEST_ENDPOINTS:
        raise HTTPException(status_code=404, detail="Not found")

    verify_auth(x_m87_key, "admin:keys")

    if not _db_available:
        return {"exists": False, "error": "DB_UNAVAILABLE"}

    from .db import get_db, Job
    try:
        with get_db(required=False) as db:
            if db is None:
                return {"exists": False, "error": "DB_UNAVAILABLE"}
            job = db.query(Job).filter(Job.proposal_id == proposal_id).first()
            return {
                "exists": job is not None,
                "proposal_id": proposal_id,
                "job_id": job.job_id if job else None,
            }
    except Exception as e:
        return {"exists": False, "error": str(e)}
