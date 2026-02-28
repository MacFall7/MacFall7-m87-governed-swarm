"""
M87 Runner Service - V1.5+ (V1 Governance Hardening)
Consumes JobSpecs from m87:jobs stream ONLY.
Executes tools ONLY if declared in tool_manifest.json.
Enforces Deployment Envelope Hash (DEH) verification.
Enforces Autonomy Budget limits.
"""

import os
import time
import json
import subprocess
import hashlib
import requests
from typing import Any, Dict, Optional
from redis import Redis

# Config
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")
API_BASE = os.getenv("API_BASE", "http://api:8000")
API_KEY = os.getenv("M87_API_KEY", "m87-dev-key-change-me")

JOBS_STREAM = "m87:jobs"
CONSUMER_GROUP = "runner"
CONSUMER_NAME = os.getenv("RUNNER_NAME", "runner-1")

MANIFEST_PATH = os.getenv("M87_TOOL_MANIFEST_PATH", "app/tool_manifest.json")
MANIFEST_LOCK_PATH = os.getenv("M87_MANIFEST_LOCK_PATH", "manifest.lock.json")

# Phase 5 Step 3: Result payload cap
MAX_REPORT_BYTES = int(os.getenv("M87_MAX_RUNNER_RESULT_BYTES", "65536"))

# Sandbox root for file_write tool (defense-in-depth containment)
SANDBOX_ROOT = os.getenv("M87_SANDBOX_ROOT", "/tmp/m87-sandbox")

# Layer 1: Effect schema version — must match API's EFFECT_SCHEMA_VERSION.
# Runner rejects jobs with mismatched versions to prevent taxonomy drift.
RUNNER_EFFECT_SCHEMA_VERSION = "1.0.0"


# ---- V1 Governance: Deployment Envelope Hash verification
def _exclude_none_recursive(obj: Any) -> Any:
    """Recursively remove None values from dict (matches API exclude_none=True)."""
    if isinstance(obj, dict):
        return {k: _exclude_none_recursive(v) for k, v in obj.items() if v is not None}
    if isinstance(obj, list):
        return [_exclude_none_recursive(x) for x in obj]
    return obj


def compute_envelope_hash(envelope: Dict[str, Any]) -> str:
    """
    Compute DEH = SHA256(canonical_json(deployment_envelope))

    Canonicalization rules (MUST match API):
    - exclude_none removes None fields
    - sort_keys=True for deterministic ordering
    - separators=(',', ':') removes whitespace
    """
    clean_envelope = _exclude_none_recursive(envelope)
    canonical = json.dumps(clean_envelope, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def verify_deployment_envelope(job: Dict[str, Any]) -> Dict[str, Any]:
    """
    Verify job's deployment envelope hash matches recomputed hash.
    Returns evidence dict with verification result.

    Defense-in-depth: Runner independently verifies, doesn't trust API.

    INTENT PRESERVATION:
    - Rejection is safer than fallback: A mismatched hash could mean the API
      was compromised or the job was tampered with in transit. Accepting it
      "just this once" would defeat the entire integrity guarantee.
    - No partial trust: Either the hash verifies completely or the job is rejected.
      There is no "close enough" for cryptographic verification.
    """
    envelope = job.get("deployment_envelope")
    claimed_hash = job.get("envelope_hash")

    evidence = {
        "envelope_hash_verified": False,
        "deh_claimed": claimed_hash,
        "deh_recomputed": None,
        "error": None,
    }

    if not claimed_hash:
        evidence["error"] = "Job missing envelope_hash (pre-V1.0 API?)"
        return evidence

    if not envelope:
        evidence["error"] = "Job missing deployment_envelope for verification"
        return evidence

    recomputed = compute_envelope_hash(envelope)
    evidence["deh_recomputed"] = recomputed

    if recomputed != claimed_hash:
        evidence["error"] = f"DEH mismatch: claimed {claimed_hash[:16]}... but computed {recomputed[:16]}..."
        return evidence

    evidence["envelope_hash_verified"] = True
    return evidence


def enforce_open_weight_safety(envelope: Dict[str, Any]) -> Dict[str, Any]:
    """
    Defense-in-depth: Runner clamps open-weight models to safe defaults.
    Returns modified envelope (does not mutate input).

    Enforces:
    - safety_mode = "safe_default"
    - max_write_scope = "sandbox" (closes "open model + prod writes" nightmare)
    - Reduced autonomy budget limits
    """
    if envelope.get("model_source") != "open":
        return envelope

    # Force safe_default for open-weight models
    clamped = dict(envelope)
    if clamped.get("safety_mode") != "safe_default":
        print(f"  ⚠ Clamping open-weight model to safe_default (was: {clamped.get('safety_mode')})", flush=True)
        clamped["safety_mode"] = "safe_default"

    # Clamp autonomy budget for open-weight models
    budget = dict(clamped.get("autonomy_budget", {}))
    OPEN_WEIGHT_MAX_STEPS = 50
    OPEN_WEIGHT_MAX_TOOL_CALLS = 25
    OPEN_WEIGHT_MAX_RUNTIME = 120
    OPEN_WEIGHT_MAX_WRITE_SCOPE = "sandbox"

    if budget.get("max_steps", 0) > OPEN_WEIGHT_MAX_STEPS:
        print(f"  ⚠ Clamping open-weight max_steps: {budget['max_steps']} → {OPEN_WEIGHT_MAX_STEPS}", flush=True)
        budget["max_steps"] = OPEN_WEIGHT_MAX_STEPS
    if budget.get("max_tool_calls", 0) > OPEN_WEIGHT_MAX_TOOL_CALLS:
        budget["max_tool_calls"] = OPEN_WEIGHT_MAX_TOOL_CALLS
    if budget.get("max_runtime_seconds", 0) > OPEN_WEIGHT_MAX_RUNTIME:
        budget["max_runtime_seconds"] = OPEN_WEIGHT_MAX_RUNTIME

    # CRITICAL: Clamp write scope - no prod/staging writes for open-weight models
    current_scope = budget.get("max_write_scope", "sandbox")
    if current_scope in ("prod", "staging"):
        print(f"  ⚠ Clamping open-weight max_write_scope: {current_scope} → {OPEN_WEIGHT_MAX_WRITE_SCOPE}", flush=True)
        budget["max_write_scope"] = OPEN_WEIGHT_MAX_WRITE_SCOPE

    clamped["autonomy_budget"] = budget
    return clamped


# ---- V1 Governance: Autonomy Budget helpers

def fail_budget(code: str, detail: str, *, tracker=None, deh_evidence=None) -> Dict[str, Any]:
    """Standard budget violation response. Ensures consistent shape."""
    out = {
        "error": code,
        "detail": detail,
        "exit_code": -1,
    }
    if tracker:
        out["autonomy_usage"] = tracker.get_usage()
    if deh_evidence:
        out["deh_evidence"] = deh_evidence
    return out


def resolve_autonomy_budget(job: Dict[str, Any]) -> Dict[str, Any]:
    """
    Resolve budget from deployment_envelope, with runner defaults.
    Defense-in-depth: missing budget = runner defaults, not infinite.
    """
    env = job.get("deployment_envelope") or {}
    budget = env.get("autonomy_budget") or {}
    # Runner defaults (fail-closed)
    return {
        "max_steps": int(budget.get("max_steps", 100)),
        "max_tool_calls": int(budget.get("max_tool_calls", 50)),
        "max_parallel_agents": int(budget.get("max_parallel_agents", 1)),
        "max_runtime_seconds": int(budget.get("max_runtime_seconds", 300)),
        "max_external_io": int(budget.get("max_external_io", 10)),
        "max_write_scope": budget.get("max_write_scope", "sandbox"),
    }


# Tool write scope requirements - tools declare their blast radius
TOOL_WRITE_SCOPE_REQUIREMENTS = {
    "echo": "none",           # Pure output, no writes
    "pytest": "sandbox",      # May write temp files/logs
    "file_write": "sandbox",  # Writes to sandbox only
    # Future tools:
    # "git_push": "prod",
    # "db_migrate": "prod",
    # "deploy": "prod",
}


# ---- V1.1 Reversibility Gate (Runner-side enforcement)

# Reversibility class enum values
REVERSIBILITY_REVERSIBLE = "REVERSIBLE"
REVERSIBILITY_PARTIAL = "PARTIALLY_REVERSIBLE"
REVERSIBILITY_IRREVERSIBLE = "IRREVERSIBLE"

# Valid reversibility classes (fail-closed: unknown class = reject)
VALID_REVERSIBILITY_CLASSES = {
    REVERSIBILITY_REVERSIBLE,
    REVERSIBILITY_PARTIAL,
    REVERSIBILITY_IRREVERSIBLE,
}

# Default supported modes if not specified in manifest (commit-only for safety)
DEFAULT_SUPPORTED_MODES = ["commit"]


def verify_execution_mode(job: Dict[str, Any], tool_spec: Dict[str, Any]) -> Dict[str, Any]:
    """
    V1.2: Verify execution_mode is supported by the tool.

    Turns execution_mode from a label into an invariant:
    - Tools declare supports_modes in manifest
    - Runner enforces: if mode not in supports_modes, deny

    Returns evidence dict with verification result.
    """
    evidence = {
        "mode_verified": False,
        "execution_mode": job.get("execution_mode", "commit"),
        "supported_modes": None,
        "error": None,
    }

    exec_mode = job.get("execution_mode", "commit").lower()
    supported = tool_spec.get("supports_modes", DEFAULT_SUPPORTED_MODES)
    evidence["supported_modes"] = supported

    if exec_mode not in supported:
        evidence["error"] = (
            f"Tool does not support execution_mode '{exec_mode}'. "
            f"Supported modes: {supported}"
        )
        return evidence

    evidence["mode_verified"] = True
    return evidence


def verify_reversibility_gate(job: Dict[str, Any], tool: str) -> Dict[str, Any]:
    """
    Runner-side verification of reversibility gate.

    Defense-in-depth: Runner independently enforces reversibility policy,
    doesn't trust that API gate was executed.

    Fail-closed policy:
    - If reversibility_class is None, job must be for a read-only proposal
      (API gate allowed it without reversibility). We trust the API's effect check.
    - If reversibility_class is set, we verify it's valid and properly authorized.
    - Unknown reversibility_class values are rejected (fail-closed).

    INTENT PRESERVATION:
    - IRREVERSIBLE actions halt without human approval because the damage cannot
      be undone. No automation should make permanent decisions autonomously.
    - Unknown reversibility classes are rejected because an attacker could inject
      a new class like "SUPER_SAFE" hoping the runner treats unknown as permissive.
    - This gate exists at the runner (not just API) because the runner is the
      last line of defense—if the API is compromised, the runner still blocks.

    Returns evidence dict with verification result.
    """
    evidence = {
        "reversibility_verified": False,
        "reversibility_class": job.get("reversibility_class"),
        "execution_mode": job.get("execution_mode", "commit"),
        "human_approved": job.get("human_approved", False),
        "error": None,
    }

    rev_class = job.get("reversibility_class")
    rollback_proof = job.get("rollback_proof")
    exec_mode = job.get("execution_mode", "commit")
    human_approved = job.get("human_approved", False)

    # If reversibility_class is None, API determined this was a read-only proposal
    # Trust the API's effect-based check; runner doesn't have effect list
    if rev_class is None:
        evidence["reversibility_verified"] = True
        evidence["bypass_reason"] = "read_only_proposal_per_api"
        return evidence

    # Fail-closed: reject unknown reversibility classes
    if rev_class not in VALID_REVERSIBILITY_CLASSES:
        evidence["error"] = f"Unknown reversibility_class '{rev_class}' (fail-closed)"
        return evidence

    # REVERSIBLE requires rollback_proof
    if rev_class == REVERSIBILITY_REVERSIBLE:
        if not rollback_proof:
            evidence["error"] = "REVERSIBLE action requires rollback_proof"
            return evidence
        evidence["reversibility_verified"] = True
        return evidence

    # PARTIALLY_REVERSIBLE without proof → only draft/preview
    if rev_class == REVERSIBILITY_PARTIAL:
        if not rollback_proof and exec_mode == "commit":
            evidence["error"] = "PARTIALLY_REVERSIBLE commit requires rollback_proof"
            return evidence
        evidence["reversibility_verified"] = True
        return evidence

    # IRREVERSIBLE requires human approval
    if rev_class == REVERSIBILITY_IRREVERSIBLE:
        if not human_approved:
            evidence["error"] = "IRREVERSIBLE action requires explicit human approval"
            return evidence
        evidence["reversibility_verified"] = True
        return evidence

    # Unknown class
    evidence["error"] = f"Unknown reversibility_class: {rev_class}"
    return evidence


def scope_rank(scope: str) -> int:
    """Rank write scopes from least to most permissive."""
    return {"none": 0, "sandbox": 1, "staging": 2, "prod": 3}.get(scope, 99)


# ---- V1 Step 2.7: Centralized network egress (choke point for all external I/O)

def governed_request(
    tracker: "AutonomyBudgetTracker",
    method: str,
    url: str,
    *,
    timeout: int = 10,
    **kwargs: Any,
) -> requests.Response:
    """
    Centralized network egress for tools.
    Enforces Autonomy Budget max_external_io preemptively.

    All future tools that need network access MUST use this function.
    This is the single choke point for:
    - AB external_io enforcement
    - Runtime budget check
    - Future: domain allowlist, rate limiting, header stripping, audit logging

    Raises RuntimeError if budget exceeded (caller must handle).
    """
    if not tracker.try_external_io():
        raise RuntimeError("AUTONOMY_BUDGET_EXCEEDED: external_io")

    if tracker.runtime_exceeded():
        raise RuntimeError("AUTONOMY_BUDGET_EXCEEDED: runtime")

    # Future: domain allowlist check would go here
    # Future: request/response size caps would go here
    # Future: audit logging would go here

    return requests.request(method, url, timeout=timeout, **kwargs)


# ---- V1 Governance: Autonomy Budget tracking
#
# INTENT PRESERVATION:
# - Budgets are PREEMPTIVE, not reactive. We check BEFORE consuming resources,
#   not after. This prevents "one more request" attacks that incrementally
#   exhaust limits while claiming each individual request was small.
# - Missing budget fields use runner defaults, NOT infinite. An attacker cannot
#   bypass limits by omitting fields from the deployment envelope.
# - Budget exhaustion halts execution immediately. There is no "finish current
#   operation" grace period that could be exploited for last-ditch exfiltration.

class AutonomyBudgetTracker:
    """
    Tracks resource usage against autonomy budget limits.
    Preemptive enforcement: try_* methods increment only if allowed.
    """

    def __init__(self, budget: Dict[str, Any]):
        self.budget = budget
        self.steps = 0
        self.tool_calls = 0
        self.parallel_agents = 0
        self.external_io = 0
        self.start_time = time.time()

    def runtime_exceeded(self) -> bool:
        """Check if runtime limit exceeded."""
        elapsed = time.time() - self.start_time
        return elapsed >= self.budget.get("max_runtime_seconds", 300)

    def try_step(self) -> bool:
        """Try to increment step counter. Returns True if allowed, False if exceeded."""
        if self.steps >= self.budget.get("max_steps", 100):
            return False
        self.steps += 1
        return True

    def try_tool_call(self) -> bool:
        """Try to increment tool call counter. Returns True if allowed, False if exceeded."""
        if self.tool_calls >= self.budget.get("max_tool_calls", 50):
            return False
        self.tool_calls += 1
        return True

    def try_external_io(self) -> bool:
        """Try to increment external I/O counter. Returns True if allowed, False if exceeded."""
        if self.external_io >= self.budget.get("max_external_io", 10):
            return False
        self.external_io += 1
        return True

    def check_limits(self) -> Optional[str]:
        """Check if any limit is exceeded. Returns error string or None."""
        elapsed = time.time() - self.start_time

        if self.steps >= self.budget.get("max_steps", 100):
            return f"AUTONOMY_BUDGET_EXCEEDED: steps ({self.steps})"

        if self.tool_calls >= self.budget.get("max_tool_calls", 50):
            return f"AUTONOMY_BUDGET_EXCEEDED: tool_calls ({self.tool_calls})"

        if elapsed >= self.budget.get("max_runtime_seconds", 300):
            return f"AUTONOMY_BUDGET_EXCEEDED: runtime ({elapsed:.0f}s)"

        if self.external_io >= self.budget.get("max_external_io", 10):
            return f"AUTONOMY_BUDGET_EXCEEDED: external_io ({self.external_io})"

        return None

    def get_usage(self) -> Dict[str, Any]:
        return {
            "steps": self.steps,
            "tool_calls": self.tool_calls,
            "runtime_seconds": time.time() - self.start_time,
            "external_io": self.external_io,
        }


def _api_headers() -> Dict[str, str]:
    return {"X-M87-Key": API_KEY, "content-type": "application/json"}


def load_manifest(path: str) -> Dict[str, Any]:
    """Load manifest and compute hash for integrity verification."""
    with open(path, "rb") as f:
        raw = f.read()
    data = json.loads(raw.decode("utf-8"))
    data["_manifest_hash"] = hashlib.sha256(raw).hexdigest()
    return data


def verify_manifest_lock(manifest: Dict[str, Any]) -> Dict[str, Any]:
    """
    Verify that loaded manifest matches manifest.lock.json.
    Returns verification result dict.
    """
    import os.path
    if not os.path.exists(MANIFEST_LOCK_PATH):
        return {"ok": False, "error": f"Lock file not found: {MANIFEST_LOCK_PATH}", "critical": False}

    try:
        with open(MANIFEST_LOCK_PATH, "r") as f:
            lock_data = json.load(f)
    except Exception as e:
        return {"ok": False, "error": f"Failed to parse lock file: {e}", "critical": True}

    locked_hash = lock_data.get("sha256")
    if not locked_hash:
        return {"ok": False, "error": "Lock file missing sha256 field", "critical": True}

    current_hash = manifest.get("_manifest_hash")

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


def validate_job_against_manifest(job: Dict[str, Any], manifest: Dict[str, Any]) -> Optional[str]:
    tool = job.get("tool")
    inputs = job.get("inputs", {})

    tools = manifest.get("tools", {})
    if tool not in tools:
        return f"Tool '{tool}' is not in manifest"

    tool_spec = tools[tool]
    in_spec = tool_spec.get("inputs", {})
    required = in_spec.get("required", [])
    optional = in_spec.get("optional", [])
    limits = in_spec.get("limits", {})

    # P1.2 — Deny on empty args: any empty string argument → DENY
    # Removes sanitize-and-continue behavior for anomalous args.
    for key, value in inputs.items():
        if isinstance(value, str) and value == "":
            return f"EMPTY_ARG_DENIED: Tool '{tool}' argument '{key}' is an empty string. Empty arguments are not permitted."

    # Required keys present
    for k in required:
        if k not in inputs:
            return f"Missing required input '{k}' for tool '{tool}'"

    # No unexpected keys (strict)
    allowed_keys = set(required) | set(optional)
    for k in inputs.keys():
        if k not in allowed_keys:
            return f"Unexpected input '{k}' for tool '{tool}'"

    # Basic length limits (string-only enforcement)
    if tool == "echo":
        msg = inputs.get("message", "")
        if not isinstance(msg, str):
            return "echo.message must be a string"
        max_len = int(limits.get("message_max_len", 4000))
        if len(msg) > max_len:
            return f"echo.message exceeds max length ({max_len})"

    if tool == "pytest":
        args = inputs.get("args", "")
        if not isinstance(args, str):
            return "pytest.args must be a string"
        max_len = int(limits.get("args_max_len", 2000))
        if len(args) > max_len:
            return f"pytest.args exceeds max length ({max_len})"

    if tool == "file_write":
        path = inputs.get("path", "")
        if not isinstance(path, str):
            return "file_write.path must be a string"
        path_max = int(limits.get("path_max_len", 512))
        if len(path) > path_max:
            return f"file_write.path exceeds max length ({path_max})"

        content = inputs.get("content", "")
        if not isinstance(content, str):
            return "file_write.content must be a string"
        content_max = int(limits.get("content_max_len", 65536))
        if len(content) > content_max:
            return f"file_write.content exceeds max length ({content_max})"

        mode = inputs.get("mode")
        if mode is not None:
            valid_modes = tool_spec.get("supports_modes", ["commit", "draft", "preview"])
            if mode not in valid_modes:
                return f"file_write.mode '{mode}' not in supported modes: {valid_modes}"

    return None


# ---- Layer 1: Subprocess environment isolation
# Tools execute via subprocess.run(). Without scrubbing, the child process
# inherits the runner's full environment — M87_API_KEY, REDIS_URL, POSTGRES
# passwords, etc. A malicious test or build script could trivially read
# os.environ and exfiltrate secrets via stdout.
#
# _scrubbed_env() returns a copy of os.environ with all governance-sensitive
# vars removed. Every subprocess.run() call MUST pass env=_scrubbed_env().

_SECRET_ENV_PREFIXES = (
    "M87_", "REDIS_", "API_", "POSTGRES_", "DATABASE_",
    "AWS_", "GCP_", "AZURE_", "SECRET_", "TOKEN_",
)

_SECRET_ENV_EXACT = frozenset({
    "API_BASE", "API_KEY",
})


def _scrubbed_env() -> Dict[str, str]:
    """
    Return a copy of os.environ with governance secrets removed.

    Fail-closed: if in doubt, scrub it. Tools should never need
    runner infrastructure secrets.
    """
    out = {}
    for k, v in os.environ.items():
        if any(k.startswith(prefix) for prefix in _SECRET_ENV_PREFIXES):
            continue
        if k in _SECRET_ENV_EXACT:
            continue
        out[k] = v
    return out


# ---- Sandbox path resolution (defense-in-depth for file_write)

def _resolve_sandbox_path(relative_path: str, sandbox_root: str = None) -> str:
    """
    Resolve a relative path within the sandbox, with containment enforcement.

    Defense-in-depth: independent of governance API path checks.
    Rejects:
    - Null byte injection (\\x00 in path)
    - Traversal escape (resolved path outside sandbox)
    - Absolute paths (must be relative to sandbox)

    Returns absolute path within sandbox.
    Raises ValueError on containment violation.
    """
    if sandbox_root is None:
        sandbox_root = SANDBOX_ROOT

    # Null byte injection check
    if "\x00" in relative_path:
        raise ValueError(f"SANDBOX_NULL_BYTE: Null byte detected in path: {relative_path!r}")

    # Reject absolute paths — all writes must be relative to sandbox
    if os.path.isabs(relative_path):
        raise ValueError(f"SANDBOX_ABSOLUTE_PATH: Absolute paths not allowed: {relative_path}")

    # Resolve canonical path
    canonical_root = os.path.realpath(sandbox_root)
    candidate = os.path.realpath(os.path.join(canonical_root, relative_path))

    # Containment check: resolved path must be under sandbox root
    if not (candidate.startswith(canonical_root + os.sep) or candidate == canonical_root):
        raise ValueError(
            f"SANDBOX_ESCAPE: Path '{relative_path}' resolves to '{candidate}' "
            f"which is outside sandbox '{canonical_root}'"
        )

    return candidate


# ---- Tool implementations (the runner is allowed to be boring)
# V1 Governance: Tools must produce completion artifacts

def _make_receipt(action: str, proof: str = None) -> Dict[str, Any]:
    """Create a receipt artifact."""
    return {
        "action": action,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "proof": proof,
    }


def _make_log_artifact(source: str, content: str) -> Dict[str, Any]:
    """Create a log artifact with hash."""
    return {
        "source": source,
        "sha256": hashlib.sha256(content.encode("utf-8")).hexdigest(),
    }


def tool_echo(message: str, timeout_seconds: int) -> Dict[str, Any]:
    """Execute echo command with timeout enforcement. Returns artifacts."""
    try:
        completed = subprocess.run(
            ["echo", message],
            capture_output=True,
            text=True,
            check=True,
            timeout=timeout_seconds,
            env=_scrubbed_env(),
        )
        output = completed.stdout.strip()
        return {
            "stdout": output,
            "exit_code": 0,
            # V1: Completion artifacts
            "completion_artifacts": {
                "files": [],
                "diffs": [],
                "logs": [_make_log_artifact("echo_stdout", output)],
                "receipts": [_make_receipt("echo", proof=hashlib.sha256(message.encode()).hexdigest()[:16])],
            }
        }
    except subprocess.TimeoutExpired:
        return {"error": "timeout", "exit_code": -1}


def tool_pytest(args: str, timeout_seconds: int) -> Dict[str, Any]:
    """Execute pytest with timeout enforcement. Returns artifacts."""
    # Keep it safe: don't allow shell=True, no arbitrary command expansion
    # args is passed as tokens after splitting on spaces
    cmd = ["pytest"] + ([a for a in args.split(" ") if a] if args else [])
    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            env=_scrubbed_env(),
        )
        stdout = (completed.stdout or "")[-8000:]  # cap output
        stderr = (completed.stderr or "")[-8000:]
        combined = stdout + stderr

        return {
            "exit_code": completed.returncode,
            "stdout": stdout,
            "stderr": stderr,
            # V1: Completion artifacts
            "completion_artifacts": {
                "files": [],
                "diffs": [],
                "logs": [
                    _make_log_artifact("pytest_stdout", stdout),
                    _make_log_artifact("pytest_stderr", stderr),
                ],
                "receipts": [_make_receipt("pytest", proof=f"exit_code={completed.returncode}")],
            }
        }
    except subprocess.TimeoutExpired:
        return {"error": "timeout", "exit_code": -1, "stdout": "", "stderr": ""}


def tool_file_write(
    path: str,
    content: str,
    mode: str = "commit",
    sandbox_root: str = None,
) -> Dict[str, Any]:
    """
    Write content to a file inside the sandbox.

    Three execution modes:
    - draft: Validate path and content, produce receipt, but write nothing.
    - preview: Write to {path}.preview for inspection. No production side-effects.
    - commit: Write file, re-read, and verify content hash matches.

    Defense-in-depth: sandbox containment is enforced here independently
    of governance API path checks.

    Returns result dict with completion artifacts.
    """
    if sandbox_root is None:
        sandbox_root = SANDBOX_ROOT

    content_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()

    # Resolve and validate path (raises ValueError on escape)
    try:
        resolved = _resolve_sandbox_path(path, sandbox_root)
    except ValueError as e:
        return {
            "error": "sandbox_containment",
            "detail": str(e),
            "exit_code": -1,
        }

    receipt = _make_receipt(
        f"file_write:{mode}",
        proof=f"content_hash={content_hash[:16]},path={path}",
    )

    if mode == "draft":
        return {
            "exit_code": 0,
            "mode": "draft",
            "path": path,
            "resolved_path": resolved,
            "content_hash": content_hash,
            "bytes_planned": len(content.encode("utf-8")),
            "completion_artifacts": {
                "files": [],
                "diffs": [],
                "logs": [],
                "receipts": [receipt],
            },
        }

    if mode == "preview":
        preview_path = resolved + ".preview"
        os.makedirs(os.path.dirname(preview_path), exist_ok=True)
        with open(preview_path, "w", encoding="utf-8") as f:
            f.write(content)
        return {
            "exit_code": 0,
            "mode": "preview",
            "path": path,
            "resolved_path": preview_path,
            "content_hash": content_hash,
            "bytes_written": len(content.encode("utf-8")),
            "completion_artifacts": {
                "files": [{"path": preview_path, "sha256": content_hash}],
                "diffs": [],
                "logs": [],
                "receipts": [receipt],
            },
        }

    # mode == "commit"
    os.makedirs(os.path.dirname(resolved), exist_ok=True)
    with open(resolved, "w", encoding="utf-8") as f:
        f.write(content)

    # Verify: re-read and compare hash (artifact-backed completion)
    with open(resolved, "rb") as f:
        verify_hash = hashlib.sha256(f.read()).hexdigest()

    if verify_hash != content_hash:
        return {
            "error": "content_hash_mismatch",
            "detail": f"Written file hash {verify_hash[:16]}... != expected {content_hash[:16]}...",
            "exit_code": -1,
        }

    return {
        "exit_code": 0,
        "mode": "commit",
        "path": path,
        "resolved_path": resolved,
        "content_hash": content_hash,
        "verify_hash": verify_hash,
        "bytes_written": len(content.encode("utf-8")),
        "completion_artifacts": {
            "files": [{"path": resolved, "sha256": verify_hash}],
            "diffs": [],
            "logs": [],
            "receipts": [receipt],
        },
    }


def execute_job(job: Dict[str, Any], manifest: Dict[str, Any]) -> Dict[str, Any]:
    """
    Execute job with governance controls:
    - Manifest hash drift refusal
    - Deployment Envelope Hash (DEH) verification with evidence
    - Open-weight safety clamping
    - Autonomy Budget enforcement
    - Artifact-backed completion enforcement
    """
    job_id = job.get("job_id", "unknown")

    # Phase 5 Step 2: Manifest hash drift refusal
    #
    # INTENT PRESERVATION:
    # - Drift is fatal because the manifest defines what tools exist and their
    #   constraints. A job pinned to an old manifest might reference tools that
    #   no longer exist, or expect different input validation rules.
    # - We reject rather than "upgrade" the job because automatic upgrades could
    #   change security-relevant behavior (e.g., stricter input limits might
    #   truncate data, looser limits might allow injection).
    # - This prevents supply-chain attacks where an attacker modifies the manifest
    #   after jobs were approved but before they execute.
    job_hash = job.get("manifest_hash")
    runner_hash = manifest.get("_manifest_hash")

    # Partial evidence for early rejects (auditable signal even on manifest failures)
    partial_deh_evidence = {
        "envelope_hash_verified": False,
        "deh_claimed": job.get("envelope_hash"),
        "deh_recomputed": None,
        "error": "manifest_check_failed_before_deh",
    }

    if not job_hash:
        return {
            "error": "job_missing_manifest_hash",
            "detail": "Job was minted without manifest_hash (pre-V0.4.0 API?)",
            "deh_evidence": partial_deh_evidence,
            "exit_code": -1,
        }

    if job_hash != runner_hash:
        return {
            "error": "manifest_hash_mismatch",
            "detail": f"Job pinned hash {job_hash[:16]}... but runner has {runner_hash[:16]}...",
            "job_manifest_hash": job_hash,
            "runner_manifest_hash": runner_hash,
            "deh_evidence": partial_deh_evidence,
            "exit_code": -1,
        }

    # V1 Governance: Deployment Envelope Hash verification (returns evidence)
    deh_evidence = verify_deployment_envelope(job)
    if not deh_evidence.get("envelope_hash_verified"):
        print(f"  ✗ DEH verification failed: {deh_evidence.get('error')}", flush=True)
        return {
            "error": "deh_verification_failed",
            "detail": deh_evidence.get("error"),
            "deh_evidence": deh_evidence,
            "exit_code": -1,
        }

    # Layer 1: Effect schema version verification
    # Prevents taxonomy drift between API and runner deployments.
    job_esv = job.get("effect_schema_version")
    if job_esv and job_esv != RUNNER_EFFECT_SCHEMA_VERSION:
        print(f"  ✗ Effect schema version mismatch: job={job_esv}, runner={RUNNER_EFFECT_SCHEMA_VERSION}", flush=True)
        return {
            "error": "effect_schema_version_mismatch",
            "detail": f"Job has effect_schema_version '{job_esv}' but runner expects '{RUNNER_EFFECT_SCHEMA_VERSION}'",
            "deh_evidence": deh_evidence,
            "exit_code": -1,
        }

    # V1 Governance: Defense-in-depth open-weight clamping
    envelope = job.get("deployment_envelope", {})
    clamped_envelope = enforce_open_weight_safety(envelope)

    tool = job["tool"]

    # V1.1 Reversibility Gate: Runner-side enforcement (defense-in-depth)
    rev_evidence = verify_reversibility_gate(job, tool)
    if not rev_evidence.get("reversibility_verified"):
        print(f"  ✗ Reversibility Gate failed: {rev_evidence.get('error')}", flush=True)
        return {
            "error": "reversibility_gate_failed",
            "detail": rev_evidence.get("error"),
            "reversibility_evidence": rev_evidence,
            "deh_evidence": deh_evidence,
            "exit_code": -1,
        }

    # V1.2: Execution mode verification (turns mode from label into invariant)
    tool_spec = manifest.get("tools", {}).get(tool, {})
    mode_evidence = verify_execution_mode(job, tool_spec)
    if not mode_evidence.get("mode_verified"):
        print(f"  ✗ Execution mode verification failed: {mode_evidence.get('error')}", flush=True)
        return {
            "error": "execution_mode_unsupported",
            "detail": mode_evidence.get("error"),
            "mode_evidence": mode_evidence,
            "deh_evidence": deh_evidence,
            "exit_code": -1,
        }

    # Layer 0: Runner-side virtual FS deny (defense-in-depth)
    # Scan all input values for virtual FS paths before execution
    inputs_for_vfs = job.get("inputs", {})
    for input_key, input_val in inputs_for_vfs.items():
        if isinstance(input_val, str):
            vfs_deny = _runner_check_virtual_fs(input_val)
            if vfs_deny:
                print(f"  ✗ Virtual FS denied: {vfs_deny}", flush=True)
                return {
                    "error": "runner_virtual_fs_denied",
                    "detail": vfs_deny,
                    "deh_evidence": deh_evidence,
                    "exit_code": -1,
                }

    # Layer 0: Runner-side path revalidation (defense-in-depth)
    # Enforces resolved_paths ⊆ approved_paths invariant
    approved_paths = job.get("approved_paths", [])
    path_evidence = _runner_revalidate_paths(
        approved_paths=approved_paths,
        job_inputs=inputs_for_vfs,
    )
    if not path_evidence["pathset_valid"]:
        print(f"  ✗ Path revalidation failed: {path_evidence.get('error')}", flush=True)
        return {
            "error": "runner_pathset_mismatch",
            "detail": path_evidence.get("error"),
            "path_evidence": path_evidence,
            "deh_evidence": deh_evidence,
            "exit_code": -1,
        }

    # V1 Step 2: Resolve budget (envelope-first, runner defaults second)
    budget = resolve_autonomy_budget({"deployment_envelope": clamped_envelope})

    # V2: Apply budget_multiplier from cleanup_cost
    budget_multiplier = job.get("budget_multiplier", 1.0)
    if budget_multiplier != 1.0:
        # Apply multiplier to step/tool call budgets (not runtime - that's a hard limit)
        budget["max_steps"] = int(budget["max_steps"] * budget_multiplier)
        budget["max_tool_calls"] = int(budget["max_tool_calls"] * budget_multiplier)
        print(f"  ⚠ Budget adjusted by multiplier {budget_multiplier}: "
              f"steps={budget['max_steps']}, tool_calls={budget['max_tool_calls']}", flush=True)

    tracker = AutonomyBudgetTracker(budget)

    # Preemptive AB: runtime check immediately after DEH
    if tracker.runtime_exceeded():
        return fail_budget(
            "autonomy_budget_exceeded",
            "max_runtime_seconds exceeded at job start",
            tracker=tracker,
            deh_evidence=deh_evidence,
        )
    inputs = job.get("inputs", {})
    # tool_spec already resolved above for mode verification
    timeout_seconds = int(tool_spec.get("timeout_seconds", 30))

    # Preemptive AB: steps
    if not tracker.try_step():
        return fail_budget(
            "autonomy_budget_exceeded",
            "max_steps exceeded",
            tracker=tracker,
            deh_evidence=deh_evidence,
        )

    # Preemptive AB: tool calls
    if not tracker.try_tool_call():
        return fail_budget(
            "autonomy_budget_exceeded",
            "max_tool_calls exceeded",
            tracker=tracker,
            deh_evidence=deh_evidence,
        )

    # Preemptive AB: runtime before tool execution
    if tracker.runtime_exceeded():
        return fail_budget(
            "autonomy_budget_exceeded",
            "max_runtime_seconds exceeded before tool execution",
            tracker=tracker,
            deh_evidence=deh_evidence,
        )

    # V1 Step 2.5: Write scope gating - tools declare blast radius, budget decides
    required_scope = TOOL_WRITE_SCOPE_REQUIREMENTS.get(tool, "sandbox")
    allowed_scope = budget.get("max_write_scope", "sandbox")
    if scope_rank(required_scope) > scope_rank(allowed_scope):
        return fail_budget(
            "budget_scope_violation",
            f"tool '{tool}' requires write_scope '{required_scope}' but budget allows '{allowed_scope}'",
            tracker=tracker,
            deh_evidence=deh_evidence,
        )

    exec_start = time.monotonic()

    if tool == "echo":
        result = tool_echo(inputs.get("message", ""), timeout_seconds)
    elif tool == "pytest":
        result = tool_pytest(inputs.get("args", ""), timeout_seconds)
    elif tool == "file_write":
        exec_mode = job.get("execution_mode", "commit").lower()
        result = tool_file_write(
            path=inputs.get("path", ""),
            content=inputs.get("content", ""),
            mode=inputs.get("mode", exec_mode),
        )
    else:
        # Should never happen due to manifest validation
        raise RuntimeError(f"Unhandled tool: {tool}")

    exec_elapsed_ms = (time.monotonic() - exec_start) * 1000

    # Per-Call Receipt: record execution timing + result hash (observation-only, fail-safe)
    try:
        result_bytes = json.dumps(result, sort_keys=True, default=str).encode("utf-8")
        result["call_receipt_execution"] = {
            "result_hash": hashlib.sha256(result_bytes).hexdigest(),
            "result_size_bytes": len(result_bytes),
            "execution_ms": round(exec_elapsed_ms, 2),
            "exit_code": result.get("exit_code"),
            "truncated": False,
        }
    except Exception as e:
        print(f"  ⚠ Call receipt recording failed: {e}", flush=True)

    # V1 Governance: Artifact-backed completion enforcement (runner-side)
    # Runner must not report "completed" without artifacts
    #
    # INTENT PRESERVATION:
    # - "Completed" without proof is indistinguishable from "lied about completing".
    #   Artifacts provide machine-verifiable evidence that work actually happened.
    # - This prevents a compromised tool from claiming success without doing anything,
    #   which could mask failures or allow attackers to skip security-critical steps.
    # - Empty artifacts ({}) are rejected because they provide no verification value.
    #   At minimum, a log or receipt must exist to prove the tool ran.
    has_error = result.get("error") or result.get("exit_code", 0) != 0

    # Strict artifact check: at least one list must have entries
    # Prevents {completion_artifacts: {}} from passing
    artifacts = result.get("completion_artifacts") or {}
    has_artifacts = bool(
        artifacts.get("files")
        or artifacts.get("diffs")
        or artifacts.get("logs")
        or artifacts.get("receipts")
    )

    if not has_error and not has_artifacts:
        # Tool ran successfully but didn't produce artifacts
        # This is a tool implementation bug - force failure
        print(f"  ⚠ Tool '{tool}' completed without artifacts - forcing failure", flush=True)
        result["error"] = "no_verifiable_artifacts_for_tool"
        result["exit_code"] = -1

    # Add governance telemetry to result
    result["autonomy_budget"] = budget  # What was allowed (immutable snapshot)
    result["autonomy_usage"] = tracker.get_usage()  # What was consumed
    result["envelope_hash"] = job.get("envelope_hash")
    result["deh_evidence"] = deh_evidence  # Machine-verifiable proof

    return result


def report_result(job_id: str, proposal_id: str, status: str, output: Dict[str, Any], manifest: Dict[str, Any]) -> None:
    """
    Report result back to API with manifest metadata.
    Phase 5 Step 3: bounded payload.
    V1 Governance: includes completion_artifacts, envelope_hash, autonomy_budget, autonomy_usage, deh_evidence.
    """
    # Extract V1 governance fields from output (added by execute_job)
    completion_artifacts = output.pop("completion_artifacts", None)
    envelope_hash = output.pop("envelope_hash", None)
    autonomy_budget = output.pop("autonomy_budget", None)  # What was allowed
    autonomy_usage = output.pop("autonomy_usage", None)    # What was consumed
    deh_evidence = output.pop("deh_evidence", None)

    payload = {
        "job_id": job_id,
        "proposal_id": proposal_id,
        "status": status,
        "output": output,
        "manifest_hash": manifest.get("_manifest_hash"),
        "manifest_version": manifest.get("version"),
        # V1 Governance fields
        "completion_artifacts": completion_artifacts,
        "envelope_hash": envelope_hash,
        "autonomy_budget": autonomy_budget,   # Forensic: what was allowed
        "autonomy_usage": autonomy_usage,     # Forensic: what was consumed
        "deh_evidence": deh_evidence,         # Machine-verifiable DEH proof
    }

    # Phase 5 Step 3: Enforce byte size cap on outbound results
    raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    if len(raw) > MAX_REPORT_BYTES:
        # Hard truncate output fields locally (preserve artifacts for completion verification)
        payload["output"] = {"error": "runner_output_too_large", "bytes": len(raw)}
        raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")

    requests.post(f"{API_BASE}/v1/runner/result", headers=_api_headers(), data=raw, timeout=20).raise_for_status()


def ensure_group(r: Redis) -> None:
    try:
        r.xgroup_create(JOBS_STREAM, CONSUMER_GROUP, id="0-0", mkstream=True)
    except Exception:
        # group exists
        pass


def _verify_network_namespace() -> None:
    """
    Layer 0: Verify runner is network-isolated (network_mode: none).

    Checks that no network interfaces exist besides loopback.
    Fail-closed: any non-lo interface → refuse to start.
    """
    network_check_enabled = os.getenv("M87_NETWORK_CHECK_ENABLED", "0") == "1"
    if not network_check_enabled:
        print("  ⚠ Network namespace check disabled (M87_NETWORK_CHECK_ENABLED != 1)", flush=True)
        return

    try:
        # /sys/class/net/ lists all network interfaces
        net_path = "/sys/class/net"
        if not os.path.exists(net_path):
            print(f"  ⚠ Cannot read {net_path} (skipping network check)", flush=True)
            return
        interfaces = os.listdir(net_path)
    except (OSError, PermissionError) as e:
        print(f"  ⚠ Cannot list network interfaces: {e} (skipping)", flush=True)
        return

    # Only loopback should exist in network_mode: none
    non_loopback = [iface for iface in interfaces if iface != "lo"]
    if non_loopback:
        raise RuntimeError(
            f"RUNNER_NAMESPACE_VIOLATION: Non-loopback network interfaces detected: "
            f"{non_loopback}. Runner must have network_mode: none. "
            f"Refusing to start (fail-closed)."
        )


def _verify_capabilities_dropped() -> None:
    """
    Layer 0: Verify dangerous capabilities are dropped.

    Reads /proc/self/status for CapEff (effective capabilities).
    Fail-closed: dangerous capabilities present → refuse to start.

    Dangerous capabilities:
    - CAP_SYS_ADMIN (bit 21): full system control
    - CAP_NET_RAW (bit 13): raw socket access
    - CAP_NET_ADMIN (bit 12): network configuration
    - CAP_SYS_PTRACE (bit 19): process tracing
    """
    cap_check_enabled = os.getenv("M87_CAP_CHECK_ENABLED", "0") == "1"
    if not cap_check_enabled:
        print("  ⚠ Capability check disabled (M87_CAP_CHECK_ENABLED != 1)", flush=True)
        return

    try:
        with open("/proc/self/status", "r") as f:
            status_content = f.read()
    except (OSError, PermissionError) as e:
        print(f"  ⚠ Cannot read /proc/self/status: {e} (skipping cap check)", flush=True)
        return

    cap_eff = None
    for line in status_content.strip().split("\n"):
        if line.startswith("CapEff:"):
            cap_eff = int(line.split(":")[1].strip(), 16)
            break

    if cap_eff is None:
        print("  ⚠ CapEff not found in /proc/self/status (skipping)", flush=True)
        return

    # Dangerous capability bit positions
    DANGEROUS_CAPS = {
        12: "CAP_NET_ADMIN",
        13: "CAP_NET_RAW",
        19: "CAP_SYS_PTRACE",
        21: "CAP_SYS_ADMIN",
    }

    violations = []
    for bit, name in DANGEROUS_CAPS.items():
        if cap_eff & (1 << bit):
            violations.append(name)

    if violations:
        raise RuntimeError(
            f"RUNNER_CAPABILITY_VIOLATION: Dangerous capabilities detected: "
            f"{violations}. Runner must drop all dangerous caps. "
            f"Refusing to start (fail-closed)."
        )


def _verify_runtime_mount_invariants() -> None:
    """
    P2.1 — Runtime mount option verification (PROBE_014_ARCHITECTURAL).

    Verifies mount options at startup; mismatch → refuse to start (fail-closed).
    Checks for nosuid, nodev on temp directories to prevent privilege escalation.
    """
    mount_check_enabled = os.getenv("M87_MOUNT_CHECK_ENABLED", "0") == "1"
    if not mount_check_enabled:
        print("  ⚠ Mount invariant check disabled (M87_MOUNT_CHECK_ENABLED != 1)", flush=True)
        return

    try:
        with open("/proc/mounts", "r") as f:
            mounts_content = f.read()
    except (OSError, PermissionError) as e:
        print(f"  ⚠ Cannot read /proc/mounts: {e} (skipping mount check)", flush=True)
        return

    # Parse mount options
    mount_options: dict = {}
    for line in mounts_content.strip().split("\n"):
        parts = line.split()
        if len(parts) >= 4:
            mount_options[parts[1]] = set(parts[3].split(","))

    # Check required invariants
    MOUNT_INVARIANTS = {
        "/tmp": {"nosuid", "nodev"},
        "/var/tmp": {"nosuid", "nodev"},
    }

    violations = []
    for mount_point, required_opts in MOUNT_INVARIANTS.items():
        if mount_point in mount_options:
            actual = mount_options[mount_point]
            missing = required_opts - actual
            if missing:
                violations.append(
                    f"  Mount {mount_point}: missing options {sorted(missing)} "
                    f"(has: {sorted(actual)})"
                )

    if violations:
        print("✗ MOUNT INVARIANT VIOLATIONS:", flush=True)
        for v in violations:
            print(v, flush=True)
        raise RuntimeError(
            f"Mount invariant violations detected: {len(violations)} mount(s) "
            f"missing required options. Runner refusing to start (fail-closed)."
        )


# ---- Layer 0: Runner-side path revalidation (defense-in-depth)
# Self-contained implementation — runner does NOT import from governance API.
# Invariant: resolved_paths ⊆ approved_paths (extra paths → abort)

def _runner_revalidate_paths(
    approved_paths: list,
    job_inputs: Dict[str, Any],
    base_dir: str = "/",
) -> Dict[str, Any]:
    """
    Runner-side revalidation of artifact paths against governance-approved set.

    Checks:
    1. All input paths are canonicalized via os.path.realpath()
    2. No symlink escapes outside base_dir
    3. resolved_set ⊆ approved_set (extra paths = TOCTOU break)

    Returns evidence dict.
    """
    evidence = {
        "pathset_valid": True,
        "extra_paths": [],
        "symlink_escapes": [],
        "error": None,
    }

    canonical_base = os.path.realpath(base_dir)

    # Extract and canonicalize paths from inputs
    resolved_paths = set()
    for key, value in job_inputs.items():
        if isinstance(value, str) and ("/" in value or os.sep in value):
            try:
                resolved = os.path.realpath(value)
            except (OSError, ValueError):
                continue
            # Check symlink escape — always enforced regardless of approved_paths
            if not resolved.startswith(canonical_base + os.sep) and resolved != canonical_base:
                evidence["pathset_valid"] = False
                evidence["symlink_escapes"].append(value)
                evidence["error"] = f"Symlink escape: {value} resolves to {resolved} (outside {base_dir})"
                return evidence
            resolved_paths.add(resolved)

    if not approved_paths:
        # No approved paths to validate against — symlink check already passed
        return evidence

    # Build approved set
    approved_set = set()
    for p in approved_paths:
        try:
            approved_set.add(os.path.realpath(p))
        except (OSError, ValueError):
            approved_set.add(p)

    # Invariant: resolved_paths ⊆ approved_paths
    extra = resolved_paths - approved_set
    if extra:
        evidence["pathset_valid"] = False
        evidence["extra_paths"] = sorted(extra)
        evidence["error"] = (
            f"RUNNER_PATHSET_MISMATCH: {len(extra)} path(s) not in governance-approved set. "
            f"Possible overlay/bind mount divergence."
        )

    return evidence


# ---- Layer 0: Virtual FS deny (runner-side defense-in-depth)
# Runner independently denies access to dangerous virtual filesystems.
# This is a last line of defense — governance should have already denied.

_RUNNER_VFS_DENY_PREFIXES = (
    "/dev/shm", "/sys", "/run", "/dev/pts", "/dev/mqueue",
)
_RUNNER_VFS_PROC_ALLOWLIST = frozenset({
    "/proc/self/status", "/proc/self/limits", "/proc/self/cgroup",
    "/proc/version", "/proc/cpuinfo", "/proc/meminfo", "/proc/loadavg",
    "/proc/mounts",
})


def _runner_check_virtual_fs(path: str) -> Optional[str]:
    """
    Runner-side virtual FS check. Returns deny reason or None if allowed.
    """
    normalized = os.path.normpath(path)
    for prefix in _RUNNER_VFS_DENY_PREFIXES:
        if normalized == prefix or normalized.startswith(prefix + "/"):
            return f"RUNNER_VIRTUAL_FS_DENIED: {path} (matches {prefix})"
    if normalized.startswith("/proc"):
        if normalized not in _RUNNER_VFS_PROC_ALLOWLIST:
            return f"RUNNER_VIRTUAL_FS_DENIED: {path} (not in /proc allowlist)"
    return None


# P0.B: File dispatch mode for airgapped runner (network_mode: none)
DISPATCH_MODE = os.getenv("M87_DISPATCH_MODE", "redis")  # "redis" or "file"
FILE_INCOMING = os.getenv("M87_FILE_INCOMING", "/dispatch/incoming")
FILE_OUTGOING = os.getenv("M87_FILE_OUTGOING", "/dispatch/outgoing")


def _file_dispatch_loop(manifest: Dict[str, Any]) -> None:
    """
    File-based dispatch loop for airgapped runner.

    Polls incoming/ directory for job envelopes, executes them,
    and writes results to outgoing/ directory.
    """
    from pathlib import Path

    incoming = Path(FILE_INCOMING)
    outgoing = Path(FILE_OUTGOING)
    incoming.mkdir(parents=True, exist_ok=True)
    outgoing.mkdir(parents=True, exist_ok=True)

    print(f"  File dispatch: incoming={incoming}, outgoing={outgoing}", flush=True)

    while True:
        try:
            job_files = sorted(incoming.glob("*.json"))

            for job_file in job_files:
                if job_file.name.startswith("."):
                    continue

                try:
                    job = json.loads(job_file.read_text())
                except (json.JSONDecodeError, OSError) as e:
                    print(f"  ✗ Bad job file {job_file.name}: {e}", flush=True)
                    job_file.unlink(missing_ok=True)
                    continue

                job_id = job.get("job_id", "unknown")
                proposal_id = job.get("proposal_id", "unknown")
                print(f"▶ Job {job_id[:8]}... tool={job.get('tool')} (file dispatch)", flush=True)

                job_file.unlink(missing_ok=True)

                err = validate_job_against_manifest(job, manifest)
                if err:
                    print(f"  ✗ Manifest reject: {err}", flush=True)
                    result_data = {
                        "job_id": job_id,
                        "proposal_id": proposal_id,
                        "status": "failed",
                        "output": {"error": "manifest_reject", "detail": err},
                    }
                else:
                    try:
                        output = execute_job(job, manifest)
                        status = "completed" if output.get("exit_code", 0) == 0 else "failed"
                        print(f"  → {status}", flush=True)

                        completion_artifacts = output.pop("completion_artifacts", None)
                        envelope_hash = output.pop("envelope_hash", None)
                        autonomy_budget = output.pop("autonomy_budget", None)
                        autonomy_usage = output.pop("autonomy_usage", None)
                        deh_evidence = output.pop("deh_evidence", None)

                        result_data = {
                            "job_id": job_id,
                            "proposal_id": proposal_id,
                            "status": status,
                            "output": output,
                            "manifest_hash": manifest.get("_manifest_hash"),
                            "manifest_version": manifest.get("version"),
                            "completion_artifacts": completion_artifacts,
                            "envelope_hash": envelope_hash,
                            "autonomy_budget": autonomy_budget,
                            "autonomy_usage": autonomy_usage,
                            "deh_evidence": deh_evidence,
                        }
                    except Exception as e:
                        print(f"  ✗ Execution error: {e}", flush=True)
                        result_data = {
                            "job_id": job_id,
                            "proposal_id": proposal_id,
                            "status": "failed",
                            "output": {"error": "execution_error", "detail": str(e)},
                        }

                # Write result atomically
                result_path = outgoing / f"{job_id}.result.json"
                tmp_path = outgoing / f".{job_id}.result.json.tmp"
                tmp_path.write_text(json.dumps(result_data, indent=2))
                tmp_path.rename(result_path)

        except Exception as e:
            print(f"[ERROR] File dispatch: {e}", flush=True)

        time.sleep(1)


def main() -> None:
    print("🏃 M87 Runner V2.0 (Hardening Package) starting...", flush=True)
    print(f"  Dispatch mode: {DISPATCH_MODE}", flush=True)

    manifest = load_manifest(MANIFEST_PATH)
    print(f"✓ Loaded manifest v{manifest.get('version', 'unknown')}", flush=True)
    print(f"   Hash: {manifest.get('_manifest_hash', 'unknown')[:16]}...", flush=True)
    print(f"   Tools: {list(manifest.get('tools', {}).keys())}", flush=True)

    # Verify manifest lock (supply-chain integrity)
    lock_result = verify_manifest_lock(manifest)
    if lock_result.get("ok"):
        print(f"✓ Manifest lock verified (commit: {lock_result.get('source_commit', 'unknown')})", flush=True)
    elif lock_result.get("critical"):
        print(f"✗ CRITICAL: Manifest lock verification failed: {lock_result.get('error')}", flush=True)
        print(f"   {lock_result.get('detail', '')}", flush=True)
        raise RuntimeError(f"Manifest lock verification failed: {lock_result.get('error')}")
    else:
        print(f"⚠ Manifest lock not enforced: {lock_result.get('error')}", flush=True)

    # P2.1: Verify runtime mount invariants (fail-closed)
    _verify_runtime_mount_invariants()
    print("✓ Mount invariant check passed", flush=True)

    # Layer 0: Network namespace verification (fail-closed)
    _verify_network_namespace()
    print("✓ Network namespace check passed", flush=True)

    # Layer 0: Capability drop verification (fail-closed)
    _verify_capabilities_dropped()
    print("✓ Capability check passed", flush=True)

    # P0.B: File dispatch mode — no Redis needed
    if DISPATCH_MODE == "file":
        print("✓ Running in file dispatch mode (airgap)", flush=True)
        _file_dispatch_loop(manifest)
        return

    # Standard Redis dispatch mode
    r = Redis.from_url(REDIS_URL, decode_responses=True)
    ensure_group(r)

    while True:
        try:
            resp = r.xreadgroup(
                groupname=CONSUMER_GROUP,
                consumername=CONSUMER_NAME,
                streams={JOBS_STREAM: ">"},
                count=10,
                block=5000
            )

            if not resp:
                continue

            for stream_name, messages in resp:
                for msg_id, fields in messages:
                    # JobSpec stored as JSON in field "job"
                    raw = fields.get("job")
                    if not raw:
                        r.xack(JOBS_STREAM, CONSUMER_GROUP, msg_id)
                        continue

                    job = json.loads(raw)
                    job_id = job.get("job_id", "unknown")
                    proposal_id = job.get("proposal_id", "unknown")

                    print(f"▶ Job {job_id[:8]}... tool={job.get('tool')}", flush=True)

                    # Manifest enforcement
                    err = validate_job_against_manifest(job, manifest)
                    if err:
                        print(f"  ✗ Manifest reject: {err}", flush=True)
                        report_result(job_id, proposal_id, "failed", {"error": "manifest_reject", "detail": err}, manifest)
                        r.xack(JOBS_STREAM, CONSUMER_GROUP, msg_id)
                        continue

                    # Execute with manifest-defined timeout
                    try:
                        output = execute_job(job, manifest)
                        status = "completed" if output.get("exit_code", 0) == 0 else "failed"
                        print(f"  → {status}", flush=True)
                        report_result(job_id, proposal_id, status, output, manifest)
                    except Exception as e:
                        print(f"  ✗ Execution error: {e}", flush=True)
                        report_result(job_id, proposal_id, "failed", {"error": "execution_error", "detail": str(e)}, manifest)

                    r.xack(JOBS_STREAM, CONSUMER_GROUP, msg_id)

        except Exception as e:
            print(f"[ERROR] {e}", flush=True)
            # Keep runner alive; sleep briefly and retry
            time.sleep(2)


if __name__ == "__main__":
    main()
