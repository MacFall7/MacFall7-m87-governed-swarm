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
    # Future tools:
    # "git_push": "prod",
    # "db_migrate": "prod",
    # "deploy": "prod",
}


def scope_rank(scope: str) -> int:
    """Rank write scopes from least to most permissive."""
    return {"none": 0, "sandbox": 1, "staging": 2, "prod": 3}.get(scope, 99)


# ---- V1 Governance: Autonomy Budget tracking
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

    return None


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
            timeout=timeout_seconds
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
            timeout=timeout_seconds
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

    # V1 Governance: Defense-in-depth open-weight clamping
    envelope = job.get("deployment_envelope", {})
    clamped_envelope = enforce_open_weight_safety(envelope)

    # V1 Step 2: Resolve budget (envelope-first, runner defaults second)
    budget = resolve_autonomy_budget({"deployment_envelope": clamped_envelope})
    tracker = AutonomyBudgetTracker(budget)

    # Preemptive AB: runtime check immediately after DEH
    if tracker.runtime_exceeded():
        return fail_budget(
            "autonomy_budget_exceeded",
            "max_runtime_seconds exceeded at job start",
            tracker=tracker,
            deh_evidence=deh_evidence,
        )

    tool = job["tool"]
    inputs = job.get("inputs", {})
    tool_spec = manifest.get("tools", {}).get(tool, {})
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

    if tool == "echo":
        result = tool_echo(inputs.get("message", ""), timeout_seconds)
    elif tool == "pytest":
        result = tool_pytest(inputs.get("args", ""), timeout_seconds)
    else:
        # Should never happen due to manifest validation
        raise RuntimeError(f"Unhandled tool: {tool}")

    # V1 Governance: Artifact-backed completion enforcement (runner-side)
    # Runner must not report "completed" without artifacts
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


def main() -> None:
    print("🏃 M87 Runner V1.5 (Manifest Lock Verification) starting...", flush=True)

    r = Redis.from_url(REDIS_URL, decode_responses=True)
    ensure_group(r)

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
