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
def compute_envelope_hash(envelope: Dict[str, Any]) -> str:
    """Compute DEH = SHA256(canonical_json(deployment_envelope))"""
    canonical = json.dumps(envelope, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def verify_deployment_envelope(job: Dict[str, Any]) -> Optional[str]:
    """
    Verify job's deployment envelope hash matches recomputed hash.
    Returns error string if mismatch, None if OK.
    """
    envelope = job.get("deployment_envelope")
    claimed_hash = job.get("envelope_hash")

    if not claimed_hash:
        return "Job missing envelope_hash (pre-V1.0 API?)"

    if not envelope:
        return "Job missing deployment_envelope for verification"

    recomputed = compute_envelope_hash(envelope)
    if recomputed != claimed_hash:
        return f"DEH mismatch: claimed {claimed_hash[:16]}... but computed {recomputed[:16]}..."

    return None


# ---- V1 Governance: Autonomy Budget tracking
class AutonomyBudgetTracker:
    """Tracks resource usage against autonomy budget limits."""

    def __init__(self, budget: Dict[str, Any]):
        self.budget = budget
        self.steps = 0
        self.tool_calls = 0
        self.parallel_agents = 0
        self.external_io = 0
        self.start_time = time.time()

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

    def increment_step(self):
        self.steps += 1

    def increment_tool_call(self):
        self.tool_calls += 1

    def increment_external_io(self):
        self.external_io += 1

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
    - Deployment Envelope Hash (DEH) verification
    - Autonomy Budget enforcement
    """
    job_id = job.get("job_id", "unknown")

    # Phase 5 Step 2: Manifest hash drift refusal
    job_hash = job.get("manifest_hash")
    runner_hash = manifest.get("_manifest_hash")

    if not job_hash:
        return {
            "error": "job_missing_manifest_hash",
            "detail": "Job was minted without manifest_hash (pre-V0.4.0 API?)",
            "exit_code": -1,
        }

    if job_hash != runner_hash:
        return {
            "error": "manifest_hash_mismatch",
            "detail": f"Job pinned hash {job_hash[:16]}... but runner has {runner_hash[:16]}...",
            "job_manifest_hash": job_hash,
            "runner_manifest_hash": runner_hash,
            "exit_code": -1,
        }

    # V1 Governance: Deployment Envelope Hash verification
    deh_error = verify_deployment_envelope(job)
    if deh_error:
        print(f"  ✗ DEH verification failed: {deh_error}", flush=True)
        return {
            "error": "deh_verification_failed",
            "detail": deh_error,
            "exit_code": -1,
        }

    # V1 Governance: Initialize autonomy budget tracker
    budget = job.get("autonomy_budget", {})
    tracker = AutonomyBudgetTracker(budget)

    # Check budget before execution
    budget_error = tracker.check_limits()
    if budget_error:
        return {
            "error": "autonomy_budget_exceeded",
            "detail": budget_error,
            "usage": tracker.get_usage(),
            "exit_code": -1,
        }

    tool = job["tool"]
    inputs = job.get("inputs", {})
    tool_spec = manifest.get("tools", {}).get(tool, {})
    timeout_seconds = int(tool_spec.get("timeout_seconds", 30))

    # Track tool call
    tracker.increment_tool_call()
    tracker.increment_step()

    # Check budget after incrementing
    budget_error = tracker.check_limits()
    if budget_error:
        return {
            "error": "autonomy_budget_exceeded",
            "detail": budget_error,
            "usage": tracker.get_usage(),
            "exit_code": -1,
        }

    if tool == "echo":
        result = tool_echo(inputs.get("message", ""), timeout_seconds)
    elif tool == "pytest":
        result = tool_pytest(inputs.get("args", ""), timeout_seconds)
    else:
        # Should never happen due to manifest validation
        raise RuntimeError(f"Unhandled tool: {tool}")

    # Add usage telemetry to result
    result["autonomy_usage"] = tracker.get_usage()
    result["envelope_hash"] = job.get("envelope_hash")

    return result


def report_result(job_id: str, proposal_id: str, status: str, output: Dict[str, Any], manifest: Dict[str, Any]) -> None:
    """
    Report result back to API with manifest metadata.
    Phase 5 Step 3: bounded payload.
    V1 Governance: includes completion_artifacts, envelope_hash, autonomy_usage.
    """
    # Extract V1 governance fields from output (added by execute_job)
    completion_artifacts = output.pop("completion_artifacts", None)
    envelope_hash = output.pop("envelope_hash", None)
    autonomy_usage = output.pop("autonomy_usage", None)

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
        "autonomy_usage": autonomy_usage,
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
