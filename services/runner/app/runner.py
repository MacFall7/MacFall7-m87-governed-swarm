"""
M87 Runner Service - V1.3+ (Phase 4: Tool Manifest)
Consumes JobSpecs from m87:jobs stream ONLY.
Executes tools ONLY if declared in tool_manifest.json.
"""

import os
import time
import json
import subprocess
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


def _api_headers() -> Dict[str, str]:
    return {"X-M87-Key": API_KEY, "content-type": "application/json"}


def load_manifest() -> Dict[str, Any]:
    with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


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

def tool_echo(message: str) -> Dict[str, Any]:
    completed = subprocess.run(["echo", message], capture_output=True, text=True, check=True)
    return {"stdout": completed.stdout.strip()}


def tool_pytest(args: str) -> Dict[str, Any]:
    # Keep it safe: don't allow shell=True, no arbitrary command expansion
    # args is passed as tokens after splitting on spaces
    cmd = ["pytest"] + ([a for a in args.split(" ") if a] if args else [])
    completed = subprocess.run(cmd, capture_output=True, text=True)
    return {
        "exit_code": completed.returncode,
        "stdout": (completed.stdout or "")[-8000:],  # cap output
        "stderr": (completed.stderr or "")[-8000:]
    }


def execute_job(job: Dict[str, Any]) -> Dict[str, Any]:
    tool = job["tool"]
    inputs = job.get("inputs", {})

    if tool == "echo":
        return tool_echo(inputs.get("message", ""))

    if tool == "pytest":
        return tool_pytest(inputs.get("args", ""))

    # Should never happen due to manifest validation
    raise RuntimeError(f"Unhandled tool: {tool}")


def report_result(job_id: str, proposal_id: str, status: str, output: Dict[str, Any]) -> None:
    payload = {
        "job_id": job_id,
        "proposal_id": proposal_id,
        "status": status,
        "output": output
    }
    requests.post(f"{API_BASE}/v1/runner/result", headers=_api_headers(), data=json.dumps(payload), timeout=20).raise_for_status()


def ensure_group(r: Redis) -> None:
    try:
        r.xgroup_create(JOBS_STREAM, CONSUMER_GROUP, id="0-0", mkstream=True)
    except Exception:
        # group exists
        pass


def main() -> None:
    print("🏃 M87 Runner V1.3 (Phase 4: Tool Manifest) starting...", flush=True)

    r = Redis.from_url(REDIS_URL, decode_responses=True)
    ensure_group(r)

    manifest = load_manifest()
    print(f"✓ Loaded manifest v{manifest.get('version', 'unknown')}", flush=True)
    print(f"   Tools: {list(manifest.get('tools', {}).keys())}", flush=True)

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
                        report_result(job_id, proposal_id, "failed", {"error": "manifest_reject", "detail": err})
                        r.xack(JOBS_STREAM, CONSUMER_GROUP, msg_id)
                        continue

                    # Execute
                    try:
                        output = execute_job(job)
                        status = "completed" if output.get("exit_code", 0) == 0 else "failed"
                        print(f"  → {status}", flush=True)
                        report_result(job_id, proposal_id, status, output)
                    except Exception as e:
                        print(f"  ✗ Execution error: {e}", flush=True)
                        report_result(job_id, proposal_id, "failed", {"error": "execution_error", "detail": str(e)})

                    r.xack(JOBS_STREAM, CONSUMER_GROUP, msg_id)

        except Exception as e:
            print(f"[ERROR] {e}", flush=True)
            # Keep runner alive; sleep briefly and retry
            time.sleep(2)


if __name__ == "__main__":
    main()
