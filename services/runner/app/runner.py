"""
M87 Runner Service - V1.2

Consumes JobSpecs from m87:jobs stream (NOT events).
Executes only allowlisted tools in sandbox.
Reports results back via API.
"""

import os
import time
import json
import subprocess
import requests
from redis import Redis

# Config
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")
API_BASE = os.getenv("API_BASE", "http://api:8000")
API_KEY = os.getenv("M87_API_KEY", "m87-dev-key-change-me")

# Stream keys
JOB_STREAM = "m87:jobs"
CONSUMER_GROUP = "runner"
CONSUMER_NAME = "runner-1"
CURSOR_KEY = "m87:runner:last_job_id"

# Tool allowlist - runner will ONLY execute these
ALLOWED_TOOLS = {"echo", "pytest", "git", "build"}


def setup_consumer_group(rdb: Redis) -> None:
    """Create consumer group if it doesn't exist."""
    try:
        rdb.xgroup_create(JOB_STREAM, CONSUMER_GROUP, id="0", mkstream=True)
        print(f"✓ Created consumer group: {CONSUMER_GROUP}", flush=True)
    except Exception as e:
        if "BUSYGROUP" not in str(e):
            raise
        print(f"✓ Consumer group exists: {CONSUMER_GROUP}", flush=True)


def execute_tool(tool: str, inputs: dict, timeout: int) -> tuple[str, str]:
    """
    Execute an allowlisted tool and return (status, output).
    V1.2: Only echo is implemented. Others return stub.
    """
    if tool not in ALLOWED_TOOLS:
        return "failed", f"Tool '{tool}' not in allowlist"

    try:
        if tool == "echo":
            message = inputs.get("message", "no message")
            result = subprocess.run(
                ["echo", message],
                capture_output=True,
                text=True,
                timeout=timeout,
                check=True
            )
            return "completed", result.stdout.strip()

        elif tool == "pytest":
            # V1.2 stub - will implement later
            return "completed", "[pytest] Would run tests (stub)"

        elif tool == "git":
            # V1.2 stub
            cmd = inputs.get("command", "status")
            return "completed", f"[git] Would run: git {cmd} (stub)"

        elif tool == "build":
            # V1.2 stub
            return "completed", "[build] Would run build (stub)"

        else:
            return "failed", f"Tool '{tool}' not implemented"

    except subprocess.TimeoutExpired:
        return "failed", f"Timeout after {timeout}s"
    except subprocess.CalledProcessError as e:
        return "failed", e.stderr or str(e)
    except Exception as e:
        return "failed", str(e)


def report_result(job_id: str, proposal_id: str, tool: str, status: str, output: str) -> None:
    """Report job result back to API."""
    try:
        requests.post(
            f"{API_BASE}/v1/runner/result",
            headers={"X-M87-Key": API_KEY},
            json={
                "job_id": job_id,
                "proposal_id": proposal_id,
                "tool": tool,
                "status": status,
                "output": output,
            },
            timeout=10,
        )
    except Exception as e:
        print(f"[WARN] Failed to report result: {e}", flush=True)


def main():
    print("🏃 M87 Runner V1.2 starting...", flush=True)
    print(f"   Consuming from: {JOB_STREAM}", flush=True)
    print(f"   Allowed tools: {ALLOWED_TOOLS}", flush=True)

    rdb = Redis.from_url(REDIS_URL, decode_responses=True)

    # Wait for Redis
    while True:
        try:
            rdb.ping()
            break
        except Exception:
            print("Waiting for Redis...", flush=True)
            time.sleep(2)

    setup_consumer_group(rdb)

    # Wait for API
    while True:
        try:
            r = requests.get(f"{API_BASE}/health", timeout=5)
            if r.status_code == 200:
                break
        except Exception:
            pass
        print("Waiting for API...", flush=True)
        time.sleep(2)

    print(f"✓ Connected to {API_BASE}", flush=True)
    print("📡 Listening for jobs...", flush=True)

    while True:
        try:
            # Read jobs from stream using consumer group
            messages = rdb.xreadgroup(
                CONSUMER_GROUP,
                CONSUMER_NAME,
                {JOB_STREAM: ">"},
                count=1,
                block=5000,  # 5 second timeout
            )

            if not messages:
                continue

            for stream_name, stream_messages in messages:
                for msg_id, fields in stream_messages:
                    job_data = json.loads(fields.get("job", "{}"))

                    job_id = job_data.get("job_id")
                    proposal_id = job_data.get("proposal_id")
                    tool = job_data.get("tool")
                    inputs = job_data.get("inputs", {})
                    timeout = job_data.get("timeout_seconds", 60)

                    if not job_id or not tool:
                        print(f"[WARN] Invalid job: {job_data}", flush=True)
                        rdb.xack(JOB_STREAM, CONSUMER_GROUP, msg_id)
                        continue

                    print(f"▶ Job {job_id[:8]}... tool={tool}", flush=True)

                    # Execute the job
                    status, output = execute_tool(tool, inputs, timeout)

                    print(f"  → {status}: {output[:50]}...", flush=True)

                    # Report result
                    report_result(job_id, proposal_id, tool, status, output)

                    # Acknowledge message
                    rdb.xack(JOB_STREAM, CONSUMER_GROUP, msg_id)

                    # Store cursor for restart recovery
                    rdb.set(CURSOR_KEY, msg_id)

        except Exception as e:
            print(f"[ERROR] {e}", flush=True)
            time.sleep(2)


if __name__ == "__main__":
    main()
