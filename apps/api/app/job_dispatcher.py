"""
P0.B — File-based job dispatcher for airgapped runner.

Bridges the API (Redis) to a network_mode: none runner via shared volumes:
  - Reads approved jobs from Redis stream
  - Writes job envelopes to /dispatch/incoming/<job_id>.json
  - Watches /dispatch/outgoing/<job_id>.result.json
  - Posts results back to the API

The runner polls incoming/ and writes to outgoing/ — no network needed.
"""
from __future__ import annotations

import json
import os
import time
import hashlib
import logging
from pathlib import Path
from typing import Any, Dict, Optional

from redis import Redis

logger = logging.getLogger(__name__)

# Config
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")
JOB_QUEUE_PATH = Path(os.getenv("JOB_QUEUE_PATH", "/dispatch/incoming"))
RESULT_QUEUE_PATH = Path(os.getenv("RESULT_QUEUE_PATH", "/dispatch/outgoing"))
API_BASE = os.getenv("API_BASE", "http://api:8000")
API_KEY = os.getenv("M87_API_KEY", "")

JOBS_STREAM = "m87:jobs"
CONSUMER_GROUP = "dispatcher"
CONSUMER_NAME = os.getenv("DISPATCHER_NAME", "dispatcher-1")

# Poll interval for result files
RESULT_POLL_SECONDS = float(os.getenv("RESULT_POLL_SECONDS", "1.0"))
# Maximum time to wait for a result before marking job as timed out
RESULT_TIMEOUT_SECONDS = int(os.getenv("RESULT_TIMEOUT_SECONDS", "600"))


def ensure_dirs() -> None:
    """Create dispatch directories if they don't exist."""
    JOB_QUEUE_PATH.mkdir(parents=True, exist_ok=True)
    RESULT_QUEUE_PATH.mkdir(parents=True, exist_ok=True)


def ensure_group(r: Redis) -> None:
    """Create consumer group if it doesn't exist."""
    try:
        r.xgroup_create(JOBS_STREAM, CONSUMER_GROUP, id="0-0", mkstream=True)
    except Exception:
        pass  # Group already exists


def write_job_envelope(job: Dict[str, Any]) -> Path:
    """
    Write a job envelope to the incoming directory.

    File format: <job_id>.json
    Includes all fields runner needs for verification:
    - deployment_envelope + envelope_hash (DEH)
    - manifest_hash (drift check)
    - tool, inputs, timeout
    - reversibility_class, execution_mode
    - autonomy_budget
    """
    job_id = job.get("job_id", "unknown")
    envelope_path = JOB_QUEUE_PATH / f"{job_id}.json"

    # Write atomically: write to temp file then rename
    tmp_path = JOB_QUEUE_PATH / f".{job_id}.json.tmp"
    tmp_path.write_text(json.dumps(job, sort_keys=True, indent=2))
    tmp_path.rename(envelope_path)

    logger.info(f"Dispatched job {job_id[:8]}... to {envelope_path}")
    return envelope_path


def read_result(job_id: str) -> Optional[Dict[str, Any]]:
    """
    Read a result file from the outgoing directory.

    Returns None if not yet available.
    """
    result_path = RESULT_QUEUE_PATH / f"{job_id}.result.json"
    if not result_path.exists():
        return None

    try:
        data = json.loads(result_path.read_text())
        # Remove result file after reading (cleanup)
        result_path.unlink(missing_ok=True)
        return data
    except (json.JSONDecodeError, OSError) as e:
        logger.error(f"Failed to read result for {job_id}: {e}")
        return None


def post_result_to_api(result: Dict[str, Any]) -> bool:
    """Post a result back to the API."""
    import requests

    try:
        resp = requests.post(
            f"{API_BASE}/v1/runner/result",
            headers={"X-M87-Key": API_KEY, "Content-Type": "application/json"},
            json=result,
            timeout=20,
        )
        resp.raise_for_status()
        return True
    except Exception as e:
        logger.error(f"Failed to post result: {e}")
        return False


def dispatch_loop() -> None:
    """
    Main dispatch loop:
    1. Read jobs from Redis stream
    2. Write to incoming/ directory
    3. Poll outgoing/ for results
    4. Post results back to API
    """
    r = Redis.from_url(REDIS_URL, decode_responses=True)
    ensure_group(r)
    ensure_dirs()

    # Track pending jobs: job_id → dispatched_at timestamp
    pending: Dict[str, float] = {}

    logger.info(f"Job dispatcher starting (incoming={JOB_QUEUE_PATH}, outgoing={RESULT_QUEUE_PATH})")

    while True:
        try:
            # Step 1: Read new jobs from Redis
            resp = r.xreadgroup(
                groupname=CONSUMER_GROUP,
                consumername=CONSUMER_NAME,
                streams={JOBS_STREAM: ">"},
                count=10,
                block=1000,  # 1s block
            )

            if resp:
                for stream_name, messages in resp:
                    for msg_id, fields in messages:
                        raw = fields.get("job")
                        if not raw:
                            r.xack(JOBS_STREAM, CONSUMER_GROUP, msg_id)
                            continue

                        job = json.loads(raw)
                        job_id = job.get("job_id", "unknown")

                        # Write job to filesystem for airgapped runner
                        write_job_envelope(job)
                        pending[job_id] = time.time()

                        r.xack(JOBS_STREAM, CONSUMER_GROUP, msg_id)

            # Step 2: Check for results from runner
            completed_jobs = []
            for job_id, dispatched_at in list(pending.items()):
                result = read_result(job_id)
                if result:
                    # Post result back to API
                    if post_result_to_api(result):
                        completed_jobs.append(job_id)
                        logger.info(f"Result for {job_id[:8]}... posted to API")
                    else:
                        logger.warning(f"Failed to post result for {job_id[:8]}... — will retry")
                elif time.time() - dispatched_at > RESULT_TIMEOUT_SECONDS:
                    # Timeout — post failure
                    timeout_result = {
                        "job_id": job_id,
                        "proposal_id": "unknown",
                        "status": "failed",
                        "output": {"error": "dispatch_timeout", "detail": f"No result after {RESULT_TIMEOUT_SECONDS}s"},
                    }
                    post_result_to_api(timeout_result)
                    completed_jobs.append(job_id)
                    logger.warning(f"Job {job_id[:8]}... timed out")

            for job_id in completed_jobs:
                pending.pop(job_id, None)

            # Brief sleep if no work
            if not resp and not completed_jobs:
                time.sleep(RESULT_POLL_SECONDS)

        except KeyboardInterrupt:
            logger.info("Dispatcher shutting down")
            break
        except Exception as e:
            logger.error(f"Dispatch loop error: {e}")
            time.sleep(2)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    dispatch_loop()


if __name__ == "__main__":
    main()
