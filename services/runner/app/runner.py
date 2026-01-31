"""
M87 Runner Service

Polls the event stream and executes jobs when proposals are allowed/approved.
V1: Safe echo execution only.
"""

import os
import time
import requests
import subprocess
import uuid

API_BASE = os.getenv("API_BASE", "http://api:8000")

# Track last processed event ID (Redis stream format: "timestamp-sequence")
last_event_id = "0-0"


def run_echo(message: str) -> str:
    """Execute safe echo command."""
    completed = subprocess.run(["echo", message], capture_output=True, text=True, check=True)
    return completed.stdout.strip()


def main():
    global last_event_id

    print("🏃 M87 Runner starting...", flush=True)

    # Wait for API to be ready
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

    # Track which proposals we've already executed jobs for
    executed_proposals = set()

    while True:
        try:
            # Fetch events after our last seen ID
            r = requests.get(f"{API_BASE}/v1/events?limit=100&after={last_event_id}", timeout=10)
            r.raise_for_status()
            events = r.json().get("events", [])

            for event in events:
                event_id = event.get("id", "")
                event_type = event.get("type", "")
                payload = event.get("payload", {})

                # Update cursor
                if event_id:
                    last_event_id = event_id

                # Only process allowed/approved proposals
                if event_type not in ("proposal.allowed", "proposal.approved"):
                    continue

                proposal_id = payload.get("proposal_id")
                if not proposal_id:
                    continue

                # Don't execute twice for the same proposal
                if proposal_id in executed_proposals:
                    continue

                executed_proposals.add(proposal_id)

                # Execute the job
                job_id = str(uuid.uuid4())
                print(f"▶ Executing job {job_id[:8]} for proposal {proposal_id[:8]}...", flush=True)

                try:
                    output = run_echo(f"m87 runner executed for proposal {proposal_id}")
                    status = "completed"
                except subprocess.CalledProcessError as e:
                    output = e.stderr or str(e)
                    status = "failed"

                # Report result back to API
                requests.post(
                    f"{API_BASE}/v1/runner/result",
                    json={
                        "job_id": job_id,
                        "proposal_id": proposal_id,
                        "status": status,
                        "tool": "echo",
                        "output": output,
                    },
                    timeout=10,
                )
                print(f"✓ Job {job_id[:8]} {status}", flush=True)

        except requests.exceptions.RequestException as e:
            print(f"[WARN] API request failed: {e}", flush=True)
        except Exception as e:
            print(f"[ERROR] {e}", flush=True)

        time.sleep(2)


if __name__ == "__main__":
    main()
