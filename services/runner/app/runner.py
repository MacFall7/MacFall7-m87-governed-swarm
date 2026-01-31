import time
import requests
import subprocess
import uuid

API_BASE = "http://api:8000"  # docker compose service name


def run_echo(message: str) -> str:
    completed = subprocess.run(["echo", message], capture_output=True, text=True, check=True)
    return completed.stdout.strip()


def main():
    seen = set()
    while True:
        try:
            r = requests.get(f"{API_BASE}/v1/events", timeout=10)
            r.raise_for_status()
            events = r.json().get("events", [])
            for e in events:
                key = f"{e.get('ts')}:{e.get('type')}"
                if key in seen:
                    continue
                seen.add(key)

                if e.get("type") in ("proposal.allowed", "proposal.approved"):
                    payload = e.get("payload", {})
                    proposal_id = payload.get("proposal_id")
                    if not proposal_id:
                        continue

                    job_id = str(uuid.uuid4())
                    output = run_echo(f"m87 runner executed for proposal {proposal_id}")

                    requests.post(
                        f"{API_BASE}/v1/runner/result",
                        json={
                            "job_id": job_id,
                            "proposal_id": proposal_id,
                            "status": "completed",
                            "tool": "echo",
                            "output": output,
                        },
                        timeout=10,
                    )
        except Exception as ex:
            # v1: just keep running
            pass

        time.sleep(2)


if __name__ == "__main__":
    main()
