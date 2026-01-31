"""
M87 Notifier Service - V1.2

Watches the event stream and sends notifications for:
- proposal.needs_approval  → "You're needed"
- job.completed            → "Job done"
- job.failed               → "Job failed"

V1.2: Console output + webhook placeholder.
Swap transport later (push/SMS/Telegram) without changing system.
"""

import os
import json
import time
import requests
from datetime import datetime
from redis import Redis

REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")
API_BASE = os.getenv("API_BASE", "http://api:8000")
WEBHOOK_URL = os.getenv("WEBHOOK_URL", "")  # Optional: external webhook

EVENT_STREAM = "m87:events"
CONSUMER_GROUP = "notifier"
CONSUMER_NAME = "notifier-1"

# Events that trigger notifications - V1.2: cleaner signals
NOTIFY_EVENTS = {
    "proposal.needs_approval": ("🔔", "APPROVAL NEEDED", "high"),
    "job.completed": ("✅", "JOB COMPLETE", "normal"),
    "job.failed": ("❌", "JOB FAILED", "high"),
    "proposal.denied": ("🚫", "PROPOSAL DENIED", "normal"),
}


def setup_consumer_group(rdb: Redis) -> None:
    """Create consumer group if it doesn't exist."""
    try:
        rdb.xgroup_create(EVENT_STREAM, CONSUMER_GROUP, id="0", mkstream=True)
        print(f"✓ Created consumer group: {CONSUMER_GROUP}", flush=True)
    except Exception as e:
        if "BUSYGROUP" not in str(e):
            raise
        print(f"✓ Consumer group exists: {CONSUMER_GROUP}", flush=True)


def send_notification(event_type: str, payload: dict) -> None:
    """Send notification via configured transport."""
    if event_type not in NOTIFY_EVENTS:
        return

    emoji, title, priority = NOTIFY_EVENTS[event_type]
    timestamp = datetime.now().strftime("%H:%M:%S")

    # Extract relevant IDs
    proposal_id = payload.get("proposal_id", "")
    job_id = payload.get("job_id", "")
    short_id = (job_id or proposal_id)[:8] if (job_id or proposal_id) else "unknown"

    # Build message based on event type
    if event_type == "proposal.needs_approval":
        reasons = payload.get("reasons", [])
        summary = payload.get("summary", "")
        agent = payload.get("agent", "unknown")
        message = f"Proposal {short_id}... from {agent} needs your approval."
        if summary:
            message += f"\n→ {summary}"
        if reasons:
            message += f"\nReasons: {', '.join(reasons)}"

    elif event_type == "job.completed":
        tool = payload.get("tool", "unknown")
        output = (payload.get("output") or "")[:80]
        message = f"Job {short_id}... completed."
        message += f"\nTool: {tool}"
        if output:
            message += f"\nOutput: {output}"

    elif event_type == "job.failed":
        tool = payload.get("tool", "unknown")
        error = (payload.get("output") or payload.get("error") or "")[:80]
        message = f"Job {short_id}... FAILED."
        message += f"\nTool: {tool}"
        if error:
            message += f"\nError: {error}"

    elif event_type == "proposal.denied":
        reasons = payload.get("reasons", [])
        message = f"Proposal {short_id}... was denied."
        if reasons:
            message += f"\nReasons: {', '.join(reasons)}"

    else:
        message = json.dumps(payload, indent=2)[:200]

    # Console notification (always)
    border = "=" * 50
    print(f"\n{border}", flush=True)
    print(f"[{timestamp}] {emoji} {title}" + (" ⚠️" if priority == "high" else ""), flush=True)
    print(f"{message}", flush=True)
    print(f"{border}\n", flush=True)

    # Webhook notification (if configured)
    if WEBHOOK_URL:
        try:
            requests.post(
                WEBHOOK_URL,
                json={
                    "event": event_type,
                    "emoji": emoji,
                    "title": title,
                    "priority": priority,
                    "message": message,
                    "proposal_id": proposal_id,
                    "job_id": job_id,
                    "timestamp": timestamp,
                },
                timeout=5,
            )
        except Exception as e:
            print(f"[WARN] Webhook failed: {e}", flush=True)


def main():
    print("🔔 M87 Notifier V1.2 starting...", flush=True)
    print(f"   Watching: {list(NOTIFY_EVENTS.keys())}", flush=True)

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
    print(f"📡 Listening on stream: {EVENT_STREAM}", flush=True)

    while True:
        try:
            # Read new messages from stream using consumer group
            messages = rdb.xreadgroup(
                CONSUMER_GROUP,
                CONSUMER_NAME,
                {EVENT_STREAM: ">"},
                count=10,
                block=5000,  # 5 second timeout
            )

            if not messages:
                continue

            for stream_name, stream_messages in messages:
                for msg_id, fields in stream_messages:
                    event_type = fields.get("type", "")

                    if event_type in NOTIFY_EVENTS:
                        payload = json.loads(fields.get("payload", "{}"))
                        send_notification(event_type, payload)

                    # Acknowledge message
                    rdb.xack(EVENT_STREAM, CONSUMER_GROUP, msg_id)

        except Exception as e:
            print(f"[ERROR] {e}", flush=True)
            time.sleep(2)


if __name__ == "__main__":
    main()
