"""
M87 Notifier Service

Watches the event stream and sends notifications for:
- proposal.needs_approval  → "You're needed"
- runner.result            → "Job complete/failed"

V1: Console output + webhook placeholder
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

STREAM_KEY = "m87:events"
CONSUMER_GROUP = "notifier"
CONSUMER_NAME = "notifier-1"

# Events that trigger notifications
NOTIFY_EVENTS = {
    "proposal.needs_approval": "🔔 APPROVAL NEEDED",
    "runner.result": "✅ JOB COMPLETE",
    "proposal.denied": "❌ PROPOSAL DENIED",
}


def setup_consumer_group(rdb: Redis) -> None:
    """Create consumer group if it doesn't exist."""
    try:
        rdb.xgroup_create(STREAM_KEY, CONSUMER_GROUP, id="0", mkstream=True)
    except Exception as e:
        if "BUSYGROUP" not in str(e):
            raise


def send_notification(event_type: str, payload: dict) -> None:
    """Send notification via configured transport."""
    title = NOTIFY_EVENTS.get(event_type, event_type)
    timestamp = datetime.now().strftime("%H:%M:%S")

    proposal_id = payload.get("proposal_id", "unknown")

    # Build message based on event type
    if event_type == "proposal.needs_approval":
        reasons = payload.get("reasons", [])
        message = f"Proposal {proposal_id[:8]}... needs your approval.\nReasons: {', '.join(reasons)}"
    elif event_type == "runner.result":
        status = payload.get("status", "unknown")
        tool = payload.get("tool", "unknown")
        output = payload.get("output", "")[:100]
        message = f"Job for {proposal_id[:8]}... {status}.\nTool: {tool}\nOutput: {output}"
    elif event_type == "proposal.denied":
        reasons = payload.get("reasons", [])
        message = f"Proposal {proposal_id[:8]}... was denied.\nReasons: {', '.join(reasons)}"
    else:
        message = json.dumps(payload, indent=2)[:200]

    # Console notification (always)
    print(f"\n{'='*50}")
    print(f"[{timestamp}] {title}")
    print(f"{message}")
    print(f"{'='*50}\n", flush=True)

    # Webhook notification (if configured)
    if WEBHOOK_URL:
        try:
            requests.post(
                WEBHOOK_URL,
                json={
                    "event": event_type,
                    "title": title,
                    "message": message,
                    "proposal_id": proposal_id,
                    "timestamp": timestamp,
                },
                timeout=5,
            )
        except Exception as e:
            print(f"[WARN] Webhook failed: {e}", flush=True)


def main():
    print("🚀 M87 Notifier starting...", flush=True)

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
    print(f"📡 Listening on stream: {STREAM_KEY}", flush=True)

    while True:
        try:
            # Read new messages from stream using consumer group
            messages = rdb.xreadgroup(
                CONSUMER_GROUP,
                CONSUMER_NAME,
                {STREAM_KEY: ">"},
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
                    rdb.xack(STREAM_KEY, CONSUMER_GROUP, msg_id)

        except Exception as e:
            print(f"[ERROR] {e}", flush=True)
            time.sleep(2)


if __name__ == "__main__":
    main()
