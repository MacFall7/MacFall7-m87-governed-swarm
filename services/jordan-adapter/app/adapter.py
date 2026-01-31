"""
Jordan Adapter - Artifacts, notifications, and PRs agent.

Jordan proposes:
- READ_REPO: Analyze code for PR readiness
- BUILD_ARTIFACT: Build and package code
- SEND_NOTIFICATION: Notify team of events
- CREATE_PR: Create pull requests

Jordan CANNOT:
- Write patches (Casey does that)
- Run tests directly (Casey does that)
- Execute proposals (governance + runner do that)
- Approve proposals (humans do that)
"""

import os
import sys
import time
import logging
from typing import Optional
from redis import Redis

# Add adapter-sdk to path for local development
sys.path.insert(0, "/app/packages/adapter-sdk")

from adapter_sdk import (
    M87Client,
    build_proposal,
    should_submit,
    Event,
    AGENT_EFFECT_SCOPES,
)

# ---- Config
AGENT_NAME = "Jordan"
API_BASE = os.getenv("M87_API_BASE", "http://api:8000")
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", "5"))
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

ALLOWED_EFFECTS = AGENT_EFFECT_SCOPES.get(AGENT_NAME, set())

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL),
    format=f"%(asctime)s [{AGENT_NAME}] %(levelname)s: %(message)s",
)
logger = logging.getLogger(__name__)


class JordanAdapter:
    """
    Jordan is an artifacts/delivery agent that:
    1. Watches for completed jobs that need follow-up
    2. Proposes builds, PRs, and notifications
    3. Coordinates delivery workflows
    """

    def __init__(self):
        self.client = M87Client(api_base=API_BASE)
        self.redis = Redis.from_url(REDIS_URL, decode_responses=True)
        self.last_event_id: Optional[str] = None
        self.proposals_submitted = 0

    def health_check(self) -> bool:
        """Check if API is healthy."""
        try:
            health = self.client.health()
            return health.get("ok", False)
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            return False

    def wait_for_api(self, max_attempts: int = 30):
        """Wait for API to become available."""
        for i in range(max_attempts):
            if self.health_check():
                logger.info("API is healthy")
                return True
            logger.info(f"Waiting for API... ({i + 1}/{max_attempts})")
            time.sleep(2)
        raise RuntimeError("API not available after max attempts")

    def poll_events(self) -> list[Event]:
        """Poll for new events since last check."""
        try:
            events = self.client.get_events(limit=50, after=self.last_event_id)
            if events:
                self.last_event_id = events[-1].id
            return events
        except Exception as e:
            logger.error(f"Failed to poll events: {e}")
            return []

    def should_react_to(self, event: Event) -> bool:
        """
        Jordan reacts to:
        - job.completed: Opportunity to build/notify/create PR
        - proposal.approved: Notify team of approvals
        - intent.created: Delivery/build requests
        """
        return event.type in ("job.completed", "proposal.approved", "intent.created")

    def analyze_completed_job(self, job_data: dict) -> Optional[dict]:
        """
        Analyze a completed job and determine follow-up actions.
        """
        job_id = job_data.get("job_id", "unknown")
        output = job_data.get("output", "")

        # If tests passed, propose building artifact
        if "tests passed" in output.lower() or "success" in output.lower():
            return {
                "summary": f"Build artifact after successful job {job_id[:8]}",
                "effects": ["READ_REPO", "BUILD_ARTIFACT"],
                "observations": [f"Job {job_id} completed successfully", f"Output: {output[:200]}"],
                "risk_score": 0.3,
            }

        # Notify about completion
        return {
            "summary": f"Notify team about job {job_id[:8]} completion",
            "effects": ["SEND_NOTIFICATION"],
            "observations": [f"Job {job_id} completed", f"Output: {output[:200]}"],
            "risk_score": 0.1,
        }

    def analyze_approval(self, approval_data: dict) -> Optional[dict]:
        """
        Notify team about proposal approvals.
        """
        proposal_id = approval_data.get("proposal_id", "unknown")

        return {
            "summary": f"Notify team: proposal {proposal_id[:8]} approved",
            "effects": ["SEND_NOTIFICATION"],
            "observations": [f"Proposal {proposal_id} was approved"],
            "risk_score": 0.1,
        }

    def analyze_intent(self, intent_data: dict) -> Optional[dict]:
        """
        Analyze delivery/build intents.
        """
        goal = intent_data.get("goal", "")
        mode = intent_data.get("mode", "")

        if mode == "build":
            return {
                "summary": f"Build artifact for: {goal[:100]}",
                "effects": ["READ_REPO", "BUILD_ARTIFACT"],
                "observations": [f"Intent requests build: {goal}"],
                "risk_score": 0.3,
            }
        elif mode == "pr":
            return {
                "summary": f"Create PR for: {goal[:100]}",
                "effects": ["READ_REPO", "CREATE_PR"],
                "observations": [f"Intent requests PR: {goal}"],
                "risk_score": 0.4,
            }
        elif mode == "notify":
            return {
                "summary": f"Send notification: {goal[:100]}",
                "effects": ["SEND_NOTIFICATION"],
                "observations": [f"Intent requests notification: {goal}"],
                "risk_score": 0.1,
            }

        return None

    def submit_proposal(self, intent_id: str, params: dict) -> bool:
        """Build and submit a proposal for governance review."""
        ok, warnings = should_submit(
            AGENT_NAME,
            params["effects"],
            params.get("risk_score"),
        )

        if not ok:
            logger.warning(f"Pre-flight check failed: {warnings}")

        proposal = build_proposal(
            agent=AGENT_NAME,
            summary=params["summary"],
            effects=params["effects"],
            observations=params["observations"],
            intent_id=intent_id,
            risk_score=params.get("risk_score"),
        )

        logger.info(f"Submitting proposal: {proposal.proposal_id}")
        logger.debug(f"  Summary: {proposal.summary}")
        logger.debug(f"  Effects: {proposal.effects}")

        try:
            decision = self.client.submit_proposal(proposal)
            self.proposals_submitted += 1

            logger.info(f"Decision: {decision.decision}")
            for reason in decision.reasons:
                logger.info(f"  - {reason}")

            return True
        except Exception as e:
            logger.error(f"Failed to submit proposal: {e}")
            return False

    def process_event(self, event: Event):
        """Process a single event."""
        logger.debug(f"Processing event: {event.type} ({event.id})")

        if event.type == "job.completed":
            params = self.analyze_completed_job(event.payload)
            if params:
                self.submit_proposal(f"job-{event.id[:8]}", params)

        elif event.type == "proposal.approved":
            params = self.analyze_approval(event.payload)
            if params:
                self.submit_proposal(f"approval-{event.id[:8]}", params)

        elif event.type == "intent.created":
            intent_data = event.payload
            intent_id = intent_data.get("intent_id", "unknown")

            params = self.analyze_intent(intent_data)
            if params:
                self.submit_proposal(intent_id, params)

    def run(self):
        """Main adapter loop."""
        logger.info(f"Starting {AGENT_NAME} adapter")
        logger.info(f"API: {API_BASE}")
        logger.info(f"Allowed effects: {sorted(ALLOWED_EFFECTS)}")

        self.wait_for_api()

        logger.info("Entering main loop...")

        while True:
            try:
                events = self.poll_events()

                for event in events:
                    if self.should_react_to(event):
                        self.process_event(event)

                time.sleep(POLL_INTERVAL)

            except KeyboardInterrupt:
                logger.info("Shutting down...")
                break
            except Exception as e:
                logger.error(f"Error in main loop: {e}")
                time.sleep(POLL_INTERVAL)

        logger.info(f"Shutdown complete. Proposals submitted: {self.proposals_submitted}")


def main():
    adapter = JordanAdapter()
    adapter.run()


if __name__ == "__main__":
    main()
