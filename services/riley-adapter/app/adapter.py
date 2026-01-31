"""
Riley Adapter - Analysis and reporting agent.

Riley proposes:
- READ_REPO: Deep code analysis and metrics
- BUILD_ARTIFACT: Generate reports and documentation
- SEND_NOTIFICATION: Alert on findings

Riley CANNOT:
- Write patches (Casey does that)
- Create PRs (Jordan does that)
- Execute proposals (governance + runner do that)
- Approve proposals (humans do that)

Riley has the lowest risk threshold (0.4) and focuses on
read-only analysis and reporting workflows.
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
AGENT_NAME = "Riley"
API_BASE = os.getenv("M87_API_BASE", "http://api:8000")
API_KEY = os.getenv("M87_API_KEY")
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", "5"))
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

ALLOWED_EFFECTS = AGENT_EFFECT_SCOPES.get(AGENT_NAME, set())

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL),
    format=f"%(asctime)s [{AGENT_NAME}] %(levelname)s: %(message)s",
)
logger = logging.getLogger(__name__)


class RileyAdapter:
    """
    Riley is an analysis/reporting agent that:
    1. Watches for events needing analysis
    2. Proposes code analysis and report generation
    3. Alerts on findings and metrics
    """

    def __init__(self):
        self.client = M87Client(api_base=API_BASE, api_key=API_KEY)
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
        Riley reacts to:
        - intent.created: Analysis/report requests
        - job.failed: Analyze failures
        - proposal.denied: Report on denied proposals
        """
        return event.type in ("intent.created", "job.failed", "proposal.denied")

    def analyze_intent(self, intent_data: dict) -> Optional[dict]:
        """
        Analyze intents for analysis/reporting work.
        """
        goal = intent_data.get("goal", "")
        mode = intent_data.get("mode", "")

        if mode == "analyze":
            return {
                "summary": f"Deep analysis: {goal[:100]}",
                "effects": ["READ_REPO"],
                "observations": [f"Intent requests analysis: {goal}"],
                "risk_score": 0.1,
            }
        elif mode == "report":
            return {
                "summary": f"Generate report: {goal[:100]}",
                "effects": ["READ_REPO", "BUILD_ARTIFACT"],
                "observations": [f"Intent requests report: {goal}"],
                "risk_score": 0.2,
            }
        elif mode == "audit":
            return {
                "summary": f"Security audit: {goal[:100]}",
                "effects": ["READ_REPO", "BUILD_ARTIFACT", "SEND_NOTIFICATION"],
                "observations": [f"Intent requests audit: {goal}"],
                "risk_score": 0.3,
            }
        elif mode == "metrics":
            return {
                "summary": f"Collect metrics: {goal[:100]}",
                "effects": ["READ_REPO", "BUILD_ARTIFACT"],
                "observations": [f"Intent requests metrics: {goal}"],
                "risk_score": 0.15,
            }

        return None

    def analyze_failure(self, failure_data: dict) -> Optional[dict]:
        """
        Analyze job failures for patterns and root causes.
        """
        job_id = failure_data.get("job_id", "unknown")
        error = failure_data.get("error", "unknown error")

        return {
            "summary": f"Failure analysis: job {job_id[:8]}",
            "effects": ["READ_REPO", "SEND_NOTIFICATION"],
            "observations": [
                f"Job {job_id} failed",
                f"Error: {error[:200]}",
                "Analyzing for patterns and root cause",
            ],
            "risk_score": 0.2,
        }

    def analyze_denial(self, denial_data: dict) -> Optional[dict]:
        """
        Report on denied proposals for visibility.
        """
        proposal_id = denial_data.get("proposal_id", "unknown")
        reasons = denial_data.get("reasons", [])
        agent = denial_data.get("agent", "unknown")

        return {
            "summary": f"Denial report: proposal {proposal_id[:8]} from {agent}",
            "effects": ["SEND_NOTIFICATION"],
            "observations": [
                f"Proposal {proposal_id} was denied",
                f"Agent: {agent}",
                f"Reasons: {', '.join(reasons)}",
            ],
            "risk_score": 0.1,
        }

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

        if event.type == "intent.created":
            intent_data = event.payload
            intent_id = intent_data.get("intent_id", "unknown")

            params = self.analyze_intent(intent_data)
            if params:
                self.submit_proposal(intent_id, params)

        elif event.type == "job.failed":
            params = self.analyze_failure(event.payload)
            if params:
                self.submit_proposal(f"failure-{event.id[:8]}", params)

        elif event.type == "proposal.denied":
            params = self.analyze_denial(event.payload)
            if params:
                self.submit_proposal(f"denial-{event.id[:8]}", params)

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
    adapter = RileyAdapter()
    adapter.run()


if __name__ == "__main__":
    main()
