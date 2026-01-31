"""
M87 Adapter SDK - API client for submitting proposals and polling events.
"""

import httpx
from typing import List, Optional, Dict, Any
from .models import Proposal, GovernanceDecision, AgentProfile, Event, TruthAccount


class M87Client:
    """
    Client for interacting with the M87 Governance API.

    Adapters use this to:
    - Submit proposals for governance review
    - Poll events to react to system state
    - Get agent profiles and effect scopes

    Example:
        client = M87Client("http://localhost:8000")
        decision = client.submit_proposal(proposal)
        if decision.decision == "ALLOW":
            print("Proposal approved!")
    """

    def __init__(
        self,
        api_base: str = "http://localhost:8000",
        api_key: Optional[str] = None,
        timeout: float = 30.0,
    ):
        """
        Initialize the M87 client.

        Args:
            api_base: Base URL of the M87 API (default: http://localhost:8000)
            api_key: Optional API key for authenticated endpoints
            timeout: Request timeout in seconds
        """
        self.api_base = api_base.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self._client = httpx.Client(timeout=timeout)

    def _headers(self, authenticated: bool = True) -> Dict[str, str]:
        """Get headers for requests. Includes API key by default if available."""
        headers = {"Content-Type": "application/json"}
        if authenticated and self.api_key:
            headers["X-M87-Key"] = self.api_key
        return headers

    def health(self) -> Dict[str, Any]:
        """Check API health status."""
        response = self._client.get(f"{self.api_base}/health")
        response.raise_for_status()
        return response.json()

    def get_agents(self) -> List[AgentProfile]:
        """
        Get list of registered agent profiles and their effect scopes.

        Returns:
            List of AgentProfile objects
        """
        response = self._client.get(f"{self.api_base}/v1/agents")
        response.raise_for_status()
        data = response.json()
        return [AgentProfile(**agent) for agent in data.get("agents", [])]

    def submit_proposal(self, proposal: Proposal) -> GovernanceDecision:
        """
        Submit a proposal for governance review.

        Args:
            proposal: The Proposal to submit

        Returns:
            GovernanceDecision from the governance engine

        Raises:
            httpx.HTTPStatusError: If the request fails
        """
        response = self._client.post(
            f"{self.api_base}/v1/govern/proposal",
            headers=self._headers(),
            json=proposal.model_dump(),
        )
        response.raise_for_status()
        return GovernanceDecision(**response.json())

    def get_events(
        self,
        limit: int = 200,
        after: Optional[str] = None,
    ) -> List[Event]:
        """
        Get events from the event stream.

        Args:
            limit: Maximum number of events to return
            after: Only return events after this event ID

        Returns:
            List of Event objects
        """
        params = {"limit": limit}
        if after:
            params["after"] = after

        response = self._client.get(
            f"{self.api_base}/v1/events",
            params=params,
        )
        response.raise_for_status()
        data = response.json()
        return [Event(**evt) for evt in data.get("events", [])]

    def get_pending_approvals(self) -> List[Dict[str, Any]]:
        """
        Get proposals awaiting human approval.

        Returns:
            List of pending approval records
        """
        response = self._client.get(f"{self.api_base}/v1/pending-approvals")
        response.raise_for_status()
        return response.json().get("pending", [])

    def close(self):
        """Close the HTTP client."""
        self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


def submit_proposal(
    api_base: str,
    proposal: Proposal,
    api_key: Optional[str] = None,
) -> GovernanceDecision:
    """
    Convenience function to submit a proposal.

    Args:
        api_base: Base URL of the M87 API
        proposal: The Proposal to submit
        api_key: Optional API key

    Returns:
        GovernanceDecision from the governance engine
    """
    with M87Client(api_base, api_key) as client:
        return client.submit_proposal(proposal)


def poll_events(
    api_base: str,
    after_id: Optional[str] = None,
    limit: int = 200,
) -> List[Event]:
    """
    Convenience function to poll events.

    Args:
        api_base: Base URL of the M87 API
        after_id: Only return events after this event ID
        limit: Maximum number of events to return

    Returns:
        List of Event objects
    """
    with M87Client(api_base) as client:
        return client.get_events(limit=limit, after=after_id)
