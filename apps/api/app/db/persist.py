"""
M87 Write-Through Persistence (Phase 2)

All state transitions must be persisted to Postgres.
If persistence fails, the mutation is denied (hard fail-safe).
"""

import uuid
import logging
from datetime import datetime
from typing import Optional, Dict, Any, List

from .models import ApiKey, Proposal, Decision, Job, Execution
from .session import get_db, PersistenceUnavailable

logger = logging.getLogger(__name__)


def persist_api_key(
    key_id: str,
    key_hash: str,
    principal_type: str,
    principal_id: str,
    endpoint_scopes: List[str],
    effect_scopes: List[str],
    max_risk: float,
    enabled: bool = True,
    expires_at: datetime = None,
    description: str = None,
) -> bool:
    """
    Persist API key to Postgres (write-through from Redis).

    Raises PersistenceUnavailable if database is down.
    """
    with get_db(required=True) as db:
        record = ApiKey(
            key_id=key_id,
            key_hash=key_hash,
            principal_type=principal_type,
            principal_id=principal_id,
            endpoint_scopes=endpoint_scopes,
            effect_scopes=effect_scopes,
            max_risk=max_risk,
            enabled=enabled,
            expires_at=expires_at,
            description=description,
        )
        db.merge(record)  # Insert or update
        db.commit()
        logger.info(f"Persisted API key: {key_id}")
        return True


def persist_proposal(
    proposal_id: str,
    intent_id: str,
    agent: str,
    summary: str,
    effects: List[str],
    artifacts: Optional[List[Dict]] = None,
    truth_account: Optional[Dict] = None,
    risk_score: Optional[float] = None,
    principal_type: Optional[str] = None,
    principal_id: Optional[str] = None,
) -> bool:
    """
    Persist proposal to Postgres (write-through).

    Raises PersistenceUnavailable if database is down.
    """
    with get_db(required=True) as db:
        record = Proposal(
            proposal_id=proposal_id,
            intent_id=intent_id,
            agent=agent,
            summary=summary,
            effects=effects,
            artifacts=artifacts,
            truth_account=truth_account,
            risk_score=risk_score,
            principal_type=principal_type,
            principal_id=principal_id,
        )
        db.merge(record)
        db.commit()
        logger.info(f"Persisted proposal: {proposal_id}")
        return True


def persist_decision(
    proposal_id: str,
    outcome: str,
    reasons: List[str],
    decided_by: str,
    required_approvals: Optional[List[str]] = None,
    allowed_effects: Optional[List[str]] = None,
) -> str:
    """
    Persist governance decision to Postgres (write-through).

    Returns decision_id.
    Raises PersistenceUnavailable if database is down.
    """
    decision_id = str(uuid.uuid4())

    with get_db(required=True) as db:
        record = Decision(
            decision_id=decision_id,
            proposal_id=proposal_id,
            outcome=outcome,
            reasons=reasons,
            decided_by=decided_by,
            required_approvals=required_approvals,
            allowed_effects=allowed_effects,
        )
        db.add(record)
        db.commit()
        logger.info(f"Persisted decision: {decision_id} for proposal {proposal_id}")
        return decision_id


def persist_job(
    job_id: str,
    proposal_id: str,
    tool: str,
    inputs: Dict[str, Any],
    sandbox: Dict[str, str],
    timeout_seconds: int,
) -> bool:
    """
    Persist job to Postgres (write-through).

    Raises PersistenceUnavailable if database is down.
    """
    with get_db(required=True) as db:
        record = Job(
            job_id=job_id,
            proposal_id=proposal_id,
            tool=tool,
            inputs=inputs,
            sandbox=sandbox,
            timeout_seconds=timeout_seconds,
            status="pending",
        )
        db.merge(record)
        db.commit()
        logger.info(f"Persisted job: {job_id}")
        return True


def persist_job_status(job_id: str, status: str) -> bool:
    """
    Update job status in Postgres.

    Raises PersistenceUnavailable if database is down.
    """
    with get_db(required=True) as db:
        job = db.query(Job).filter(Job.job_id == job_id).first()
        if job:
            job.status = status
            db.commit()
            logger.info(f"Updated job status: {job_id} -> {status}")
            return True
        logger.warning(f"Job not found for status update: {job_id}")
        return False


def persist_execution(
    job_id: str,
    status: str,
    output: Optional[str] = None,
    error: Optional[str] = None,
    runner_id: Optional[str] = None,
    started_at: Optional[datetime] = None,
) -> str:
    """
    Persist execution receipt to Postgres (write-through).

    Returns execution_id.
    Raises PersistenceUnavailable if database is down.
    """
    execution_id = str(uuid.uuid4())

    with get_db(required=True) as db:
        record = Execution(
            execution_id=execution_id,
            job_id=job_id,
            status=status,
            output=output,
            error=error,
            runner_id=runner_id,
            started_at=started_at,
        )
        db.add(record)

        # Also update job status
        job = db.query(Job).filter(Job.job_id == job_id).first()
        if job:
            job.status = status

        db.commit()
        logger.info(f"Persisted execution: {execution_id} for job {job_id}")
        return execution_id


def update_api_key_enabled(key_id: str, enabled: bool) -> bool:
    """
    Update API key enabled status in Postgres.

    Raises PersistenceUnavailable if database is down.
    """
    with get_db(required=True) as db:
        key = db.query(ApiKey).filter(ApiKey.key_id == key_id).first()
        if key:
            key.enabled = enabled
            db.commit()
            logger.info(f"Updated key {key_id} enabled={enabled}")
            return True
        return False


def delete_api_key(key_id: str) -> bool:
    """
    Delete API key from Postgres.

    Raises PersistenceUnavailable if database is down.
    """
    with get_db(required=True) as db:
        key = db.query(ApiKey).filter(ApiKey.key_id == key_id).first()
        if key:
            db.delete(key)
            db.commit()
            logger.info(f"Deleted key from Postgres: {key_id}")
            return True
        return False
