"""
M87 Database Models (Phase 2)

SQLAlchemy table definitions for persistent audit trail.
All state transitions are write-through to Postgres.
"""

from datetime import datetime
from typing import Optional, List
from sqlalchemy import (
    Column,
    String,
    Float,
    Boolean,
    DateTime,
    Text,
    JSON,
    ForeignKey,
    Index,
    Enum as SQLEnum,
)
from sqlalchemy.orm import DeclarativeBase, relationship
import enum


class Base(DeclarativeBase):
    """Base class for all models."""
    pass


class PrincipalType(enum.Enum):
    """Principal types for API keys."""
    ADAPTER = "adapter"
    RUNNER = "runner"
    HUMAN = "human"
    ADMIN = "admin"


class DecisionOutcome(enum.Enum):
    """Possible governance decisions."""
    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_HUMAN = "REQUIRE_HUMAN"
    NEED_MORE_EVIDENCE = "NEED_MORE_EVIDENCE"


class JobStatus(enum.Enum):
    """Job execution status."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class ApiKey(Base):
    """
    Persistent API key records.

    Write-through: Created keys are persisted here.
    Redis remains source of truth for runtime auth.
    Postgres provides audit trail and recovery.
    """
    __tablename__ = "api_keys"

    key_id = Column(String(64), primary_key=True)
    key_hash = Column(String(128), nullable=False, unique=True, index=True)
    principal_type = Column(String(32), nullable=False)
    principal_id = Column(String(128), nullable=False)
    endpoint_scopes = Column(JSON, nullable=False, default=list)
    effect_scopes = Column(JSON, nullable=False, default=list)
    max_risk = Column(Float, nullable=False, default=1.0)
    enabled = Column(Boolean, nullable=False, default=True)
    expires_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    description = Column(Text, nullable=True)

    __table_args__ = (
        Index("ix_api_keys_principal", "principal_type", "principal_id"),
    )


class Proposal(Base):
    """
    Persistent proposal records.

    Write-through: Every proposal submitted is persisted.
    """
    __tablename__ = "proposals"

    proposal_id = Column(String(64), primary_key=True)
    intent_id = Column(String(64), nullable=True)
    agent = Column(String(64), nullable=False)
    summary = Column(Text, nullable=False)
    effects = Column(JSON, nullable=False)  # List[str]
    artifacts = Column(JSON, nullable=True)  # List[Dict]
    truth_account = Column(JSON, nullable=True)  # Dict
    risk_score = Column(Float, nullable=True)

    # Auth context
    principal_type = Column(String(32), nullable=True)
    principal_id = Column(String(128), nullable=True)

    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    # Relationships
    decisions = relationship("Decision", back_populates="proposal")
    jobs = relationship("Job", back_populates="proposal")

    __table_args__ = (
        Index("ix_proposals_agent", "agent"),
        Index("ix_proposals_created", "created_at"),
    )


class Decision(Base):
    """
    Persistent governance decision records.

    Write-through: Every decision (ALLOW/DENY/REQUIRE_HUMAN) is persisted.
    """
    __tablename__ = "decisions"

    decision_id = Column(String(64), primary_key=True)
    proposal_id = Column(String(64), ForeignKey("proposals.proposal_id"), nullable=False)
    outcome = Column(String(32), nullable=False)  # ALLOW, DENY, REQUIRE_HUMAN
    reasons = Column(JSON, nullable=False)  # List[str]
    required_approvals = Column(JSON, nullable=True)  # List[str]
    allowed_effects = Column(JSON, nullable=True)  # List[str]

    # Who made the decision
    decided_by = Column(String(32), nullable=False)  # "policy", "human:{id}"

    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    # Relationship
    proposal = relationship("Proposal", back_populates="decisions")

    __table_args__ = (
        Index("ix_decisions_proposal", "proposal_id"),
        Index("ix_decisions_outcome", "outcome"),
    )


class Job(Base):
    """
    Persistent job records.

    Write-through: Every minted job is persisted.
    """
    __tablename__ = "jobs"

    job_id = Column(String(64), primary_key=True)
    proposal_id = Column(String(64), ForeignKey("proposals.proposal_id"), nullable=False)
    tool = Column(String(64), nullable=False)
    inputs = Column(JSON, nullable=False, default=dict)
    sandbox = Column(JSON, nullable=False, default=dict)
    timeout_seconds = Column(Float, nullable=False, default=60)

    status = Column(String(32), nullable=False, default="pending")

    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    # Relationships
    proposal = relationship("Proposal", back_populates="jobs")
    executions = relationship("Execution", back_populates="job")

    __table_args__ = (
        Index("ix_jobs_proposal", "proposal_id"),
        Index("ix_jobs_status", "status"),
        Index("ix_jobs_created", "created_at"),
    )


class Execution(Base):
    """
    Persistent execution receipt records.

    Write-through: Every runner result is persisted.
    """
    __tablename__ = "executions"

    execution_id = Column(String(64), primary_key=True)
    job_id = Column(String(64), ForeignKey("jobs.job_id"), nullable=False)

    status = Column(String(32), nullable=False)  # completed, failed
    output = Column(Text, nullable=True)
    error = Column(Text, nullable=True)

    # Runner context
    runner_id = Column(String(128), nullable=True)

    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    # Relationship
    job = relationship("Job", back_populates="executions")

    __table_args__ = (
        Index("ix_executions_job", "job_id"),
        Index("ix_executions_status", "status"),
    )
