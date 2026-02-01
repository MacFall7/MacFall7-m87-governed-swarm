"""
M87 Database Module (Phase 2)

Postgres persistence layer with:
- SQLAlchemy models for api_keys, proposals, decisions, jobs, executions
- Write-through on all state transitions
- Hard fail-safe: deny mutations if Postgres unavailable
"""

from .models import (
    Base,
    ApiKey,
    Proposal,
    Decision,
    Job,
    Execution,
)

from .session import (
    DatabaseSession,
    get_db,
    check_db_health,
    init_db,
    PersistenceUnavailable,
)

from .persist import (
    persist_api_key,
    persist_proposal,
    persist_decision,
    persist_job,
    persist_job_status,
    persist_execution,
    update_api_key_enabled,
    delete_api_key,
)

__all__ = [
    # Models
    "Base",
    "ApiKey",
    "Proposal",
    "Decision",
    "Job",
    "Execution",
    # Session
    "DatabaseSession",
    "get_db",
    "check_db_health",
    "init_db",
    "PersistenceUnavailable",
    # Persistence
    "persist_api_key",
    "persist_proposal",
    "persist_decision",
    "persist_job",
    "persist_job_status",
    "persist_execution",
    "update_api_key_enabled",
    "delete_api_key",
]
