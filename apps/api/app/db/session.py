"""
M87 Database Session Management (Phase 2)

Provides:
- Connection pool management
- Health checking
- Hard fail-safe: PersistenceUnavailable exception
"""

import os
import logging
from typing import Generator
from contextlib import contextmanager

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.exc import OperationalError

logger = logging.getLogger(__name__)


class PersistenceUnavailable(Exception):
    """
    Raised when Postgres is unavailable.

    This is the hard fail-safe: when persistence is unavailable,
    mutations (proposal creation, job minting, etc.) must be denied.
    """
    pass


# Database URL from environment
DATABASE_URL = os.getenv("DATABASE_URL", "")

# Engine and session factory (initialized lazily)
_engine = None
_SessionLocal = None


def get_engine():
    """Get or create the database engine."""
    global _engine
    if _engine is None:
        if not DATABASE_URL:
            raise PersistenceUnavailable("DATABASE_URL not configured")
        _engine = create_engine(
            DATABASE_URL,
            pool_pre_ping=True,  # Verify connections before use
            pool_size=5,
            max_overflow=10,
            pool_recycle=300,  # Recycle connections after 5 minutes
        )
    return _engine


def get_session_factory():
    """Get or create the session factory."""
    global _SessionLocal
    if _SessionLocal is None:
        _SessionLocal = sessionmaker(
            autocommit=False,
            autoflush=False,
            bind=get_engine(),
        )
    return _SessionLocal


class DatabaseSession:
    """
    Database session context manager with hard fail-safe.

    Usage:
        with DatabaseSession() as db:
            db.add(record)
            db.commit()

    If Postgres is unavailable, raises PersistenceUnavailable.
    """

    def __init__(self, required: bool = True):
        """
        Args:
            required: If True (default), raises PersistenceUnavailable on failure.
                      If False, returns None for read-only fallback scenarios.
        """
        self.required = required
        self.session: Session = None

    def __enter__(self) -> Session:
        try:
            SessionLocal = get_session_factory()
            self.session = SessionLocal()
            # Test the connection
            self.session.execute(text("SELECT 1"))
            return self.session
        except Exception as e:
            logger.error(f"Database connection failed: {e}")
            if self.required:
                raise PersistenceUnavailable(f"Database unavailable: {e}")
            return None

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            if exc_type is not None:
                self.session.rollback()
            self.session.close()
        return False  # Don't suppress exceptions


@contextmanager
def get_db(required: bool = True) -> Generator[Session, None, None]:
    """
    Context manager for database sessions.

    Args:
        required: If True, raises PersistenceUnavailable when DB is down.

    Usage:
        with get_db() as db:
            db.query(Proposal).all()

    For mutations, always use required=True (the default).
    """
    with DatabaseSession(required=required) as db:
        yield db


def check_db_health() -> dict:
    """
    Check database health.

    Returns:
        {"connected": True/False, "error": str|None}
    """
    if not DATABASE_URL:
        return {"connected": False, "error": "DATABASE_URL not configured"}

    try:
        with get_db(required=True) as db:
            db.execute(text("SELECT 1"))
            return {"connected": True, "error": None}
    except PersistenceUnavailable as e:
        return {"connected": False, "error": str(e)}
    except Exception as e:
        return {"connected": False, "error": str(e)}


def init_db():
    """
    Initialize database tables.

    Should be called at startup. Creates tables if they don't exist.
    """
    from .models import Base

    try:
        engine = get_engine()
        Base.metadata.create_all(bind=engine)
        logger.info("Database tables initialized")
        return True
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
        return False
