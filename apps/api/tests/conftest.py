"""
M87 API Test Configuration

Pytest fixtures for unit and integration tests.
"""

import os
import pytest
from unittest.mock import MagicMock, patch
from typing import Generator

# Test configuration
TEST_API_KEY = "test-key-for-unit-tests"
TEST_BOOTSTRAP_KEY = "m87-test-bootstrap-key"


@pytest.fixture
def mock_redis():
    """Mock Redis client for unit tests."""
    redis_mock = MagicMock()
    redis_mock.ping.return_value = True
    redis_mock.xadd.return_value = "mock-event-id"
    redis_mock.hgetall.return_value = {}
    redis_mock.get.return_value = None
    return redis_mock


@pytest.fixture
def mock_db_available():
    """Patch _db_available to True for tests requiring persistence."""
    with patch("app.main._db_available", True):
        yield


@pytest.fixture
def mock_db_unavailable():
    """Patch _db_available to False for testing fail-safe."""
    with patch("app.main._db_available", False):
        yield


@pytest.fixture
def test_env(monkeypatch):
    """Set test environment variables."""
    monkeypatch.setenv("M87_API_KEY", TEST_BOOTSTRAP_KEY)
    monkeypatch.setenv("REDIS_URL", "redis://localhost:6379/0")
    monkeypatch.setenv("DATABASE_URL", "")
    monkeypatch.setenv("M87_ENABLE_TEST_ENDPOINTS", "true")


# Integration test fixtures (require running services)

@pytest.fixture
def api_base():
    """Get API base URL from environment."""
    return os.getenv("API_BASE", "http://localhost:8000")


@pytest.fixture
def api_key():
    """Get API key from environment."""
    return os.getenv("M87_API_KEY", "m87-dev-key-change-me")


@pytest.fixture
def integration_skip():
    """Skip marker for integration tests when API is not available."""
    import requests
    api_base = os.getenv("API_BASE", "http://localhost:8000")
    try:
        resp = requests.get(f"{api_base}/health", timeout=2)
        if resp.status_code != 200:
            pytest.skip("API not healthy")
    except requests.exceptions.ConnectionError:
        pytest.skip("API not reachable")
    except requests.exceptions.Timeout:
        pytest.skip("API timeout")
