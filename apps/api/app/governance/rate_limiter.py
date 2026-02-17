"""
P2.A — Per-key rate limiting + per-key compute budget.

Uses Redis sorted sets (sliding window) to enforce:
- Max proposals per minute per principal_id
- Evaluation cost budget per principal_id (tracks governance compute)

Exceeding limits → HTTP 429 Too Many Requests.
"""
from __future__ import annotations

import os
import time
import uuid
import logging
from typing import Optional, Dict, Any

from redis import Redis

logger = logging.getLogger(__name__)

# Defaults (overridable via env)
DEFAULT_MAX_PROPOSALS_PER_MINUTE = int(os.getenv("M87_RATE_LIMIT_PROPOSALS_PER_MIN", "30"))
DEFAULT_MAX_EVAL_COST_PER_MINUTE = float(os.getenv("M87_RATE_LIMIT_EVAL_COST_PER_MIN", "100.0"))
RATE_LIMIT_WINDOW_SECONDS = 60

# Per-principal overrides (principal_id → limit)
# In production these would be stored in Redis/DB; for now, hardcoded profiles.
PRINCIPAL_RATE_OVERRIDES: Dict[str, int] = {
    "bootstrap": 60,   # Admin gets higher limit
}


class RateLimitResult:
    """Result of a rate limit check."""

    __slots__ = ("allowed", "current", "limit", "remaining", "retry_after", "reason")

    def __init__(
        self,
        allowed: bool,
        current: int,
        limit: int,
        remaining: int,
        retry_after: float = 0.0,
        reason: str = "",
    ):
        self.allowed = allowed
        self.current = current
        self.limit = limit
        self.remaining = remaining
        self.retry_after = retry_after
        self.reason = reason


class KeyRateLimiter:
    """
    Redis sliding-window rate limiter per principal_id.

    Uses sorted sets with timestamps as scores:
    - Key: m87:ratelimit:{principal_id}
    - Score: timestamp (float)
    - Member: unique request ID (timestamp + counter)

    On each check:
    1. Remove entries older than window
    2. Count remaining entries
    3. If under limit, add new entry and allow
    4. If over limit, deny with retry_after
    """

    KEY_PREFIX = "m87:ratelimit:"

    def __init__(self, redis: Redis):
        self.redis = redis

    def check_rate_limit(
        self,
        principal_id: str,
        max_per_minute: Optional[int] = None,
    ) -> RateLimitResult:
        """
        Check and record a request against the rate limit.

        Args:
            principal_id: The principal making the request
            max_per_minute: Override limit (uses default if None)

        Returns:
            RateLimitResult with allowed status
        """
        limit = max_per_minute or PRINCIPAL_RATE_OVERRIDES.get(
            principal_id, DEFAULT_MAX_PROPOSALS_PER_MINUTE
        )

        now = time.time()
        window_start = now - RATE_LIMIT_WINDOW_SECONDS
        key = f"{self.KEY_PREFIX}{principal_id}"

        pipe = self.redis.pipeline()
        # Remove old entries outside window
        pipe.zremrangebyscore(key, "-inf", window_start)
        # Count current entries in window
        pipe.zcard(key)
        results = pipe.execute()

        current_count = results[1]

        if current_count >= limit:
            # Find oldest entry to compute retry_after
            oldest = self.redis.zrange(key, 0, 0, withscores=True)
            retry_after = 0.0
            if oldest:
                oldest_score = oldest[0][1]
                retry_after = max(0.0, (oldest_score + RATE_LIMIT_WINDOW_SECONDS) - now)

            logger.warning(
                "Rate limit exceeded: principal=%s current=%d limit=%d",
                principal_id, current_count, limit,
            )
            return RateLimitResult(
                allowed=False,
                current=current_count,
                limit=limit,
                remaining=0,
                retry_after=retry_after,
                reason=f"Rate limit exceeded: {current_count}/{limit} requests per minute",
            )

        # Add new entry — member must be globally unique.
        # Using uuid4 nonce prevents collisions under concurrency
        # (timestamp + counter can collide when two requests arrive
        # in the same instant with the same ZSET count).
        member = f"{now}:{uuid.uuid4().hex}"
        pipe2 = self.redis.pipeline()
        pipe2.zadd(key, {member: now})
        # Auto-expire the key after 2x window to prevent leak
        pipe2.expire(key, RATE_LIMIT_WINDOW_SECONDS * 2)
        pipe2.execute()

        remaining = limit - current_count - 1
        return RateLimitResult(
            allowed=True,
            current=current_count + 1,
            limit=limit,
            remaining=max(0, remaining),
        )

    def get_usage(self, principal_id: str) -> Dict[str, Any]:
        """Get current rate limit usage for a principal."""
        now = time.time()
        window_start = now - RATE_LIMIT_WINDOW_SECONDS
        key = f"{self.KEY_PREFIX}{principal_id}"

        # Clean and count
        self.redis.zremrangebyscore(key, "-inf", window_start)
        current = self.redis.zcard(key)
        limit = PRINCIPAL_RATE_OVERRIDES.get(
            principal_id, DEFAULT_MAX_PROPOSALS_PER_MINUTE
        )

        return {
            "principal_id": principal_id,
            "current": current,
            "limit": limit,
            "remaining": max(0, limit - current),
            "window_seconds": RATE_LIMIT_WINDOW_SECONDS,
        }
