# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Rate Limiter Service for Integration Execution

Implements token bucket algorithm for per-integration rate limiting.
Prevents exceeding API rate limits for external services.

Features:
- Per-integration rate limiting
- Per-action rate limiting
- Configurable limits per minute
- Automatic reset after time window
- Rate limit status reporting
"""

import time
import logging
from typing import Dict, Optional, Tuple
from datetime import datetime
from threading import Lock
from pydantic import BaseModel

logger = logging.getLogger(__name__)


class RateLimitStatus(BaseModel):
    """Status of rate limit for an integration/action"""
    integration_id: str
    action_id: Optional[str] = None
    allowed: bool
    remaining_calls: int
    limit_per_minute: int
    reset_at: datetime
    wait_seconds: Optional[float] = None


class TokenBucket:
    """
    Token bucket rate limiter.

    Allows burst traffic up to bucket capacity while enforcing
    an average rate limit over time.
    """

    def __init__(self, rate_per_minute: int):
        """
        Initialize bucket.

        Args:
            rate_per_minute: Maximum requests per minute
        """
        self.rate_per_minute = rate_per_minute
        self.tokens = float(rate_per_minute)  # Start with full bucket
        self.max_tokens = float(rate_per_minute)
        self.last_update = time.time()
        self.lock = Lock()

    def _refill(self) -> None:
        """Refill tokens based on elapsed time"""
        now = time.time()
        elapsed = now - self.last_update

        # Add tokens based on elapsed time (rate_per_minute / 60 = rate_per_second)
        tokens_to_add = elapsed * (self.rate_per_minute / 60.0)
        self.tokens = min(self.max_tokens, self.tokens + tokens_to_add)
        self.last_update = now

    def try_consume(self, tokens: int = 1) -> Tuple[bool, float]:
        """
        Try to consume tokens.

        Args:
            tokens: Number of tokens to consume (usually 1)

        Returns:
            Tuple of (allowed, wait_seconds)
            - allowed: True if request can proceed
            - wait_seconds: Seconds to wait if not allowed (0 if allowed)
        """
        with self.lock:
            self._refill()

            if self.tokens >= tokens:
                self.tokens -= tokens
                return True, 0.0
            else:
                # Calculate wait time until enough tokens
                tokens_needed = tokens - self.tokens
                wait_seconds = tokens_needed / (self.rate_per_minute / 60.0)
                return False, wait_seconds

    def get_remaining(self) -> int:
        """Get remaining tokens (requests allowed)"""
        with self.lock:
            self._refill()
            return int(self.tokens)

    def get_reset_time(self) -> datetime:
        """Get time when bucket will be full again"""
        with self.lock:
            self._refill()
            if self.tokens >= self.max_tokens:
                return datetime.utcnow()

            tokens_needed = self.max_tokens - self.tokens
            seconds_to_full = tokens_needed / (self.rate_per_minute / 60.0)
            return datetime.utcnow().replace(microsecond=0).__class__.utcnow()


class RateLimiter:
    """
    Rate limiter for integration API calls.

    Manages rate limits per integration and per action.
    Uses token bucket algorithm for fair rate limiting.
    """

    def __init__(self):
        self._integration_buckets: Dict[str, TokenBucket] = {}
        self._action_buckets: Dict[str, TokenBucket] = {}  # key: "integration:action"
        self._lock = Lock()

        # Default rate limits (can be overridden per integration/action)
        self._default_rate_per_minute = 60
        self._integration_overrides: Dict[str, int] = {}

    def _get_integration_bucket(self, integration_id: str, rate_per_minute: Optional[int] = None) -> TokenBucket:
        """Get or create bucket for integration"""
        with self._lock:
            if integration_id not in self._integration_buckets:
                rate = rate_per_minute or self._integration_overrides.get(integration_id, self._default_rate_per_minute)
                self._integration_buckets[integration_id] = TokenBucket(rate)
            return self._integration_buckets[integration_id]

    def _get_action_bucket(self, integration_id: str, action_id: str, rate_per_minute: Optional[int] = None) -> TokenBucket:
        """Get or create bucket for specific action"""
        key = f"{integration_id}:{action_id}"
        with self._lock:
            if key not in self._action_buckets:
                # Use provided rate or fall back to integration bucket (no action-specific limit)
                if rate_per_minute:
                    self._action_buckets[key] = TokenBucket(rate_per_minute)
                else:
                    return None  # No action-specific limit
            return self._action_buckets.get(key)

    def set_integration_limit(self, integration_id: str, rate_per_minute: int) -> None:
        """Set rate limit for an integration"""
        with self._lock:
            self._integration_overrides[integration_id] = rate_per_minute
            # Reset bucket if exists
            if integration_id in self._integration_buckets:
                self._integration_buckets[integration_id] = TokenBucket(rate_per_minute)

    def check_rate_limit(
        self,
        integration_id: str,
        action_id: Optional[str] = None,
        action_rate_limit: Optional[int] = None
    ) -> RateLimitStatus:
        """
        Check if request is allowed under rate limit.

        Does NOT consume a token - use try_acquire for that.

        Args:
            integration_id: Integration to check
            action_id: Specific action (optional)
            action_rate_limit: Rate limit for this action (from ActionSchema)

        Returns:
            RateLimitStatus with allowed status and details
        """
        # Check action-specific limit first if provided
        if action_id and action_rate_limit:
            bucket = self._get_action_bucket(integration_id, action_id, action_rate_limit)
            if bucket:
                remaining = bucket.get_remaining()
                reset_at = bucket.get_reset_time()
                allowed = remaining > 0
                wait_seconds = None if allowed else (60.0 / action_rate_limit)

                return RateLimitStatus(
                    integration_id=integration_id,
                    action_id=action_id,
                    allowed=allowed,
                    remaining_calls=remaining,
                    limit_per_minute=action_rate_limit,
                    reset_at=reset_at,
                    wait_seconds=wait_seconds
                )

        # Fall back to integration-level limit
        bucket = self._get_integration_bucket(integration_id)
        remaining = bucket.get_remaining()
        reset_at = bucket.get_reset_time()
        allowed = remaining > 0
        wait_seconds = None if allowed else (60.0 / bucket.rate_per_minute)

        return RateLimitStatus(
            integration_id=integration_id,
            action_id=action_id,
            allowed=allowed,
            remaining_calls=remaining,
            limit_per_minute=bucket.rate_per_minute,
            reset_at=reset_at,
            wait_seconds=wait_seconds
        )

    def try_acquire(
        self,
        integration_id: str,
        action_id: Optional[str] = None,
        action_rate_limit: Optional[int] = None
    ) -> RateLimitStatus:
        """
        Try to acquire a rate limit token.

        Consumes a token if available. Call this before making API request.

        Args:
            integration_id: Integration to acquire for
            action_id: Specific action (optional)
            action_rate_limit: Rate limit for this action (from ActionSchema)

        Returns:
            RateLimitStatus indicating if request can proceed
        """
        # Check action-specific limit first if provided
        if action_id and action_rate_limit:
            bucket = self._get_action_bucket(integration_id, action_id, action_rate_limit)
            if bucket:
                allowed, wait_seconds = bucket.try_consume()
                remaining = bucket.get_remaining()
                reset_at = bucket.get_reset_time()

                if not allowed:
                    logger.warning(
                        f"Rate limit exceeded for {integration_id}:{action_id}. "
                        f"Wait {wait_seconds:.1f}s"
                    )

                return RateLimitStatus(
                    integration_id=integration_id,
                    action_id=action_id,
                    allowed=allowed,
                    remaining_calls=remaining,
                    limit_per_minute=action_rate_limit,
                    reset_at=reset_at,
                    wait_seconds=wait_seconds if not allowed else None
                )

        # Fall back to integration-level limit
        bucket = self._get_integration_bucket(integration_id)
        allowed, wait_seconds = bucket.try_consume()
        remaining = bucket.get_remaining()
        reset_at = bucket.get_reset_time()

        if not allowed:
            logger.warning(
                f"Rate limit exceeded for {integration_id}. "
                f"Wait {wait_seconds:.1f}s"
            )

        return RateLimitStatus(
            integration_id=integration_id,
            action_id=action_id,
            allowed=allowed,
            remaining_calls=remaining,
            limit_per_minute=bucket.rate_per_minute,
            reset_at=reset_at,
            wait_seconds=wait_seconds if not allowed else None
        )

    def get_all_limits(self) -> Dict[str, Dict]:
        """Get status of all rate limiters"""
        with self._lock:
            result = {}

            for integration_id, bucket in self._integration_buckets.items():
                result[integration_id] = {
                    "remaining": bucket.get_remaining(),
                    "limit_per_minute": bucket.rate_per_minute,
                    "type": "integration"
                }

            for key, bucket in self._action_buckets.items():
                result[key] = {
                    "remaining": bucket.get_remaining(),
                    "limit_per_minute": bucket.rate_per_minute,
                    "type": "action"
                }

            return result

    def reset(self, integration_id: Optional[str] = None) -> None:
        """Reset rate limiter(s)"""
        with self._lock:
            if integration_id:
                # Reset specific integration
                if integration_id in self._integration_buckets:
                    bucket = self._integration_buckets[integration_id]
                    self._integration_buckets[integration_id] = TokenBucket(bucket.rate_per_minute)

                # Reset associated action buckets
                keys_to_reset = [k for k in self._action_buckets if k.startswith(f"{integration_id}:")]
                for key in keys_to_reset:
                    bucket = self._action_buckets[key]
                    self._action_buckets[key] = TokenBucket(bucket.rate_per_minute)
            else:
                # Reset all
                self._integration_buckets.clear()
                self._action_buckets.clear()


# Singleton instance
_rate_limiter: Optional[RateLimiter] = None


def get_rate_limiter() -> RateLimiter:
    """Get the global rate limiter instance"""
    global _rate_limiter
    if _rate_limiter is None:
        _rate_limiter = RateLimiter()
    return _rate_limiter
