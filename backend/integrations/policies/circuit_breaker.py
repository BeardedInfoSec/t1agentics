# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Circuit Breaker Pattern for Integration Resilience

Prevents cascading failures by temporarily blocking calls to failing integrations.
Implements the circuit breaker pattern with three states:
- CLOSED: Normal operation, calls go through
- OPEN: Failing, calls blocked for a timeout period
- HALF_OPEN: Testing, allowing limited calls to check recovery

Features:
- Configurable failure thresholds per integration
- Automatic recovery attempts
- Health status exposure via API
- Persistent state across restarts (optional)
"""

import asyncio
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, Optional, Any, Callable
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class CircuitState(str, Enum):
    """Circuit breaker states"""
    CLOSED = "closed"      # Normal operation
    OPEN = "open"          # Blocking calls
    HALF_OPEN = "half_open"  # Testing recovery


@dataclass
class CircuitBreakerConfig:
    """Configuration for a circuit breaker"""
    failure_threshold: int = 5          # Failures before opening
    success_threshold: int = 3          # Successes to close from half-open
    timeout_seconds: int = 60           # How long to stay open
    half_open_max_calls: int = 3        # Max calls in half-open state
    monitoring_window_seconds: int = 120  # Window for counting failures


@dataclass
class CircuitBreakerState:
    """State of a circuit breaker"""
    state: CircuitState = CircuitState.CLOSED
    failure_count: int = 0
    success_count: int = 0
    last_failure_time: Optional[datetime] = None
    last_success_time: Optional[datetime] = None
    opened_at: Optional[datetime] = None
    half_open_calls: int = 0
    total_calls: int = 0
    total_failures: int = 0
    last_error: Optional[str] = None
    consecutive_failures: int = 0


class CircuitBreaker:
    """
    Circuit breaker for a single integration.

    Usage:
        breaker = CircuitBreaker("virustotal")

        # Check if call is allowed
        if not breaker.can_call():
            return {"error": "Circuit open, integration unavailable"}

        try:
            result = await make_api_call()
            breaker.record_success()
            return result
        except Exception as e:
            breaker.record_failure(str(e))
            raise
    """

    def __init__(
        self,
        integration_id: str,
        config: Optional[CircuitBreakerConfig] = None
    ):
        self.integration_id = integration_id
        self.config = config or CircuitBreakerConfig()
        self.state = CircuitBreakerState()
        self._lock = asyncio.Lock()

    @property
    def is_closed(self) -> bool:
        return self.state.state == CircuitState.CLOSED

    @property
    def is_open(self) -> bool:
        return self.state.state == CircuitState.OPEN

    @property
    def is_half_open(self) -> bool:
        return self.state.state == CircuitState.HALF_OPEN

    def can_call(self) -> bool:
        """Check if a call is allowed through the circuit breaker."""
        now = datetime.now(timezone.utc)

        if self.state.state == CircuitState.CLOSED:
            return True

        if self.state.state == CircuitState.OPEN:
            # Check if timeout has elapsed
            if self.state.opened_at:
                timeout_end = self.state.opened_at + timedelta(
                    seconds=self.config.timeout_seconds
                )
                if now >= timeout_end:
                    # Transition to half-open
                    self._transition_to_half_open()
                    return True
            return False

        if self.state.state == CircuitState.HALF_OPEN:
            # Allow limited calls in half-open
            return self.state.half_open_calls < self.config.half_open_max_calls

        return False

    def record_success(self) -> None:
        """Record a successful call."""
        self.state.total_calls += 1
        self.state.last_success_time = datetime.now(timezone.utc)
        self.state.consecutive_failures = 0

        if self.state.state == CircuitState.HALF_OPEN:
            self.state.success_count += 1
            if self.state.success_count >= self.config.success_threshold:
                self._transition_to_closed()
                logger.info(
                    f"Circuit breaker for {self.integration_id} CLOSED "
                    f"after {self.state.success_count} successful calls"
                )

    def record_failure(self, error: Optional[str] = None) -> None:
        """Record a failed call."""
        now = datetime.now(timezone.utc)
        self.state.total_calls += 1
        self.state.total_failures += 1
        self.state.failure_count += 1
        self.state.consecutive_failures += 1
        self.state.last_failure_time = now
        self.state.last_error = error

        if self.state.state == CircuitState.CLOSED:
            # Reset failure count if outside monitoring window
            window_start = now - timedelta(
                seconds=self.config.monitoring_window_seconds
            )
            if self.state.last_failure_time and self.state.last_failure_time < window_start:
                self.state.failure_count = 1

            # Check if threshold reached
            if self.state.consecutive_failures >= self.config.failure_threshold:
                self._transition_to_open()
                logger.warning(
                    f"Circuit breaker for {self.integration_id} OPENED "
                    f"after {self.state.consecutive_failures} consecutive failures. "
                    f"Last error: {error}"
                )

        elif self.state.state == CircuitState.HALF_OPEN:
            # Any failure in half-open reopens the circuit
            self._transition_to_open()
            logger.warning(
                f"Circuit breaker for {self.integration_id} REOPENED "
                f"after failure in half-open state. Error: {error}"
            )

    def _transition_to_open(self) -> None:
        """Transition to open state."""
        self.state.state = CircuitState.OPEN
        self.state.opened_at = datetime.now(timezone.utc)
        self.state.success_count = 0
        self.state.half_open_calls = 0

    def _transition_to_half_open(self) -> None:
        """Transition to half-open state."""
        self.state.state = CircuitState.HALF_OPEN
        self.state.success_count = 0
        self.state.half_open_calls = 0
        logger.info(
            f"Circuit breaker for {self.integration_id} entering HALF_OPEN state"
        )

    def _transition_to_closed(self) -> None:
        """Transition to closed state."""
        self.state.state = CircuitState.CLOSED
        self.state.failure_count = 0
        self.state.consecutive_failures = 0
        self.state.success_count = 0
        self.state.half_open_calls = 0
        self.state.opened_at = None

    def reset(self) -> None:
        """Manually reset the circuit breaker to closed state."""
        self._transition_to_closed()
        logger.info(f"Circuit breaker for {self.integration_id} manually reset")

    def get_status(self) -> Dict[str, Any]:
        """Get current circuit breaker status."""
        now = datetime.now(timezone.utc)
        time_until_retry = None

        if self.state.state == CircuitState.OPEN and self.state.opened_at:
            retry_at = self.state.opened_at + timedelta(
                seconds=self.config.timeout_seconds
            )
            if retry_at > now:
                time_until_retry = int((retry_at - now).total_seconds())

        return {
            "integration_id": self.integration_id,
            "state": self.state.state.value,
            "failure_count": self.state.failure_count,
            "consecutive_failures": self.state.consecutive_failures,
            "success_count": self.state.success_count,
            "total_calls": self.state.total_calls,
            "total_failures": self.state.total_failures,
            "last_failure_time": self.state.last_failure_time.isoformat() if self.state.last_failure_time else None,
            "last_success_time": self.state.last_success_time.isoformat() if self.state.last_success_time else None,
            "last_error": self.state.last_error,
            "opened_at": self.state.opened_at.isoformat() if self.state.opened_at else None,
            "time_until_retry_seconds": time_until_retry,
            "config": {
                "failure_threshold": self.config.failure_threshold,
                "success_threshold": self.config.success_threshold,
                "timeout_seconds": self.config.timeout_seconds
            }
        }


class CircuitBreakerRegistry:
    """
    Registry for managing circuit breakers across all integrations.

    Usage:
        registry = get_circuit_breaker_registry()

        # Get or create breaker for an integration
        breaker = registry.get_breaker("virustotal")

        # Check health of all integrations
        health = registry.get_health_summary()
    """

    # Default configurations per integration type
    DEFAULT_CONFIGS = {
        # Critical security tools - lower thresholds
        "crowdstrike": CircuitBreakerConfig(
            failure_threshold=3,
            timeout_seconds=120,
            success_threshold=2
        ),
        "microsoft_defender": CircuitBreakerConfig(
            failure_threshold=3,
            timeout_seconds=120,
            success_threshold=2
        ),
        "sentinelone": CircuitBreakerConfig(
            failure_threshold=3,
            timeout_seconds=120,
            success_threshold=2
        ),
        # Threat intel - higher tolerance
        "virustotal": CircuitBreakerConfig(
            failure_threshold=5,
            timeout_seconds=60,
            success_threshold=3
        ),
        "abuseipdb": CircuitBreakerConfig(
            failure_threshold=5,
            timeout_seconds=60,
            success_threshold=3
        ),
        "shodan": CircuitBreakerConfig(
            failure_threshold=5,
            timeout_seconds=60,
            success_threshold=3
        ),
        # AI providers - moderate tolerance
        "ollama": CircuitBreakerConfig(
            failure_threshold=3,
            timeout_seconds=30,
            success_threshold=2
        ),
        "openai": CircuitBreakerConfig(
            failure_threshold=5,
            timeout_seconds=60,
            success_threshold=3
        ),
        "anthropic": CircuitBreakerConfig(
            failure_threshold=5,
            timeout_seconds=60,
            success_threshold=3
        )
    }

    def __init__(self):
        self._breakers: Dict[str, CircuitBreaker] = {}
        self._lock = asyncio.Lock()

    def get_breaker(
        self,
        integration_id: str,
        config: Optional[CircuitBreakerConfig] = None
    ) -> CircuitBreaker:
        """Get or create a circuit breaker for an integration."""
        if integration_id not in self._breakers:
            # Use custom config, integration-specific default, or global default
            breaker_config = (
                config or
                self.DEFAULT_CONFIGS.get(integration_id) or
                CircuitBreakerConfig()
            )
            self._breakers[integration_id] = CircuitBreaker(
                integration_id,
                breaker_config
            )
        return self._breakers[integration_id]

    def can_call(self, integration_id: str) -> bool:
        """Check if calls to an integration are allowed."""
        breaker = self.get_breaker(integration_id)
        return breaker.can_call()

    def record_success(self, integration_id: str) -> None:
        """Record a successful call to an integration."""
        breaker = self.get_breaker(integration_id)
        breaker.record_success()

    def record_failure(self, integration_id: str, error: Optional[str] = None) -> None:
        """Record a failed call to an integration."""
        breaker = self.get_breaker(integration_id)
        breaker.record_failure(error)

    def reset_breaker(self, integration_id: str) -> bool:
        """Manually reset a circuit breaker."""
        if integration_id in self._breakers:
            self._breakers[integration_id].reset()
            return True
        return False

    def get_status(self, integration_id: str) -> Optional[Dict[str, Any]]:
        """Get status of a specific circuit breaker."""
        if integration_id in self._breakers:
            return self._breakers[integration_id].get_status()
        return None

    def get_all_statuses(self) -> Dict[str, Dict[str, Any]]:
        """Get status of all circuit breakers."""
        return {
            integration_id: breaker.get_status()
            for integration_id, breaker in self._breakers.items()
        }

    def get_health_summary(self) -> Dict[str, Any]:
        """Get overall health summary."""
        statuses = self.get_all_statuses()

        open_circuits = [
            s["integration_id"]
            for s in statuses.values()
            if s["state"] == "open"
        ]
        half_open_circuits = [
            s["integration_id"]
            for s in statuses.values()
            if s["state"] == "half_open"
        ]

        total_failures = sum(s["total_failures"] for s in statuses.values())
        total_calls = sum(s["total_calls"] for s in statuses.values())

        return {
            "total_integrations": len(statuses),
            "healthy": len(statuses) - len(open_circuits) - len(half_open_circuits),
            "open_circuits": open_circuits,
            "half_open_circuits": half_open_circuits,
            "total_calls": total_calls,
            "total_failures": total_failures,
            "failure_rate": (total_failures / total_calls * 100) if total_calls > 0 else 0,
            "all_circuits": statuses
        }

    def get_open_circuits(self) -> list:
        """Get list of integrations with open circuits."""
        return [
            integration_id
            for integration_id, breaker in self._breakers.items()
            if breaker.is_open
        ]


# ============================================================================
# SINGLETON
# ============================================================================

_circuit_breaker_registry: Optional[CircuitBreakerRegistry] = None


def get_circuit_breaker_registry() -> CircuitBreakerRegistry:
    """Get the global circuit breaker registry."""
    global _circuit_breaker_registry
    if _circuit_breaker_registry is None:
        _circuit_breaker_registry = CircuitBreakerRegistry()
    return _circuit_breaker_registry


# ============================================================================
# DECORATOR FOR EASY INTEGRATION
# ============================================================================

def with_circuit_breaker(integration_id: str):
    """
    Decorator to wrap a function with circuit breaker protection.

    Usage:
        @with_circuit_breaker("virustotal")
        async def call_virustotal(hash_value: str):
            return await make_vt_request(hash_value)
    """
    def decorator(func: Callable):
        async def wrapper(*args, **kwargs):
            registry = get_circuit_breaker_registry()

            if not registry.can_call(integration_id):
                raise CircuitBreakerOpenError(
                    f"Circuit breaker open for {integration_id}"
                )

            try:
                result = await func(*args, **kwargs)
                registry.record_success(integration_id)
                return result
            except Exception as e:
                registry.record_failure(integration_id, str(e))
                raise

        return wrapper
    return decorator


class CircuitBreakerOpenError(Exception):
    """Raised when attempting to call through an open circuit breaker."""
    pass
