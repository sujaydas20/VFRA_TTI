"""Shared Redis Circuit Breaker for graceful degradation and per-process fallback.

Prevents blocking application threads and event loops with repeated TCP connection
timeouts when Redis is unavailable or degraded.
"""

from enum import Enum
import logging
import time
from typing import Callable, Optional

logger = logging.getLogger("tti.redis_breaker")


class BreakerState(str, Enum):
    """Operational state of the Redis circuit breaker."""
    CLOSED = "CLOSED"       # Redis is healthy; operations proceed normally
    OPEN = "OPEN"           # Redis failed; skip network calls during cooldown
    HALF_OPEN = "HALF_OPEN" # Cooldown elapsed; single probe permitted to check recovery


class RedisCircuitBreaker:
    """Circuit breaker for Redis availability with injectable clock and configurable cooldown."""

    def __init__(
        self,
        cooldown_seconds: float = 30.0,
        clock: Optional[Callable[[], float]] = None,
    ) -> None:
        self.cooldown_seconds = cooldown_seconds
        self._clock = clock if clock is not None else time.monotonic
        self._state: BreakerState = BreakerState.CLOSED
        self._last_state_change: float = self._clock()
        self._last_failure_time: float = 0.0
        self._probe_in_flight: bool = False

    @property
    def state(self) -> BreakerState:
        return self._state

    def can_attempt(self) -> bool:
        """Evaluate if an external Redis call is permitted.
        
        Returns:
            bool: True if call should proceed to Redis, False if caller should
                  bypass immediately to in-memory fallback.
        """
        now = self._clock()
        if self._state == BreakerState.CLOSED:
            return True

        if self._state == BreakerState.OPEN:
            if (now - self._last_failure_time) >= self.cooldown_seconds:
                # Transition to HALF_OPEN to allow exactly one probe
                self._transition_to(BreakerState.HALF_OPEN, now)
                self._probe_in_flight = True
                return True
            return False

        if self._state == BreakerState.HALF_OPEN:
            # If a probe is already attempting or allowed, block subsequent calls until result
            if not self._probe_in_flight:
                self._probe_in_flight = True
                return True
            return False

        return False

    def record_success(self) -> None:
        """Record successful Redis operation. Closes breaker if OPEN or HALF_OPEN."""
        now = self._clock()
        self._probe_in_flight = False
        if self._state != BreakerState.CLOSED:
            self._transition_to(BreakerState.CLOSED, now)

    def record_failure(self, exc: Optional[Exception] = None) -> None:
        """Record failed Redis operation. Trips breaker to OPEN state."""
        now = self._clock()
        self._probe_in_flight = False
        self._last_failure_time = now
        if self._state != BreakerState.OPEN:
            self._transition_to(BreakerState.OPEN, now, exc=exc)

    def _transition_to(
        self,
        new_state: BreakerState,
        now: float,
        exc: Optional[Exception] = None,
    ) -> None:
        old_state = self._state
        self._state = new_state
        self._last_state_change = now

        if new_state == BreakerState.OPEN:
            err_msg = f": {exc}" if exc else ""
            logger.warning(
                "Redis connection failed%s. Circuit breaker OPEN for %.1fs cooldown. "
                "Limits and idempotency are now operating per-process in local memory.",
                err_msg,
                self.cooldown_seconds,
            )
        elif new_state == BreakerState.CLOSED:
            logger.info(
                "Redis connectivity restored. Circuit breaker CLOSED. Resuming distributed operations."
            )
        elif new_state == BreakerState.HALF_OPEN:
            logger.debug(
                "Redis cooldown of %.1fs elapsed. Circuit breaker HALF_OPEN; probing single health check.",
                self.cooldown_seconds,
            )

    def reset(self) -> None:
        """Reset breaker to initial CLOSED state (primarily for test harnesses)."""
        self._state = BreakerState.CLOSED
        self._last_state_change = self._clock()
        self._last_failure_time = 0.0
        self._probe_in_flight = False


_global_breaker: Optional[RedisCircuitBreaker] = None


def get_redis_circuit_breaker(cooldown_seconds: Optional[float] = None) -> RedisCircuitBreaker:
    """Return application-wide Redis circuit breaker singleton."""
    global _global_breaker
    if _global_breaker is None:
        from app.core.config import get_settings
        settings = get_settings()
        cooldown = cooldown_seconds if cooldown_seconds is not None else settings.REDIS_CIRCUIT_BREAKER_COOLDOWN
        _global_breaker = RedisCircuitBreaker(cooldown_seconds=cooldown)
    return _global_breaker
