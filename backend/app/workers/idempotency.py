"""Task idempotency and duplicate execution prevention.

Ensures that tasks with a designated idempotency key cannot execute concurrently
or redundantly if already processed within the idempotency window.
"""

import time
from typing import Dict, Optional, Tuple
import redis

from app.core.config import get_settings
from app.core.redis_breaker import RedisCircuitBreaker, get_redis_circuit_breaker


class TaskIdempotencyManager:
    """Manages task idempotency keys across Redis with local in-memory fallback."""

    def __init__(
        self,
        redis_client: Optional[redis.Redis] = None,
        breaker: Optional[RedisCircuitBreaker] = None,
    ) -> None:
        self._redis = redis_client
        self._breaker = breaker or get_redis_circuit_breaker()
        self._memory_cache: Dict[str, Tuple[str, float]] = {}  # key -> (status, expiry)

    def _get_redis(self) -> redis.Redis:
        if self._redis is None:
            settings = get_settings()
            self._redis = redis.from_url(
                settings.redis_url,
                decode_responses=True,
                socket_connect_timeout=settings.REDIS_SOCKET_CONNECT_TIMEOUT,
                socket_timeout=settings.REDIS_SOCKET_TIMEOUT,
            )
        return self._redis

    def acquire_idempotency_lock(self, key: str, ttl_seconds: int = 86400) -> bool:
        """Attempt to acquire idempotency lock for task execution.

        Returns True if this is the first execution (lock acquired).
        Returns False if task is already in-flight or completed.
        """
        if self._breaker.can_attempt():
            redis_key = f"tti:idemp:{key}"
            try:
                r = self._get_redis()
                # SET NX EX atomically sets if not exists
                acquired = r.set(redis_key, "IN_FLIGHT", nx=True, ex=ttl_seconds)
                self._breaker.record_success()
                return bool(acquired)
            except Exception as exc:
                self._breaker.record_failure(exc)

        # Memory fallback
        now = time.time()
        if key in self._memory_cache:
            status, expiry = self._memory_cache[key]
            if now < expiry:
                return False
        self._memory_cache[key] = ("IN_FLIGHT", now + ttl_seconds)
        return True

    def mark_completed(self, key: str, ttl_seconds: int = 86400) -> None:
        """Mark task execution as successfully completed."""
        if self._breaker.can_attempt():
            redis_key = f"tti:idemp:{key}"
            try:
                r = self._get_redis()
                r.set(redis_key, "COMPLETED", ex=ttl_seconds)
                self._breaker.record_success()
                return
            except Exception as exc:
                self._breaker.record_failure(exc)

        self._memory_cache[key] = ("COMPLETED", time.time() + ttl_seconds)

    def release_lock(self, key: str) -> None:
        """Release lock upon failure to allow retry."""
        if self._breaker.can_attempt():
            redis_key = f"tti:idemp:{key}"
            try:
                r = self._get_redis()
                r.delete(redis_key)
                self._breaker.record_success()
                return
            except Exception as exc:
                self._breaker.record_failure(exc)

        self._memory_cache.pop(key, None)


_global_idempotency_manager: Optional[TaskIdempotencyManager] = None


def get_idempotency_manager() -> TaskIdempotencyManager:
    """Return singleton idempotency manager."""
    global _global_idempotency_manager
    if _global_idempotency_manager is None:
        _global_idempotency_manager = TaskIdempotencyManager()
    return _global_idempotency_manager
