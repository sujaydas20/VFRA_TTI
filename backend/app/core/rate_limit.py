"""Redis sliding-window rate limiter with in-memory fallback and circuit breaker.

Protects authentication and sensitive endpoints from brute-force attacks.
Fails closed with structured 429 Retry-After responses when limits are reached.
Gracefully degrades to per-process memory limits when Redis is unavailable.
"""

import asyncio
from datetime import datetime, timezone
import math
import time
from typing import Dict, List, Optional, Tuple
from fastapi import HTTPException, status
import redis.asyncio as aioredis

from app.core.config import get_settings
from app.core.redis_breaker import RedisCircuitBreaker, get_redis_circuit_breaker
from app.services.protocols import RateLimiter


class RedisSlidingWindowRateLimiter:
    """Sliding-window rate limiter utilizing Redis with local memory fallback."""

    def __init__(
        self,
        redis_client: Optional[aioredis.Redis] = None,
        breaker: Optional[RedisCircuitBreaker] = None,
    ) -> None:
        self._redis_client = redis_client
        self._breaker = breaker or get_redis_circuit_breaker()
        self._memory_cache: Dict[str, List[float]] = {}
        self._lock = asyncio.Lock()
        self._max_memory_keys = 50000

    def _get_redis(self) -> aioredis.Redis:
        if self._redis_client is None:
            settings = get_settings()
            self._redis_client = aioredis.from_url(
                settings.redis_url,
                decode_responses=True,
                socket_connect_timeout=settings.REDIS_SOCKET_CONNECT_TIMEOUT,
                socket_timeout=settings.REDIS_SOCKET_TIMEOUT,
            )
        return self._redis_client

    async def check_rate_limit(
        self,
        key: str,
        limit: int,
        window_seconds: int,
    ) -> Tuple[bool, int]:
        """Check rate limit for a given key using a sliding window.

        Returns:
            Tuple[bool, int]: (allowed, retry_after_seconds)
        """
        now = time.time()
        settings = get_settings()

        # If configured explicitly to memory backend, bypass Redis completely
        if settings.TTI_RATE_LIMIT_BACKEND == "memory":
            return await self._check_memory_fallback(key, limit, window_seconds, now)

        # Check circuit breaker before attempting network IO
        if not self._breaker.can_attempt():
            return await self._check_memory_fallback(key, limit, window_seconds, now)

        redis_key = f"tti:ratelimit:{key}"

        # 1. Try Redis sliding window
        try:
            r = self._get_redis()
            cutoff = now - window_seconds
            pipe = r.pipeline(transaction=True)
            pipe.zremrangebyscore(redis_key, 0, cutoff)
            pipe.zcard(redis_key)
            pipe.zrange(redis_key, 0, 0, withscores=True)
            results = await pipe.execute()

            current_count = results[1]
            oldest_entries = results[2]

            if current_count < limit:
                # Add current request to window
                add_pipe = r.pipeline(transaction=True)
                member = f"{now}:{time.perf_counter()}"
                add_pipe.zadd(redis_key, {member: now})
                add_pipe.expire(redis_key, window_seconds + 5)
                await add_pipe.execute()
                self._breaker.record_success()
                return True, 0

            # Limit exceeded: compute retry-after based on oldest entry in window
            if oldest_entries:
                _, oldest_ts = oldest_entries[0]
                retry_after = max(1, math.ceil(float(oldest_ts) + window_seconds - now))
            else:
                retry_after = window_seconds
            self._breaker.record_success()
            return False, retry_after

        except Exception as exc:
            # 2. Redis failure fallback: trip breaker and use local in-memory sliding window
            self._breaker.record_failure(exc)
            return await self._check_memory_fallback(key, limit, window_seconds, now)

    async def _check_memory_fallback(
        self,
        key: str,
        limit: int,
        window_seconds: int,
        now: float,
    ) -> Tuple[bool, int]:
        """Thread-safe in-memory sliding window fallback during Redis outages."""
        async with self._lock:
            # Saturated cache defense: Fail closed if cache under memory attack
            if len(self._memory_cache) > self._max_memory_keys and key not in self._memory_cache:
                return False, window_seconds

            timestamps = self._memory_cache.setdefault(key, [])
            cutoff = now - window_seconds
            timestamps = [ts for ts in timestamps if ts > cutoff]
            self._memory_cache[key] = timestamps

            if len(timestamps) < limit:
                timestamps.append(now)
                return True, 0

            oldest_ts = timestamps[0]
            retry_after = max(1, math.ceil(oldest_ts + window_seconds - now))
            return False, retry_after

    async def close(self) -> None:
        """Close underlying Redis connection pool."""
        if self._redis_client is not None:
            await self._redis_client.aclose()


_global_rate_limiter: Optional[RedisSlidingWindowRateLimiter] = None


def get_rate_limiter() -> RateLimiter:
    """Return singleton RateLimiter instance."""
    global _global_rate_limiter
    if _global_rate_limiter is None:
        _global_rate_limiter = RedisSlidingWindowRateLimiter()
    return _global_rate_limiter


async def enforce_login_rate_limits(
    limiter: RateLimiter,
    client_ip: str,
    email: str,
) -> None:
    """Enforce rate limits on authentication: by client IP and by account (hashed)."""
    settings = get_settings()
    import hashlib

    # 1. IP-level rate limit
    ip_key = f"login:ip:{client_ip}"
    allowed_ip, retry_ip = await limiter.check_rate_limit(
        key=ip_key,
        limit=settings.TTI_RATE_LIMIT_LOGIN_IP_LIMIT,
        window_seconds=settings.TTI_RATE_LIMIT_LOGIN_IP_WINDOW,
    )
    if not allowed_ip:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many login attempts from this IP address. Please retry in {retry_ip} seconds.",
            headers={"Retry-After": str(retry_ip)},
        )

    # 2. Account-level rate limit (blind SHA-256 hash to protect username in cache)
    account_hash = hashlib.sha256(email.lower().strip().encode()).hexdigest()
    account_key = f"login:account:{account_hash}"
    allowed_account, retry_account = await limiter.check_rate_limit(
        key=account_key,
        limit=settings.TTI_RATE_LIMIT_LOGIN_ACCOUNT_LIMIT,
        window_seconds=settings.TTI_RATE_LIMIT_LOGIN_ACCOUNT_WINDOW,
    )
    if not allowed_account:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many failed login attempts for this account. Please retry in {retry_account} seconds.",
            headers={"Retry-After": str(retry_account)},
        )
