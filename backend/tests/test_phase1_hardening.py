"""Phase 1: Security hardening tests (Production secrets refusal, CORS, and Auth rate limiting)."""

import asyncio
import time
import pytest
from httpx import AsyncClient
from pydantic import ValidationError

from app.core.config import Settings
from app.core.rate_limit import RedisSlidingWindowRateLimiter
from app.core.redis_breaker import BreakerState, RedisCircuitBreaker


def test_production_config_refuses_default_secret_key():
    """Verify Settings raises ValueError in production when using dev fallback secret key."""
    with pytest.raises(ValidationError) as exc_info:
        Settings(
            TTI_ENV="production",
            TTI_SECRET_KEY="dev_insecure_secret_key_must_be_changed_in_production_min32chars!",
            POSTGRES_PASSWORD="a_sufficiently_long_production_postgres_password_123!",
        )
    assert "TTI_SECRET_KEY must be changed from default dev secret in production!" in str(exc_info.value)


def test_production_config_refuses_short_secret_key():
    """Verify Settings raises ValueError in production when secret key is under 32 characters."""
    with pytest.raises(ValidationError) as exc_info:
        Settings(
            TTI_ENV="production",
            TTI_SECRET_KEY="too_short_secret_key",
            POSTGRES_PASSWORD="a_sufficiently_long_production_postgres_password_123!",
        )
    assert "TTI_SECRET_KEY must be at least 32 characters in production!" in str(exc_info.value)


def test_production_config_refuses_default_postgres_password():
    """Verify Settings raises ValueError in production when using dev fallback database password."""
    with pytest.raises(ValidationError) as exc_info:
        Settings(
            TTI_ENV="production",
            TTI_SECRET_KEY="a_sufficiently_long_custom_production_secret_key_123!",
            POSTGRES_PASSWORD="tti_dev_password_change_in_production",
        )
    assert "POSTGRES_PASSWORD must be changed from default dev password in production!" in str(exc_info.value)


def test_production_config_refuses_short_postgres_password():
    """Verify Settings raises ValueError in production when postgres password is under 32 characters."""
    with pytest.raises(ValidationError) as exc_info:
        Settings(
            TTI_ENV="production",
            TTI_SECRET_KEY="a_sufficiently_long_custom_production_secret_key_123!",
            POSTGRES_PASSWORD="short_pw_123",
        )
    assert "POSTGRES_PASSWORD must be at least 32 characters in production!" in str(exc_info.value)


def test_production_config_accepts_strong_credentials():
    """Verify Settings boots successfully in production with compliant 32+ char credentials."""
    cfg = Settings(
        TTI_ENV="production",
        TTI_SECRET_KEY="a_sufficiently_long_custom_production_secret_key_123!",
        POSTGRES_PASSWORD="a_sufficiently_long_production_postgres_password_123!",
        TTI_ID_PEPPER="a_sufficiently_long_production_id_pepper_123!",
        TTI_WEBHOOK_SECRET="a_sufficiently_long_production_webhook_secret_123!",
    )
    assert cfg.TTI_ENV == "production"


@pytest.mark.asyncio
async def test_cors_preflight_and_allowed_headers(async_client: AsyncClient):
    """Verify CORS preflight returns explicit methods and handles origins correctly."""
    headers = {
        "Origin": "http://localhost:3000",
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "Authorization, Content-Type, X-Tenant-ID",
    }
    resp = await async_client.options("/api/v1/auth/login", headers=headers)
    assert resp.status_code == 200
    assert resp.headers.get("access-control-allow-origin") == "http://localhost:3000"
    assert "POST" in resp.headers.get("access-control-allow-methods", "")


@pytest.mark.asyncio
async def test_sliding_window_rate_limiter_local_memory_fallback():
    """Verify RateLimiter sliding window memory fallback blocks excess requests and expires."""
    limiter = RedisSlidingWindowRateLimiter()
    key = "test_memory_ratelimit_key"
    limit = 3
    window = 1  # 1 second window

    # 1. First 3 requests permitted
    for _ in range(limit):
        allowed, retry = await limiter._check_memory_fallback(key, limit=limit, window_seconds=window, now=time.time())
        assert allowed is True
        assert retry == 0

    # 2. 4th request blocked
    allowed, retry = await limiter._check_memory_fallback(key, limit=limit, window_seconds=window, now=time.time())
    assert allowed is False
    assert retry >= 1

    # 3. Fast-forward past window: request permitted again
    future_time = time.time() + window + 0.1
    allowed, retry = await limiter._check_memory_fallback(key, limit=limit, window_seconds=window, now=future_time)
    assert allowed is True
    assert retry == 0


@pytest.mark.asyncio
async def test_auth_login_rate_limiting_returns_429(async_client: AsyncClient, test_tenant_id: str):
    """Verify rapid successive failed login attempts trigger HTTP 429 with Retry-After header."""
    headers = {"X-Tenant-ID": test_tenant_id}
    payload = {"email": "rate_limit_victim@agency.gov", "password": "wrong_password_123"}

    got_429 = False
    retry_after_val = None

    # Settings: TTI_RATE_LIMIT_LOGIN_ACCOUNT_LIMIT=5
    for _ in range(8):
        resp = await async_client.post("/api/v1/auth/login", json=payload, headers=headers)
        if resp.status_code == 429:
            got_429 = True
            retry_after_val = resp.headers.get("Retry-After")
            break

    assert got_429 is True
    assert retry_after_val is not None
    assert int(retry_after_val) > 0


class FakeClock:
    """Controllable clock for circuit breaker unit tests."""
    def __init__(self, start_time: float = 1000.0) -> None:
        self.current = start_time

    def __call__(self) -> float:
        return self.current

    def advance(self, seconds: float) -> None:
        self.current += seconds


def test_redis_circuit_breaker_lifecycle_and_state_transitions(caplog):
    """Verify breaker opens on failure, suppresses calls during cooldown, and closes on success."""
    clock = FakeClock(1000.0)
    breaker = RedisCircuitBreaker(cooldown_seconds=30.0, clock=clock)

    assert breaker.state == BreakerState.CLOSED
    assert breaker.can_attempt() is True

    # 1. Failure opens breaker and logs warning once
    with caplog.at_level("WARNING"):
        breaker.record_failure(ConnectionError("Connection refused"))
    assert breaker.state == BreakerState.OPEN
    assert "Circuit breaker OPEN for 30.0s cooldown" in caplog.text
    assert "per-process in local memory" in caplog.text

    # 2. Calls are skipped during cooldown
    clock.advance(10.0)
    assert breaker.can_attempt() is False

    clock.advance(19.0)  # total 29.0s elapsed (< 30.0s)
    assert breaker.can_attempt() is False

    # 3. Retry happens after cooldown (HALF_OPEN allows exactly one probe)
    clock.advance(2.0)  # total 31.0s elapsed (>= 30.0s)
    assert breaker.can_attempt() is True
    assert breaker.state == BreakerState.HALF_OPEN

    # Probe in flight blocks second attempt
    assert breaker.can_attempt() is False

    # 4. Success closes breaker
    breaker.record_success()
    assert breaker.state == BreakerState.CLOSED
    assert breaker.can_attempt() is True


def test_redis_circuit_breaker_failure_during_half_open():
    """Verify failed probe in HALF_OPEN resets breaker back to OPEN."""
    clock = FakeClock(1000.0)
    breaker = RedisCircuitBreaker(cooldown_seconds=30.0, clock=clock)

    breaker.record_failure()
    assert breaker.state == BreakerState.OPEN

    clock.advance(35.0)
    assert breaker.can_attempt() is True
    assert breaker.state == BreakerState.HALF_OPEN

    breaker.record_failure(TimeoutError("Socket timeout"))
    assert breaker.state == BreakerState.OPEN
    assert breaker.can_attempt() is False


@pytest.mark.asyncio
async def test_rate_limiter_memory_backend_direct():
    """Verify rate limiter operates directly on memory backend without invoking Redis."""
    breaker = RedisCircuitBreaker(cooldown_seconds=30.0)
    limiter = RedisSlidingWindowRateLimiter(redis_client=None, breaker=breaker)

    allowed, retry = await limiter.check_rate_limit("user:test@agency.gov", limit=2, window_seconds=10)
    assert allowed is True
    assert retry == 0

    allowed, retry = await limiter.check_rate_limit("user:test@agency.gov", limit=2, window_seconds=10)
    assert allowed is True
    assert retry == 0

    allowed, retry = await limiter.check_rate_limit("user:test@agency.gov", limit=2, window_seconds=10)
    assert allowed is False
    assert retry > 0


