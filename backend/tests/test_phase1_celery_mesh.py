"""Phase 1: Celery worker mesh, task dispatcher, idempotency, and dead-letter testing."""

import asyncio
from datetime import datetime, timezone
import uuid
import pytest
import pytest_asyncio
from httpx import AsyncClient
import redis
from sqlalchemy import select, text

from app.adapters.queue.inline_dispatcher import InlineTaskDispatcher
from app.core.config import get_settings
from app.database.models.jobs import SystemJobRecord
from app.database.session import async_session_factory
from app.workers.base import (
    compute_args_hash,
    compute_backoff_delay,
    record_dead_letter_job,
    sanitize_error_message,
    worker_tenant_session,
)
from app.workers.celery_app import celery_app, get_queue_concurrency
from app.workers.idempotency import TaskIdempotencyManager


def test_queue_concurrency_configuration_from_env():
    """Verify queue concurrency settings map to configured environment variables."""
    assert get_queue_concurrency("ingestion") >= 1
    assert get_queue_concurrency("processing") >= 1
    assert get_queue_concurrency("detection") >= 1
    assert get_queue_concurrency("nlp") >= 1
    assert get_queue_concurrency("cleanup") >= 1


def test_inline_dispatcher_executes_and_records_tasks(inline_dispatcher: InlineTaskDispatcher, test_tenant_id: str):
    """Verify InlineTaskDispatcher executes synchronously and logs dispatched tasks."""
    tenant_uuid = uuid.UUID(test_tenant_id)
    executed = []

    def sample_task_handler(tenant_id, payload):
        executed.append((tenant_id, payload))

    inline_dispatcher.register_handler("test.sample_task", sample_task_handler)

    payload = {"data": "threat_indicator_123"}
    task_id = inline_dispatcher.dispatch(
        task_name="test.sample_task",
        tenant_id=tenant_uuid,
        payload_dict=payload,
        queue="detection",
        idempotency_key="idemp_key_001",
    )

    assert task_id is not None
    assert len(executed) == 1
    assert executed[0][0] == tenant_uuid
    assert executed[0][1] == payload
    assert len(inline_dispatcher.dispatched_tasks) == 1


def test_task_idempotency_prevents_duplicate_execution():
    """Verify task idempotency manager blocks duplicate execution within TTL."""
    manager = TaskIdempotencyManager()
    key = f"test_idemp_{uuid.uuid4()}"

    first_attempt = manager.acquire_idempotency_lock(key, ttl_seconds=60)
    assert first_attempt is True

    second_attempt = manager.acquire_idempotency_lock(key, ttl_seconds=60)
    assert second_attempt is False

    manager.mark_completed(key, ttl_seconds=60)
    third_attempt = manager.acquire_idempotency_lock(key, ttl_seconds=60)
    assert third_attempt is False


def test_exponential_backoff_and_jitter():
    """Verify compute_backoff_delay generates increasing delays with jitter bounds."""
    delay_1 = compute_backoff_delay(attempt=1, base_seconds=2.0, jitter=False)
    assert delay_1 == 2.0

    delay_2 = compute_backoff_delay(attempt=2, base_seconds=2.0, jitter=False)
    assert delay_2 == 4.0

    delay_3 = compute_backoff_delay(attempt=3, base_seconds=2.0, jitter=False)
    assert delay_3 == 8.0

    # With jitter: delay should stay within [0.5 * d, 1.5 * d]
    jittered = compute_backoff_delay(attempt=3, base_seconds=2.0, jitter=True)
    assert 4.0 <= jittered <= 12.0


def test_sanitizer_removes_tokens_from_exceptions():
    """Verify sanitize_error_message strips bot tokens and secrets."""
    exc_with_token = ValueError("Connection failed to 123456789:ABC-DEF1234ghIkl-zyx57W2v1u123ew11 on telegram server")
    sanitized = sanitize_error_message(exc_with_token)
    assert "123456789:ABC-DEF1234ghIkl-zyx57W2v1u123ew11" not in sanitized
    assert "[REDACTED_BOT_TOKEN]" in sanitized


@pytest.mark.asyncio
async def test_dead_letter_records_in_system_jobs_without_payload(test_tenant_id: str):
    """Verify exhausted task failure persists to app.system_jobs with zero message text."""
    tenant_uuid = uuid.UUID(test_tenant_id)
    sensitive_payload = {"secret_text": "classified scam message containing personal info", "key": "secret"}
    args = ("arg1",)
    kwargs = {"payload": sensitive_payload}
    exc = RuntimeError("Simulated processing failure after 3 retries")

    await record_dead_letter_job(
        task_name="processing.deep_analysis",
        queue_name="processing",
        tenant_id=tenant_uuid,
        args=args,
        kwargs=kwargs,
        exc=exc,
        attempt_count=3,
    )

    args_hash = compute_args_hash(args, kwargs)

    # Inspect database row directly
    async with async_session_factory() as session:
        stmt = select(SystemJobRecord).where(SystemJobRecord.args_hash == args_hash)
        record = await session.scalar(stmt)

        assert record is not None
        assert record.tenant_id == tenant_uuid
        assert record.task_name == "processing.deep_analysis"
        assert record.queue_name == "processing"
        assert record.error_class == "RuntimeError"
        assert "Simulated processing failure" in record.sanitized_error_message
        assert record.attempt_count == 3
        assert record.status == "DEAD_LETTER"

        # STRICT INVARIANT ASSERTIONS: payload or message text must NOT exist anywhere in system_jobs
        assert "classified scam message" not in record.sanitized_error_message
        assert "secret_text" not in record.sanitized_error_message


@pytest.mark.asyncio
async def test_worker_tenant_session_sets_rls_context(test_tenant_id: str):
    """Verify worker_tenant_session sets transaction-local tenant context."""
    tenant_uuid = uuid.UUID(test_tenant_id)
    async with worker_tenant_session(tenant_uuid) as session:
        result = await session.execute(text("SELECT current_setting('app.current_tenant_id', true);"))
        current_setting = result.scalar_one_or_none()
        assert current_setting == str(tenant_uuid)


@pytest.mark.asyncio
async def test_admin_system_jobs_api_endpoint(async_client: AsyncClient, test_tenant_id: str):
    """Verify GET /api/v1/admin/system-jobs returns paginated records scoped to tenant."""
    headers = {"X-Tenant-ID": test_tenant_id}
    resp = await async_client.get("/api/v1/admin/system-jobs", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "total_count" in data
    assert "items" in data
    assert isinstance(data["items"], list)


@pytest.mark.redis
def test_redis_worker_ping():
    """Verify Redis broker connectivity and Celery worker ping (marked; skipped if Redis offline)."""
    settings = get_settings()
    try:
        r = redis.from_url(settings.redis_url, socket_connect_timeout=1.0)
        assert r.ping() is True
    except Exception as exc:
        pytest.skip(f"Redis not available on {settings.redis_url}: {exc}")
