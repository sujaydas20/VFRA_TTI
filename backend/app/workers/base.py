"""Base task utilities, tenant context injection, and dead-letter queue persistence."""

from contextlib import asynccontextmanager
from datetime import datetime, timezone
import hashlib
import json
import logging
import random
import re
from typing import Any, AsyncGenerator, Dict, Tuple
from uuid import UUID
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import async_session_factory, set_transaction_tenant_context

logger = logging.getLogger("tti.workers")


@asynccontextmanager
async def worker_tenant_session(tenant_id: UUID | str) -> AsyncGenerator[AsyncSession, None]:
    """Provide an asynchronous database session with transaction-local tenant context.

    Enforces SET LOCAL app.current_tenant_id so all row-level security (RLS) policies
    and tenant constraints are automatically applied within the worker process.
    """
    if isinstance(tenant_id, str):
        tenant_id = UUID(tenant_id)

    async with async_session_factory() as session:
        async with session.begin():
            await set_transaction_tenant_context(session, tenant_id)
            yield session


def compute_backoff_delay(
    attempt: int,
    base_seconds: float = 2.0,
    max_seconds: float = 60.0,
    jitter: bool = True,
) -> float:
    """Compute exponential backoff delay with decorrelated jitter."""
    delay = min(max_seconds, base_seconds * (2 ** (attempt - 1)))
    if jitter:
        # Full jitter between 0.5 * delay and 1.5 * delay
        delay = random.uniform(0.5 * delay, 1.5 * delay)
    return round(delay, 2)


def compute_args_hash(args: Tuple[Any, ...], kwargs: Dict[str, Any]) -> str:
    """Compute SHA-256 cryptographic digest of task inputs.

    Guarantees that no raw message text, user parameters, or credentials
    are stored in dead-letter audit tables.
    """
    try:
        serialized = json.dumps({"args": args, "kwargs": kwargs}, sort_keys=True, default=str)
    except Exception:
        serialized = f"args:{str(args)}|kwargs:{str(kwargs)}"
    return hashlib.sha256(serialized.encode()).hexdigest()


def sanitize_error_message(exc: Exception) -> str:
    """Extract and sanitize error representation, stripping token-like strings."""
    raw = str(exc)
    # Match Telegram bot token pattern: digits:alphanumeric_or_hyphen (30-45 chars)
    cleaned = re.sub(r"\b\d{8,12}:[-A-Za-z0-9_]{30,45}\b", "[REDACTED_BOT_TOKEN]", raw)
    return cleaned[:1000]


async def record_dead_letter_job(
    task_name: str,
    queue_name: str,
    tenant_id: UUID | str | None,
    args: Tuple[Any, ...],
    kwargs: Dict[str, Any],
    exc: Exception,
    attempt_count: int,
) -> None:
    """Persist exhausted failed task to app.system_jobs table.

    STRICT INVARIANT: NEVER stores task arguments, payload data, or raw message text.
    """
    t_id = UUID(str(tenant_id)) if tenant_id else None
    args_hash = compute_args_hash(args, kwargs)
    error_class = type(exc).__name__
    sanitized_msg = sanitize_error_message(exc)

    insert_query = text(
        """
        INSERT INTO app.system_jobs (
            job_id, tenant_id, task_name, queue_name, args_hash,
            error_class, sanitized_error_message, attempt_count,
            status, created_at, failed_at
        ) VALUES (
            gen_random_uuid(), :tenant_id, :task_name, :queue_name, :args_hash,
            :error_class, :sanitized_msg, :attempt_count,
            'DEAD_LETTER', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
        );
        """
    )

    try:
        async with async_session_factory() as session:
            async with session.begin():
                await session.execute(
                    insert_query,
                    {
                        "tenant_id": t_id,
                        "task_name": task_name,
                        "queue_name": queue_name,
                        "args_hash": args_hash,
                        "error_class": error_class,
                        "sanitized_msg": sanitized_msg,
                        "attempt_count": attempt_count,
                    },
                )
        logger.error(
            "Task dead-lettered to system_jobs",
            extra={
                "task_name": task_name,
                "queue_name": queue_name,
                "error_class": error_class,
                "attempts": attempt_count,
            },
        )
    except Exception as db_err:
        logger.critical(f"Failed to record dead-letter job in database: {db_err}", exc_info=False)
