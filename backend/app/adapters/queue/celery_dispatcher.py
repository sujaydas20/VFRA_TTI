"""Celery task dispatcher adapter for production queue execution."""

from typing import Any, Dict
from uuid import UUID
import uuid

from app.services.protocols import TaskDispatcher
from app.workers.celery_app import celery_app
from app.workers.idempotency import get_idempotency_manager


class CeleryTaskDispatcher(TaskDispatcher):
    """Dispatches background tasks to Celery worker mesh over Redis broker."""

    def __init__(self) -> None:
        self._idempotency = get_idempotency_manager()

    def dispatch(
        self,
        task_name: str,
        tenant_id: UUID,
        payload_dict: Dict[str, Any],
        queue: str = "processing",
        idempotency_key: str | None = None,
        countdown: int = 0,
    ) -> str:
        """Dispatch task to designated queue with tenant context."""
        # 1. Enforce idempotency if key provided
        if idempotency_key:
            acquired = self._idempotency.acquire_idempotency_lock(idempotency_key)
            if not acquired:
                return f"idempotent_duplicate:{idempotency_key}"

        # 2. Dispatch task via Celery
        kwargs = {
            "tenant_id": str(tenant_id),
            "payload": payload_dict,
            "idempotency_key": idempotency_key,
        }

        async_result = celery_app.send_task(
            name=task_name,
            kwargs=kwargs,
            queue=queue,
            countdown=countdown,
        )
        return async_result.id
