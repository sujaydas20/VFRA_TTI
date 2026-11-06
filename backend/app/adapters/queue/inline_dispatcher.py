"""Inline synchronous task dispatcher for hermetic unit testing without Redis/Celery."""

from typing import Any, Callable, Dict, List
from uuid import UUID
import uuid

from app.services.protocols import TaskDispatcher
from app.workers.idempotency import get_idempotency_manager


class InlineTaskDispatcher(TaskDispatcher):
    """Executes background tasks synchronously in-process for test environments."""

    def __init__(self) -> None:
        self.dispatched_tasks: List[Dict[str, Any]] = []
        self._handlers: Dict[str, Callable[..., Any]] = {}
        self._idempotency = get_idempotency_manager()

    def register_handler(self, task_name: str, handler: Callable[..., Any]) -> None:
        """Register a callable handler for a specific task name."""
        self._handlers[task_name] = handler

    def dispatch(
        self,
        task_name: str,
        tenant_id: UUID,
        payload_dict: Dict[str, Any],
        queue: str = "processing",
        idempotency_key: str | None = None,
        countdown: int = 0,
    ) -> str:
        """Execute or record task inline."""
        if idempotency_key:
            acquired = self._idempotency.acquire_idempotency_lock(idempotency_key)
            if not acquired:
                return f"idempotent_duplicate:{idempotency_key}"

        task_id = str(uuid.uuid4())
        record = {
            "task_id": task_id,
            "task_name": task_name,
            "tenant_id": tenant_id,
            "payload": payload_dict,
            "queue": queue,
            "idempotency_key": idempotency_key,
            "countdown": countdown,
        }
        self.dispatched_tasks.append(record)

        # If a handler is registered, execute it immediately
        if task_name in self._handlers:
            handler = self._handlers[task_name]
            handler(tenant_id=tenant_id, payload=payload_dict)

        if idempotency_key:
            self._idempotency.mark_completed(idempotency_key)

        return task_id

    def clear(self) -> None:
        """Reset recorded dispatches."""
        self.dispatched_tasks.clear()
