"""Core service protocols and abstract interfaces for TTI.

Services depend on these abstract protocols, strictly isolating them
from underlying queue frameworks (Celery), caches (Redis), or databases.
"""

from typing import Any, Dict, List, Optional, Protocol, Tuple, runtime_checkable
from uuid import UUID
from sqlalchemy.ext.asyncio import AsyncSession


@runtime_checkable
class TaskDispatcher(Protocol):
    """Abstract interface for dispatching background tasks to worker mesh."""

    def dispatch(
        self,
        task_name: str,
        tenant_id: UUID,
        payload_dict: Dict[str, Any],
        queue: str = "processing",
        idempotency_key: str | None = None,
        countdown: int = 0,
    ) -> str:
        """Dispatch a task with tenant context and return a unique task identifier."""
        ...


@runtime_checkable
class RateLimiter(Protocol):
    """Abstract interface for sliding-window rate limiters."""

    async def check_rate_limit(
        self,
        key: str,
        limit: int,
        window_seconds: int,
    ) -> Tuple[bool, int]:
        """Check if action is allowed under the rate limit.

        Returns:
            Tuple[bool, int]: (allowed, retry_after_seconds)
            If allowed is True, retry_after_seconds is 0.
            If allowed is False, retry_after_seconds is > 0.
        """
        ...


@runtime_checkable
class ConsentCheckerProtocol(Protocol):
    """Protocol defining the statutory consent verification contract."""

    async def check_permission(
        self,
        session: AsyncSession,
        telegram_user_id: int,
        permission: str,
        chat_type: str = "private",
    ) -> bool:
        """Return True if subject has active, non-superseded consent for this permission."""
        ...

    async def enforce_permission(
        self,
        session: AsyncSession,
        telegram_user_id: int,
        permission: str,
        chat_type: str = "private",
    ) -> None:
        """Raise ConsentRequiredError if permission is not granted."""
        ...

    async def grant_permissions(
        self,
        session: AsyncSession,
        telegram_user_id: int,
        permissions_update: Dict[str, bool],
        chat_context: Optional[Dict[str, Any]] = None,
    ) -> Any:
        """Store versioned consent grant."""
        ...

    async def revoke_consent(
        self,
        session: AsyncSession,
        telegram_user_id: int,
        permissions_to_revoke: Optional[List[str]] = None,
    ) -> Any:
        """Revoke active consent permissions and trigger retention policies."""
        ...

    async def execute_deletion(
        self,
        session: AsyncSession,
        telegram_user_id: int,
    ) -> Dict[str, Any]:
        """Erase subject telemetry and record non-reversible audit ledger entry."""
        ...


@runtime_checkable
class DetectionSink(Protocol):
    """Protocol defining output destinations for threat detection events.
    
    Decouples detection engine from downstream alerts, message queues, and metrics.
    """

    async def emit(self, detection: Any) -> None:
        """Emit a detection event to sink."""
        ...
