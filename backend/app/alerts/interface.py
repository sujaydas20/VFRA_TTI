"""Alert notification interface."""

from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Dict, List
from pydantic import BaseModel, Field


class AlertPayload(BaseModel):
    """Structured threat alert message."""
    tenant_id: str
    alert_id: str
    severity: str
    title: str
    summary: str
    channels: List[str]  # e.g., ["email", "webhook", "slack"]
    created_at_utc: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = Field(default_factory=dict)


class AlertNotificationInterface(ABC):
    """Abstract interface for dispatching tenant-isolated alerts."""

    @abstractmethod
    async def dispatch_alert(self, alert: AlertPayload) -> bool:
        """Dispatch an alert through configured customer delivery channels."""
        pass
