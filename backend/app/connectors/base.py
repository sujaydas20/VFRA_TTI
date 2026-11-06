"""Base connector abstractions and lifecycle contracts.

NON-NEGOTIABLE ARCHITECTURAL RULES:
1. Connectors are sandboxed and must never initiate unauthorized network activity.
2. Credentials and configuration must be validated before any operation.
3. In Phase 1, live collection is deactivated. All connectors operate in safe stub mode.
4. All raw payloads ingested must be routed through the input sanitization pipeline.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional


class ConnectorStatus(str, Enum):
    """Lifecycle status of an intelligence source connector."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    DISCONNECTED = "disconnected"
    DISABLED = "disabled"
    UNCONFIGURED = "unconfigured"


@dataclass
class ConnectorHealth:
    """Diagnostic health assessment of a connector."""
    connector_id: str
    status: ConnectorStatus
    message: str
    is_live_collection_active: bool
    rate_limit_remaining: Optional[int] = None
    last_checked_utc: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


class BaseConnector(ABC):
    """
    Abstract interface defining the lifecycle and contract for all data sources.
    Connectors for Telegram and dark-web forums must adhere to this contract.
    """

    def __init__(self, connector_id: str):
        self.connector_id = connector_id

    @abstractmethod
    def validate_configuration(self) -> bool:
        """Validate presence and syntactic validity of required connector settings."""
        pass

    @abstractmethod
    async def health_check(self) -> ConnectorHealth:
        """Perform non-intrusive health assessment of the source connection."""
        pass

    @abstractmethod
    async def collect_batch(
        self,
        tenant_id: str,
        target_reference: str,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """
        Collect a batch of raw records.
        STRICT REQUIREMENT: In Phase 1, live collection MUST NOT be executed.
        """
        pass

    @abstractmethod
    async def disconnect(self) -> None:
        """Gracefully release network sockets, proxies, or client sessions."""
        pass
