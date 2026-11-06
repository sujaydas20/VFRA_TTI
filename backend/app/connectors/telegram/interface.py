"""Contract interface for Telegram ingestion connectors."""

from abc import abstractmethod
from typing import List, Optional
from app.connectors.base import BaseConnector
from app.connectors.telegram.models import TelegramChannelMetadata, TelegramMessagePayload


class TelegramConnectorInterface(BaseConnector):
    """
    Specialized interface for Telegram channel and thread intelligence collection.
    Concrete implementations must handle MTProto/TDLib or official API gateways
    under authorized governance policies.
    """

    def __init__(self, connector_id: str = "telegram-connector"):
        super().__init__(connector_id=connector_id)

    @abstractmethod
    async def fetch_channel_info(self, channel_identifier: str) -> Optional[TelegramChannelMetadata]:
        """Retrieve non-intrusive metadata for an authorized public target."""
        pass

    @abstractmethod
    async def collect_channel_messages(
        self,
        tenant_id: str,
        channel_identifier: str,
        limit: int = 50,
        offset_id: int = 0,
    ) -> List[TelegramMessagePayload]:
        """
        Ingest message thread history.
        Must enforce tenant_id propagation and return strictly typed payloads.
        """
        pass
