"""Contract interface for Dark-Web ingestion connectors."""

from abc import abstractmethod
from typing import List, Optional
from app.connectors.base import BaseConnector
from app.connectors.darkweb.models import DarkWebPagePayload


class DarkWebConnectorInterface(BaseConnector):
    """
    Specialized interface for Tor / I2P / Dark-Web marketplace and forum collection.
    Concrete implementations must handle Tor SOCKS5 proxies, rate-limiting backoff,
    and circuit isolation under strict legal and operational authorization.
    """

    def __init__(self, connector_id: str = "darkweb-connector"):
        super().__init__(connector_id=connector_id)

    @abstractmethod
    async def fetch_page(
        self,
        tenant_id: str,
        target_onion_url: str,
    ) -> Optional[DarkWebPagePayload]:
        """Fetch and structure an authorized target page."""
        pass

    @abstractmethod
    async def collect_forum_threads(
        self,
        tenant_id: str,
        target_onion_url: str,
        limit: int = 20,
    ) -> List[DarkWebPagePayload]:
        """
        Collect forum thread topics and posts.
        Must enforce tenant isolation and return typed raw payloads.
        """
        pass
