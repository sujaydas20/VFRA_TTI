"""Safe stub implementation of Dark-Web connector for Phase 1 foundation.

SECURITY COMPLIANCE:
--------------------
- Live dark-web / Tor scraping is STRICTLY DISABLED in Phase 1.
- No live SOCKS5 proxy circuits are established.
- No active .onion network probes or connections are initiated.
- Provides controlled, synthetic mock payloads for testing ingestion and sanitization.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from app.connectors.base import ConnectorHealth, ConnectorStatus
from app.connectors.darkweb.interface import DarkWebConnectorInterface
from app.connectors.darkweb.models import DarkWebPagePayload, DarkWebThreadItem
from app.core.config import get_settings
from app.core.errors import ConnectorNotConfiguredError


class DarkWebConnectorStub(DarkWebConnectorInterface):
    """
    Phase 1 inert Dark-Web connector stub.
    Implements interface compliance, proxy health verification stubs, and synthetic samples.
    """

    def __init__(self, connector_id: str = "darkweb-stub"):
        super().__init__(connector_id=connector_id)
        self.settings = get_settings()

    def validate_configuration(self) -> bool:
        """Check if connector has active operational configuration."""
        return bool(self.settings.TTI_DARKWEB_CONNECTOR_ACTIVE)

    async def health_check(self) -> ConnectorHealth:
        """Perform diagnostic health check without initiating network requests."""
        is_active = self.settings.TTI_DARKWEB_CONNECTOR_ACTIVE
        status = ConnectorStatus.HEALTHY if is_active else ConnectorStatus.DISABLED
        message = (
            "Dark-web connector is running in Phase 1 safe stub mode (live collection disabled)."
            if not is_active
            else "Dark-web connector active."
        )

        return ConnectorHealth(
            connector_id=self.connector_id,
            status=status,
            message=message,
            is_live_collection_active=is_active,
            rate_limit_remaining=500 if not is_active else 10,
            last_checked_utc=datetime.now(timezone.utc).isoformat(),
            metadata={
                "mode": "inert_stub",
                "phase": "phase_1_initialization",
                "proxy_configured": bool(self.settings.TTI_DARKWEB_SOCKS_PROXY),
            },
        )

    async def fetch_page(
        self,
        tenant_id: str,
        target_onion_url: str,
    ) -> Optional[DarkWebPagePayload]:
        """Return synthetic mock dark-web payload for ingestion testing."""
        if not self.settings.TTI_DARKWEB_CONNECTOR_ACTIVE:
            return DarkWebPagePayload(
                page_id="dw_mock_9876",
                onion_url=target_onion_url or "http://mockleaksv463456345.onion",
                site_title="Mock Underground Leak Forum",
                category="ransomware_leak",
                captured_at_utc=datetime.now(timezone.utc),
                raw_html="<html><body><h1>Synthetic Threat Sample</h1><p>Credentials dump sample...</p></body></html>",
                extracted_text="Synthetic Threat Sample: Credentials dump sample...",
                thread_items=[
                    DarkWebThreadItem(
                        post_id="post_001",
                        author_alias="dark_actor_99",
                        raw_content="Target credentials database archive verified.",
                    )
                ],
                proxy_routed_via="simulated_socks5_internal",
                extra_metadata={"mock_sample": True, "tenant_id": tenant_id},
            )
        raise ConnectorNotConfiguredError("Live Dark-Web collection is not authorized or configured.")

    async def collect_forum_threads(
        self,
        tenant_id: str,
        target_onion_url: str,
        limit: int = 20,
    ) -> List[DarkWebPagePayload]:
        """Collect forum thread samples for test harnesses."""
        page = await self.fetch_page(tenant_id=tenant_id, target_onion_url=target_onion_url)
        return [page] if page else []

    async def collect_batch(
        self,
        tenant_id: str,
        target_reference: str,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """Generic connector batch interface implementation."""
        pages = await self.collect_forum_threads(
            tenant_id=tenant_id,
            target_onion_url=target_reference,
            limit=limit,
        )
        return [p.model_dump() for p in pages]

    async def disconnect(self) -> None:
        """Inert stub cleanup."""
        pass
