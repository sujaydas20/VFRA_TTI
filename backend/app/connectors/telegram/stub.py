"""Safe stub implementation of Telegram connector for Phase 1 foundation.

SECURITY COMPLIANCE:
--------------------
- Live collection is STRICTLY DISABLED in Phase 1.
- No real Telegram credentials (api_id, api_hash, bot_token) are requested or used.
- No live network requests to Telegram servers are initiated.
- Provides test-safe mock records to validate the ingestion and sanitization pipeline.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from app.connectors.base import ConnectorHealth, ConnectorStatus
from app.connectors.telegram.interface import TelegramConnectorInterface
from app.connectors.telegram.models import TelegramChannelMetadata, TelegramMessagePayload
from app.core.config import get_settings
from app.core.errors import ConnectorNotConfiguredError


class TelegramConnectorStub(TelegramConnectorInterface):
    """
    Phase 1 inert Telegram connector stub.
    Implements interface compliance, health diagnostics, and mock collection for test harnesses.
    """

    def __init__(self, connector_id: str = "telegram-stub"):
        super().__init__(connector_id=connector_id)
        self.settings = get_settings()

    def validate_configuration(self) -> bool:
        """Check if connector has valid operational configuration."""
        # In Phase 1, live collection is explicitly disabled by design.
        return bool(self.settings.TTI_TELEGRAM_CONNECTOR_ACTIVE)

    async def health_check(self) -> ConnectorHealth:
        """Perform diagnostic health check without initiating external network requests."""
        is_active = self.settings.TTI_TELEGRAM_CONNECTOR_ACTIVE
        status = ConnectorStatus.HEALTHY if is_active else ConnectorStatus.DISABLED
        message = (
            "Telegram connector is running in Phase 1 safe stub mode (live collection disabled)."
            if not is_active
            else "Telegram connector active."
        )

        return ConnectorHealth(
            connector_id=self.connector_id,
            status=status,
            message=message,
            is_live_collection_active=is_active,
            rate_limit_remaining=1000 if not is_active else 50,
            last_checked_utc=datetime.now(timezone.utc).isoformat(),
            metadata={
                "mode": "inert_stub",
                "phase": "phase_1_initialization",
                "auth_required_in_phase_2": True,
            },
        )

    async def fetch_channel_info(self, channel_identifier: str) -> Optional[TelegramChannelMetadata]:
        """Return inert simulated channel metadata for testing pipeline behavior."""
        if not channel_identifier:
            return None
        return TelegramChannelMetadata(
            channel_id=123456789,
            title=f"Mock Threat Channel ({channel_identifier})",
            username=channel_identifier.replace("@", ""),
            participant_count=1337,
            is_broadcast=True,
            is_verified=False,
            description="Phase 1 Mock Channel for Schema and Sanitization Validation",
        )

    async def collect_channel_messages(
        self,
        tenant_id: str,
        channel_identifier: str,
        limit: int = 50,
        offset_id: int = 0,
    ) -> List[TelegramMessagePayload]:
        """
        Simulate message retrieval for pipeline and test verification.
        Refuses live collection if TTI_TELEGRAM_CONNECTOR_ACTIVE is False.
        """
        if not self.settings.TTI_TELEGRAM_CONNECTOR_ACTIVE:
            # Provide controlled mock data to exercise the downstream ingestion pipeline
            return [
                TelegramMessagePayload(
                    message_id=101,
                    channel_id=123456789,
                    channel_title=f"Mock Threat Channel ({channel_identifier})",
                    sender_id=987654321,
                    sender_username="threat_actor_alpha",
                    date_utc=datetime.now(timezone.utc),
                    raw_text="Sample raw message containing IOC: hxxps://threat-sample[.]local/leak.zip",
                    views_count=42,
                    extra_metadata={"mock_sample": True, "tenant_id": tenant_id},
                )
            ]
        raise ConnectorNotConfiguredError("Live Telegram collection is not authorized or implemented.")

    async def collect_batch(
        self,
        tenant_id: str,
        target_reference: str,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """Generic connector batch interface implementation."""
        messages = await self.collect_channel_messages(
            tenant_id=tenant_id,
            channel_identifier=target_reference,
            limit=limit,
        )
        return [msg.model_dump() for msg in messages]

    async def disconnect(self) -> None:
        """Inert stub cleanup."""
        pass
