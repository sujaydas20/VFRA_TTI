"""Tests for modular connector interfaces and safe stub implementations."""

import pytest
from app.connectors.base import ConnectorStatus
from app.connectors.telegram.stub import TelegramConnectorStub
from app.connectors.darkweb.stub import DarkWebConnectorStub


@pytest.mark.asyncio
async def test_telegram_connector_stub_lifecycle():
    """Verify Telegram connector stub operates strictly in safe inert mode."""
    stub = TelegramConnectorStub()

    # In Phase 1, live configuration validation returns False
    assert stub.validate_configuration() is False

    # Health check reflects DISABLED status by security policy
    health = await stub.health_check()
    assert health.connector_id == "telegram-stub"
    assert health.status == ConnectorStatus.DISABLED
    assert health.is_live_collection_active is False
    assert "safe stub mode" in health.message

    # Test simulated fetch without live network
    channel_info = await stub.fetch_channel_info("@testthreatintel")
    assert channel_info is not None
    assert channel_info.username == "testthreatintel"

    # Test mock batch collection
    messages = await stub.collect_channel_messages(
        tenant_id="00000000-0000-0000-0000-000000000001",
        channel_identifier="@testthreatintel",
    )
    assert len(messages) == 1
    assert "mock_sample" in messages[0].extra_metadata


@pytest.mark.asyncio
async def test_darkweb_connector_stub_lifecycle():
    """Verify Dark-Web connector stub operates strictly in safe inert mode."""
    stub = DarkWebConnectorStub()

    # Configuration validation
    assert stub.validate_configuration() is False

    # Health check reflects DISABLED status
    health = await stub.health_check()
    assert health.connector_id == "darkweb-stub"
    assert health.status == ConnectorStatus.DISABLED
    assert health.is_live_collection_active is False

    # Test simulated page fetch
    page = await stub.fetch_page(
        tenant_id="00000000-0000-0000-0000-000000000001",
        target_onion_url="http://syntheticforum7894.onion",
    )
    assert page is not None
    assert page.onion_url == "http://syntheticforum7894.onion"
    assert len(page.thread_items) > 0
