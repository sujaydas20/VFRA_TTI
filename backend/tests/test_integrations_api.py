"""GET /api/v1/integrations returns real inventory and never leaks secrets."""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_integrations_endpoint_static_inventory(async_client: AsyncClient):
    """Static (probe=false) inventory resolves without touching the network."""
    response = await async_client.get("/api/v1/integrations?probe=false")
    assert response.status_code == 200
    payload = response.json()

    assert payload["total"] >= 6
    providers = {row["provider"] for row in payload["integrations"]}
    assert "Telegram MTProto (Telethon)" in providers
    assert "Telegram Bot API (aiogram)" in providers

    for row in payload["integrations"]:
        assert "credential_fingerprint" in row
        assert row["connection_status"] in ("connected", "not_connected", "disabled")
        assert row["configuration_completeness"] in ("complete", "partial", "missing_credentials")


@pytest.mark.asyncio
async def test_integrations_endpoint_never_returns_secret_values(async_client: AsyncClient):
    """No configured secret value may appear anywhere in the response body."""
    from app.core.config import get_settings

    settings = get_settings()
    secrets_to_protect = [
        settings.TTI_TELEGRAM_BOT_TOKEN,
        settings.TTI_TELEGRAM_SESSION,
        settings.TTI_TELEGRAM_API_HASH,
        settings.TTI_SECRET_KEY,
    ]
    response = await async_client.get("/api/v1/integrations?probe=false")
    body = response.text

    for secret in secrets_to_protect:
        if secret:
            assert secret not in body, "credential leaked into integrations response"