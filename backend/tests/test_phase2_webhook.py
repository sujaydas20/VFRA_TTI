"""Tests for Telegram webhook ingestion, secret verification, and deduplication."""

import json
import pytest
from httpx import AsyncClient
from sqlalchemy import text
from app.core.config import get_settings
from app.database.session import async_session_factory


@pytest.mark.asyncio
async def test_webhook_missing_secret_token_returns_403(async_client: AsyncClient):
    """Webhook rejects requests lacking X-Telegram-Bot-Api-Secret-Token with 403."""
    payload = {"update_id": 10001, "message": {"message_id": 1, "date": 1600000000, "chat": {"id": 123, "type": "private"}, "text": "hello"}}
    resp = await async_client.post("/api/v1/telegram/webhook", json=payload)
    assert resp.status_code == 403
    assert "Invalid or missing webhook secret token" in resp.json()["detail"]["message"]


@pytest.mark.asyncio
async def test_webhook_invalid_secret_token_returns_403(async_client: AsyncClient):
    """Webhook rejects requests with wrong secret token with 403."""
    payload = {"update_id": 10002, "message": {"message_id": 2, "date": 1600000000, "chat": {"id": 123, "type": "private"}, "text": "hello"}}
    headers = {"X-Telegram-Bot-Api-Secret-Token": "incorrect_secret_token_attempt"}
    resp = await async_client.post("/api/v1/telegram/webhook", json=payload, headers=headers)
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_webhook_valid_secret_token_returns_200_and_stores_update(async_client: AsyncClient):
    """Webhook accepts valid secret token, returns 200, and records update in app.webhook_updates."""
    settings = get_settings()
    update_id = 90001
    payload = {
        "update_id": update_id,
        "message": {
            "message_id": 501,
            "date": 1600000000,
            "chat": {"id": 999888, "type": "private"},
            "from": {"id": 999888, "is_bot": False, "first_name": "Alice"},
            "text": "/start",
        },
    }
    headers = {"X-Telegram-Bot-Api-Secret-Token": settings.TTI_WEBHOOK_SECRET}
    resp = await async_client.post("/api/v1/telegram/webhook", json=payload, headers=headers)
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"
    assert resp.json()["update_id"] == update_id

    # Verify update row in database
    async with async_session_factory() as session:
        res = await session.execute(
            text("SELECT update_id, status FROM app.webhook_updates WHERE update_id = :uid"),
            {"uid": update_id},
        )
        row = res.fetchone()
        assert row is not None
        assert row[0] == update_id


@pytest.mark.asyncio
async def test_webhook_duplicate_update_id_is_idempotent(async_client: AsyncClient):
    """Re-delivering the same update_id returns 200 and processes only once."""
    settings = get_settings()
    update_id = 90002
    payload = {
        "update_id": update_id,
        "message": {
            "message_id": 502,
            "date": 1600000000,
            "chat": {"id": 999888, "type": "private"},
            "from": {"id": 999888, "is_bot": False, "first_name": "Alice"},
            "text": "/help",
        },
    }
    headers = {"X-Telegram-Bot-Api-Secret-Token": settings.TTI_WEBHOOK_SECRET}

    # First delivery
    resp1 = await async_client.post("/api/v1/telegram/webhook", json=payload, headers=headers)
    assert resp1.status_code == 200
    assert resp1.json()["status"] == "ok"

    # Second delivery (duplicate)
    resp2 = await async_client.post("/api/v1/telegram/webhook", json=payload, headers=headers)
    assert resp2.status_code == 200
    assert resp2.json()["status"] == "ok"
    assert resp2.json().get("message") == "duplicate_update_ignored"


@pytest.mark.asyncio
async def test_webhook_ignores_unsupported_update_type(async_client: AsyncClient):
    """Updates outside allowed types (e.g. channel_post) return 200 with ignored status."""
    settings = get_settings()
    update_id = 90003
    payload = {
        "update_id": update_id,
        "channel_post": {
            "message_id": 901,
            "date": 1600000000,
            "chat": {"id": -100111222333, "type": "channel", "title": "Public Broadcast"},
            "text": "Broadcast message",
        },
    }
    headers = {"X-Telegram-Bot-Api-Secret-Token": settings.TTI_WEBHOOK_SECRET}
    resp = await async_client.post("/api/v1/telegram/webhook", json=payload, headers=headers)
    assert resp.status_code == 200
    assert resp.json()["status"] == "ignored"
    assert resp.json()["reason"] == "update_type_channel_post_not_in_allowed_set"
