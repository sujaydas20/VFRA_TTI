"""Tests for non-negotiable group privacy invariants."""

import pytest
from httpx import AsyncClient
from sqlalchemy import select, func
from app.core.config import get_settings
from app.database.models.consent import ConsentedSubmissionRecord
from app.database.session import async_session_factory


@pytest.mark.asyncio
async def test_group_message_non_consenting_user_writes_zero_rows(async_client: AsyncClient):
    """In approved groups, non-command messages from unconsented users write zero rows."""
    settings = get_settings()
    update_id = 90050
    non_consenting_user_id = 777666555
    group_chat_id = -1001234567890

    # Count consented submission rows before
    async with async_session_factory() as session:
        count_before = (
            await session.execute(
                select(func.count()).select_from(ConsentedSubmissionRecord)
            )
        ).scalar() or 0

    payload = {
        "update_id": update_id,
        "message": {
            "message_id": 8801,
            "date": 1600000000,
            "chat": {"id": group_chat_id, "type": "supergroup", "title": "Test Group"},
            "from": {"id": non_consenting_user_id, "is_bot": False, "first_name": "Stranger"},
            "text": "Hey everyone, check this link out: https://suspicious-domain[.]example",
        },
    }
    headers = {"X-Telegram-Bot-Api-Secret-Token": settings.TTI_WEBHOOK_SECRET}

    resp = await async_client.post("/api/v1/telegram/webhook", json=payload, headers=headers)
    assert resp.status_code == 200

    # Assert row count remains completely unchanged
    async with async_session_factory() as session:
        count_after = (
            await session.execute(
                select(func.count()).select_from(ConsentedSubmissionRecord)
            )
        ).scalar() or 0

    assert count_after == count_before, "Unconsented group message must write zero rows to database!"

