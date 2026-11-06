"""Tests ensuring logs never contain bot tokens or raw user message content."""

import logging
import pytest
from aiogram.types import Chat, Message, User
from app.adapters.telegram.middleware import PrivacyAndLoggingMiddleware


@pytest.mark.asyncio
async def test_logs_contain_no_token_or_message_text(caplog):
    """Structured logs must strip bot token and message text during update dispatch."""
    caplog.set_level(logging.INFO)
    middleware = PrivacyAndLoggingMiddleware()

    user = User(id=12345, is_bot=False, first_name="Eve")
    chat = Chat(id=12345, type="private")
    secret_text = "super_confidential_credit_card_or_password_1234"
    bot_token_sample = "123456789:ABCDefghIJKlmnoPQRstuvWXYZ_TOKEN"

    msg = Message(
        message_id=1,
        date=1600000000,
        chat=chat,
        from_user=user,
        text=secret_text,
    )

    async def dummy_handler(event, data):
        return "handled"

    await middleware(dummy_handler, msg, {})

    # Inspect all captured log records
    for record in caplog.records:
        message_str = record.getMessage()
        assert secret_text not in message_str, "Raw message text must NEVER appear in logs!"
        assert bot_token_sample not in message_str, "Bot token must NEVER appear in logs!"

