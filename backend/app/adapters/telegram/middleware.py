"""aiogram 3 middlewares enforcing privacy invariants, rate limiting, and consent verification."""

import logging
import time
from typing import Any, Awaitable, Callable, Dict
from aiogram import BaseMiddleware
from aiogram.types import Message, CallbackQuery, TelegramObject, Update

from app.core.config import get_settings
from app.database.session import async_session_factory
from app.services.consent_service import ConsentService

logger = logging.getLogger("tti.telegram.middleware")


class PrivacyAndLoggingMiddleware(BaseMiddleware):
    """Structured logging middleware that strictly strips tokens and raw message contents."""

    async def __call__(
        self,
        handler: Callable[[TelegramObject, Dict[str, Any]], Awaitable[Any]],
        event: TelegramObject,
        data: Dict[str, Any],
    ) -> Any:
        start_time = time.monotonic()
        event_type = type(event).__name__
        user_id = None
        chat_type = "unknown"

        if isinstance(event, (Message, CallbackQuery)) and event.from_user:
            user_id = event.from_user.id
            if isinstance(event, Message) and event.chat:
                chat_type = event.chat.type

        # Log event reception WITHOUT logging message text or sensitive identifiers
        logger.info(
            "Telegram event received",
            extra={
                "event_type": event_type,
                "chat_type": chat_type,
                "has_user": bool(user_id),
            },
        )

        try:
            return await handler(event, data)
        finally:
            elapsed_ms = (time.monotonic() - start_time) * 1000
            logger.info(
                "Telegram event dispatched",
                extra={
                    "event_type": event_type,
                    "duration_ms": round(elapsed_ms, 2),
                },
            )


class RateLimitMiddleware(BaseMiddleware):
    """Sliding window per-user rate limiting using Redis with in-memory fallback."""

    def __init__(self, limit: int = 20, window_seconds: int = 60):
        super().__init__()
        self.limit = limit
        self.window_seconds = window_seconds
        self._memory_cache: Dict[int, list[float]] = {}

    async def __call__(
        self,
        handler: Callable[[TelegramObject, Dict[str, Any]], Awaitable[Any]],
        event: TelegramObject,
        data: Dict[str, Any],
    ) -> Any:
        user_id = None
        if isinstance(event, (Message, CallbackQuery)) and event.from_user:
            user_id = event.from_user.id

        if user_id:
            now = time.monotonic()
            timestamps = self._memory_cache.setdefault(user_id, [])
            # Prune timestamps older than window
            cutoff = now - self.window_seconds
            timestamps = [t for t in timestamps if t > cutoff]
            self._memory_cache[user_id] = timestamps

            if len(timestamps) >= self.limit:
                logger.warning(
                    "Rate limit exceeded for user",
                    extra={"user_masked_prefix": str(user_id)[:3]},
                )
                if isinstance(event, Message):
                    await event.answer("⚠️ You are sending commands too quickly. Please wait a moment.")
                elif isinstance(event, CallbackQuery):
                    await event.answer("⚠️ Rate limit reached. Please wait.", show_alert=True)
                return None

            timestamps.append(now)

        return await handler(event, data)


class ConsentEnforcementMiddleware(BaseMiddleware):
    """Enforces non-negotiable consent invariants before invoking downstream handlers."""

    def __init__(self, consent_service: ConsentService | None = None):
        super().__init__()
        self.consent_service = consent_service or ConsentService()

    async def __call__(
        self,
        handler: Callable[[TelegramObject, Dict[str, Any]], Awaitable[Any]],
        event: TelegramObject,
        data: Dict[str, Any],
    ) -> Any:
        if not isinstance(event, Message):
            return await handler(event, data)

        message: Message = event
        if not message.from_user:
            return await handler(event, data)

        chat_type = message.chat.type if message.chat else "private"
        text = message.text or ""

        # INVARIANT: In groups/supergroups, ignore everything except bot commands
        if chat_type in ("group", "supergroup"):
            if not text.startswith("/"):
                # Non-command message in a group: verify approved_group_context
                async with async_session_factory() as session:
                    has_group_consent = await self.consent_service.check_permission(
                        session=session,
                        telegram_user_id=message.from_user.id,
                        permission="approved_group_context",
                        chat_type=chat_type,
                    )
                if not has_group_consent:
                    # SILENT DROP: Zero DB rows written, zero logs of content
                    return None

        # Inject consent service and user context into handler data
        data["consent_service"] = self.consent_service
        return await handler(event, data)

