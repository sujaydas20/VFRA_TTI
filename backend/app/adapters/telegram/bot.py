"""Telegram bot initialization and factory for aiogram 3.

Adheres to:
- aiogram 3.x modern asynchronous dispatcher.
- HTML parse mode default.
- Zero credential exposure in logs or exceptions.
- Unified middleware pipeline across webhook and polling modes.
"""

from typing import Any, Optional
from aiogram import Bot, Dispatcher
from aiogram.client.default import DefaultBotProperties
from aiogram.client.session.base import BaseSession
from aiogram.enums import ParseMode
from aiogram.methods import TelegramMethod
from aiogram.methods.base import TelegramType
from aiogram.types import Chat, Message, User

from app.adapters.telegram.handlers import get_main_router
from app.adapters.telegram.middleware import (
    ConsentEnforcementMiddleware,
    PrivacyAndLoggingMiddleware,
    RateLimitMiddleware,
)
from app.core.config import get_settings


class MockTelegramSession(BaseSession):
    """Hermetic in-memory Telegram session for local testing and offline execution."""

    def __init__(self) -> None:
        super().__init__()
        self.sent_methods: list[Any] = []

    async def close(self) -> None:
        pass

    async def make_request(
        self,
        bot: Bot,
        method: TelegramMethod[TelegramType],
        timeout: int | None = None,
    ) -> TelegramType:
        from datetime import datetime, timezone

        self.sent_methods.append(method)
        ret_type = method.__returning__
        if ret_type is bool:
            return True  # type: ignore
        if ret_type is Message:
            chat_id = getattr(method, "chat_id", 1)
            c_id = int(chat_id) if str(chat_id).lstrip("-").isdigit() else 1
            return Message(
                message_id=9999,
                date=datetime.now(timezone.utc),
                chat=Chat(id=c_id, type="private"),
                from_user=User(id=0, is_bot=True, first_name="TTI Bot"),
                text=getattr(method, "text", ""),
            )  # type: ignore
        if hasattr(ret_type, "__call__"):
            try:
                return ret_type()  # type: ignore
            except Exception:
                pass
        return True  # type: ignore

    async def stream_content(self, url: str, timeout: int = 30, chunk_size: int = 65536):
        yield b""


def create_bot(token: Optional[str] = None, session: Optional[BaseSession] = None) -> Bot:
    """Create and configure aiogram Bot instance with safe defaults."""
    settings = get_settings()
    active_token = token or settings.TTI_TELEGRAM_BOT_TOKEN
    if not active_token:
        # Provide a synthetic dummy token for offline/test environments
        active_token = "0000000000:AAEBogusTestTokenForLocalHarness000"

    active_session = session
    if active_session is None and settings.TTI_ENV in ("test", "testing"):
        active_session = MockTelegramSession()

    return Bot(
        token=active_token,
        session=active_session,
        default=DefaultBotProperties(parse_mode=ParseMode.HTML),
    )


_dispatcher_singleton: Optional[Dispatcher] = None


def create_dispatcher() -> Dispatcher:
    """Create and configure aiogram Dispatcher with middleware and handlers.

    Handler sub-routers are module-level singletons that can only be attached to
    one parent router per process, so the Dispatcher itself is cached and reused.
    """
    global _dispatcher_singleton
    if _dispatcher_singleton is not None:
        return _dispatcher_singleton

    dp = Dispatcher()

    # Outer middlewares (executed for all incoming updates)
    dp.update.outer_middleware(PrivacyAndLoggingMiddleware())
    dp.update.outer_middleware(RateLimitMiddleware())
    dp.update.outer_middleware(ConsentEnforcementMiddleware())

    # Include consolidated command & callback routers
    dp.include_router(get_main_router())

    _dispatcher_singleton = dp
    return dp
