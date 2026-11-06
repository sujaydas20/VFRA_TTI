"""Telegram adapter package exporting Bot and Dispatcher factories."""

from app.adapters.telegram.bot import create_bot, create_dispatcher
from app.adapters.telegram.handlers import get_main_router

__all__ = [
    "create_bot",
    "create_dispatcher",
    "get_main_router",
]

