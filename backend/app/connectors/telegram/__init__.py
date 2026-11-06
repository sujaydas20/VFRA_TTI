"""Telegram connector package for TTI."""
from app.connectors.telegram.interface import TelegramConnectorInterface
from app.connectors.telegram.stub import TelegramConnectorStub
from app.connectors.telegram.models import TelegramMessagePayload, TelegramChannelMetadata

__all__ = [
    "TelegramConnectorInterface",
    "TelegramConnectorStub",
    "TelegramMessagePayload",
    "TelegramChannelMetadata",
]
