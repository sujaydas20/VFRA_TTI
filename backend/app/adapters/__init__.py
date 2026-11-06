"""External adapter interfaces and implementations."""

from app.adapters.protocols import (
    TelegramBotAdapterProtocol,
    AlertNotifierProtocol,
    NLPEngineProtocol,
)

__all__ = [
    "TelegramBotAdapterProtocol",
    "AlertNotifierProtocol",
    "NLPEngineProtocol",
]

