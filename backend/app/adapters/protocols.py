"""Abstract interface protocols for external adapters.

Follows SOLID Principles: High-level application modules depend on these
abstractions, not on concrete I/O or vendor libraries.
"""

from typing import Any, Dict, List, Optional, Protocol, runtime_checkable


@runtime_checkable
class TelegramBotAdapterProtocol(Protocol):
    """Protocol for Telegram Bot operations and webhook dispatching."""

    async def send_message(
        self,
        chat_id: int | str,
        text: str,
        parse_mode: Optional[str] = None,
        reply_markup: Optional[Any] = None,
    ) -> bool:
        """Send message to a Telegram chat or subject."""
        ...

    async def set_webhook(
        self,
        url: str,
        secret_token: Optional[str] = None,
    ) -> bool:
        """Register the official webhook URL and secret token with Telegram Bot API."""
        ...

    async def delete_webhook(self, drop_pending_updates: bool = False) -> bool:
        """Deregister active webhook from Telegram Bot API."""
        ...

    async def get_bot_info(self) -> Dict[str, Any]:
        """Fetch current bot profile and operational status from Telegram."""
        ...


@runtime_checkable
class AlertNotifierProtocol(Protocol):
    """Protocol for dispatching notifications for generated threat alerts."""

    async def send_alert_notification(
        self,
        alert_id: str,
        severity: str,
        title: str,
        summary: str,
        destination: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Dispatch real-time alert to analyst channel or webhook."""
        ...


@runtime_checkable
class NLPEngineProtocol(Protocol):
    """Protocol for local multilingual NLP inference engine."""

    def detect_language(self, text: str) -> str:
        """Identify language (en, hi, mr, hinglish)."""
        ...

    def extract_entities(self, text: str) -> List[Dict[str, Any]]:
        """Extract domain entities (UPI VPA, IFSC, Phone, URL, Crypto, etc.)."""
        ...

    def classify_threat(self, text: str) -> Dict[str, Any]:
        """Produce topic/threat classification with confidence score and evidence spans."""
        ...

