"""Telegram MTProto connector (Telethon) for authorized channel/group collection.

SECURITY & GOVERNANCE INVARIANTS:
- Credentials come exclusively from environment settings (TTI_TELEGRAM_API_ID/API_HASH).
- Session state is a Telethon StringSession supplied via TTI_TELEGRAM_SESSION (gitignored .env).
- Never downloads media binaries; only lightweight metadata references are captured.
- Never bypasses Telegram authorization: only chats the authenticated account may access.
- Never logs api_hash, session string, or phone numbers.

Telethon is an OPTIONAL dependency: when absent, the connector reports DISABLED so the
test environment stays hermetic without live-network side effects.
"""

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.connectors.base import ConnectorHealth, ConnectorStatus
from app.connectors.telegram.interface import TelegramConnectorInterface
from app.connectors.telegram.models import (
    TelegramChannelMetadata,
    TelegramMediaAttachmentReference,
    TelegramMessagePayload,
)
from app.core.config import get_settings
from app.core.errors import ConnectorNotConfiguredError

logger = logging.getLogger("tti.connectors.mtproto")

try:  # Optional dependency guard
    from telethon import TelegramClient
    from telethon.errors import FloodWaitError, RPCError
    from telethon.sessions import StringSession
    from telethon.tl.types import (
        Channel,
        Chat as TlChat,
        MessageMediaDocument,
        MessageMediaPhoto,
        User,
    )

    TELETHON_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised only when telethon absent
    TELETHON_AVAILABLE = False

FLOOD_WAIT_CAP_SECONDS = 60.0
FLOOD_MAX_RETRIES = 2


class MTProtoTelegramConnector(TelegramConnectorInterface):
    """
    Live Telegram connector over MTProto via Telethon.

    Implements the existing TelegramConnectorInterface contract
    (fetch_channel_info / collect_channel_messages / collect_batch / disconnect)
    plus connection lifecycle, health checks, and channel discovery restricted
    to dialogs the authorized account can access.
    """

    def __init__(self, connector_id: str = "telegram-mtproto"):
        super().__init__(connector_id=connector_id)
        self.settings = get_settings()
        self._client: Any = None  # TelegramClient when TELETHON_AVAILABLE
        self._connected: bool = False
        self._authorized: bool = False
        self._last_connected_utc: Optional[datetime] = None
        self._last_sync_utc: Optional[datetime] = None
        self._last_error: Optional[str] = None
        self._account_username: Optional[str] = None

    # ------------------------------------------------------------------
    # Configuration & lifecycle
    # ------------------------------------------------------------------
    def validate_configuration(self) -> bool:
        """api_id/api_hash present and valid; session string required for live ops."""
        return self.settings.mtproto_credentials_configured and bool(self.settings.TTI_TELEGRAM_SESSION)

    def _require_telethon(self) -> None:
        if not TELETHON_AVAILABLE:
            raise ConnectorNotConfiguredError(
                "Telethon is not installed. Add 'telethon' to backend dependencies to enable MTProto collection."
            )


    def _require_authorized(self) -> None:
        self._require_telethon()
        if not self._connected or self._client is None:
            raise ConnectorNotConfiguredError("MTProto client is not connected.")
        if not self._authorized:
            raise ConnectorNotConfiguredError(
                "MTProto session is not authorized. Run 'python -m app.cli mtproto-login' to authenticate."
            )

    async def connect(self) -> None:
        """Establish MTProto connection and validate user authorization."""
        self._require_telethon()
        if not self.settings.mtproto_credentials_configured:
            raise ConnectorNotConfiguredError(
                "TTI_TELEGRAM_API_ID / TTI_TELEGRAM_API_HASH are missing or invalid."
            )
        if self._client is not None and self._connected:
            return

        session = (
            StringSession(self.settings.TTI_TELEGRAM_SESSION)
            if self.settings.TTI_TELEGRAM_SESSION
            else StringSession()
        )
        client = TelegramClient(
            session,
            int(self.settings.TTI_TELEGRAM_API_ID),
            self.settings.TTI_TELEGRAM_API_HASH,
            device_model="TTI-Intelligence-Collector",
            system_version="TTI",
            app_version="0.1.0",
        )
        await client.connect()

        if not await client.is_user_authorized():
            await client.disconnect()
            self._connected = False
            self._authorized = False
            self._last_error = "MTProto session not authorized"
            raise ConnectorNotConfiguredError(
                "MTProto session is not authorized. Run 'python -m app.cli mtproto-login' to authenticate."
            )

        me = await client.get_me()
        self._client = client
        self._connected = True
        self._authorized = True
        self._account_username = getattr(me, "username", None)
        self._last_connected_utc = datetime.now(timezone.utc)
        self._last_error = None
        logger.info(
            "MTProto collector connected and authorized (api_id=%s).",
            self.settings.TTI_TELEGRAM_API_ID,
        )

    async def disconnect(self) -> None:
        """Gracefully release the MTProto session and sockets."""
        if self._client is not None:
            try:
                await self._client.disconnect()
            except Exception as exc:  # noqa: BLE001 - shutdown must never raise
                logger.warning("MTProto disconnect raised: %s", type(exc).__name__)
        self._client = None
        self._connected = False
        self._authorized = False

    async def _reconnect_if_needed(self) -> None:
        """Automatic reconnection guard invoked before every network operation."""
        if self._client is None or not self._connected:
            await self.connect()
            return
        if not self._client.is_connected():
            logger.info("MTProto connection dropped; reconnecting.")
            await self._client.connect()
            self._connected = self._client.is_connected()
            if not self._connected:
                raise ConnectorNotConfiguredError("MTProto reconnect failed.")

    async def _rpc(self, coro_factory, *, retries: int = FLOOD_MAX_RETRIES) -> Any:
        """Execute a Telethon RPC with FloodWait handling and bounded retries."""
        await self._reconnect_if_needed()
        attempt = 0
        while True:
            try:
                return await coro_factory()
            except FloodWaitError as flood:
                if attempt >= retries:
                    self._last_error = f"FloodWait persisted ({flood.seconds}s)"
                    raise
                wait_s = min(float(flood.seconds), FLOOD_WAIT_CAP_SECONDS)
                logger.warning("Telegram FloodWait: backing off %.1fs (attempt %d).", wait_s, attempt + 1)
                await asyncio.sleep(wait_s)
                attempt += 1

    # ------------------------------------------------------------------
    # Health diagnostics
    # ------------------------------------------------------------------
    async def health_check(self) -> ConnectorHealth:
        """Non-intrusive MTProto health assessment (no message fetch)."""
        metadata: Dict[str, Any] = {
            "mode": "mtproto_live",
            "credentials_configured": self.settings.mtproto_credentials_configured,
            "session_configured": bool(self.settings.TTI_TELEGRAM_SESSION),
            "telethon_installed": TELETHON_AVAILABLE,
            "authenticated": self._authorized,
            "account_username": self._account_username,
            "last_connected_utc": self._last_connected_utc.isoformat() if self._last_connected_utc else None,
            "last_sync_utc": self._last_sync_utc.isoformat() if self._last_sync_utc else None,
        }
        now_iso = datetime.now(timezone.utc).isoformat()

        if not self.settings.mtproto_credentials_configured:
            return ConnectorHealth(
                connector_id=self.connector_id,
                status=ConnectorStatus.UNCONFIGURED,
                message="MTProto api_id/api_hash missing or invalid.",
                is_live_collection_active=False,
                last_checked_utc=now_iso,
                metadata=metadata,
            )
        if not TELETHON_AVAILABLE:
            return ConnectorHealth(
                connector_id=self.connector_id,
                status=ConnectorStatus.DISABLED,
                message="Telethon not installed; MTProto collection unavailable.",
                is_live_collection_active=False,
                last_checked_utc=now_iso,
                metadata=metadata,
            )
        if not self.settings.TTI_TELEGRAM_SESSION:
            return ConnectorHealth(
                connector_id=self.connector_id,
                status=ConnectorStatus.DISABLED,
                message="No authorized session string configured (TTI_TELEGRAM_SESSION empty).",
                is_live_collection_active=False,
                last_checked_utc=now_iso,
                metadata=metadata,
            )

        if self._connected and self._authorized:
            status = ConnectorStatus.HEALTHY
            message = "MTProto connected and authorized."
        elif self._connected:
            status = ConnectorStatus.DEGRADED
            message = "MTProto connected but session not authorized."
        else:
            status = ConnectorStatus.DISCONNECTED
            message = "MTProto not connected (collector idle or authentication pending)."
        if self._last_error:
            message = f"{message} Last error: {self._last_error}"

        return ConnectorHealth(
            connector_id=self.connector_id,
            status=status,
            message=message,
            is_live_collection_active=self._connected and self._authorized,
            last_checked_utc=now_iso,
            metadata=metadata,
        )

    # ------------------------------------------------------------------
    # Channel discovery & metadata
    # ------------------------------------------------------------------
    async def discover_dialogs(self, limit: int = 200) -> List[TelegramChannelMetadata]:
        """Enumerate chats the AUTHORIZED account can access (never bypasses permissions)."""
        self._require_authorized()
        discovered: List[TelegramChannelMetadata] = []
        async for dialog in self._client.iter_dialogs(limit=limit):
            entity = dialog.entity
            if isinstance(entity, Channel):
                discovered.append(
                    TelegramChannelMetadata(
                        channel_id=int(entity.id),
                        title=dialog.name or f"channel-{entity.id}",
                        username=getattr(entity, "username", None),
                        participant_count=getattr(entity, "participants_count", None),
                        is_broadcast=bool(getattr(entity, "broadcast", False)),
                        is_verified=bool(getattr(entity, "verified", False)),
                    )
                )
            elif isinstance(entity, TlChat):
                discovered.append(
                    TelegramChannelMetadata(
                        channel_id=int(entity.id),
                        title=dialog.name or f"group-{entity.id}",
                        is_broadcast=False,
                    )
                )
        return discovered

    async def fetch_channel_info(self, channel_identifier: str) -> Optional[TelegramChannelMetadata]:
        """Retrieve non-intrusive metadata for an authorized public target."""
        self._require_authorized()

        def _fetch():
            return self._client.get_entity(channel_identifier)

        try:
            entity = await self._rpc(_fetch)
        except ValueError:
            return None  # Unknown identifier / not accessible to this account
        except RPCError as rpc_err:
            self._last_error = type(rpc_err).__name__
            raise ConnectorNotConfiguredError(f"Telegram RPC error: {type(rpc_err).__name__}")

        return TelegramChannelMetadata(
            channel_id=int(entity.id),
            title=getattr(entity, "title", None) or getattr(entity, "username", None) or str(entity.id),
            username=getattr(entity, "username", None),
            participant_count=getattr(entity, "participants_count", None),
            is_broadcast=bool(getattr(entity, "broadcast", False)),
            is_verified=bool(getattr(entity, "verified", False)),
        )

    # ------------------------------------------------------------------
    # Message collection
    # ------------------------------------------------------------------
    @staticmethod
    def _media_reference(message: Any) -> Optional[TelegramMediaAttachmentReference]:
        """Extract lightweight media metadata WITHOUT downloading any media file."""
        media = getattr(message, "media", None)
        if media is None:
            return None
        if isinstance(media, MessageMediaPhoto):
            photo = getattr(media, "photo", None)
            sizes = getattr(photo, "sizes", None) if photo else None
            return TelegramMediaAttachmentReference(
                media_id=f"photo-{getattr(photo, 'id', 0)}",
                file_type="photo",
                file_size_bytes=getattr(sizes[-1], "size", None) if sizes else None,
                mime_type="image/jpeg",
            )
        if isinstance(media, MessageMediaDocument):
            doc = getattr(media, "document", None)
            return TelegramMediaAttachmentReference(
                media_id=f"doc-{getattr(doc, 'id', 0)}",
                file_type="document",
                file_size_bytes=getattr(doc, "size", None),
                mime_type=getattr(doc, "mime_type", None),
            )
        return TelegramMediaAttachmentReference(media_id="other", file_type="unsupported")

    def _map_message(self, message: Any, channel_id: int, channel_title: Optional[str]) -> TelegramMessagePayload:
        """Map a Telethon Message onto the existing normalized payload schema."""
        sender = getattr(message, "sender", None)
        date_utc = message.date if message.date else datetime.now(timezone.utc)
        if date_utc.tzinfo is None:
            date_utc = date_utc.replace(tzinfo=timezone.utc)

        forward = getattr(message, "forward", None)
        forward_chat = getattr(forward, "from_chat", None) if forward else None

        return TelegramMessagePayload(
            message_id=int(message.id),
            channel_id=channel_id,
            channel_title=channel_title,
            sender_id=getattr(sender, "id", None) if sender is not None else None,
            sender_username=getattr(sender, "username", None) if sender is not None else None,
            date_utc=date_utc,
            raw_text=message.message or "",
            reply_to_message_id=getattr(message, "reply_to_msg_id", None),
            forward_from_chat_id=int(forward_chat.id) if forward_chat is not None and hasattr(forward_chat, "id") else None,
            views_count=getattr(message, "views", None),
            media=self._media_reference(message),
            extra_metadata={
                "edit_date_utc": message.edit_date.isoformat() if getattr(message, "edit_date", None) else None,
                "is_reply": bool(getattr(message, "reply_to_msg_id", None)),
                "forwarded": forward is not None,
                "sender_type": "user" if isinstance(sender, User) else ("channel" if isinstance(sender, Channel) else None),
            },
        )

    async def collect_channel_messages(
        self,
        tenant_id: str,
        channel_identifier: str,
        limit: int = 50,
        offset_id: int = 0,
    ) -> List[TelegramMessagePayload]:
        """
        Ingest message history incrementally.
        offset_id semantics: returns messages with id > offset_id (checkpoint continuation).
        """
        self._require_authorized()

        def _resolve():
            peer = int(channel_identifier) if str(channel_identifier).lstrip("-").isdigit() else channel_identifier
            return self._client.get_input_entity(peer)

        try:
            entity = await self._rpc(_resolve)
        except (ValueError, RPCError) as err:
            self._last_error = type(err).__name__
            raise ConnectorNotConfiguredError(
                f"Cannot access channel '{channel_identifier}': {type(err).__name__}"
            )

        messages: List[TelegramMessagePayload] = []
        try:
            async for message in self._client.iter_messages(entity, limit=limit, min_id=offset_id or 0, reverse=True):
                if message is None or getattr(message, "action", None) is not None:
                    continue  # Skip service messages (joins, pins, calls)
                messages.append(
                    self._map_message(
                        message,
                        channel_id=int(getattr(message, "chat_id", 0) or 0),
                        channel_title=getattr(getattr(message, "chat", None), "title", None),
                    )
                )
        except FloodWaitError:
            raise
        except RPCError as rpc_err:
            self._last_error = type(rpc_err).__name__
            raise ConnectorNotConfiguredError(
                f"Telegram RPC error during collection: {type(rpc_err).__name__}"
            )

        self._last_sync_utc = datetime.now(timezone.utc)
        self._last_error = None
        return messages

    async def collect_batch(
        self,
        tenant_id: str,
        target_reference: str,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """Generic connector batch interface (BaseConnector contract)."""
        messages = await self.collect_channel_messages(
            tenant_id=tenant_id,
            channel_identifier=target_reference,
            limit=limit,
        )
        return [msg.model_dump(mode="json") for msg in messages]

    @property
    def connected(self) -> bool:
        return self._connected

    @property
    def authorized(self) -> bool:
        return self._authorized

