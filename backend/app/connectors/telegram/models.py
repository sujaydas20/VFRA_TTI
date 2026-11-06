"""Data transfer schemas for Telegram thread and message structures."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class TelegramMediaAttachmentReference(BaseModel):
    """Reference metadata for media attachments (never auto-downloaded without consent)."""
    media_id: str
    file_type: str  # document, photo, video, audio
    file_size_bytes: Optional[int] = None
    mime_type: Optional[str] = None


class TelegramMessagePayload(BaseModel):
    """Raw message structure ingested from a monitored Telegram channel or group."""
    message_id: int
    channel_id: int
    channel_title: Optional[str] = None
    sender_id: Optional[int] = None
    sender_username: Optional[str] = None
    date_utc: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    raw_text: str = ""
    reply_to_message_id: Optional[int] = None
    forward_from_chat_id: Optional[int] = None
    views_count: Optional[int] = None
    media: Optional[TelegramMediaAttachmentReference] = None
    extra_metadata: Dict[str, Any] = Field(default_factory=dict)


class TelegramChannelMetadata(BaseModel):
    """Metadata describing a Telegram channel target."""
    channel_id: int
    title: str
    username: Optional[str] = None
    participant_count: Optional[int] = None
    is_broadcast: bool = True
    is_verified: bool = False
    description: Optional[str] = None
