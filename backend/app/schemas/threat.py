"""Threat intelligence ingestion, search, and presentation schemas."""

from datetime import datetime
from typing import List, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class ThreatMessageIngestItem(BaseModel):
    """Individual threat source message submitted for ingestion."""

    model_config = ConfigDict(from_attributes=True)

    message_id: str = Field(..., min_length=1, max_length=128, description="Unique source message identifier")
    source_sequence_id: int = Field(..., description="Monotonically increasing sequence/id within the channel")
    raw_text: str = Field(..., max_length=4096, description="Untrusted raw message text payload")
    broadcast_timestamp_utc: datetime = Field(..., description="Timestamp when message was originally published")
    message_thread_id: Optional[str] = Field(None, max_length=128, description="Topic/thread identifier if forum-style")
    sender_username: Optional[str] = Field(None, max_length=255, description="Sender username or alias")
    sender_native_id: Optional[str] = Field(None, max_length=128, description="Sender upstream platform ID")
    reply_to_message_id: Optional[str] = Field(None, max_length=128, description="Parent message ID if reply")
    has_media: bool = Field(False, description="Whether message includes attached media")


class ThreatIngestRequest(BaseModel):
    """
    Batch ingestion request payload.
    
    NON-NEGOTIABLE ARCHITECTURAL RULE (SEC-THREAT-01):
    Source authorization is derived exclusively from server-side trusted state in
    threat.source_channels. Client-controlled authorization fields are prohibited.
    """

    model_config = ConfigDict(from_attributes=True)

    source_reference: str = Field(..., min_length=1, max_length=255, description="Target channel handle, ID or URL")
    source_type: str = Field(default="telegram", pattern="^(telegram|darkweb)$", description="Intelligence source type")
    channel_title: Optional[str] = Field(None, max_length=500, description="Descriptive title of channel/source")
    channel_handle: Optional[str] = Field(None, max_length=255, description="Channel handle e.g. @dark_market")
    messages: List[ThreatMessageIngestItem] = Field(..., min_length=1, description="List of messages to normalize and ingest")


class IngestionJobResponse(BaseModel):
    """Status and provenance tracking for an ingestion batch job."""

    model_config = ConfigDict(from_attributes=True)

    job_id: UUID
    tenant_id: UUID
    source_reference: str
    source_type: str
    status: str
    records_processed: int
    payload_sha256: str
    error_message: Optional[str] = None
    submitted_by_user_id: Optional[UUID] = None
    created_at_utc: datetime
    completed_at_utc: Optional[datetime] = None


class ThreatMessageItem(BaseModel):
    """
    Sanitized intelligence message item returned to clients.
    
    NON-NEGOTIABLE ARCHITECTURAL RULE:
    Raw evidence filesystem paths, raw storage locators, and raw binary bytes
    MUST NEVER be included in this schema or returned to general search/detail queries.
    """

    model_config = ConfigDict(from_attributes=True)

    message_id: str
    channel_id: str
    source_sequence_id: int
    message_thread_id: Optional[str] = None
    sender_username: Optional[str] = None
    sender_native_id: Optional[str] = None
    broadcast_timestamp_utc: datetime
    reply_to_message_id: Optional[str] = None
    has_media: bool
    sanitized_text: str
    sanitization_flags: List[str]
    content_sha256: str


class ThreatSearchResponse(BaseModel):
    """Search query response containing matching sanitized intelligence items."""

    model_config = ConfigDict(from_attributes=True)

    query: str
    total_results: int
    limit: int
    offset: int
    items: List[ThreatMessageItem]


class ThreatThreadResponse(BaseModel):
    """Thread detail response containing all sanitized messages within a conversation thread."""

    model_config = ConfigDict(from_attributes=True)

    channel_id: str
    channel_title: Optional[str] = None
    thread_id: str
    total_messages: int
    messages: List[ThreatMessageItem]


# =============================================================================
# Phase 4 Source Channel Administration Schemas
# =============================================================================

class SourceChannelItem(BaseModel):
    """Source channel metadata representation with tenant scoping."""

    model_config = ConfigDict(from_attributes=True)

    tenant_id: UUID
    channel_id: str
    channel_title: str
    channel_handle: Optional[str] = None
    source_type: str
    is_authorized: bool
    created_at_utc: datetime
    updated_at_utc: datetime


class SourceChannelListResponse(BaseModel):
    """Paginated list of source channels for the authenticated tenant."""

    model_config = ConfigDict(from_attributes=True)

    total_channels: int
    limit: int
    offset: int
    channels: List[SourceChannelItem]


class ChannelRegisterRequest(BaseModel):
    """Request payload to register a new threat intelligence source channel."""

    model_config = ConfigDict(from_attributes=True)

    channel_id: str = Field(
        ...,
        min_length=1,
        max_length=128,
        pattern=r"^[a-zA-Z0-9_\-\.\+@]+$",
        description="Upstream platform channel/topic identifier",
    )
    channel_title: str = Field(
        ...,
        min_length=1,
        max_length=500,
        description="Descriptive title of channel/source",
    )
    channel_handle: Optional[str] = Field(
        None,
        max_length=255,
        description="Platform handle e.g. @dark_market",
    )
    source_type: str = Field(
        default="telegram",
        pattern="^(telegram|darkweb)$",
        description="Source platform type",
    )
    is_authorized: bool = Field(
        default=False,
        description="Initial collection authorization. Defaults to False pending operational approval.",
    )


class ChannelUpdateRequest(BaseModel):
    """Request payload to update channel metadata or collection authorization."""

    model_config = ConfigDict(from_attributes=True)

    channel_title: Optional[str] = Field(None, min_length=1, max_length=500, description="Updated channel title")
    channel_handle: Optional[str] = Field(None, max_length=255, description="Updated channel handle")
    is_authorized: Optional[bool] = Field(None, description="Explicitly enable (true) or disable (false) collection authorization")

