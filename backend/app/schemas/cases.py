"""Case management schemas for request validation and API responses."""

from datetime import datetime
from typing import List, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


VALID_CASE_STATUSES = {"ACTIVE", "PENDING_REVIEW", "FINALIZED_LOCKED", "ARCHIVED"}
CLOSED_CASE_STATUSES = {"FINALIZED_LOCKED", "ARCHIVED"}


class CaseCreateRequest(BaseModel):
    """Request payload to create a new investigative case container."""

    model_config = ConfigDict(from_attributes=True)

    case_title: str = Field(..., min_length=3, max_length=500, description="Title of the investigative case")
    case_reference: Optional[str] = Field(
        None,
        min_length=3,
        max_length=64,
        pattern=r"^[A-Za-z0-9_\-]+$",
        description="Optional human-readable reference code (auto-generated if omitted)",
    )
    internal_agency_ref: Optional[str] = Field(
        None,
        max_length=255,
        description="Optional judicial warrant, docket, or internal ticket identifier",
    )
    description: Optional[str] = Field(
        None,
        max_length=10000,
        description="Narrative case summary or investigative background",
    )
    lead_investigator_id: Optional[UUID] = Field(
        None,
        description="Lead investigator user ID (defaults to current user if omitted)",
    )


class CaseUpdateRequest(BaseModel):
    """Request payload to update case metadata or status."""

    model_config = ConfigDict(from_attributes=True)

    case_title: Optional[str] = Field(None, min_length=3, max_length=500)
    case_status: Optional[str] = Field(
        None,
        pattern=r"^(ACTIVE|PENDING_REVIEW|FINALIZED_LOCKED|ARCHIVED)$",
        description="Target case lifecycle state",
    )
    internal_agency_ref: Optional[str] = Field(None, max_length=255)
    description: Optional[str] = Field(None, max_length=10000)
    lead_investigator_id: Optional[UUID] = None


class CasePinMessageRequest(BaseModel):
    """Request payload to pin a threat source message to an active case."""

    model_config = ConfigDict(from_attributes=True)

    message_id: str = Field(..., min_length=1, max_length=128, description="Target threat message ID")
    investigator_tags: List[str] = Field(
        default_factory=list,
        description="Investigator categorization tags (e.g. ['threat_actor', 'malware'])",
    )
    analyst_annotation: Optional[str] = Field(
        None,
        max_length=5000,
        description="Confidential analyst observations on this evidentiary message",
    )


class CaseNoteCreateRequest(BaseModel):
    """Request payload to add an investigative hypothesis or note to a case."""

    model_config = ConfigDict(from_attributes=True)

    note_title: str = Field(..., min_length=1, max_length=255, description="Summary title of the note")
    note_content: str = Field(..., min_length=1, max_length=50000, description="Hypothesis or observation text")


class CaseMessageAssociationItem(BaseModel):
    """Item representation of a pinned message in a case."""

    model_config = ConfigDict(from_attributes=True)

    association_id: UUID
    case_id: UUID
    message_id: str
    investigator_tags: List[str]
    analyst_annotation: Optional[str] = None
    pinned_by_user_id: UUID
    pinned_at_utc: datetime


class CaseNoteItem(BaseModel):
    """Item representation of an analyst note."""

    model_config = ConfigDict(from_attributes=True)

    note_id: UUID
    case_id: UUID
    author_user_id: UUID
    note_title: str
    note_content: str
    created_at_utc: datetime
    updated_at_utc: datetime


class CaseResponse(BaseModel):
    """Investigative case summary response."""

    model_config = ConfigDict(from_attributes=True)

    case_id: UUID
    tenant_id: UUID
    case_title: str
    case_reference: str
    internal_agency_ref: Optional[str] = None
    case_status: str
    lead_investigator_id: UUID
    description: Optional[str] = None
    created_at_utc: datetime
    closed_at_utc: Optional[datetime] = None
    pinned_messages_count: int = 0
    notes_count: int = 0


class CaseDetailResponse(BaseModel):
    """Detailed case response including pinned messages and analyst notes."""

    model_config = ConfigDict(from_attributes=True)

    case_id: UUID
    tenant_id: UUID
    case_title: str
    case_reference: str
    internal_agency_ref: Optional[str] = None
    case_status: str
    lead_investigator_id: UUID
    description: Optional[str] = None
    created_at_utc: datetime
    closed_at_utc: Optional[datetime] = None
    pinned_messages: List[CaseMessageAssociationItem] = Field(default_factory=list)
    notes: List[CaseNoteItem] = Field(default_factory=list)


class CaseListResponse(BaseModel):
    """Paginated collection of cases."""

    model_config = ConfigDict(from_attributes=True)

    items: List[CaseResponse]
    total: int
    limit: int
    offset: int
