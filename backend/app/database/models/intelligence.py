"""Intelligence database entities with mandatory tenant isolation.

Defines:
- Phase 0 prototype entities:
  - CollectedThread (public.collected_threads)
  - RawArtifact (public.raw_artifacts)
- Phase 3 Core Threat Intelligence entities:
  - SourceChannel (threat.source_channels): Registered and authorized intelligence feeds/channels
  - SourceMessage (threat.source_messages): Normalized threat message records with thread references
  - DerivedContentRepresentation (threat.derived_content_representations): Sanitized display/search layer
  - RawEvidenceBlob (evidence.raw_evidence_blobs): Verbatim raw evidence storage pointers (append-only)
  - IngestionJob (app.ingestion_jobs): Ingestion batch status tracking and provenance
"""

from datetime import datetime, timezone
from typing import List, Optional
import uuid

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base, TenantAwareModel


# =============================================================================
# Phase 0 Prototype Entities (Kept for backwards compatibility)
# =============================================================================

class CollectedThread(Base, TenantAwareModel):
    """
    Metadata representation of an ingested message thread or dark-web forum topic.
    Guaranteed tenant-isolated via TenantAwareModel.
    """

    __tablename__ = "collected_threads"

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    source_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        index=True,
        comment="Source identifier, e.g. 'telegram' or 'darkweb'",
    )
    external_id: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
        comment="Original upstream thread/channel/topic ID",
    )
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    sanitization_status: Mapped[str] = mapped_column(
        String(50),
        default="pending",
        nullable=False,
        comment="Status: pending, sanitized, quarantined",
    )
    raw_evidence_sha256: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
        comment="Cryptographic SHA-256 fingerprint of original immutable payload",
    )

    artifacts: Mapped[list["RawArtifact"]] = relationship(
        "RawArtifact",
        back_populates="thread",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return f"<CollectedThread id={self.id} source={self.source_type} tenant_id={self.tenant_id}>"


class RawArtifact(Base, TenantAwareModel):
    """
    Pointer to raw collected payload stored in segregated evidence storage.
    Public frontend assets MUST NOT directly access this table or raw paths.
    """

    __tablename__ = "raw_artifacts"

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    thread_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("collected_threads.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    source_type: Mapped[str] = mapped_column(String(50), nullable=False)
    content_sha256: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
        comment="Immutable SHA-256 hash for integrity validation",
    )
    storage_relative_path: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="Relative path within the isolated evidence store",
    )
    byte_size: Mapped[int] = mapped_column(nullable=False)
    mime_type: Mapped[str] = mapped_column(String(100), default="application/json", nullable=False)

    thread: Mapped[CollectedThread] = relationship("CollectedThread", back_populates="artifacts")

    def __repr__(self) -> str:
        return f"<RawArtifact id={self.id} sha256={self.content_sha256} tenant_id={self.tenant_id}>"


# =============================================================================
# Phase 3 Core Threat Intelligence Entities
# =============================================================================

class SourceChannel(Base):
    """
    Registered and authorized intelligence feeds/channels per tenant.

    Canonical Reference:
    - Physical Schema: threat.source_channels (migration 0005)
    """

    __tablename__ = "source_channels"
    __table_args__ = (
        {"schema": "threat"},
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("iam.tenant_organizations.tenant_id", ondelete="RESTRICT"),
        primary_key=True,
        nullable=False,
    )
    channel_id: Mapped[str] = mapped_column(
        String(128),
        primary_key=True,
        nullable=False,
    )
    channel_title: Mapped[str] = mapped_column(
        String(500),
        nullable=False,
    )
    channel_handle: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
    )
    source_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )
    is_authorized: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )
    created_at_utc: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    updated_at_utc: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    def __repr__(self) -> str:
        return f"<SourceChannel channel_id={self.channel_id} tenant_id={self.tenant_id} authorized={self.is_authorized}>"


class SourceMessage(Base):
    """
    Normalized source messages and forum topic/thread associations.

    Canonical Reference:
    - Physical Schema: threat.source_messages (migration 0005)
    """

    __tablename__ = "source_messages"
    __table_args__ = (
        UniqueConstraint("tenant_id", "channel_id", "source_sequence_id", name="uq_source_messages_seq"),
        {"schema": "threat"},
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("iam.tenant_organizations.tenant_id", ondelete="RESTRICT"),
        primary_key=True,
        nullable=False,
    )
    message_id: Mapped[str] = mapped_column(
        String(128),
        primary_key=True,
        nullable=False,
    )
    channel_id: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
    )
    source_sequence_id: Mapped[int] = mapped_column(
        BigInteger,
        nullable=False,
    )
    message_thread_id: Mapped[Optional[str]] = mapped_column(
        String(128),
        nullable=True,
    )
    sender_username: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
    )
    sender_native_id: Mapped[Optional[str]] = mapped_column(
        String(128),
        nullable=True,
    )
    broadcast_timestamp_utc: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    reply_to_message_id: Mapped[Optional[str]] = mapped_column(
        String(128),
        nullable=True,
    )
    has_media: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )
    ingested_at_utc: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    def __repr__(self) -> str:
        return f"<SourceMessage message_id={self.message_id} channel_id={self.channel_id} seq={self.source_sequence_id}>"


class DerivedContentRepresentation(Base):
    """
    Sanitized display & search text representation with applied sanitization filter metadata.

    Canonical Reference:
    - Physical Schema: threat.derived_content_representations (migration 0005)
    """

    __tablename__ = "derived_content_representations"
    __table_args__ = (
        UniqueConstraint("tenant_id", "source_message_id", name="uq_derived_content_message"),
        {"schema": "threat"},
    )

    derived_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("iam.tenant_organizations.tenant_id", ondelete="RESTRICT"),
        nullable=False,
    )
    source_message_id: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
    )
    sanitized_message_text: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    content_sha256: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    sanitization_flags: Mapped[list] = mapped_column(
        JSON,
        default=list,
        nullable=False,
    )
    transformation_timestamp_utc: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    def __repr__(self) -> str:
        return f"<DerivedContentRepresentation id={self.derived_id} msg_id={self.source_message_id} sha={self.content_sha256[:8]}>"


class RawEvidenceBlob(Base):
    """
    Immutable raw evidence vault pointers.
    STRICTLY FORBIDDEN from direct search exposure or unauthenticated access.
    Append-only: No UPDATE or DELETE grants for tti_app_role.

    Canonical Reference:
    - Physical Schema: evidence.raw_evidence_blobs (migration 0005)
    - Decision: DEC-21
    """

    __tablename__ = "raw_evidence_blobs"
    __table_args__ = (
        UniqueConstraint("tenant_id", "source_message_id", name="uq_raw_evidence_message"),
        UniqueConstraint("tenant_id", "payload_sha256_hash", name="uq_raw_evidence_sha256"),
        {"schema": "evidence"},
    )

    raw_blob_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("iam.tenant_organizations.tenant_id", ondelete="RESTRICT"),
        nullable=False,
    )
    source_message_id: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
    )
    payload_sha256_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    byte_size: Mapped[int] = mapped_column(
        BigInteger,
        nullable=False,
    )
    payload_storage_locator: Mapped[str] = mapped_column(
        String(500),
        nullable=False,
    )
    ingestion_timestamp_utc: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    def __repr__(self) -> str:
        return f"<RawEvidenceBlob id={self.raw_blob_id} sha={self.payload_sha256_hash[:8]} bytes={self.byte_size}>"


class IngestionJob(Base):
    """
    Batch status and provenance tracking for intelligence ingestion requests.

    Canonical Reference:
    - Physical Schema: app.ingestion_jobs (migration 0005)
    """

    __tablename__ = "ingestion_jobs"
    __table_args__ = (
        CheckConstraint(
            "status IN ('RECEIVED', 'PROCESSING', 'COMPLETED', 'FAILED', 'REJECTED')",
            name="ck_ingestion_jobs_status",
        ),
        {"schema": "app"},
    )

    job_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("iam.tenant_organizations.tenant_id", ondelete="RESTRICT"),
        nullable=False,
    )
    source_reference: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    source_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )
    status: Mapped[str] = mapped_column(
        String(30),
        default="RECEIVED",
        nullable=False,
    )
    records_processed: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )
    payload_sha256: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    error_message: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )
    submitted_by_user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("iam.user_profiles.user_id", ondelete="SET NULL"),
        nullable=True,
    )
    created_at_utc: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    completed_at_utc: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    def __repr__(self) -> str:
        return f"<IngestionJob id={self.job_id} status={self.status} processed={self.records_processed}>"
