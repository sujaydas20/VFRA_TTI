"""Digital forensics, version history, and change-tracking models.

Canonical Reference:
- Migration: 0012_forensics_change_tracking
- Physical Schema:
  - app.message_versions        (stable message identity + version chain)
  - app.change_events           (centralised change-event ledger)
  - app.file_metadata           (file identity + head metadata)
  - app.file_versions           (immutable file version chain)
  - app.change_reviews          (analyst review history)

NON-NEGOTIABLE INVARIANTS:
- Multi-tenant isolated (non-nullable tenant_id, RLS-enforced).
- Version rows are APPEND-ONLY. Original evidence is never overwritten.
- Text stored here is the masked/sanitized representation (never raw secrets);
  verbatim payloads live in evidence.raw_evidence_blobs.
- Timestamps that the source did not provide are stored NULL, never invented.
"""

from datetime import datetime, timezone
from typing import Optional
import uuid

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base

# ---------------------------------------------------------------------------
# Canonical enumerations
# ---------------------------------------------------------------------------

# Change event types (§4 of the forensics requirements)
EVENT_MESSAGE_CREATED = "MESSAGE_CREATED"
EVENT_MESSAGE_EDITED = "MESSAGE_EDITED"
EVENT_MESSAGE_CONTENT_CHANGED = "MESSAGE_CONTENT_CHANGED"
EVENT_MESSAGE_IOC_CHANGED = "MESSAGE_IOC_CHANGED"
EVENT_MESSAGE_ENTITY_CHANGED = "MESSAGE_ENTITY_CHANGED"
EVENT_FILE_CREATED = "FILE_CREATED"
EVENT_FILE_MODIFIED = "FILE_MODIFIED"
EVENT_FILE_RENAMED = "FILE_RENAMED"
EVENT_FILE_REPLACED = "FILE_REPLACED"
EVENT_FILE_METADATA_CHANGED = "FILE_METADATA_CHANGED"
EVENT_FILE_DELETED = "FILE_DELETED"
EVENT_FILE_VERSION_CREATED = "FILE_VERSION_CREATED"
EVENT_INTEGRITY_MISMATCH = "INTEGRITY_MISMATCH"

CHANGE_EVENT_TYPES = (
    EVENT_MESSAGE_CREATED, EVENT_MESSAGE_EDITED, EVENT_MESSAGE_CONTENT_CHANGED,
    EVENT_MESSAGE_IOC_CHANGED, EVENT_MESSAGE_ENTITY_CHANGED,
    EVENT_FILE_CREATED, EVENT_FILE_MODIFIED, EVENT_FILE_RENAMED,
    EVENT_FILE_REPLACED, EVENT_FILE_METADATA_CHANGED, EVENT_FILE_DELETED,
    EVENT_FILE_VERSION_CREATED, EVENT_INTEGRITY_MISMATCH,
)

ENTITY_TYPE_MESSAGE = "MESSAGE"
ENTITY_TYPE_FILE = "FILE"

# Change-event triage lifecycle
REVIEW_PENDING = "PENDING"
REVIEW_ACKNOWLEDGED = "ACKNOWLEDGED"
REVIEW_RESOLVED = "RESOLVED"
REVIEW_BENIGN = "BENIGN"
REVIEW_ESCALATED = "ESCALATED"
REVIEW_FLAGGED = "FLAGGED"
CHANGE_REVIEW_STATUSES = (
    REVIEW_PENDING, REVIEW_ACKNOWLEDGED, REVIEW_RESOLVED,
    REVIEW_BENIGN, REVIEW_ESCALATED, REVIEW_FLAGGED,
)

# Ingestion/downstream processing state
PROCESSING_PENDING = "PENDING"
PROCESSING_COMPLETE = "COMPLETE"
PROCESSING_FAILED = "FAILED"

# Severity scale (shared with the detection engine)
SEVERITY_RANK = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}


class MessageVersionRecord(Base):
    """Immutable version chain for a stable source message identity.

    A message keeps ONE identity across edits; each observed content state is a
    separate append-only version row. `version_number` starts at 1.
    """

    __tablename__ = "message_versions"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "message_id", "version_number",
            name="uq_message_versions_identity_version",
        ),
        CheckConstraint("version_number >= 1", name="ck_message_versions_number_positive"),
        Index("ix_app_message_versions_tenant_message", "tenant_id", "message_id"),
        Index("ix_app_message_versions_tenant_created", "tenant_id", "created_at"),
        Index("ix_app_message_versions_content_sha", "content_sha256"),
        {"schema": "app"},
    )

    message_version_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("iam.tenant_organizations.tenant_id", ondelete="CASCADE"),
        nullable=False,
    )
    message_id: Mapped[str] = mapped_column(String(128), nullable=False)
    source_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    source_type: Mapped[str] = mapped_column(String(50), nullable=False, default="telegram")
    version_number: Mapped[int] = mapped_column(Integer, nullable=False)
    content_text: Mapped[str] = mapped_column(Text, nullable=False, default="")
    content_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    previous_content_sha256: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    previous_version_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("app.message_versions.message_version_id", ondelete="SET NULL"),
        nullable=True,
    )
    evidence_blob_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("evidence.raw_evidence_blobs.raw_blob_id", ondelete="SET NULL"),
        nullable=True,
    )
    source_published_at_utc: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    source_edited_at_utc: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    first_observed_at_utc: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    last_observed_at_utc: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    detection_timestamp_utc: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    observed_iocs: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    observed_entities: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    observed_keywords: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    is_current: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    edit_status: Mapped[str] = mapped_column(String(32), nullable=False, default="ORIGINAL")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(),
        default=lambda: datetime.now(timezone.utc), nullable=False,
    )

    def __repr__(self) -> str:
        return (
            f"<MessageVersionRecord msg={self.message_id} v{self.version_number} "
            f"sha={self.content_sha256[:8]} current={self.is_current}>"
        )


class FileMetadataRecord(Base):
    """Head metadata for a tracked file identity.

    A file identity is the stable handle for one logical artifact across renames,
    replacements and content changes. Full metadata for each observed state lives
    in `app.file_versions`; this row carries the CURRENT (head) state.
    """

    __tablename__ = "file_metadata"
    __table_args__ = (
        UniqueConstraint("tenant_id", "file_id", name="uq_file_metadata_identity"),
        Index("ix_app_file_metadata_tenant_sha", "tenant_id", "sha256_hash"),
        Index("ix_app_file_metadata_tenant_source", "tenant_id", "source_id"),
        Index("ix_app_file_metadata_sha256", "sha256_hash"),
        Index("ix_app_file_metadata_integrity", "tenant_id", "integrity_status"),
        {"schema": "app"},
    )

    file_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("iam.tenant_organizations.tenant_id", ondelete="CASCADE"),
        nullable=False,
    )
    source_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    source_type: Mapped[str] = mapped_column(String(50), nullable=False, default="telegram")
    original_filename: Mapped[str] = mapped_column(String(512), nullable=False)
    current_filename: Mapped[str] = mapped_column(String(512), nullable=False)
    file_extension: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    mime_type: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    file_format: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    storage_reference: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    sha256_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    sha1_hash: Mapped[Optional[str]] = mapped_column(String(40), nullable=True)
    md5_hash: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    current_version_number: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    total_versions: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    integrity_status: Mapped[str] = mapped_column(String(32), nullable=False, default="VERIFIED")
    availability_status: Mapped[str] = mapped_column(String(32), nullable=False, default="PRESENT")
    source_created_at_utc: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    source_modified_at_utc: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    source_accessed_at_utc: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    collected_at_utc: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    uploaded_at_utc: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    first_observed_at_utc: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    last_observed_at_utc: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    last_metadata_verified_at_utc: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(),
        default=lambda: datetime.now(timezone.utc), nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc), nullable=False,
    )

    def __repr__(self) -> str:
        return (
            f"<FileMetadataRecord id={self.file_id} name={self.current_filename} "
            f"v{self.current_version_number} sha={self.sha256_hash[:8]}>"
        )


class FileVersionRecord(Base):
    """Immutable version snapshot for a file identity.

    Every observed state (new, renamed, content-changed, replaced) is stored as a
    separate row. The current (latest) version is referenced from `app.file_metadata`.
    """

    __tablename__ = "file_versions"
    __table_args__ = (
        UniqueConstraint(
            "file_id", "version_number",
            name="uq_file_versions_identity_version",
        ),
        CheckConstraint("version_number >= 1", name="ck_file_versions_number_positive"),
        Index("ix_app_file_versions_tenant_file", "tenant_id", "file_id"),
        Index("ix_app_file_versions_tenant_created", "tenant_id", "created_at"),
        Index("ix_app_file_versions_sha256", "sha256_hash"),
        {"schema": "app"},
    )

    file_version_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    file_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("app.file_metadata.file_id", ondelete="CASCADE"),
        nullable=False,
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("iam.tenant_organizations.tenant_id", ondelete="CASCADE"),
        nullable=False,
    )
    version_number: Mapped[int] = mapped_column(Integer, nullable=False)
    change_type: Mapped[str] = mapped_column(String(32), nullable=False)
    filename: Mapped[str] = mapped_column(String(512), nullable=False)
    previous_filename: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    file_extension: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    mime_type: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    file_format: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    previous_size_bytes: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)
    storage_reference: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    sha256_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    sha1_hash: Mapped[Optional[str]] = mapped_column(String(40), nullable=True)
    md5_hash: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    previous_sha256_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    evidence_blob_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("evidence.raw_evidence_blobs.raw_blob_id", ondelete="SET NULL"),
        nullable=True,
    )
    source_modified_at_utc: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    detection_timestamp_utc: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    collected_at_utc: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(),
        default=lambda: datetime.now(timezone.utc), nullable=False,
    )

    def __repr__(self) -> str:
        return (
            f"<FileVersionRecord file={self.file_id} v{self.version_number} "
            f"change={self.change_type} sha={self.sha256_hash[:8]}>"
        )
