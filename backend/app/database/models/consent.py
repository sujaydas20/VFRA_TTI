"""SQLAlchemy models for Telegram bot ingestion, subjects, consent records, and deletion ledger.

Enforces:
- Schema: app (with RLS isolation)
- Encrypted identity at rest with blind HMAC-SHA256 indexing
- Granular consent tracking and irreversible deletion requests
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
import uuid

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base


class WebhookUpdateRecord(Base):
    """Log of incoming Telegram webhook updates for idempotent deduplication."""

    __tablename__ = "webhook_updates"
    __table_args__ = (
        Index("ix_app_webhook_updates_status", "status"),
        {"schema": "app"},
    )

    update_id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=False)
    update_type: Mapped[str] = mapped_column(String(32), nullable=False)
    payload_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=func.now(), nullable=False)
    processed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="received", nullable=False)


class TelegramSubjectRecord(Base):
    """Subject identity record protecting user privacy with encrypted IDs and keyed hashes."""

    __tablename__ = "telegram_subjects"
    __table_args__ = (
        Index("ix_app_telegram_subjects_hash", "telegram_user_id_hash"),
        {"schema": "app"},
    )

    id: Mapped[uuid.UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("iam.tenant_organizations.tenant_id", ondelete="CASCADE"),
        nullable=False,
    )
    telegram_user_id_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    encrypted_telegram_user_id: Mapped[str] = mapped_column(Text, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    consent_records: Mapped[List["ConsentRecord"]] = relationship(
        "ConsentRecord",
        back_populates="subject",
        cascade="all, delete-orphan",
        order_by="desc(ConsentRecord.created_at)",
    )
    submissions: Mapped[List["ConsentedSubmissionRecord"]] = relationship(
        "ConsentedSubmissionRecord",
        back_populates="subject",
        cascade="all, delete-orphan",
    )


class ConsentRecord(Base):
    """Versioned and purpose-specific consent record for a Telegram subject."""

    __tablename__ = "consent_records"
    __table_args__ = (
        Index("ix_app_consent_records_subject", "subject_id"),
        Index("ix_app_consent_records_status", "status"),
        {"schema": "app"},
    )

    id: Mapped[uuid.UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("iam.tenant_organizations.tenant_id", ondelete="CASCADE"),
        nullable=False,
    )
    subject_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("app.telegram_subjects.id", ondelete="CASCADE"),
        nullable=False,
    )
    consent_version: Mapped[str] = mapped_column(String(32), nullable=False)
    purpose: Mapped[str] = mapped_column(String(128), nullable=False)
    permitted_categories: Mapped[Dict[str, Any]] = mapped_column(JSONB, nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="active", nullable=False)
    chat_context: Mapped[Dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    granted_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=func.now(), nullable=False)

    subject: Mapped["TelegramSubjectRecord"] = relationship("TelegramSubjectRecord", back_populates="consent_records")


class DeletionRequestRecord(Base):
    """Irreversible audit ledger of fulfilled subject erasure requests."""

    __tablename__ = "deletion_requests"
    __table_args__ = (
        Index("ix_app_deletion_requests_hash", "subject_hash"),
        {"schema": "app"},
    )

    id: Mapped[uuid.UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("iam.tenant_organizations.tenant_id", ondelete="CASCADE"),
        nullable=False,
    )
    subject_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=func.now(), nullable=False)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="pending", nullable=False)
    deleted_counts: Mapped[Dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)


class ConsentedSubmissionRecord(Base):
    """Persisted submissions originating exclusively from consenting subjects."""

    __tablename__ = "consented_submissions"
    __table_args__ = (
        Index("ix_app_consented_submissions_subject", "subject_id"),
        {"schema": "app"},
    )

    id: Mapped[uuid.UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("iam.tenant_organizations.tenant_id", ondelete="CASCADE"),
        nullable=False,
    )
    subject_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("app.telegram_subjects.id", ondelete="CASCADE"),
        nullable=False,
    )
    submission_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    sanitized_text: Mapped[str] = mapped_column(Text, nullable=False)
    detected_language: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=func.now(), nullable=False)

    subject: Mapped["TelegramSubjectRecord"] = relationship("TelegramSubjectRecord", back_populates="submissions")
