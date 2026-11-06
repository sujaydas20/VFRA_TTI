"""Case management database entities with strict multi-tenant isolation.

Defines:
- InvestigativeCase (app.investigative_cases): Tenant case workspaces
- CaseMessageAssociation (app.case_message_associations): Pins threat messages to cases with annotations
- CaseNote (app.case_notes): Confidential analyst notes and hypotheses
"""

from datetime import datetime, timezone
from typing import List, Optional
import uuid

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    JSON,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base


class InvestigativeCase(Base):
    """
    Tenant-scoped investigative case container.

    Canonical Reference:
    - Physical Schema: app.investigative_cases (migration 0006)
    - Functional Requirements: FR-EVI-001
    - Security Invariants: Multi-tenant isolated, RLS-enforced
    """

    __tablename__ = "investigative_cases"
    __table_args__ = (
        CheckConstraint(
            "case_status IN ('ACTIVE', 'PENDING_REVIEW', 'FINALIZED_LOCKED', 'ARCHIVED')",
            name="ck_case_status",
        ),
        UniqueConstraint("tenant_id", "case_reference", name="uq_case_reference"),
        {"schema": "app"},
    )

    case_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("iam.tenant_organizations.tenant_id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    case_title: Mapped[str] = mapped_column(
        String(500),
        nullable=False,
    )
    case_reference: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
    )
    internal_agency_ref: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
    )
    case_status: Mapped[str] = mapped_column(
        String(40),
        nullable=False,
        default="ACTIVE",
    )
    lead_investigator_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("iam.user_profiles.user_id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    description: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )
    created_at_utc: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )
    closed_at_utc: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Relationships
    pinned_messages: Mapped[List["CaseMessageAssociation"]] = relationship(
        back_populates="case",
        cascade="all, delete-orphan",
        order_by="CaseMessageAssociation.pinned_at_utc.desc()",
    )
    notes: Mapped[List["CaseNote"]] = relationship(
        back_populates="case",
        cascade="all, delete-orphan",
        order_by="CaseNote.created_at_utc.asc()",
    )
    lead_investigator = relationship("UserProfile", foreign_keys=[lead_investigator_id])

    def __repr__(self) -> str:
        return f"<InvestigativeCase id={self.case_id} ref='{self.case_reference}' status='{self.case_status}'>"


class CaseMessageAssociation(Base):
    """
    Bridge entity pinning a threat source message to an investigative case.

    Canonical Reference:
    - Physical Schema: app.case_message_associations (migration 0006)
    - Functional Requirements: FR-EVI-001
    """

    __tablename__ = "case_message_associations"
    __table_args__ = (
        UniqueConstraint("case_id", "message_id", name="uq_case_message"),
        ForeignKeyConstraint(
            ["tenant_id", "message_id"],
            ["threat.source_messages.tenant_id", "threat.source_messages.message_id"],
            name="fk_case_assoc_message",
            ondelete="RESTRICT",
        ),
        {"schema": "app"},
    )

    association_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("iam.tenant_organizations.tenant_id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    case_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("app.investigative_cases.case_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    message_id: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        index=True,
    )
    investigator_tags: Mapped[list] = mapped_column(
        JSON,
        nullable=False,
        default=list,
    )
    analyst_annotation: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )
    pinned_by_user_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("iam.user_profiles.user_id", ondelete="RESTRICT"),
        nullable=False,
    )
    pinned_at_utc: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    case: Mapped["InvestigativeCase"] = relationship(back_populates="pinned_messages")
    pinned_by = relationship("UserProfile", foreign_keys=[pinned_by_user_id])

    def __repr__(self) -> str:
        return f"<CaseMessageAssociation case={self.case_id} msg={self.message_id}>"


class CaseNote(Base):
    """
    Investigative notes, theories, and hypotheses attached to a case.

    Canonical Reference:
    - Physical Schema: app.case_notes (migration 0006)
    - Functional Requirements: FR-EVI-001
    """

    __tablename__ = "case_notes"
    __table_args__ = (
        {"schema": "app"},
    )

    note_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("iam.tenant_organizations.tenant_id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    case_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("app.investigative_cases.case_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    author_user_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("iam.user_profiles.user_id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    note_title: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    note_content: Mapped[str] = mapped_column(
        Text,
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

    # Relationships
    case: Mapped["InvestigativeCase"] = relationship(back_populates="notes")
    author = relationship("UserProfile", foreign_keys=[author_user_id])

    def __repr__(self) -> str:
        return f"<CaseNote id={self.note_id} case={self.case_id} title='{self.note_title}'>"
