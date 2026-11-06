"""Threat Detection & Fraud Rules Engine database models.

Includes:
- ThreatCategoryRecord: Canonical threat and scam categories (global reference).
- KeywordRuleRecord: Versioned taxonomy detection rules (global reference).
- DetectionRecord: Tenant-scoped threat detection results with masked excerpts and uncalibrated confidence.
- DetectionRuleHitRecord: Rule matches and bounding spans for forensic review.
- URLIndicatorRecord: Offline heuristic indicators for extracted URLs (defanged).
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base


class ThreatCategoryRecord(Base):
    """Global taxonomy threat categories (read-only to tenant application role)."""

    __tablename__ = "threat_categories"
    __table_args__ = {"schema": "threat"}

    category_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    display_name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    default_severity: Mapped[str] = mapped_column(String(32), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )

    rules: Mapped[List["KeywordRuleRecord"]] = relationship(
        "KeywordRuleRecord", back_populates="category_rel"
    )


class KeywordRuleRecord(Base):
    """Global version-controlled detection rules compiled from YAML taxonomy."""

    __tablename__ = "keyword_rules"
    __table_args__ = {"schema": "threat"}

    rule_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    category: Mapped[str] = mapped_column(
        String(64), ForeignKey("threat.threat_categories.category_id"), nullable=False
    )
    rule_type: Mapped[str] = mapped_column(String(32), nullable=False)  # keyword | phrase | regex | entity
    languages: Mapped[List[str]] = mapped_column(JSONB, nullable=False)
    pattern_payload: Mapped[Dict[str, Any]] = mapped_column(JSONB, nullable=False)
    weight: Mapped[float] = mapped_column(Float, default=1.0, nullable=False)
    default_severity: Mapped[str] = mapped_column(String(32), nullable=False)
    explanation_template: Mapped[str] = mapped_column(Text, nullable=False)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_reviewed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    taxonomy_version: Mapped[str] = mapped_column(String(64), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )

    category_rel: Mapped["ThreatCategoryRecord"] = relationship(
        "ThreatCategoryRecord", back_populates="rules"
    )


class DetectionRecord(Base):
    """Tenant-scoped analytical threat detection indicator.

    INVARIANTS:
    - Never stores full message text.
    - Confidence is strictly labelled as rule confidence (uncalibrated).
    - Idempotency guaranteed across (message_id, category, taxonomy_version).
    """

    __tablename__ = "detections"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "message_id", "category", "taxonomy_version",
            name="uq_tenant_message_category_taxonomy"
        ),
        Index("ix_app_detections_tenant_created", "tenant_id", "created_at"),
        Index("ix_app_detections_category", "tenant_id", "category"),
        Index("ix_app_detections_severity", "tenant_id", "severity"),
        {"schema": "app"},
    )

    detection_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("iam.tenant_organizations.tenant_id", ondelete="CASCADE"),
        nullable=False,
    )
    subject_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("app.telegram_subjects.id", ondelete="SET NULL"),
        nullable=True,
    )
    message_id: Mapped[str] = mapped_column(String(128), nullable=False)
    category: Mapped[str] = mapped_column(String(64), nullable=False)
    stance: Mapped[str] = mapped_column(String(32), nullable=False)  # facilitating, warning, reporting, discussing, unclear
    severity: Mapped[str] = mapped_column(String(32), nullable=False)  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    rule_confidence: Mapped[float] = mapped_column(Float, nullable=False)  # uncalibrated heuristic
    explanation: Mapped[str] = mapped_column(Text, nullable=False)
    taxonomy_version: Mapped[str] = mapped_column(String(64), nullable=False)
    engine_version: Mapped[str] = mapped_column(String(32), nullable=False)
    review_status: Mapped[str] = mapped_column(
        String(32), default="unreviewed", nullable=False
    )  # unreviewed, confirmed, false_positive, dismissed
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )

    hits: Mapped[List["DetectionRuleHitRecord"]] = relationship(
        "DetectionRuleHitRecord",
        back_populates="detection",
        cascade="all, delete-orphan",
    )
    url_indicators: Mapped[List["URLIndicatorRecord"]] = relationship(
        "URLIndicatorRecord",
        back_populates="detection",
        cascade="all, delete-orphan",
    )


class DetectionRuleHitRecord(Base):
    """Child table storing specific rule hits and masked excerpts for forensic validation.

    INVARIANTS:
    - Excerpts are bounded in length and masked for OTPs, card numbers, Aadhaar/PAN.
    """

    __tablename__ = "detection_rule_hits"
    __table_args__ = (
        Index("ix_app_rule_hits_detection", "detection_id"),
        Index("ix_app_rule_hits_tenant", "tenant_id"),
        {"schema": "app"},
    )

    hit_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    detection_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("app.detections.detection_id", ondelete="CASCADE"),
        nullable=False,
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("iam.tenant_organizations.tenant_id", ondelete="CASCADE"),
        nullable=False,
    )
    rule_id: Mapped[str] = mapped_column(String(64), nullable=False)
    rule_version: Mapped[str] = mapped_column(String(64), nullable=False)
    span_start: Mapped[int] = mapped_column(Integer, nullable=False)
    span_end: Mapped[int] = mapped_column(Integer, nullable=False)
    masked_excerpt: Mapped[str] = mapped_column(String(256), nullable=False)

    detection: Mapped["DetectionRecord"] = relationship(
        "DetectionRecord", back_populates="hits"
    )


class URLIndicatorRecord(Base):
    """Offline static heuristic indicators extracted from URLs without network resolution."""

    __tablename__ = "url_indicators"
    __table_args__ = (
        Index("ix_app_url_indicators_detection", "detection_id"),
        Index("ix_app_url_indicators_tenant", "tenant_id"),
        Index("ix_app_url_indicators_domain", "domain"),
        {"schema": "app"},
    )

    indicator_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    detection_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("app.detections.detection_id", ondelete="CASCADE"),
        nullable=False,
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("iam.tenant_organizations.tenant_id", ondelete="CASCADE"),
        nullable=False,
    )
    defanged_url: Mapped[str] = mapped_column(Text, nullable=False)
    domain: Mapped[str] = mapped_column(String(255), nullable=False)
    indicator_flags: Mapped[List[str]] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )

    detection: Mapped["DetectionRecord"] = relationship(
        "DetectionRecord", back_populates="url_indicators"
    )
