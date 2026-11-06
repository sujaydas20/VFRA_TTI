"""Alerting subsystem database models (Phase 4).

Includes:
- AlertRecord: Tenant-scoped alert generated from a threat detection, with
  duplicate suppression (hit count) and analyst triage state.
- AnalystFeedbackRecord: Analyst validation feedback recorded for offline
  evaluation (Phase 4 learning loop; no live model self-modification).

INVARIANTS:
- Multi-tenant isolated (non-nullable tenant_id, RLS-enforced).
- No message content is ever stored; only category, severity, and rule
  explanation metadata are persisted.
- Alert severity derives from the uncalibrated detection severity and is
  explicitly labelled as rule confidence (uncalibrated).
"""

from datetime import datetime, timezone
from typing import Optional
import uuid

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base

# Canonical alert lifecycle states
ALERT_STATUS_OPEN = "OPEN"
ALERT_STATUS_ASSIGNED = "ASSIGNED"
ALERT_STATUS_TRIAGED = "TRIAGED"
ALERT_STATUS_DISMISSED = "DISMISSED"
ALERT_STATUSES = (ALERT_STATUS_OPEN, ALERT_STATUS_ASSIGNED, ALERT_STATUS_TRIAGED, ALERT_STATUS_DISMISSED)

# Canonical analyst decisions
ANALYST_DECISION_CONFIRMED = "CONFIRMED"
ANALYST_DECISION_FALSE_POSITIVE = "FALSE_POSITIVE"
ANALYST_DECISIONS = (ANALYST_DECISION_CONFIRMED, ANALYST_DECISION_FALSE_POSITIVE)

# Canonical alert priorities (aligned with app.detection.scoring.SEVERITY_ORDER)
SEVERITY_PRIORITY = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}


class AlertRecord(Base):
    """Tenant-scoped alert raised from a persisted threat detection.

    Canonical Reference:
    - Physical Schema: app.alerts (migration 0011)
    - Phase 4 acceptance: duplicate alerts inside the suppression window
      increment `hit_count` instead of emitting a new alert row.
    """

    __tablename__ = "alerts"
    __table_args__ = (
        CheckConstraint(
            "alert_status IN ('OPEN', 'ASSIGNED', 'TRIAGED', 'DISMISSED')",
            name="ck_alert_status",
        ),
        CheckConstraint(
            "analyst_decision IS NULL OR analyst_decision IN ('CONFIRMED', 'FALSE_POSITIVE')",
            name="ck_alert_analyst_decision",
        ),
        CheckConstraint("hit_count >= 1", name="ck_alert_hit_count_positive"),
        Index("ix_app_alerts_tenant_status", "tenant_id", "alert_status"),
        Index("ix_app_alerts_tenant_created", "tenant_id", "created_at"),
        Index("ix_app_alerts_tenant_category", "tenant_id", "category"),
        {"schema": "app"},
    )

    alert_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("iam.tenant_organizations.tenant_id", ondelete="CASCADE"),
        nullable=False,
    )
    detection_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("app.detections.detection_id", ondelete="CASCADE"),
        nullable=True,
    )
    category: Mapped[str] = mapped_column(String(64), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    priority: Mapped[int] = mapped_column(Integer, nullable=False)
    alert_title: Mapped[str] = mapped_column(String(255), nullable=False)
    explanation: Mapped[str] = mapped_column(Text, nullable=False)
    confidence_label: Mapped[str] = mapped_column(
        String(64), nullable=False, default="rule confidence (uncalibrated)"
    )
    hit_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    alert_status: Mapped[str] = mapped_column(
        String(32), nullable=False, default=ALERT_STATUS_OPEN
    )
    assigned_to_user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("iam.user_profiles.user_id", ondelete="SET NULL"),
        nullable=True,
    )
    analyst_decision: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    analyst_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    reviewed_by_user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("iam.user_profiles.user_id", ondelete="SET NULL"),
        nullable=True,
    )
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    reviewed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )

    feedback: Mapped[list["AnalystFeedbackRecord"]] = relationship(
        "AnalystFeedbackRecord", back_populates="alert", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return (
            f"<AlertRecord id={self.alert_id} category={self.category} "
            f"severity={self.severity} status={self.alert_status}>"
        )


class AnalystFeedbackRecord(Base):
    """Analyst validation feedback recorded for offline model evaluation.

    GOVERNANCE & NON-NEGOTIABLE RULE:
    Live reinforcement learning and unmonitored model self-modification are
    strictly prohibited. This table only records analyst judgements for
    offline evaluation and benchmark validation.
    """

    __tablename__ = "analyst_feedback"
    __table_args__ = (
        Index("ix_app_analyst_feedback_tenant", "tenant_id"),
        Index("ix_app_analyst_feedback_alert", "alert_id"),
        {"schema": "app"},
    )

    feedback_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("iam.tenant_organizations.tenant_id", ondelete="CASCADE"),
        nullable=False,
    )
    alert_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("app.alerts.alert_id", ondelete="CASCADE"),
        nullable=False,
    )
    analyst_user_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("iam.user_profiles.user_id", ondelete="RESTRICT"),
        nullable=False,
    )
    is_true_positive: Mapped[bool] = mapped_column(Boolean, nullable=False)
    corrected_severity: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    feedback_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )

    alert: Mapped["AlertRecord"] = relationship(
        "AlertRecord", back_populates="feedback"
    )

    def __repr__(self) -> str:
        return f"<AnalystFeedbackRecord id={self.feedback_id} alert={self.alert_id}>"
