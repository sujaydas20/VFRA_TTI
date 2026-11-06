"""Alerting subsystem service (Phase 4).

Canonical Reference:
- Phase 4 objective: alert state machine, priority calculation, duplicate
  suppression within a configurable window, analyst triage and feedback.

INVARIANTS:
- Multi-tenant isolated; RLS-enforced.
- Never stores message content: only category, severity, and rule explanation.
- Severity derives from the uncalibrated detection severity and is labelled as
  rule confidence (uncalibrated).
"""

from datetime import datetime, timedelta, timezone
from typing import List, Optional, Tuple
from uuid import UUID
import uuid

from fastapi import HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.rbac import (
    ROLE_INVESTIGATOR_LEAD,
    ROLE_TENANT_ADMIN,
)
from app.database.models.alerts import (
    ALERT_STATUS_ASSIGNED,
    ALERT_STATUS_DISMISSED,
    ALERT_STATUS_OPEN,
    ALERT_STATUS_TRIAGED,
    ANALYST_DECISION_CONFIRMED,
    ANALYST_DECISION_FALSE_POSITIVE,
    SEVERITY_PRIORITY,
    AlertRecord,
    AnalystFeedbackRecord,
)
from app.database.models.audit import AuditEventRecord
from app.database.models.detection import DetectionRecord
from app.database.models.iam import TenantMembership

# Default duplicate suppression window (seconds). ponytail: hardcoded default;
# promote to Settings when a tenant-configurable window is actually requested.
DEFAULT_SUPPRESSION_WINDOW_SECONDS = 3600

# Only detections at or above MEDIUM severity raise alerts (alert-fatigue guard).
MIN_ALERT_SEVERITY_RANK = SEVERITY_PRIORITY["MEDIUM"]


class AlertService:
    """Domain service orchestrating alert generation, suppression, and triage."""

    async def create_alert_for_detection(
        self,
        session: AsyncSession,
        tenant_id: UUID,
        detection: DetectionRecord,
        suppression_window_seconds: int = DEFAULT_SUPPRESSION_WINDOW_SECONDS,
    ) -> Tuple[Optional[AlertRecord], str]:
        """Raise an alert for a persisted detection, or suppress a duplicate.

        Returns:
            Tuple[Optional[AlertRecord], str]: (alert_or_None, outcome)
            outcome is one of: "created", "suppressed", "below_threshold".
        """
        severity_rank = SEVERITY_PRIORITY.get(detection.severity.upper(), 1)
        if severity_rank < MIN_ALERT_SEVERITY_RANK:
            return None, "below_threshold"

        now = datetime.now(timezone.utc)
        window_start = now - timedelta(seconds=suppression_window_seconds)

        # Duplicate suppression: collapse repeated hits of the same category
        # inside the window by incrementing hit_count (no duplicate alert row).
        existing_stmt = (
            select(AlertRecord)
            .where(
                AlertRecord.tenant_id == tenant_id,
                AlertRecord.category == detection.category,
                AlertRecord.alert_status.in_([ALERT_STATUS_OPEN, ALERT_STATUS_ASSIGNED]),
                AlertRecord.last_seen_at >= window_start,
            )
            .order_by(AlertRecord.last_seen_at.desc())
            .limit(1)
        )
        existing = (await session.execute(existing_stmt)).scalar_one_or_none()
        if existing:
            existing.hit_count += 1
            existing.last_seen_at = now
            # Escalate severity if a later hit is more severe (never downgrade).
            if severity_rank > SEVERITY_PRIORITY.get(existing.severity.upper(), 1):
                existing.severity = detection.severity.upper()
                existing.priority = severity_rank
            await session.flush()
            return existing, "suppressed"

        alert = AlertRecord(
            alert_id=uuid.uuid4(),
            tenant_id=tenant_id,
            detection_id=detection.detection_id,
            category=detection.category,
            severity=detection.severity.upper(),
            priority=severity_rank,
            alert_title=f"{detection.category.replace('_', ' ').title()} detection",
            explanation=detection.explanation,
            hit_count=1,
            alert_status=ALERT_STATUS_OPEN,
            first_seen_at=now,
            last_seen_at=now,
            created_at=now,
        )
        session.add(alert)
        await session.flush()
        return alert, "created"

    async def list_alerts(
        self,
        session: AsyncSession,
        tenant_id: UUID,
        alert_status: Optional[str] = None,
        severity: Optional[str] = None,
        category: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[AlertRecord], int]:
        """List tenant-scoped alerts ordered by priority and recency."""
        query = select(AlertRecord).where(AlertRecord.tenant_id == tenant_id)
        if alert_status:
            query = query.where(AlertRecord.alert_status == alert_status.upper())
        if severity:
            query = query.where(AlertRecord.severity == severity.upper())
        if category:
            query = query.where(AlertRecord.category == category)

        count_stmt = select(func.count()).select_from(query.subquery())
        total = (await session.execute(count_stmt)).scalar() or 0

        paginated = (
            query.order_by(AlertRecord.priority.desc(), AlertRecord.last_seen_at.desc())
            .limit(limit)
            .offset(offset)
        )
        records = (await session.execute(paginated)).scalars().all()
        return list(records), total

    async def get_alert(
        self, session: AsyncSession, tenant_id: UUID, alert_id: UUID
    ) -> AlertRecord:
        """Retrieve a single tenant-scoped alert or raise 404."""
        stmt = select(AlertRecord).where(
            AlertRecord.alert_id == alert_id,
            AlertRecord.tenant_id == tenant_id,
        )
        alert = (await session.execute(stmt)).scalar_one_or_none()
        if not alert:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Alert {alert_id} not found in tenant context",
            )
        return alert

    async def _audit(self, session: AsyncSession, tenant_id: UUID, user_id: UUID, action: str, details: dict) -> None:
        """Append an audit ledger entry for an alert lifecycle action."""
        session.add(
            AuditEventRecord(
                audit_event_id=uuid.uuid4(),
                tenant_id=tenant_id,
                user_id=user_id,
                action_type=action,
                correlation_id=uuid.uuid4(),
                details=details,
                event_timestamp_utc=datetime.now(timezone.utc),
            )
        )

    async def assign_alert(
        self,
        session: AsyncSession,
        tenant_id: UUID,
        actor_user_id: UUID,
        alert_id: UUID,
        assigned_to_user_id: UUID,
    ) -> AlertRecord:
        """Assign an open alert to an active tenant member (analyst review)."""
        if assigned_to_user_id != actor_user_id:
            membership_stmt = select(TenantMembership.membership_id).where(
                TenantMembership.tenant_id == tenant_id,
                TenantMembership.user_id == assigned_to_user_id,
                TenantMembership.membership_status == "ACTIVE",
            )
            if not (await session.execute(membership_stmt)).scalar_one_or_none():
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Assignee must be an active member of this organization.",
                )

        alert = await self.get_alert(session, tenant_id, alert_id)
        if alert.alert_status in (ALERT_STATUS_TRIAGED, ALERT_STATUS_DISMISSED):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Alert {alert_id} is already {alert.alert_status} and cannot be reassigned.",
            )

        alert.assigned_to_user_id = assigned_to_user_id
        alert.alert_status = ALERT_STATUS_ASSIGNED
        await self._audit(
            session,
            tenant_id,
            actor_user_id,
            "ALERT_ASSIGNED",
            {"alert_id": str(alert_id), "assigned_to_user_id": str(assigned_to_user_id)},
        )
        await session.flush()
        return alert

    async def triage_alert(
        self,
        session: AsyncSession,
        tenant_id: UUID,
        actor_user_id: UUID,
        alert_id: UUID,
        analyst_decision: str,
        analyst_notes: Optional[str] = None,
        dismiss: bool = False,
    ) -> AlertRecord:
        """Record analyst triage decision (CONFIRMED / FALSE_POSITIVE, optional dismiss)."""
        alert = await self.get_alert(session, tenant_id, alert_id)
        if alert.alert_status in (ALERT_STATUS_TRIAGED, ALERT_STATUS_DISMISSED):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Alert {alert_id} is already {alert.alert_status}.",
            )

        now = datetime.now(timezone.utc)
        alert.analyst_decision = analyst_decision
        alert.analyst_notes = analyst_notes
        alert.reviewed_by_user_id = actor_user_id
        alert.reviewed_at = now
        alert.alert_status = ALERT_STATUS_DISMISSED if dismiss else ALERT_STATUS_TRIAGED
        await self._audit(
            session,
            tenant_id,
            actor_user_id,
            "ALERT_TRIAGED",
            {
                "alert_id": str(alert_id),
                "analyst_decision": analyst_decision,
                "alert_status": alert.alert_status,
            },
        )

        session.add(
            AnalystFeedbackRecord(
                feedback_id=uuid.uuid4(),
                tenant_id=tenant_id,
                alert_id=alert_id,
                analyst_user_id=actor_user_id,
                is_true_positive=(analyst_decision == ANALYST_DECISION_CONFIRMED),
                feedback_notes=analyst_notes,
                created_at=now,
            )
        )
        await session.flush()
        return alert

    async def overview(self, session: AsyncSession, tenant_id: UUID) -> dict:
        """Aggregate dashboard overview counts for the tenant."""
        base = select(
            func.count().label("total"),
            func.coalesce(func.sum(AlertRecord.hit_count), 0).label("hits"),
        ).where(AlertRecord.tenant_id == tenant_id)
        row = (await session.execute(base)).one()

        counts = {s: 0 for s in (ALERT_STATUS_OPEN, ALERT_STATUS_ASSIGNED, ALERT_STATUS_TRIAGED, ALERT_STATUS_DISMISSED)}
        status_stmt = (
            select(AlertRecord.alert_status, func.count())
            .where(AlertRecord.tenant_id == tenant_id)
            .group_by(AlertRecord.alert_status)
        )
        for st, c in (await session.execute(status_stmt)).all():
            counts[st] = c

        sev_counts = {s: 0 for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
        sev_stmt = (
            select(AlertRecord.severity, func.count())
            .where(AlertRecord.tenant_id == tenant_id, AlertRecord.alert_status == ALERT_STATUS_OPEN)
            .group_by(AlertRecord.severity)
        )
        for sev, c in (await session.execute(sev_stmt)).all():
            if sev in sev_counts:
                sev_counts[sev] = c

        return {
            "total_alerts": row.total,
            "open_alerts": counts[ALERT_STATUS_OPEN],
            "assigned_alerts": counts[ALERT_STATUS_ASSIGNED],
            "triaged_alerts": counts[ALERT_STATUS_TRIAGED],
            "dismissed_alerts": counts[ALERT_STATUS_DISMISSED],
            "critical_open": sev_counts["CRITICAL"],
            "high_open": sev_counts["HIGH"],
            "medium_open": sev_counts["MEDIUM"],
            "low_open": sev_counts["LOW"],
            "total_hits_suppressed": int(row.hits),
        }
