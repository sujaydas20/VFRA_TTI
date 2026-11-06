"""Alerting Subsystem API endpoints (Phase 4).

Canonical Reference:
- Phase 4: alert review, assignment, false-positive marking, and dashboard
  overview counters for the unified console.
- Security Invariants: RBAC-gated, tenant-scoped, RLS-enforced, audited.
"""

from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import (
    TenantSecurityContext,
    get_authorized_tenant_db,
    require_permission_dep,
)
from app.core.rbac import (
    PERM_ALERT_ASSIGN,
    PERM_ALERT_READ,
    PERM_ALERT_TRIAGE,
)
from app.database.models.alerts import AnalystFeedbackRecord
from app.schemas.alerts import (
    AlertAssignRequest,
    AlertItem,
    AlertListResponse,
    AlertOverviewResponse,
    AlertTriageRequest,
    AnalystFeedbackItem,
    AnalystFeedbackRequest,
)
from app.services.alert_service import AlertService

router = APIRouter(prefix="/alerts", tags=["Alerting"])
alert_service = AlertService()


@router.get(
    "/overview",
    response_model=AlertOverviewResponse,
    summary="Alert dashboard overview counters",
)
async def get_alert_overview(
    ctx: TenantSecurityContext = Depends(require_permission_dep(PERM_ALERT_READ)),
    db: AsyncSession = Depends(get_authorized_tenant_db),
) -> AlertOverviewResponse:
    """Aggregate tenant-scoped alert counters for the console overview."""
    return AlertOverviewResponse(**await alert_service.overview(db, ctx.organization.tenant_id))


@router.get(
    "",
    response_model=AlertListResponse,
    summary="List tenant alerts",
)
async def list_alerts(
    alert_status: Optional[str] = Query(None, alias="status"),
    severity: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    ctx: TenantSecurityContext = Depends(require_permission_dep(PERM_ALERT_READ)),
    db: AsyncSession = Depends(get_authorized_tenant_db),
) -> AlertListResponse:
    """Retrieve paginated alerts scoped to the authenticated tenant."""
    records, total = await alert_service.list_alerts(
        session=db,
        tenant_id=ctx.organization.tenant_id,
        alert_status=alert_status,
        severity=severity,
        category=category,
        limit=limit,
        offset=offset,
    )
    return AlertListResponse(
        items=[AlertItem.model_validate(r) for r in records],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/{alert_id}",
    response_model=AlertItem,
    summary="Get single alert details",
)
async def get_alert(
    alert_id: UUID,
    ctx: TenantSecurityContext = Depends(require_permission_dep(PERM_ALERT_READ)),
    db: AsyncSession = Depends(get_authorized_tenant_db),
) -> AlertItem:
    """Retrieve detailed forensics of a single alert (isolated to tenant)."""
    alert = await alert_service.get_alert(db, ctx.organization.tenant_id, alert_id)
    return AlertItem.model_validate(alert)


@router.post(
    "/{alert_id}/assign",
    response_model=AlertItem,
    summary="Assign alert to an analyst",
)
async def assign_alert(
    alert_id: UUID,
    payload: AlertAssignRequest,
    ctx: TenantSecurityContext = Depends(require_permission_dep(PERM_ALERT_ASSIGN)),
    db: AsyncSession = Depends(get_authorized_tenant_db),
) -> AlertItem:
    """Assign an OPEN or ASSIGNED alert to an active tenant member."""
    alert = await alert_service.assign_alert(
        session=db,
        tenant_id=ctx.organization.tenant_id,
        actor_user_id=ctx.user.user_id,
        alert_id=alert_id,
        assigned_to_user_id=payload.assigned_to_user_id,
    )
    return AlertItem.model_validate(alert)


@router.patch(
    "/{alert_id}/triage",
    response_model=AlertItem,
    summary="Triage alert (confirm / false positive / dismiss)",
)
async def triage_alert(
    alert_id: UUID,
    payload: AlertTriageRequest,
    ctx: TenantSecurityContext = Depends(require_permission_dep(PERM_ALERT_TRIAGE)),
    db: AsyncSession = Depends(get_authorized_tenant_db),
) -> AlertItem:
    """Record analyst decision, emit offline feedback record, optionally dismiss."""
    alert = await alert_service.triage_alert(
        session=db,
        tenant_id=ctx.organization.tenant_id,
        actor_user_id=ctx.user.user_id,
        alert_id=alert_id,
        analyst_decision=payload.analyst_decision,
        analyst_notes=payload.analyst_notes,
        dismiss=payload.dismiss,
    )
    return AlertItem.model_validate(alert)


@router.get(
    "/{alert_id}/feedback",
    response_model=List[AnalystFeedbackItem],
    summary="List analyst feedback for an alert",
)
async def list_alert_feedback(
    alert_id: UUID,
    ctx: TenantSecurityContext = Depends(require_permission_dep(PERM_ALERT_READ)),
    db: AsyncSession = Depends(get_authorized_tenant_db),
) -> List[AnalystFeedbackItem]:
    """Retrieve offline evaluation feedback recorded against an alert."""
    await alert_service.get_alert(db, ctx.organization.tenant_id, alert_id)
    stmt = (
        select(AnalystFeedbackRecord)
        .where(
            AnalystFeedbackRecord.alert_id == alert_id,
            AnalystFeedbackRecord.tenant_id == ctx.organization.tenant_id,
        )
        .order_by(AnalystFeedbackRecord.created_at.desc())
    )
    records = (await db.execute(stmt)).scalars().all()
    return [AnalystFeedbackItem.model_validate(r) for r in records]
