"""Threat Detection Engine API endpoints."""

from datetime import datetime, timezone
from typing import List, Optional
import uuid
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.deps import (
    TenantSecurityContext,
    get_authorized_tenant_db,
    require_permission_dep,
)
from app.core.rbac import (
    PERM_CASE_UPDATE,
    PERM_SEARCH_QUERY,
)
from app.database.models.audit import AuditEventRecord
from app.database.models.detection import (
    DetectionRecord,
    DetectionRuleHitRecord,
    KeywordRuleRecord,
    ThreatCategoryRecord,
    URLIndicatorRecord,
)
from app.schemas.detection import (
    DetectionItem,
    DetectionListResponse,
    DetectionReviewRequest,
    KeywordRuleItem,
    ThreatCategoryItem,
)

router = APIRouter(tags=["Threat Detection"])


@router.get(
    "/detections",
    response_model=DetectionListResponse,
    summary="List tenant threat detections",
)
async def list_detections(
    category: Optional[str] = Query(None, description="Filter by threat category"),
    severity: Optional[str] = Query(None, description="Filter by severity level"),
    stance: Optional[str] = Query(None, description="Filter by message stance"),
    review_status: Optional[str] = Query(None, description="Filter by analyst review status"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    ctx: TenantSecurityContext = Depends(require_permission_dep(PERM_SEARCH_QUERY)),
    db: AsyncSession = Depends(get_authorized_tenant_db),
) -> DetectionListResponse:
    """Retrieve paginated threat detections scoped to tenant with masked excerpts."""
    query = (
        select(DetectionRecord)
        .options(
            selectinload(DetectionRecord.hits),
            selectinload(DetectionRecord.url_indicators),
        )
        .where(DetectionRecord.tenant_id == ctx.organization.tenant_id)
        .order_by(DetectionRecord.created_at.desc())
    )

    if category:
        query = query.where(DetectionRecord.category == category)
    if severity:
        query = query.where(DetectionRecord.severity == severity.upper())
    if stance:
        query = query.where(DetectionRecord.stance == stance.lower())
    if review_status:
        query = query.where(DetectionRecord.review_status == review_status.lower())

    count_stmt = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_stmt)).scalar() or 0

    paginated_query = query.limit(limit).offset(offset)
    records = (await db.execute(paginated_query)).scalars().all()

    items = [DetectionItem.model_validate(r) for r in records]
    return DetectionListResponse(
        items=items,
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/detections/{detection_id}",
    response_model=DetectionItem,
    summary="Get single threat detection details",
)
async def get_detection(
    detection_id: UUID,
    ctx: TenantSecurityContext = Depends(require_permission_dep(PERM_SEARCH_QUERY)),
    db: AsyncSession = Depends(get_authorized_tenant_db),
) -> DetectionItem:
    """Retrieve detailed forensics of a single detection (isolated to tenant)."""
    stmt = (
        select(DetectionRecord)
        .options(
            selectinload(DetectionRecord.hits),
            selectinload(DetectionRecord.url_indicators),
        )
        .where(
            DetectionRecord.detection_id == detection_id,
            DetectionRecord.tenant_id == ctx.organization.tenant_id,
        )
    )
    rec = (await db.execute(stmt)).scalar_one_or_none()
    if not rec:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Detection {detection_id} not found in tenant context",
        )
    return DetectionItem.model_validate(rec)


@router.patch(
    "/detections/{detection_id}/review",
    response_model=DetectionItem,
    summary="Update detection analyst review status",
)
async def review_detection(
    detection_id: UUID,
    payload: DetectionReviewRequest,
    request: Request,
    ctx: TenantSecurityContext = Depends(require_permission_dep(PERM_CASE_UPDATE)),
    db: AsyncSession = Depends(get_authorized_tenant_db),
) -> DetectionItem:
    """Triage detection item review status (unreviewed, confirmed, false_positive, dismissed)."""
    stmt = (
        select(DetectionRecord)
        .options(
            selectinload(DetectionRecord.hits),
            selectinload(DetectionRecord.url_indicators),
        )
        .where(
            DetectionRecord.detection_id == detection_id,
            DetectionRecord.tenant_id == ctx.organization.tenant_id,
        )
    )
    rec = (await db.execute(stmt)).scalar_one_or_none()
    if not rec:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Detection {detection_id} not found in tenant context",
        )

    old_status = rec.review_status
    rec.review_status = payload.review_status
    now = datetime.now(timezone.utc)
    client_ip = request.client.host if request.client else None

    header_cid = request.headers.get("X-Correlation-ID")
    try:
        correlation_id = uuid.UUID(header_cid) if header_cid else uuid.uuid4()
    except (ValueError, TypeError):
        correlation_id = uuid.uuid4()

    audit_event = AuditEventRecord(
        audit_event_id=uuid.uuid4(),
        tenant_id=ctx.organization.tenant_id,
        user_id=ctx.user.user_id,
        action_type="DETECTION_REVIEW_STATUS_UPDATED",
        client_ip_address=client_ip,
        correlation_id=correlation_id,
        details={
            "detection_id": str(detection_id),
            "old_status": old_status,
            "new_status": payload.review_status,
        },
        event_timestamp_utc=now,
    )
    db.add(audit_event)
    await db.flush()

    return DetectionItem.model_validate(rec)


@router.get(
    "/threat-categories",
    response_model=List[ThreatCategoryItem],
    summary="List canonical threat categories",
)
async def list_threat_categories(
    ctx: TenantSecurityContext = Depends(require_permission_dep(PERM_SEARCH_QUERY)),
    db: AsyncSession = Depends(get_authorized_tenant_db),
) -> List[ThreatCategoryItem]:
    """Retrieve global canonical threat categories."""
    stmt = select(ThreatCategoryRecord).where(ThreatCategoryRecord.is_active == True)
    cats = (await db.execute(stmt)).scalars().all()
    return [ThreatCategoryItem.model_validate(c) for c in cats]


@router.get(
    "/keyword-rules",
    response_model=List[KeywordRuleItem],
    summary="List active taxonomy keyword rules",
)
async def list_keyword_rules(
    category: Optional[str] = Query(None, description="Filter rules by threat category"),
    ctx: TenantSecurityContext = Depends(require_permission_dep(PERM_SEARCH_QUERY)),
    db: AsyncSession = Depends(get_authorized_tenant_db),
) -> List[KeywordRuleItem]:
    """Retrieve compiled taxonomy rules."""
    stmt = select(KeywordRuleRecord).where(KeywordRuleRecord.is_enabled == True)
    if category:
        stmt = stmt.where(KeywordRuleRecord.category == category)
    rules = (await db.execute(stmt)).scalars().all()
    return [KeywordRuleItem.model_validate(r) for r in rules]
