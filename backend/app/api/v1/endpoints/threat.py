"""Threat Intelligence Core API endpoints (Ingestion, Search, and Thread Reconstruction)."""

from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import (
    TenantSecurityContext,
    get_authorized_tenant_db,
    require_permission_dep,
)
from app.core.rbac import (
    PERM_INGEST_READ,
    PERM_INGEST_SUBMIT,
    PERM_ORG_MANAGE,
    PERM_SEARCH_QUERY,
    PERM_THREAD_READ,
)
from app.ingestion.threat_service import ThreatService
from app.schemas.threat import (
    ChannelRegisterRequest,
    ChannelUpdateRequest,
    IngestionJobResponse,
    SourceChannelItem,
    SourceChannelListResponse,
    ThreatIngestRequest,
    ThreatSearchResponse,
    ThreatThreadResponse,
)

router = APIRouter(prefix="/threat", tags=["Threat Intelligence"])
threat_service = ThreatService()


@router.post(
    "/ingest",
    response_model=IngestionJobResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Submit controlled threat intelligence batch",
    description="Ingests, normalizes, sanitizes, and verifies raw intelligence messages under tenant boundary.",
)
async def ingest_threat_records(
    payload: ThreatIngestRequest,
    request: Request,
    ctx: TenantSecurityContext = Depends(require_permission_dep(PERM_INGEST_SUBMIT)),
    db: AsyncSession = Depends(get_authorized_tenant_db),
) -> IngestionJobResponse:
    """Submit batch intelligence records for normalization, sanitization, and evidence persistence."""
    client_ip = request.client.host if request.client else None
    job = await threat_service.ingest_batch(
        session=db,
        tenant_id=ctx.organization.tenant_id,
        user_id=ctx.user.user_id,
        request=payload,
        client_ip=client_ip,
    )
    return IngestionJobResponse.model_validate(job)


@router.get(
    "/ingest/jobs/{job_id}",
    response_model=IngestionJobResponse,
    summary="Get ingestion job status and provenance",
    description="Poll batch status, record count, and execution errors for an ingestion job.",
)
async def get_ingestion_job(
    job_id: UUID,
    ctx: TenantSecurityContext = Depends(require_permission_dep(PERM_INGEST_READ)),
    db: AsyncSession = Depends(get_authorized_tenant_db),
) -> IngestionJobResponse:
    """Retrieve status and metrics of a previous batch ingestion job."""
    job = await threat_service.get_job(
        session=db,
        tenant_id=ctx.organization.tenant_id,
        job_id=job_id,
    )
    if job is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Ingestion job '{job_id}' not found.",
        )
    return IngestionJobResponse.model_validate(job)


@router.get(
    "/search",
    response_model=ThreatSearchResponse,
    summary="Search sanitized threat intelligence",
    description="Query sanitized message content with tenant isolation. Prohibits exposure of raw evidence paths.",
)
async def search_threat_records(
    request: Request,
    q: str = Query(..., min_length=1, max_length=500, description="Search term or phrase"),
    channel_id: Optional[str] = Query(None, description="Optional channel identifier filter"),
    limit: int = Query(50, ge=1, le=100, description="Maximum number of items to return"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    ctx: TenantSecurityContext = Depends(require_permission_dep(PERM_SEARCH_QUERY)),
    db: AsyncSession = Depends(get_authorized_tenant_db),
) -> ThreatSearchResponse:
    """Search sanitized intelligence messages matching search parameters."""
    client_ip = request.client.host if request.client else None
    return await threat_service.search_threats(
        session=db,
        tenant_id=ctx.organization.tenant_id,
        user_id=ctx.user.user_id,
        query=q,
        channel_id=channel_id,
        limit=limit,
        offset=offset,
        client_ip=client_ip,
    )


@router.get(
    "/threads/{channel_id}/{thread_id}",
    response_model=ThreatThreadResponse,
    summary="Retrieve sanitized message thread",
    description="Retrieve all messages in a specific channel thread in chronological sequence.",
)
async def get_thread_detail(
    channel_id: str,
    thread_id: str,
    request: Request,
    ctx: TenantSecurityContext = Depends(require_permission_dep(PERM_THREAD_READ)),
    db: AsyncSession = Depends(get_authorized_tenant_db),
) -> ThreatThreadResponse:
    """Retrieve thread detail and message sequence."""
    client_ip = request.client.host if request.client else None
    return await threat_service.get_thread(
        session=db,
        tenant_id=ctx.organization.tenant_id,
        user_id=ctx.user.user_id,
        channel_id=channel_id,
        thread_id=thread_id,
        client_ip=client_ip,
    )


# =============================================================================
# Source Channel Administration Endpoints (SEC-THREAT-05)
# =============================================================================

@router.get(
    "/channels",
    response_model=SourceChannelListResponse,
    summary="List registered source channels",
    description="Retrieve registered threat intelligence feeds and channels for the authenticated tenant.",
)
async def list_threat_channels(
    limit: int = Query(50, ge=1, le=100, description="Maximum number of channels to return"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    is_authorized: Optional[bool] = Query(None, description="Optional filter by authorization status"),
    source_type: Optional[str] = Query(None, pattern="^(telegram|darkweb)$", description="Optional filter by source type"),
    ctx: TenantSecurityContext = Depends(require_permission_dep(PERM_INGEST_READ)),
    db: AsyncSession = Depends(get_authorized_tenant_db),
) -> SourceChannelListResponse:
    """List tenant-scoped threat channels with pagination and filtering."""
    return await threat_service.list_channels(
        session=db,
        tenant_id=ctx.organization.tenant_id,
        limit=limit,
        offset=offset,
        is_authorized=is_authorized,
        source_type=source_type,
    )


@router.post(
    "/channels",
    response_model=SourceChannelItem,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new intelligence source channel",
    description="Register a new channel for monitoring under tenant boundary. Defaults to is_authorized=False.",
)
async def register_threat_channel(
    payload: ChannelRegisterRequest,
    request: Request,
    ctx: TenantSecurityContext = Depends(require_permission_dep(PERM_ORG_MANAGE)),
    db: AsyncSession = Depends(get_authorized_tenant_db),
) -> SourceChannelItem:
    """Register new channel; requires tenant admin permission."""
    client_ip = request.client.host if request.client else None
    return await threat_service.register_channel(
        session=db,
        tenant_id=ctx.organization.tenant_id,
        user_id=ctx.user.user_id,
        request=payload,
        client_ip=client_ip,
    )


@router.patch(
    "/channels/{channel_id}",
    response_model=SourceChannelItem,
    summary="Update channel metadata or authorization status",
    description="Update channel descriptive title/handle or enable/disable collection authorization.",
)
async def update_threat_channel(
    channel_id: str,
    payload: ChannelUpdateRequest,
    request: Request,
    ctx: TenantSecurityContext = Depends(require_permission_dep(PERM_ORG_MANAGE)),
    db: AsyncSession = Depends(get_authorized_tenant_db),
) -> SourceChannelItem:
    """Update channel metadata or authorization status; requires tenant admin permission."""
    client_ip = request.client.host if request.client else None
    return await threat_service.update_channel(
        session=db,
        tenant_id=ctx.organization.tenant_id,
        user_id=ctx.user.user_id,
        channel_id=channel_id,
        request=payload,
        client_ip=client_ip,
    )

