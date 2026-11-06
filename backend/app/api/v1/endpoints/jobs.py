"""Admin endpoint for inspecting system jobs and dead-letter records."""

from typing import List, Optional
from uuid import UUID
from fastapi import APIRouter, Depends, Header, Query
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db
from app.database.models.jobs import SystemJobRecord

router = APIRouter(prefix="/admin/system-jobs", tags=["Admin & System Jobs"])


class SystemJobItemResponse(BaseModel):
    """Public read model for system jobs (zero raw task payload)."""

    model_config = ConfigDict(from_attributes=True)

    job_id: UUID
    tenant_id: Optional[UUID]
    task_name: str
    queue_name: str
    args_hash: str
    error_class: str
    sanitized_error_message: str
    attempt_count: int
    status: str


class SystemJobListResponse(BaseModel):
    """Paginated collection of system jobs."""

    total_count: int
    items: List[SystemJobItemResponse]


@router.get(
    "",
    response_model=SystemJobListResponse,
    summary="List failed or dead-letter background tasks",
    description="Read-only diagnostic ledger of exhausted worker jobs. Returns metadata and cryptographic hashes only.",
)
async def list_system_jobs(
    status_filter: Optional[str] = Query(None, alias="status"),
    queue_filter: Optional[str] = Query(None, alias="queue"),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    x_tenant_id: Optional[str] = Header(None, alias="X-Tenant-ID"),
    db: AsyncSession = Depends(get_db),
) -> SystemJobListResponse:
    """Retrieve system jobs scoped to caller's tenant."""
    stmt = select(SystemJobRecord)

    if x_tenant_id:
        try:
            t_uuid = UUID(x_tenant_id)
            stmt = stmt.where(
                (SystemJobRecord.tenant_id == t_uuid)
                | (SystemJobRecord.tenant_id.is_(None))
            )
        except ValueError:
            pass

    if status_filter:
        stmt = stmt.where(SystemJobRecord.status == status_filter)
    if queue_filter:
        stmt = stmt.where(SystemJobRecord.queue_name == queue_filter)

    stmt = stmt.order_by(SystemJobRecord.failed_at.desc()).offset(offset).limit(limit)
    result = await db.scalars(stmt)
    records = list(result.all())

    items = [SystemJobItemResponse.model_validate(r) for r in records]
    return SystemJobListResponse(total_count=len(items), items=items)
