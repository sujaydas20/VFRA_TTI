"""Investigative Case Management API endpoints (FR-EVI-001, AC-REQ-004)."""

from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import (
    TenantSecurityContext,
    get_authorized_tenant_db,
    require_permission_dep,
)
from app.core.rbac import (
    PERM_CASE_CREATE,
    PERM_CASE_MESSAGE_PIN,
    PERM_CASE_NOTE_CREATE,
    PERM_CASE_READ,
    PERM_CASE_UPDATE,
)
from app.schemas.cases import (
    CaseCreateRequest,
    CaseDetailResponse,
    CaseListResponse,
    CaseMessageAssociationItem,
    CaseNoteCreateRequest,
    CaseNoteItem,
    CasePinMessageRequest,
    CaseResponse,
    CaseUpdateRequest,
)
from app.services.case_service import CaseService

router = APIRouter(prefix="/cases", tags=["Case Management"])
case_service = CaseService()


@router.post(
    "",
    response_model=CaseResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create investigative case container",
    description="Creates a new tenant-scoped case container with mandatory audit logging.",
)
async def create_case(
    payload: CaseCreateRequest,
    request: Request,
    ctx: TenantSecurityContext = Depends(require_permission_dep(PERM_CASE_CREATE)),
    db: AsyncSession = Depends(get_authorized_tenant_db),
) -> CaseResponse:
    client_ip = request.client.host if request.client else None
    case = await case_service.create_case(
        session=db,
        tenant_id=ctx.organization.tenant_id,
        user_id=ctx.user.user_id,
        request=payload,
        client_ip=client_ip,
    )
    return CaseResponse(
        case_id=case.case_id,
        tenant_id=case.tenant_id,
        case_title=case.case_title,
        case_reference=case.case_reference,
        internal_agency_ref=case.internal_agency_ref,
        case_status=case.case_status,
        lead_investigator_id=case.lead_investigator_id,
        description=case.description,
        created_at_utc=case.created_at_utc,
        closed_at_utc=case.closed_at_utc,
        pinned_messages_count=0,
        notes_count=0,
    )


@router.get(
    "",
    response_model=CaseListResponse,
    summary="List investigative cases",
    description="Returns a paginated list of cases belonging exclusively to the authenticated tenant.",
)
async def list_cases(
    case_status: Optional[str] = Query(None, alias="status"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    ctx: TenantSecurityContext = Depends(require_permission_dep(PERM_CASE_READ)),
    db: AsyncSession = Depends(get_authorized_tenant_db),
) -> CaseListResponse:
    items, total = await case_service.list_cases(
        session=db,
        tenant_id=ctx.organization.tenant_id,
        status_filter=case_status,
        limit=limit,
        offset=offset,
    )
    return CaseListResponse(
        items=[CaseResponse.model_validate(i) for i in items],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/{case_id}",
    response_model=CaseDetailResponse,
    summary="Get investigative case details",
    description="Retrieves a specific case record including all pinned messages and analyst notes.",
)
async def get_case_detail(
    case_id: UUID,
    ctx: TenantSecurityContext = Depends(require_permission_dep(PERM_CASE_READ)),
    db: AsyncSession = Depends(get_authorized_tenant_db),
) -> CaseDetailResponse:
    case = await case_service.get_case(
        session=db,
        tenant_id=ctx.organization.tenant_id,
        case_id=case_id,
    )
    return CaseDetailResponse(
        case_id=case.case_id,
        tenant_id=case.tenant_id,
        case_title=case.case_title,
        case_reference=case.case_reference,
        internal_agency_ref=case.internal_agency_ref,
        case_status=case.case_status,
        lead_investigator_id=case.lead_investigator_id,
        description=case.description,
        created_at_utc=case.created_at_utc,
        closed_at_utc=case.closed_at_utc,
        pinned_messages=[CaseMessageAssociationItem.model_validate(p) for p in case.pinned_messages],
        notes=[CaseNoteItem.model_validate(n) for n in case.notes],
    )


@router.patch(
    "/{case_id}",
    response_model=CaseResponse,
    summary="Update investigative case metadata or status",
    description="Updates case metadata or changes lifecycle status. Locked cases reject metadata modifications.",
)
async def update_case(
    case_id: UUID,
    payload: CaseUpdateRequest,
    request: Request,
    ctx: TenantSecurityContext = Depends(require_permission_dep(PERM_CASE_UPDATE)),
    db: AsyncSession = Depends(get_authorized_tenant_db),
) -> CaseResponse:
    client_ip = request.client.host if request.client else None
    case = await case_service.update_case(
        session=db,
        tenant_id=ctx.organization.tenant_id,
        user_id=ctx.user.user_id,
        case_id=case_id,
        request=payload,
        client_ip=client_ip,
        caller_role=ctx.membership.assigned_role,
    )
    return CaseResponse(
        case_id=case.case_id,
        tenant_id=case.tenant_id,
        case_title=case.case_title,
        case_reference=case.case_reference,
        internal_agency_ref=case.internal_agency_ref,
        case_status=case.case_status,
        lead_investigator_id=case.lead_investigator_id,
        description=case.description,
        created_at_utc=case.created_at_utc,
        closed_at_utc=case.closed_at_utc,
        pinned_messages_count=len(case.pinned_messages),
        notes_count=len(case.notes),
    )


@router.post(
    "/{case_id}/messages",
    response_model=CaseMessageAssociationItem,
    status_code=status.HTTP_201_CREATED,
    summary="Pin threat message to case",
    description="Pins an ingested message to an active case with optional investigator tags and annotations.",
)
async def pin_message_to_case(
    case_id: UUID,
    payload: CasePinMessageRequest,
    request: Request,
    ctx: TenantSecurityContext = Depends(require_permission_dep(PERM_CASE_MESSAGE_PIN)),
    db: AsyncSession = Depends(get_authorized_tenant_db),
) -> CaseMessageAssociationItem:
    client_ip = request.client.host if request.client else None
    assoc = await case_service.pin_message(
        session=db,
        tenant_id=ctx.organization.tenant_id,
        user_id=ctx.user.user_id,
        case_id=case_id,
        request=payload,
        client_ip=client_ip,
    )
    return CaseMessageAssociationItem.model_validate(assoc)


@router.delete(
    "/{case_id}/messages/{message_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Unpin threat message from case",
    description="Removes message pin from case without mutating underlying threat intelligence telemetry.",
)
async def unpin_message_from_case(
    case_id: UUID,
    message_id: str,
    request: Request,
    ctx: TenantSecurityContext = Depends(require_permission_dep(PERM_CASE_MESSAGE_PIN)),
    db: AsyncSession = Depends(get_authorized_tenant_db),
) -> None:
    client_ip = request.client.host if request.client else None
    await case_service.unpin_message(
        session=db,
        tenant_id=ctx.organization.tenant_id,
        user_id=ctx.user.user_id,
        case_id=case_id,
        message_id=message_id,
        client_ip=client_ip,
    )


@router.post(
    "/{case_id}/notes",
    response_model=CaseNoteItem,
    status_code=status.HTTP_201_CREATED,
    summary="Create case analyst note",
    description="Adds a confidential investigator note or hypothesis to the case.",
)
async def create_case_note(
    case_id: UUID,
    payload: CaseNoteCreateRequest,
    request: Request,
    ctx: TenantSecurityContext = Depends(require_permission_dep(PERM_CASE_NOTE_CREATE)),
    db: AsyncSession = Depends(get_authorized_tenant_db),
) -> CaseNoteItem:
    client_ip = request.client.host if request.client else None
    note = await case_service.create_note(
        session=db,
        tenant_id=ctx.organization.tenant_id,
        user_id=ctx.user.user_id,
        case_id=case_id,
        request=payload,
        client_ip=client_ip,
    )
    return CaseNoteItem.model_validate(note)


@router.get(
    "/{case_id}/notes",
    response_model=List[CaseNoteItem],
    summary="List case notes",
    description="Lists all confidential investigator notes associated with the case.",
)
async def list_case_notes(
    case_id: UUID,
    ctx: TenantSecurityContext = Depends(require_permission_dep(PERM_CASE_READ)),
    db: AsyncSession = Depends(get_authorized_tenant_db),
) -> List[CaseNoteItem]:
    notes = await case_service.list_notes(
        session=db,
        tenant_id=ctx.organization.tenant_id,
        case_id=case_id,
    )
    return [CaseNoteItem.model_validate(n) for n in notes]
