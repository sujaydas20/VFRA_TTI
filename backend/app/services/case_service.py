"""Case Management Service: Workspaces, Message Pinning, Notes, and Evidentiary Controls.

Canonical Reference:
- Requirements: FR-EVI-001, AC-REQ-004
- Physical Schema: app.investigative_cases, app.case_message_associations, app.case_notes
- Security Invariants: Multi-tenant isolated, RLS-enforced, transactional audit trails
"""

from datetime import datetime, timezone
import hashlib
from typing import List, Optional, Tuple
from uuid import UUID
import uuid

from fastapi import HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.rbac import ROLE_INVESTIGATOR_LEAD
from app.database.models.audit import AuditEventRecord
from app.database.models.cases import CaseMessageAssociation, CaseNote, InvestigativeCase
from app.database.models.iam import TenantMembership
from app.database.models.intelligence import SourceMessage
from app.schemas.cases import (
    CLOSED_CASE_STATUSES,
    CaseCreateRequest,
    CaseNoteCreateRequest,
    CasePinMessageRequest,
    CaseUpdateRequest,
)


class CaseService:
    """Core domain service orchestrating tenant case lifecycle, message pinning, and investigative notes."""

    async def create_case(
        self,
        session: AsyncSession,
        tenant_id: UUID,
        user_id: UUID,
        request: CaseCreateRequest,
        client_ip: Optional[str] = None,
    ) -> InvestigativeCase:
        """Create a new tenant-scoped investigative case container."""
        # 1. Determine or auto-generate case_reference
        case_ref = request.case_reference
        if not case_ref:
            current_year = datetime.now(timezone.utc).year
            # Determine sequence count within tenant for the current year
            count_stmt = select(func.count(InvestigativeCase.case_id)).where(
                InvestigativeCase.tenant_id == tenant_id
            )
            count_res = await session.execute(count_stmt)
            existing_count = count_res.scalar() or 0
            case_ref = f"CASE-{current_year}-{existing_count + 1:04d}"

        # 2. Check if case_reference already exists in this tenant
        existing_stmt = select(InvestigativeCase.case_id).where(
            InvestigativeCase.tenant_id == tenant_id,
            InvestigativeCase.case_reference == case_ref,
        )
        existing_res = await session.execute(existing_stmt)
        if existing_res.scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Case reference '{case_ref}' already exists in this tenant.",
            )

        # 3. Validate and resolve lead investigator membership within this tenant (SEC-CASE-01)
        lead_id = request.lead_investigator_id or user_id
        membership_stmt = select(TenantMembership.membership_id).where(
            TenantMembership.tenant_id == tenant_id,
            TenantMembership.user_id == lead_id,
            TenantMembership.membership_status == "ACTIVE",
        )
        mem_res = await session.execute(membership_stmt)
        if not mem_res.scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Lead investigator must be an active member of this organization.",
            )

        new_case = InvestigativeCase(
            case_id=uuid.uuid4(),
            tenant_id=tenant_id,
            case_title=request.case_title,
            case_reference=case_ref,
            internal_agency_ref=request.internal_agency_ref,
            case_status="ACTIVE",
            lead_investigator_id=lead_id,
            description=request.description,
            created_at_utc=datetime.now(timezone.utc),
        )
        session.add(new_case)

        # 4. Transactional Audit Event
        ref_hash = hashlib.sha256(case_ref.encode("utf-8")).hexdigest()
        audit_event = AuditEventRecord(
            audit_event_id=uuid.uuid4(),
            tenant_id=tenant_id,
            user_id=user_id,
            action_type="CASE_CREATED",
            target_identifier_hash=ref_hash,
            client_ip_address=client_ip,
            correlation_id=uuid.uuid4(),
            details={
                "case_id": str(new_case.case_id),
                "case_reference": case_ref,
                "case_title": new_case.case_title,
                "lead_investigator_id": str(lead_id),
            },
            event_timestamp_utc=datetime.now(timezone.utc),
        )
        session.add(audit_event)

        try:
            await session.commit()
            await session.refresh(new_case)
        except IntegrityError as exc:
            await session.rollback()
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Integrity conflict creating case '{case_ref}': {str(exc.orig)}",
            )

        return new_case

    async def get_case(
        self,
        session: AsyncSession,
        tenant_id: UUID,
        case_id: UUID,
    ) -> InvestigativeCase:
        """Retrieve a specific case record including its pinned messages and notes."""
        stmt = (
            select(InvestigativeCase)
            .where(
                InvestigativeCase.tenant_id == tenant_id,
                InvestigativeCase.case_id == case_id,
            )
            .options(
                selectinload(InvestigativeCase.pinned_messages),
                selectinload(InvestigativeCase.notes),
            )
        )
        result = await session.execute(stmt)
        case = result.scalar_one_or_none()
        if not case:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Investigative case '{case_id}' not found.",
            )
        return case

    async def list_cases(
        self,
        session: AsyncSession,
        tenant_id: UUID,
        status_filter: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[dict], int]:
        """List tenant cases with counts of pinned messages and notes."""
        base_query = select(InvestigativeCase).where(InvestigativeCase.tenant_id == tenant_id)
        count_query = select(func.count(InvestigativeCase.case_id)).where(InvestigativeCase.tenant_id == tenant_id)

        if status_filter:
            base_query = base_query.where(InvestigativeCase.case_status == status_filter)
            count_query = count_query.where(InvestigativeCase.case_status == status_filter)

        total_res = await session.execute(count_query)
        total = total_res.scalar() or 0

        stmt = (
            base_query.order_by(InvestigativeCase.created_at_utc.desc())
            .offset(offset)
            .limit(limit)
            .options(
                selectinload(InvestigativeCase.pinned_messages),
                selectinload(InvestigativeCase.notes),
            )
        )
        cases_res = await session.execute(stmt)
        cases = cases_res.scalars().all()

        items = []
        for c in cases:
            items.append({
                "case_id": c.case_id,
                "tenant_id": c.tenant_id,
                "case_title": c.case_title,
                "case_reference": c.case_reference,
                "internal_agency_ref": c.internal_agency_ref,
                "case_status": c.case_status,
                "lead_investigator_id": c.lead_investigator_id,
                "description": c.description,
                "created_at_utc": c.created_at_utc,
                "closed_at_utc": c.closed_at_utc,
                "pinned_messages_count": len(c.pinned_messages),
                "notes_count": len(c.notes),
            })

        return items, total

    async def update_case(
        self,
        session: AsyncSession,
        tenant_id: UUID,
        user_id: UUID,
        case_id: UUID,
        request: CaseUpdateRequest,
        client_ip: Optional[str] = None,
        caller_role: Optional[str] = None,
    ) -> InvestigativeCase:
        """Update case metadata or advance its lifecycle status."""
        case = await self.get_case(session, tenant_id, case_id)

        # Closed-case guard: if already locked/archived, disallow metadata modifications
        is_currently_closed = case.case_status in CLOSED_CASE_STATUSES
        has_metadata_changes = (
            (request.case_title is not None and request.case_title != case.case_title)
            or (request.internal_agency_ref is not None and request.internal_agency_ref != case.internal_agency_ref)
            or (request.description is not None and request.description != case.description)
            or (request.lead_investigator_id is not None and request.lead_investigator_id != case.lead_investigator_id)
        )

        # Reopening governance check (SEC-CASE-02):
        # Only the assigned lead investigator or a user holding ROLE_INVESTIGATOR_LEAD may reopen
        is_reopening = (
            is_currently_closed
            and request.case_status is not None
            and request.case_status not in CLOSED_CASE_STATUSES
        )
        if is_reopening:
            if caller_role is None:
                role_stmt = select(TenantMembership.assigned_role).where(
                    TenantMembership.tenant_id == tenant_id,
                    TenantMembership.user_id == user_id,
                    TenantMembership.membership_status == "ACTIVE",
                )
                role_res = await session.execute(role_stmt)
                caller_role = role_res.scalar_one_or_none()

            is_lead_role = caller_role == ROLE_INVESTIGATOR_LEAD
            is_case_lead = user_id == case.lead_investigator_id

            if not (is_lead_role or is_case_lead):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Only the assigned lead investigator or an Investigator Lead can reopen a finalized or archived case.",
                )

        if is_currently_closed and has_metadata_changes:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Cannot modify metadata of a case with status '{case.case_status}'. Reopen the case first.",
            )

        ref_hash = hashlib.sha256(case.case_reference.encode("utf-8")).hexdigest()

        # Update metadata if provided and case is active/review
        if request.case_title is not None:
            case.case_title = request.case_title
        if request.internal_agency_ref is not None:
            case.internal_agency_ref = request.internal_agency_ref
        if request.description is not None:
            case.description = request.description
        if request.lead_investigator_id is not None:
            # Validate target lead investigator is an active member of this tenant (SEC-CASE-01)
            membership_stmt = select(TenantMembership.membership_id).where(
                TenantMembership.tenant_id == tenant_id,
                TenantMembership.user_id == request.lead_investigator_id,
                TenantMembership.membership_status == "ACTIVE",
            )
            mem_res = await session.execute(membership_stmt)
            if not mem_res.scalar_one_or_none():
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Lead investigator must be an active member of this organization.",
                )
            case.lead_investigator_id = request.lead_investigator_id

        # Update lifecycle status if requested
        if request.case_status is not None and request.case_status != case.case_status:
            old_status = case.case_status
            case.case_status = request.case_status

            if case.case_status in CLOSED_CASE_STATUSES:
                case.closed_at_utc = datetime.now(timezone.utc)
            elif old_status in CLOSED_CASE_STATUSES and case.case_status not in CLOSED_CASE_STATUSES:
                case.closed_at_utc = None

            status_audit = AuditEventRecord(
                audit_event_id=uuid.uuid4(),
                tenant_id=tenant_id,
                user_id=user_id,
                action_type="CASE_STATUS_CHANGED",
                target_identifier_hash=ref_hash,
                client_ip_address=client_ip,
                correlation_id=uuid.uuid4(),
                details={
                    "case_id": str(case.case_id),
                    "case_reference": case.case_reference,
                    "old_status": old_status,
                    "new_status": case.case_status,
                },
                event_timestamp_utc=datetime.now(timezone.utc),
            )
            session.add(status_audit)

        # General metadata update audit
        if has_metadata_changes:
            meta_audit = AuditEventRecord(
                audit_event_id=uuid.uuid4(),
                tenant_id=tenant_id,
                user_id=user_id,
                action_type="CASE_UPDATED",
                target_identifier_hash=ref_hash,
                client_ip_address=client_ip,
                correlation_id=uuid.uuid4(),
                details={
                    "case_id": str(case.case_id),
                    "case_reference": case.case_reference,
                    "title": case.case_title,
                },
                event_timestamp_utc=datetime.now(timezone.utc),
            )
            session.add(meta_audit)

        await session.commit()
        await session.refresh(case)
        return case

    async def pin_message(
        self,
        session: AsyncSession,
        tenant_id: UUID,
        user_id: UUID,
        case_id: UUID,
        request: CasePinMessageRequest,
        client_ip: Optional[str] = None,
    ) -> CaseMessageAssociation:
        """Pin an ingested threat message to an active case container."""
        case = await self.get_case(session, tenant_id, case_id)

        # Closed-case guard: Cannot pin messages to locked or archived cases
        if case.case_status in CLOSED_CASE_STATUSES:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Cannot pin messages to case '{case.case_reference}' with status '{case.case_status}'.",
            )

        # Verify source message exists in the same tenant
        msg_stmt = select(SourceMessage.message_id).where(
            SourceMessage.tenant_id == tenant_id,
            SourceMessage.message_id == request.message_id,
        )
        msg_res = await session.execute(msg_stmt)
        if not msg_res.scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Source message '{request.message_id}' not found in this tenant.",
            )

        # Check if message is already pinned
        pinned_stmt = select(CaseMessageAssociation.association_id).where(
            CaseMessageAssociation.case_id == case_id,
            CaseMessageAssociation.message_id == request.message_id,
        )
        pinned_res = await session.execute(pinned_stmt)
        if pinned_res.scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Message '{request.message_id}' is already pinned to case '{case.case_reference}'.",
            )

        # Create Association
        association = CaseMessageAssociation(
            association_id=uuid.uuid4(),
            tenant_id=tenant_id,
            case_id=case_id,
            message_id=request.message_id,
            investigator_tags=request.investigator_tags or [],
            analyst_annotation=request.analyst_annotation,
            pinned_by_user_id=user_id,
            pinned_at_utc=datetime.now(timezone.utc),
        )
        session.add(association)

        # Transactional Audit Event
        pin_target = f"{case_id}:{request.message_id}"
        pin_hash = hashlib.sha256(pin_target.encode("utf-8")).hexdigest()
        audit_event = AuditEventRecord(
            audit_event_id=uuid.uuid4(),
            tenant_id=tenant_id,
            user_id=user_id,
            action_type="MESSAGE_PINNED_TO_CASE",
            target_identifier_hash=pin_hash,
            client_ip_address=client_ip,
            correlation_id=uuid.uuid4(),
            details={
                "case_id": str(case_id),
                "case_reference": case.case_reference,
                "message_id": request.message_id,
                "tags": request.investigator_tags,
            },
            event_timestamp_utc=datetime.now(timezone.utc),
        )
        session.add(audit_event)

        try:
            await session.commit()
            await session.refresh(association)
        except IntegrityError as exc:
            await session.rollback()
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Integrity conflict pinning message: {str(exc.orig)}",
            )

        return association

    async def unpin_message(
        self,
        session: AsyncSession,
        tenant_id: UUID,
        user_id: UUID,
        case_id: UUID,
        message_id: str,
        client_ip: Optional[str] = None,
    ) -> bool:
        """Unpin an evidentiary message from a case without mutating shared threat data."""
        case = await self.get_case(session, tenant_id, case_id)

        # Closed-case guard: Cannot unpin from locked or archived cases
        if case.case_status in CLOSED_CASE_STATUSES:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Cannot unpin messages from case '{case.case_reference}' with status '{case.case_status}'.",
            )

        assoc_stmt = select(CaseMessageAssociation).where(
            CaseMessageAssociation.case_id == case_id,
            CaseMessageAssociation.message_id == message_id,
            CaseMessageAssociation.tenant_id == tenant_id,
        )
        assoc_res = await session.execute(assoc_stmt)
        assoc = assoc_res.scalar_one_or_none()
        if not assoc:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Message '{message_id}' is not pinned to case '{case.case_reference}'.",
            )

        await session.delete(assoc)

        # Transactional Audit Event
        unpin_target = f"{case_id}:{message_id}"
        unpin_hash = hashlib.sha256(unpin_target.encode("utf-8")).hexdigest()
        audit_event = AuditEventRecord(
            audit_event_id=uuid.uuid4(),
            tenant_id=tenant_id,
            user_id=user_id,
            action_type="MESSAGE_UNPINNED_FROM_CASE",
            target_identifier_hash=unpin_hash,
            client_ip_address=client_ip,
            correlation_id=uuid.uuid4(),
            details={
                "case_id": str(case_id),
                "case_reference": case.case_reference,
                "message_id": message_id,
            },
            event_timestamp_utc=datetime.now(timezone.utc),
        )
        session.add(audit_event)

        await session.commit()
        return True

    async def create_note(
        self,
        session: AsyncSession,
        tenant_id: UUID,
        user_id: UUID,
        case_id: UUID,
        request: CaseNoteCreateRequest,
        client_ip: Optional[str] = None,
    ) -> CaseNote:
        """Add a confidential analyst hypothesis or investigation note to a case."""
        case = await self.get_case(session, tenant_id, case_id)

        # Closed-case guard: Cannot add notes to locked or archived cases
        if case.case_status in CLOSED_CASE_STATUSES:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Cannot add notes to case '{case.case_reference}' with status '{case.case_status}'.",
            )

        note = CaseNote(
            note_id=uuid.uuid4(),
            tenant_id=tenant_id,
            case_id=case_id,
            author_user_id=user_id,
            note_title=request.note_title,
            note_content=request.note_content,
            created_at_utc=datetime.now(timezone.utc),
            updated_at_utc=datetime.now(timezone.utc),
        )
        session.add(note)

        # Transactional Audit Event
        note_hash = hashlib.sha256(str(note.note_id).encode("utf-8")).hexdigest()
        audit_event = AuditEventRecord(
            audit_event_id=uuid.uuid4(),
            tenant_id=tenant_id,
            user_id=user_id,
            action_type="CASE_NOTE_ADDED",
            target_identifier_hash=note_hash,
            client_ip_address=client_ip,
            correlation_id=uuid.uuid4(),
            details={
                "case_id": str(case_id),
                "case_reference": case.case_reference,
                "note_id": str(note.note_id),
                "note_title": note.note_title,
            },
            event_timestamp_utc=datetime.now(timezone.utc),
        )
        session.add(audit_event)

        await session.commit()
        await session.refresh(note)
        return note

    async def list_notes(
        self,
        session: AsyncSession,
        tenant_id: UUID,
        case_id: UUID,
    ) -> List[CaseNote]:
        """List all analyst notes belonging to a specific case."""
        # Ensure case exists and belongs to tenant
        await self.get_case(session, tenant_id, case_id)

        stmt = (
            select(CaseNote)
            .where(
                CaseNote.tenant_id == tenant_id,
                CaseNote.case_id == case_id,
            )
            .order_by(CaseNote.created_at_utc.asc())
        )
        result = await session.execute(stmt)
        return list(result.scalars().all())
