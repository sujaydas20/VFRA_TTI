"""Threat Intelligence Core Service: Ingestion, Validation, Sanitization, Evidence Storage, and Search."""

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from uuid import UUID
import uuid

from fastapi import HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.models.audit import AuditEventRecord
from app.database.models.intelligence import (
    DerivedContentRepresentation,
    IngestionJob,
    RawEvidenceBlob,
    SourceChannel,
    SourceMessage,
)
from app.evidence.storage import LocalEvidenceStore
from app.ingestion.sanitizer import InputSanitizer
from app.schemas.threat import (
    ChannelRegisterRequest,
    ChannelUpdateRequest,
    IngestionJobResponse,
    SourceChannelItem,
    SourceChannelListResponse,
    ThreatIngestRequest,
    ThreatMessageIngestItem,
    ThreatMessageItem,
    ThreatSearchResponse,
    ThreatThreadResponse,
)


class TamperConflictError(Exception):
    """Raised when an ingested message conflicts with existing immutable raw evidence."""
    pass


class ThreatService:
    """Core domain service orchestrating threat intelligence ingestion and tenant-isolated retrieval."""

    def __init__(self, evidence_store: Optional[LocalEvidenceStore] = None):
        self.evidence_store = evidence_store or LocalEvidenceStore()

    async def ingest_batch(
        self,
        session: AsyncSession,
        tenant_id: UUID,
        user_id: UUID,
        request: ThreatIngestRequest,
        client_ip: Optional[str] = None,
    ) -> IngestionJob:
        """
        Execute controlled ingestion pipeline:
        1. In-batch duplicate message validation (rejects conflicting duplicates with HTTP 422, collapses identical).
        2. Batch envelope fingerprinting and provenance tracking.
        3. Trusted server-side source authorization enforcement (rejects unregistered/disabled with HTTP 403).
        4. Atomic batch message processing within a transaction savepoint.
        5. Content sanitization and derived representation persistence.
        6. Immutable raw evidence storage, tamper conflict detection, and rollback cleanup.
        7. Append-only audit logging.
        """
        now = datetime.now(timezone.utc)

        # ---------------------------------------------------------------------
        # 1. In-Batch Duplicate Message Validation (SEC-THREAT-03)
        # ---------------------------------------------------------------------
        seen_messages: Dict[str, ThreatMessageIngestItem] = {}
        conflicting_dups: List[str] = []
        for msg in request.messages:
            if msg.message_id in seen_messages:
                prior = seen_messages[msg.message_id]
                if (
                    prior.raw_text != msg.raw_text
                    or prior.source_sequence_id != msg.source_sequence_id
                    or prior.broadcast_timestamp_utc != msg.broadcast_timestamp_utc
                ):
                    conflicting_dups.append(msg.message_id)
            else:
                seen_messages[msg.message_id] = msg

        if conflicting_dups:
            sorted_conflicts = sorted(list(set(conflicting_dups)))
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=(
                    f"DUPLICATE_MESSAGE_ID_CONFLICT: Ingestion batch contains conflicting duplicate "
                    f"message IDs: {sorted_conflicts}. Conflicting payloads for the same message_id "
                    f"within a single request are prohibited."
                ),
            )

        # Collapse identical duplicates in-memory to prevent UniqueViolation / HTTP 500
        unique_messages: List[ThreatMessageIngestItem] = list(seen_messages.values())

        # ---------------------------------------------------------------------
        # 2. Batch Provenance Job Creation
        # ---------------------------------------------------------------------
        batch_serialized = json.dumps(
            request.model_dump(mode="json"),
            sort_keys=True,
            default=str,
        ).encode("utf-8")
        envelope_sha256 = hashlib.sha256(batch_serialized).hexdigest()

        job = IngestionJob(
            job_id=uuid.uuid4(),
            tenant_id=tenant_id,
            source_reference=request.source_reference,
            source_type=request.source_type,
            status="RECEIVED",
            records_processed=0,
            payload_sha256=envelope_sha256,
            submitted_by_user_id=user_id,
            created_at_utc=now,
        )
        session.add(job)
        await session.flush()

        source_ref_hash = hashlib.sha256(request.source_reference.encode("utf-8")).hexdigest()

        # ---------------------------------------------------------------------
        # 3. Server-Side Source Authorization Enforcement (SEC-THREAT-01)
        # Must exist in threat.source_channels for this tenant and have is_authorized = True
        # ---------------------------------------------------------------------
        stmt_channel = select(SourceChannel).where(
            SourceChannel.tenant_id == tenant_id,
            SourceChannel.channel_id == request.source_reference,
        )
        existing_channel = await session.scalar(stmt_channel)

        if existing_channel is None:
            job.status = "REJECTED"
            job.error_message = (
                f"SOURCE_NOT_REGISTERED: Intelligence source '{request.source_reference}' is not "
                f"registered for this tenant. An administrator must register and authorize this source before ingestion."
            )
            job.completed_at_utc = datetime.now(timezone.utc)

            audit_event = AuditEventRecord(
                audit_event_id=uuid.uuid4(),
                tenant_id=tenant_id,
                user_id=user_id,
                action_type="INGESTION_SOURCE_UNAUTHORIZED",
                target_identifier_hash=source_ref_hash,
                client_ip_address=client_ip,
                correlation_id=job.job_id,
                details={
                    "source_reference": request.source_reference,
                    "reason": "source_not_registered",
                    "payload_sha256": envelope_sha256,
                },
                event_timestamp_utc=datetime.now(timezone.utc),
            )
            session.add(audit_event)
            await session.commit()
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"SOURCE_NOT_REGISTERED: Intelligence source '{request.source_reference}' is not registered for this tenant.",
            )

        if not existing_channel.is_authorized:
            job.status = "REJECTED"
            job.error_message = (
                f"SOURCE_UNAUTHORIZED: Intelligence source '{request.source_reference}' "
                f"is marked unauthorized or disabled in tenant registry."
            )
            job.completed_at_utc = datetime.now(timezone.utc)

            audit_event = AuditEventRecord(
                audit_event_id=uuid.uuid4(),
                tenant_id=tenant_id,
                user_id=user_id,
                action_type="INGESTION_SOURCE_UNAUTHORIZED",
                target_identifier_hash=source_ref_hash,
                client_ip_address=client_ip,
                correlation_id=job.job_id,
                details={
                    "source_reference": request.source_reference,
                    "reason": "channel_authorization_revoked",
                    "payload_sha256": envelope_sha256,
                },
                event_timestamp_utc=datetime.now(timezone.utc),
            )
            session.add(audit_event)
            await session.commit()
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"SOURCE_UNAUTHORIZED: Channel '{request.source_reference}' is marked unauthorized in tenant registry.",
            )

        job.status = "PROCESSING"
        await session.flush()

        # ---------------------------------------------------------------------
        # 4. Atomic Batch Staging with Savepoint & Filesystem Cleanup (SEC-THREAT-02)
        # ---------------------------------------------------------------------
        written_evidence_files: List[Path] = []
        records_processed = 0

        try:
            async with session.begin_nested():
                for msg in unique_messages:
                    raw_bytes = msg.raw_text.encode("utf-8")
                    raw_sha256 = hashlib.sha256(raw_bytes).hexdigest()

                    # Anti-tamper & Idempotency Check:
                    stmt_evidence = select(RawEvidenceBlob).where(
                        RawEvidenceBlob.tenant_id == tenant_id,
                        RawEvidenceBlob.source_message_id == msg.message_id,
                    )
                    existing_blob = await session.scalar(stmt_evidence)

                    if existing_blob is not None:
                        if existing_blob.payload_sha256_hash != raw_sha256:
                            # TAMPER CONFLICT: Same message ID submitted with conflicting content
                            raise TamperConflictError(
                                f"TAMPER_CONFLICT: Message '{msg.message_id}' was previously ingested "
                                f"with digest '{existing_blob.payload_sha256_hash}', which conflicts with "
                                f"new digest '{raw_sha256}'. Raw evidence overwrite prohibited."
                            )
                        # Identical payload re-submitted -> Idempotent skip
                        records_processed += 1
                        continue

                    stmt_msg = select(SourceMessage).where(
                        SourceMessage.tenant_id == tenant_id,
                        SourceMessage.message_id == msg.message_id,
                    )
                    existing_msg = await session.scalar(stmt_msg)
                    if existing_msg is not None:
                        records_processed += 1
                        continue

                    # Store Raw Verbatim Evidence into LocalEvidenceStore
                    evidence_rec = self.evidence_store.store_raw_evidence(
                        tenant_id=str(tenant_id),
                        artifact_id=msg.message_id,
                        source_type=request.source_type,
                        raw_bytes=raw_bytes,
                    )
                    # Track newly written file for cleanup if batch subsequently fails
                    written_evidence_files.append(Path(self.evidence_store.base_dir) / evidence_rec.relative_path)

                    raw_blob = RawEvidenceBlob(
                        raw_blob_id=uuid.uuid4(),
                        tenant_id=tenant_id,
                        source_message_id=msg.message_id,
                        payload_sha256_hash=raw_sha256,
                        byte_size=len(raw_bytes),
                        payload_storage_locator=evidence_rec.relative_path,
                        ingestion_timestamp_utc=now,
                    )
                    session.add(raw_blob)

                    source_msg = SourceMessage(
                        tenant_id=tenant_id,
                        message_id=msg.message_id,
                        channel_id=request.source_reference,
                        source_sequence_id=msg.source_sequence_id,
                        message_thread_id=msg.message_thread_id,
                        sender_username=msg.sender_username,
                        sender_native_id=msg.sender_native_id,
                        broadcast_timestamp_utc=msg.broadcast_timestamp_utc,
                        reply_to_message_id=msg.reply_to_message_id,
                        has_media=msg.has_media,
                        ingested_at_utc=now,
                    )
                    session.add(source_msg)

                    sanitized_text, applied_flags = InputSanitizer.sanitize_text(msg.raw_text)
                    content_sha256 = hashlib.sha256(sanitized_text.encode("utf-8")).hexdigest()

                    derived_repr = DerivedContentRepresentation(
                        derived_id=uuid.uuid4(),
                        tenant_id=tenant_id,
                        source_message_id=msg.message_id,
                        sanitized_message_text=sanitized_text,
                        content_sha256=content_sha256,
                        sanitization_flags=applied_flags,
                        transformation_timestamp_utc=now,
                    )
                    session.add(derived_repr)
                    records_processed += 1

        except TamperConflictError as tamper_err:
            # 1. Clean up uncommitted evidence files from disk
            for f_path in written_evidence_files:
                try:
                    f_path.unlink(missing_ok=True)
                except OSError:
                    pass

            # 2. Savepoint rollback has discarded all staged messages and derived content.
            # 3. Update the job status to FAILED and record audit event in the outer transaction:
            job.status = "FAILED"
            job.error_message = str(tamper_err)
            job.records_processed = 0
            job.completed_at_utc = datetime.now(timezone.utc)

            audit_event = AuditEventRecord(
                audit_event_id=uuid.uuid4(),
                tenant_id=tenant_id,
                user_id=user_id,
                action_type="INGESTION_TAMPER_CONFLICT",
                target_identifier_hash=source_ref_hash,
                client_ip_address=client_ip,
                correlation_id=job.job_id,
                details={
                    "job_id": str(job.job_id),
                    "source_reference": request.source_reference,
                    "error": str(tamper_err),
                },
                event_timestamp_utc=datetime.now(timezone.utc),
            )
            session.add(audit_event)
            await session.commit()
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=str(tamper_err),
            )

        except Exception:
            # Clean up written files on any unexpected error
            for f_path in written_evidence_files:
                try:
                    f_path.unlink(missing_ok=True)
                except OSError:
                    pass
            raise

        # ---------------------------------------------------------------------
        # 5. Finalize Job Status & Commit Batch
        # ---------------------------------------------------------------------
        completed_time = datetime.now(timezone.utc)

        # Update metadata attributes only after message batch savepoint succeeds (SEC-THREAT-06)
        if request.channel_title:
            existing_channel.channel_title = request.channel_title
        if request.channel_handle:
            existing_channel.channel_handle = request.channel_handle
        existing_channel.updated_at_utc = completed_time

        job.status = "COMPLETED"
        job.records_processed = records_processed
        job.completed_at_utc = completed_time

        # ---------------------------------------------------------------------
        # 6. Audit Trail Recording
        # ---------------------------------------------------------------------
        audit_event = AuditEventRecord(
            audit_event_id=uuid.uuid4(),
            tenant_id=tenant_id,
            user_id=user_id,
            action_type="INGESTION_RECORD_SUBMITTED",
            target_identifier_hash=source_ref_hash,
            client_ip_address=client_ip,
            correlation_id=job.job_id,
            details={
                "job_id": str(job.job_id),
                "source_reference": request.source_reference,
                "source_type": request.source_type,
                "records_processed": records_processed,
                "payload_sha256": envelope_sha256,
            },
            event_timestamp_utc=completed_time,
        )
        session.add(audit_event)
        await session.commit()
        await session.refresh(job)
        return job

    async def get_job(
        self,
        session: AsyncSession,
        tenant_id: UUID,
        job_id: UUID,
    ) -> Optional[IngestionJob]:
        """Retrieve an ingestion job by ID scoped to tenant."""
        stmt = select(IngestionJob).where(
            IngestionJob.tenant_id == tenant_id,
            IngestionJob.job_id == job_id,
        )
        return await session.scalar(stmt)

    async def search_threats(
        self,
        session: AsyncSession,
        tenant_id: UUID,
        user_id: UUID,
        query: str,
        channel_id: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
        client_ip: Optional[str] = None,
    ) -> ThreatSearchResponse:
        """
        Execute tenant-isolated threat search over sanitized content representations.
        STRICT SECURITY INVARIANT: Zero raw evidence locators or raw payload bytes returned.
        """
        query_clean = query.strip()
        search_pattern = f"%{query_clean}%"

        # Base query joining SourceMessage and DerivedContentRepresentation
        base_filters = [
            SourceMessage.tenant_id == tenant_id,
            DerivedContentRepresentation.tenant_id == tenant_id,
            SourceMessage.message_id == DerivedContentRepresentation.source_message_id,
            DerivedContentRepresentation.sanitized_message_text.ilike(search_pattern),
        ]

        if channel_id:
            base_filters.append(SourceMessage.channel_id == channel_id)

        # Count total matches
        count_stmt = (
            select(func.count(SourceMessage.message_id))
            .select_from(SourceMessage)
            .join(
                DerivedContentRepresentation,
                (SourceMessage.tenant_id == DerivedContentRepresentation.tenant_id)
                & (SourceMessage.message_id == DerivedContentRepresentation.source_message_id),
            )
            .where(*base_filters)
        )
        total_results = (await session.scalar(count_stmt)) or 0

        # Fetch page items
        query_stmt = (
            select(SourceMessage, DerivedContentRepresentation)
            .join(
                DerivedContentRepresentation,
                (SourceMessage.tenant_id == DerivedContentRepresentation.tenant_id)
                & (SourceMessage.message_id == DerivedContentRepresentation.source_message_id),
            )
            .where(*base_filters)
            .order_by(SourceMessage.broadcast_timestamp_utc.desc())
            .offset(offset)
            .limit(limit)
        )
        results = (await session.execute(query_stmt)).all()

        items: List[ThreatMessageItem] = []
        for msg, derived in results:
            items.append(
                ThreatMessageItem(
                    message_id=msg.message_id,
                    channel_id=msg.channel_id,
                    source_sequence_id=msg.source_sequence_id,
                    message_thread_id=msg.message_thread_id,
                    sender_username=msg.sender_username,
                    sender_native_id=msg.sender_native_id,
                    broadcast_timestamp_utc=msg.broadcast_timestamp_utc,
                    reply_to_message_id=msg.reply_to_message_id,
                    has_media=msg.has_media,
                    sanitized_text=derived.sanitized_message_text,
                    sanitization_flags=derived.sanitization_flags or [],
                    content_sha256=derived.content_sha256,
                )
            )

        # Record audit event for search
        query_hash = hashlib.sha256(query_clean.encode("utf-8")).hexdigest()
        audit_event = AuditEventRecord(
            audit_event_id=uuid.uuid4(),
            tenant_id=tenant_id,
            user_id=user_id,
            action_type="THREAT_SEARCH_EXECUTED",
            target_identifier_hash=query_hash,
            client_ip_address=client_ip,
            correlation_id=uuid.uuid4(),
            details={
                "query_length": len(query_clean),
                "channel_id": channel_id,
                "limit": limit,
                "offset": offset,
                "results_count": len(items),
                "total_results": total_results,
            },
            event_timestamp_utc=datetime.now(timezone.utc),
        )
        session.add(audit_event)
        await session.commit()

        return ThreatSearchResponse(
            query=query_clean,
            total_results=total_results,
            limit=limit,
            offset=offset,
            items=items,
        )

    async def get_thread(
        self,
        session: AsyncSession,
        tenant_id: UUID,
        user_id: UUID,
        channel_id: str,
        thread_id: str,
        client_ip: Optional[str] = None,
    ) -> ThreatThreadResponse:
        """
        Retrieve all sanitized messages within a conversation thread.
        STRICT SECURITY INVARIANT: Zero raw evidence locators or raw payload bytes returned.
        """
        # Retrieve channel metadata
        stmt_channel = select(SourceChannel).where(
            SourceChannel.tenant_id == tenant_id,
            SourceChannel.channel_id == channel_id,
        )
        channel = await session.scalar(stmt_channel)

        stmt_messages = (
            select(SourceMessage, DerivedContentRepresentation)
            .join(
                DerivedContentRepresentation,
                (SourceMessage.tenant_id == DerivedContentRepresentation.tenant_id)
                & (SourceMessage.message_id == DerivedContentRepresentation.source_message_id),
            )
            .where(
                SourceMessage.tenant_id == tenant_id,
                SourceMessage.channel_id == channel_id,
                SourceMessage.message_thread_id == thread_id,
            )
            .order_by(
                SourceMessage.source_sequence_id.asc(),
                SourceMessage.broadcast_timestamp_utc.asc(),
            )
        )
        results = (await session.execute(stmt_messages)).all()

        if not results:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Thread '{thread_id}' not found in channel '{channel_id}'.",
            )

        items: List[ThreatMessageItem] = []
        for msg, derived in results:
            items.append(
                ThreatMessageItem(
                    message_id=msg.message_id,
                    channel_id=msg.channel_id,
                    source_sequence_id=msg.source_sequence_id,
                    message_thread_id=msg.message_thread_id,
                    sender_username=msg.sender_username,
                    sender_native_id=msg.sender_native_id,
                    broadcast_timestamp_utc=msg.broadcast_timestamp_utc,
                    reply_to_message_id=msg.reply_to_message_id,
                    has_media=msg.has_media,
                    sanitized_text=derived.sanitized_message_text,
                    sanitization_flags=derived.sanitization_flags or [],
                    content_sha256=derived.content_sha256,
                )
            )

        # Record audit event for thread access
        thread_ref_hash = hashlib.sha256(f"{channel_id}:{thread_id}".encode("utf-8")).hexdigest()
        audit_event = AuditEventRecord(
            audit_event_id=uuid.uuid4(),
            tenant_id=tenant_id,
            user_id=user_id,
            action_type="THREAD_DETAIL_ACCESSED",
            target_identifier_hash=thread_ref_hash,
            client_ip_address=client_ip,
            correlation_id=uuid.uuid4(),
            details={
                "channel_id": channel_id,
                "thread_id": thread_id,
                "message_count": len(items),
            },
            event_timestamp_utc=datetime.now(timezone.utc),
        )
        session.add(audit_event)
        await session.commit()

        return ThreatThreadResponse(
            channel_id=channel_id,
            channel_title=channel.channel_title if channel else channel_id,
            thread_id=thread_id,
            total_messages=len(items),
            messages=items,
        )

    # =========================================================================
    # Phase 4 Source Channel Administration (SEC-THREAT-05)
    # =========================================================================

    async def list_channels(
        self,
        session: AsyncSession,
        tenant_id: UUID,
        limit: int = 50,
        offset: int = 0,
        is_authorized: Optional[bool] = None,
        source_type: Optional[str] = None,
    ) -> SourceChannelListResponse:
        """
        List threat intelligence source channels for the authenticated tenant.
        Deterministic ordering: created_at_utc desc, channel_id asc.
        """
        base_filters = [SourceChannel.tenant_id == tenant_id]

        if is_authorized is not None:
            base_filters.append(SourceChannel.is_authorized == is_authorized)
        if source_type:
            base_filters.append(SourceChannel.source_type == source_type)

        count_stmt = (
            select(func.count(SourceChannel.channel_id))
            .select_from(SourceChannel)
            .where(*base_filters)
        )
        total_channels = (await session.scalar(count_stmt)) or 0

        query_stmt = (
            select(SourceChannel)
            .where(*base_filters)
            .order_by(SourceChannel.created_at_utc.desc(), SourceChannel.channel_id.asc())
            .offset(offset)
            .limit(limit)
        )
        channels = (await session.scalars(query_stmt)).all()

        return SourceChannelListResponse(
            total_channels=total_channels,
            limit=limit,
            offset=offset,
            channels=[SourceChannelItem.model_validate(c) for c in channels],
        )

    async def register_channel(
        self,
        session: AsyncSession,
        tenant_id: UUID,
        user_id: UUID,
        request: ChannelRegisterRequest,
        client_ip: Optional[str] = None,
    ) -> SourceChannelItem:
        """
        Register a new source channel for the authenticated tenant.

        Invariants:
        1. Tenant ID derived exclusively from authenticated security context.
        2. Enforces tenant-scoped channel uniqueness (HTTP 409 on duplicate).
        3. Default is_authorized=False unless explicitly authorized.
        4. Emits CHANNEL_REGISTERED audit event atomically.
        5. Zero external network requests or collector invocation.
        """
        # Pre-check for duplicate within tenant
        stmt_existing = select(SourceChannel).where(
            SourceChannel.tenant_id == tenant_id,
            SourceChannel.channel_id == request.channel_id,
        )
        existing = await session.scalar(stmt_existing)
        if existing is not None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"CHANNEL_ALREADY_EXISTS: Channel '{request.channel_id}' is already registered for this tenant.",
            )

        now = datetime.now(timezone.utc)
        channel = SourceChannel(
            tenant_id=tenant_id,
            channel_id=request.channel_id,
            channel_title=request.channel_title,
            channel_handle=request.channel_handle,
            source_type=request.source_type,
            is_authorized=request.is_authorized,
            created_at_utc=now,
            updated_at_utc=now,
        )
        session.add(channel)

        # Audit event recording (fail-closed transaction)
        channel_ref_hash = hashlib.sha256(request.channel_id.encode("utf-8")).hexdigest()
        audit_event = AuditEventRecord(
            audit_event_id=uuid.uuid4(),
            tenant_id=tenant_id,
            user_id=user_id,
            action_type="CHANNEL_REGISTERED",
            target_identifier_hash=channel_ref_hash,
            client_ip_address=client_ip,
            correlation_id=uuid.uuid4(),
            details={
                "channel_id": request.channel_id,
                "channel_title": request.channel_title,
                "channel_handle": request.channel_handle,
                "source_type": request.source_type,
                "is_authorized": request.is_authorized,
            },
            event_timestamp_utc=now,
        )
        session.add(audit_event)

        if request.is_authorized:
            authz_event = AuditEventRecord(
                audit_event_id=uuid.uuid4(),
                tenant_id=tenant_id,
                user_id=user_id,
                action_type="CHANNEL_AUTHORIZATION_GRANTED",
                target_identifier_hash=channel_ref_hash,
                client_ip_address=client_ip,
                correlation_id=uuid.uuid4(),
                details={
                    "channel_id": request.channel_id,
                    "reason": "granted_at_registration",
                },
                event_timestamp_utc=now,
            )
            session.add(authz_event)

        try:
            await session.commit()
            await session.refresh(channel)
        except IntegrityError:
            await session.rollback()
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"CHANNEL_ALREADY_EXISTS: Channel '{request.channel_id}' is already registered for this tenant.",
            )

        return SourceChannelItem.model_validate(channel)

    async def update_channel(
        self,
        session: AsyncSession,
        tenant_id: UUID,
        user_id: UUID,
        channel_id: str,
        request: ChannelUpdateRequest,
        client_ip: Optional[str] = None,
    ) -> SourceChannelItem:
        """
        Update channel metadata or authorization status for the authenticated tenant.

        Invariants:
        1. Tenant ID and channel_id are strictly tenant-scoped (cross-tenant -> 404).
        2. channel_id, tenant_id, source_type are IMMUTABLE.
        3. Emits CHANNEL_AUTHORIZATION_GRANTED / CHANNEL_AUTHORIZATION_REVOKED on authorization changes.
        4. Emits CHANNEL_METADATA_UPDATED on title/handle changes.
        5. Zero external network requests or collector invocation.
        """
        if request.channel_title is None and request.channel_handle is None and request.is_authorized is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="NO_UPDATES_PROVIDED: At least one field (channel_title, channel_handle, is_authorized) must be specified for update.",
            )

        stmt = select(SourceChannel).where(
            SourceChannel.tenant_id == tenant_id,
            SourceChannel.channel_id == channel_id,
        )
        channel = await session.scalar(stmt)
        if channel is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"CHANNEL_NOT_FOUND: Channel '{channel_id}' not found for this tenant.",
            )

        now = datetime.now(timezone.utc)
        channel_ref_hash = hashlib.sha256(channel_id.encode("utf-8")).hexdigest()
        correlation_id = uuid.uuid4()

        # Track metadata mutations
        old_title = channel.channel_title
        old_handle = channel.channel_handle
        metadata_changed = False

        if request.channel_title is not None and request.channel_title != old_title:
            channel.channel_title = request.channel_title
            metadata_changed = True

        if request.channel_handle is not None and request.channel_handle != old_handle:
            channel.channel_handle = request.channel_handle
            metadata_changed = True

        if metadata_changed:
            meta_audit = AuditEventRecord(
                audit_event_id=uuid.uuid4(),
                tenant_id=tenant_id,
                user_id=user_id,
                action_type="CHANNEL_METADATA_UPDATED",
                target_identifier_hash=channel_ref_hash,
                client_ip_address=client_ip,
                correlation_id=correlation_id,
                details={
                    "channel_id": channel_id,
                    "old_title": old_title,
                    "new_title": channel.channel_title,
                    "old_handle": old_handle,
                    "new_handle": channel.channel_handle,
                },
                event_timestamp_utc=now,
            )
            session.add(meta_audit)

        # Track authorization state transition
        if request.is_authorized is not None and request.is_authorized != channel.is_authorized:
            old_authz = channel.is_authorized
            channel.is_authorized = request.is_authorized
            authz_action = "CHANNEL_AUTHORIZATION_GRANTED" if request.is_authorized else "CHANNEL_AUTHORIZATION_REVOKED"

            authz_audit = AuditEventRecord(
                audit_event_id=uuid.uuid4(),
                tenant_id=tenant_id,
                user_id=user_id,
                action_type=authz_action,
                target_identifier_hash=channel_ref_hash,
                client_ip_address=client_ip,
                correlation_id=correlation_id,
                details={
                    "channel_id": channel_id,
                    "old_is_authorized": old_authz,
                    "new_is_authorized": channel.is_authorized,
                },
                event_timestamp_utc=now,
            )
            session.add(authz_audit)

        channel.updated_at_utc = now
        await session.commit()
        await session.refresh(channel)

        return SourceChannelItem.model_validate(channel)
