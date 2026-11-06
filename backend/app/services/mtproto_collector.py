"""Background MTProto collection service.

Continuously monitors AUTHORIZED Telegram channels registered in
threat.source_channels (is_authorized = true, source_type = 'telegram') and
feeds the EXISTING ingestion pipeline:

    MTProto -> MTProtoTelegramConnector -> ThreatService.ingest_batch
            -> ThreatDetectionService.analyze_and_record -> detections

REUSE INVARIANTS:
- No second ingestion pipeline: ThreatService.ingest_batch performs
  normalization, sanitization, deduplication, evidence storage, and audit.
- No second AI pipeline: ThreatDetectionService.analyze_and_record is the
  exact service the Celery detection task invokes.
- Checkpoints derive from max(source_sequence_id); no new tables.
- Credentials never logged; user_id is NULL (automated system operation).

PONYTAIL: collection runs in-process (matches existing modular-monolith ADR and
the inline dispatcher default). Scale by running a dedicated collector worker
process with TASK_DISPATCHER=celery when channel volume grows.
"""

import asyncio
import hashlib
import logging
import uuid as uuid_module
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.connectors.telegram.models import TelegramMessagePayload
from app.core.config import get_settings
from app.core.errors import ConnectorNotConfiguredError
from app.database.models.audit import AuditEventRecord
from app.database.models.intelligence import RawEvidenceBlob, SourceChannel, SourceMessage
from app.database.session import async_session_factory, set_transaction_tenant_context
from app.ingestion.threat_service import ThreatService
from app.schemas.threat import ThreatIngestRequest, ThreatMessageIngestItem
from app.services.detection_service import ThreatDetectionService

logger = logging.getLogger("tti.collector.mtproto")


def composite_message_id(channel_reference: str, telegram_message_id: int) -> str:
    """Stable, channel-scoped message identifier: '<channel_ref>:<tg_id>'."""
    return f"{channel_reference}:{int(telegram_message_id)}"


async def list_authorized_channels(session: AsyncSession, tenant_id: UUID) -> List[SourceChannel]:
    """Registered, authorized Telegram channels for the tenant."""
    stmt = (
        select(SourceChannel)
        .where(
            SourceChannel.tenant_id == tenant_id,
            SourceChannel.source_type == "telegram",
            SourceChannel.is_authorized.is_(True),
        )
        .order_by(SourceChannel.channel_id)
    )
    return list((await session.scalars(stmt)).all())


async def get_checkpoint(session: AsyncSession, tenant_id: UUID, channel_reference: str) -> int:
    """Latest ingested Telegram message id for the channel (incremental cursor)."""
    stmt = select(func.max(SourceMessage.source_sequence_id)).where(
        SourceMessage.tenant_id == tenant_id,
        SourceMessage.channel_id == channel_reference,
    )
    return int((await session.scalar(stmt)) or 0)


async def compare_edits(
    session: AsyncSession,
    tenant_id: UUID,
    channel_reference: str,
    live_messages: List[TelegramMessagePayload],
    checkpoint: int,
) -> int:
    """
    Detect edits: compare live raw-text digests of already-ingested window
    messages against the immutable evidence ledger (RawEvidenceBlob).
    Edits are audit-logged and SKIPPED (raw evidence is never overwritten).
    Returns number of edits detected.
    """
    if checkpoint == 0:
        return 0
    window = [m for m in live_messages if m.message_id <= checkpoint]
    if not window:
        return 0

    ids = [composite_message_id(channel_reference, m.message_id) for m in window]
    blob_stmt = select(RawEvidenceBlob.source_message_id, RawEvidenceBlob.payload_sha256_hash).where(
        RawEvidenceBlob.tenant_id == tenant_id,
        RawEvidenceBlob.source_message_id.in_(ids),
    )
    stored: Dict[str, str] = {
        row.source_message_id: row.payload_sha256_hash
        for row in (await session.execute(blob_stmt)).all()
    }

    edits = 0
    for m in window:
        key = composite_message_id(channel_reference, m.message_id)
        stored_digest = stored.get(key)
        if stored_digest is None:
            continue
        live_digest = hashlib.sha256((m.raw_text or "").encode("utf-8")).hexdigest()
        if live_digest != stored_digest:
            edits += 1
            logger.info(
                "Message edit detected (channel=%s, tg_id=%s); immutable evidence preserved.",
                channel_reference,
                m.message_id,
            )
            session.add(
                AuditEventRecord(
                    tenant_id=tenant_id,
                    user_id=None,
                    action_type="MTPROTO_MESSAGE_EDIT_DETECTED",
                    target_identifier_hash=hashlib.sha256(key.encode("utf-8")).hexdigest(),
                    correlation_id=uuid_module.uuid4(),
                    details={
                        "channel_reference": channel_reference,
                        "telegram_message_id": m.message_id,
                        "previous_digest": stored_digest,
                        "live_digest": live_digest,
                        "handling": "raw_evidence_immutable_skipped",
                    },
                    event_timestamp_utc=datetime.now(timezone.utc),
                )
            )
    return edits


class MTProtoCollectorService:
    """
    Background service running incremental MTProto collection cycles.

    One cycle per poll interval:
      1. Resolve tenants with authorized Telegram channels.
      2. Per channel: read checkpoint (max source_sequence_id), collect new
         messages, detect edits in the lookback window, ingest via the
         EXISTING ThreatService.ingest_batch, then run AI analysis via the
         EXISTING ThreatDetectionService.
    """

    def __init__(self, connector: Any = None) -> None:
        self.settings = get_settings()
        self.connector = connector  # MTProtoTelegramConnector; built lazily
        self.threat_service = ThreatService()
        self.detection_service = ThreatDetectionService()
        self._task: Optional[asyncio.Task] = None
        self._stop_event = asyncio.Event()
        self._cycle_lock = asyncio.Lock()
        self.stats: Dict[str, Any] = {
            "status": "IDLE",
            "cycles_completed": 0,
            "cycles_failed": 0,
            "channels_monitored": 0,
            "messages_collected_total": 0,
            "messages_collected_today": 0,
            "duplicates_skipped": 0,
            "edits_detected": 0,
            "failed_messages": 0,
            "threats_detected": 0,
            "last_cycle_utc": None,
            "last_error": None,
        }

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    async def start(self) -> None:
        """Start the background collection loop (idempotent)."""
        if self._task is not None and not self._task.done():
            return
        if not self.settings.TTI_MTPROTO_ENABLED:
            logger.info("MTProto collection disabled (TTI_MTPROTO_ENABLED=false).")
            self.stats["status"] = "DISABLED"
            return
        if not self.settings.mtproto_credentials_configured:
            logger.warning("MTProto enabled but api_id/api_hash invalid; collector staying idle.")
            self.stats["status"] = "UNCONFIGURED"
            return
        if not self.settings.TTI_TELEGRAM_SESSION:
            logger.warning(
                "MTProto enabled but no session string; run 'python -m app.cli mtproto-login'."
            )
            self.stats["status"] = "UNAUTHENTICATED"
            return

        if self.connector is None:
            from app.connectors.telegram.mtproto import MTProtoTelegramConnector

            self.connector = MTProtoTelegramConnector()

        self._stop_event.clear()
        self._task = asyncio.create_task(self._run_loop(), name="mtproto-collector")
        logger.info("MTProto collector background loop started.")

    async def stop(self) -> None:
        """Graceful shutdown: cancel loop and disconnect the MTProto client."""
        self._stop_event.set()
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
            self._task = None
        if self.connector is not None:
            try:
                await self.connector.disconnect()
            except Exception:  # noqa: BLE001
                pass
        self.stats["status"] = "OFFLINE"
        logger.info("MTProto collector stopped.")

    async def _run_loop(self) -> None:
        interval = max(5, self.settings.TTI_MTPROTO_POLL_INTERVAL_SECONDS)
        while not self._stop_event.is_set():
            try:
                await self.run_collection_cycle()
                self.stats["status"] = "ONLINE"
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 - loop must survive failures
                self.stats["cycles_failed"] += 1
                self.stats["last_error"] = type(exc).__name__
                self.stats["status"] = "ERROR"
                logger.error("MTProto collection cycle failed: %s", type(exc).__name__)
            try:
                await asyncio.wait_for(self._stop_event.wait(), timeout=interval)
            except asyncio.TimeoutError:
                continue

    @property
    def is_running(self) -> bool:
        return self._task is not None and not self._task.done()

    # ------------------------------------------------------------------
    # Collection core
    # ------------------------------------------------------------------
    def _to_ingest_item(self, channel_reference: str, payload: TelegramMessagePayload) -> ThreatMessageIngestItem:
        """Map connector payload onto the EXISTING ingestion schema."""
        return ThreatMessageIngestItem(
            message_id=composite_message_id(channel_reference, payload.message_id),
            source_sequence_id=payload.message_id,
            raw_text=payload.raw_text or "",
            broadcast_timestamp_utc=payload.date_utc,
            sender_username=payload.sender_username,
            sender_native_id=str(payload.sender_id) if payload.sender_id is not None else None,
            reply_to_message_id=(
                composite_message_id(channel_reference, payload.reply_to_message_id)
                if payload.reply_to_message_id
                else None
            ),
            has_media=payload.media is not None,
        )

    async def _collect_tenant(
        self,
        tenant_id: UUID,
        batch_limit: int,
        historical_limit: int,
        edit_lookback: int,
    ) -> Dict[str, int]:
        """Run one collection pass for every authorized channel of a tenant."""
        counters = {"collected": 0, "duplicates": 0, "edits": 0, "failed": 0, "analyzed": 0}

        async with async_session_factory() as session:
            await set_transaction_tenant_context(session, tenant_id)
            channels = await list_authorized_channels(session, tenant_id)
            self.stats["channels_monitored"] = len(channels)

            for channel in channels:
                reference = channel.channel_handle or channel.channel_id
                checkpoint = await get_checkpoint(session, tenant_id, channel.channel_id)

                # Fetch: new messages past the checkpoint + a small edit lookback window.
                fetch_from = max(0, checkpoint - edit_lookback) if checkpoint else 0
                fetch_limit = historical_limit if checkpoint == 0 else (batch_limit + edit_lookback)
                try:
                    payloads = await self.connector.collect_channel_messages(
                        tenant_id=str(tenant_id),
                        channel_identifier=reference,
                        limit=fetch_limit,
                        offset_id=fetch_from,
                    )
                except ConnectorNotConfiguredError as err:
                    logger.error("Collection skipped for '%s': %s", channel.channel_id, err.message)
                    counters["failed"] += 1
                    continue

                if not payloads:
                    continue

                # 1. Edit detection on the already-ingested window (immutability preserved)
                counters["edits"] += await compare_edits(
                    session, tenant_id, channel.channel_id, payloads, checkpoint
                )

                # Messages re-seen in the lookback window are already ingested -> deduped
                window = [p for p in payloads if p.message_id <= checkpoint]
                counters["duplicates"] += len(window)

                # 2. Build ingest request for messages beyond the checkpoint
                new_payloads = [p for p in payloads if p.message_id > checkpoint]
                if not new_payloads:
                    await session.commit()
                    continue

                request = ThreatIngestRequest(
                    source_reference=channel.channel_id,
                    source_type="telegram",
                    channel_title=channel.channel_title,
                    channel_handle=channel.channel_handle,
                    messages=[self._to_ingest_item(channel.channel_id, p) for p in new_payloads],
                )

                # 3. EXISTING pipeline: normalize, sanitize, dedup, evidence, audit, persist.
                try:
                    job = await self.threat_service.ingest_batch(
                        session=session,
                        tenant_id=tenant_id,
                        user_id=None,  # Automated system collection (audit ledger supports NULL)
                        request=request,
                        client_ip=None,
                    )
                    counters["collected"] += job.records_processed
                    counters["duplicates"] += len(new_payloads) - job.records_processed
                except Exception as exc:  # noqa: BLE001 - per-channel isolation
                    counters["failed"] += len(new_payloads)
                    logger.error(
                        "Ingest failed for channel '%s': %s", channel.channel_id, type(exc).__name__
                    )
                    await session.rollback()
                    await set_transaction_tenant_context(session, tenant_id)
                    continue

                # 4. EXISTING AI analysis pipeline (same service as Celery detection task).
                for item in request.messages:
                    try:
                        detections = await self.detection_service.analyze_and_record(
                            session=session,
                            tenant_id=tenant_id,
                            message_id=item.message_id,
                            raw_text=item.raw_text,
                            subject_id=None,
                        )
                        counters["analyzed"] += 1
                        self.stats["threats_detected"] += len(detections)
                    except Exception as exc:  # noqa: BLE001
                        logger.error(
                            "AI analysis failed for '%s': %s", item.message_id, type(exc).__name__
                        )
                await session.commit()

        return counters

    # ------------------------------------------------------------------
    # Cycle orchestration
    # ------------------------------------------------------------------
    async def run_collection_cycle(self, tenant_id: Optional[UUID] = None) -> Dict[str, Any]:
        """Run a full collection pass (all tenants or one). Serialized by lock."""
        async with self._cycle_lock:
            settings = get_settings()
            batch_limit = settings.TTI_MTPROTO_BATCH_LIMIT
            historical_limit = settings.TTI_MTPROTO_HISTORICAL_LIMIT
            edit_lookback = settings.TTI_MTPROTO_EDIT_LOOKBACK

            if self.connector is None:
                from app.connectors.telegram.mtproto import MTProtoTelegramConnector

                self.connector = MTProtoTelegramConnector()
            if not self.connector.connected:
                await self.connector.connect()

            tenant_ids: List[UUID]
            if tenant_id is not None:
                tenant_ids = [tenant_id]
            else:
                async with async_session_factory() as session:
                    stmt = (
                        select(SourceChannel.tenant_id)
                        .where(
                            SourceChannel.source_type == "telegram",
                            SourceChannel.is_authorized.is_(True),
                        )
                        .distinct()
                    )
                    tenant_ids = [UUID(str(t)) for t in (await session.scalars(stmt)).all()]

            totals = {"collected": 0, "duplicates": 0, "edits": 0, "failed": 0, "analyzed": 0}
            for tid in tenant_ids:
                try:
                    counters = await self._collect_tenant(tid, batch_limit, historical_limit, edit_lookback)
                    for key in totals:
                        totals[key] += counters[key]
                except Exception as exc:  # noqa: BLE001
                    totals["failed"] += 1
                    logger.error("Tenant %s collection failed: %s", tid, type(exc).__name__)

            self.stats["cycles_completed"] += 1
            self.stats["messages_collected_total"] += totals["collected"]
            self.stats["messages_collected_today"] += totals["collected"]
            self.stats["duplicates_skipped"] += totals["duplicates"]
            self.stats["edits_detected"] += totals["edits"]
            self.stats["failed_messages"] += totals["failed"]
            self.stats["last_cycle_utc"] = datetime.now(timezone.utc).isoformat()
            self.stats["last_error"] = None if totals["failed"] == 0 else "collection_errors_in_cycle"
            return totals


_collector_singleton: Optional[MTProtoCollectorService] = None


def get_mtproto_collector() -> MTProtoCollectorService:
    """Process-wide collector singleton (created lazily)."""
    global _collector_singleton
    if _collector_singleton is None:
        _collector_singleton = MTProtoCollectorService()
    return _collector_singleton


