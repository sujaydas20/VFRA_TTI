"""Telegram MTProto collection endpoints: status, on-demand collection, discovery.

All statistics are computed from real backend state:
- Connector health from MTProtoTelegramConnector.
- Collection counters from the running collector service.
- Message/detection/IOC counts from PostgreSQL (tenant-scoped).
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import (
    TenantSecurityContext,
    get_authorized_tenant_db,
    require_permission_dep,
)
from app.connectors.base import ConnectorHealth
from app.connectors.telegram.mtproto import MTProtoTelegramConnector
from app.core.rbac import PERM_INGEST_READ, PERM_INGEST_SUBMIT, PERM_ORG_MANAGE
from app.database.models.detection import DetectionRecord, URLIndicatorRecord
from app.database.models.intelligence import IngestionJob, SourceChannel, SourceMessage
from app.services.mtproto_collector import get_mtproto_collector

router = APIRouter(prefix="/mtproto", tags=["Telegram MTProto"])


class MTProtoConnectionInfo(BaseModel):
    status: str
    authenticated: bool
    connected: bool
    telethon_installed: bool
    last_connected_utc: Optional[str] = None
    last_sync_utc: Optional[str] = None
    last_error: Optional[str] = None


class MTProtoStatusResponse(BaseModel):
    connection: MTProtoConnectionInfo
    collector: Dict[str, Any]
    channels_monitored: int
    total_messages_collected: int
    messages_collected_today: int
    duplicate_messages: int
    failed_messages: int
    edited_messages_detected: int
    pending_analysis: int
    messages_analyzed: int
    threats_detected: int
    iocs_extracted: int
    high_risk_findings: int
    last_processing_error: Optional[str] = None


async def _tenant_stats(db: AsyncSession, tenant_id) -> Dict[str, Any]:
    """Real tenant-scoped collection and intelligence statistics."""
    today_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)

    total_messages = (
        await db.scalar(select(func.count(SourceMessage.message_id)).where(SourceMessage.tenant_id == tenant_id))
    ) or 0
    today_messages = (
        await db.scalar(
            select(func.count(SourceMessage.message_id)).where(
                SourceMessage.tenant_id == tenant_id,
                SourceMessage.broadcast_timestamp_utc >= today_start,
            )
        )
    ) or 0
    detections = (
        await db.scalar(select(func.count(DetectionRecord.detection_id)).where(DetectionRecord.tenant_id == tenant_id))
    ) or 0
    iocs = (
        await db.scalar(select(func.count(URLIndicatorRecord.indicator_id)).where(URLIndicatorRecord.tenant_id == tenant_id))
    ) or 0
    high_risk = (
        await db.scalar(
            select(func.count(DetectionRecord.detection_id)).where(
                DetectionRecord.tenant_id == tenant_id,
                DetectionRecord.severity.in_(("HIGH", "CRITICAL")),
            )
        )
    ) or 0
    # Messages without any detection row = awaiting analysis (correlated EXISTS)
    detection_exists = (
        select(DetectionRecord.message_id)
        .where(
            DetectionRecord.tenant_id == tenant_id,
            DetectionRecord.message_id == SourceMessage.message_id,
        )
        .exists()
    )
    pending = (
        await db.scalar(
            select(func.count(SourceMessage.message_id))
            .select_from(SourceMessage)
            .where(SourceMessage.tenant_id == tenant_id, ~detection_exists)
        )
    ) or 0
    last_failed_job = (
        await db.scalar(
            select(IngestionJob.error_message)
            .where(IngestionJob.tenant_id == tenant_id, IngestionJob.status == "FAILED")
            .order_by(IngestionJob.created_at_utc.desc())
            .limit(1)
        )
    )
    return {
        "total_messages": int(total_messages),
        "today_messages": int(today_messages),
        "detections": int(detections),
        "iocs": int(iocs),
        "high_risk": int(high_risk),
        "pending": int(pending),
        "last_failed_job_error": last_failed_job,
    }


@router.get(
    "/status",
    response_model=MTProtoStatusResponse,
    summary="MTProto collection status and live statistics",
    description="Real-time MTProto connection state plus tenant-scoped collection and intelligence statistics from the database.",
)
async def get_mtproto_status(
    ctx: TenantSecurityContext = Depends(require_permission_dep(PERM_INGEST_READ)),
    db: AsyncSession = Depends(get_authorized_tenant_db),
) -> MTProtoStatusResponse:
    """Aggregate MTProto status from connector health, collector, and database."""
    tenant_id = ctx.organization.tenant_id
    collector = get_mtproto_collector()
    connector_health: ConnectorHealth
    if collector.connector is not None:
        connector_health = await collector.connector.health_check()
    else:
        connector_health = await MTProtoTelegramConnector().health_check()

    meta = connector_health.metadata or {}
    connection = MTProtoConnectionInfo(
        status=connector_health.status.value,
        authenticated=bool(meta.get("authenticated", False)),
        connected=bool(collector.connector.connected if collector.connector else False),
        telethon_installed=bool(meta.get("telethon_installed", False)),
        last_connected_utc=meta.get("last_connected_utc"),
        last_sync_utc=meta.get("last_sync_utc"),
        last_error=collector.stats.get("last_error"),
    )

    stats = await _tenant_stats(db, tenant_id)
    collector_stats = dict(collector.stats)

    # Monitored channels = DB truth (authorized telegram channels of this tenant)
    authorized_channels = (
        await db.scalar(
            select(func.count(SourceChannel.channel_id)).where(
                SourceChannel.tenant_id == tenant_id,
                SourceChannel.source_type == "telegram",
                SourceChannel.is_authorized.is_(True),
            )
        )
    ) or 0

    return MTProtoStatusResponse(
        connection=connection,
        collector=collector_stats,
        channels_monitored=int(authorized_channels),
        total_messages_collected=stats["total_messages"],
        messages_collected_today=stats["today_messages"],
        duplicate_messages=int(collector_stats.get("duplicates_skipped", 0)),
        failed_messages=int(collector_stats.get("failed_messages", 0)),
        edited_messages_detected=int(collector_stats.get("edits_detected", 0)),
        pending_analysis=stats["pending"],
        messages_analyzed=max(0, stats["total_messages"] - stats["pending"]),
        threats_detected=stats["detections"],
        iocs_extracted=stats["iocs"],
        high_risk_findings=stats["high_risk"],
        last_processing_error=stats["last_failed_job_error"],
    )


@router.post(
    "/collect",
    summary="Trigger an on-demand MTProto collection cycle",
    description="Runs one incremental collection cycle for the authenticated tenant using the existing ingestion and AI pipelines.",
)
async def trigger_mtproto_collection(
    ctx: TenantSecurityContext = Depends(require_permission_dep(PERM_INGEST_SUBMIT)),
) -> Dict[str, Any]:
    """Execute a single collection cycle synchronously for this tenant."""
    collector = get_mtproto_collector()
    try:
        totals = await collector.run_collection_cycle(tenant_id=ctx.organization.tenant_id)
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=503, detail=f"COLLECTION_FAILED: {type(exc).__name__}")
    return {"status": "completed", "tenant_id": str(ctx.organization.tenant_id), "counters": totals}


@router.get(
    "/channels/discover",
    summary="Discover Telegram dialogs the authorized account can access",
    description="Lists channels/groups available to the authenticated MTProto account. Never bypasses Telegram permissions.",
)
async def discover_mtproto_channels(
    limit: int = 200,
    ctx: TenantSecurityContext = Depends(require_permission_dep(PERM_ORG_MANAGE)),
) -> Dict[str, Any]:
    """Enumerate accessible dialogs for registration as source channels."""
    collector = get_mtproto_collector()
    if collector.connector is None or not collector.connector.connected:
        raise HTTPException(
            status_code=503,
            detail="MTPROTO_NOT_CONNECTED: Collector is not connected. Verify session and enablement.",
        )
    try:
        dialogs = await collector.connector.discover_dialogs(limit=limit)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"DISCOVERY_FAILED: {type(exc).__name__}")

    return {
        "count": len(dialogs),
        "channels": [
            {
                "channel_id": str(d.channel_id),
                "title": d.title,
                "username": d.username,
                "participant_count": d.participant_count,
                "is_broadcast": d.is_broadcast,
            }
            for d in dialogs
        ],
    }

