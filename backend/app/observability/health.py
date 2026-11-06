"""Health evaluation and subsystem diagnostics."""

import asyncio
from datetime import datetime, timezone
import os
from pathlib import Path
from typing import Any, Dict, Optional
from pydantic import BaseModel
import redis.asyncio as aioredis
from sqlalchemy import text
from app.core.config import get_settings
from app.core.redis_breaker import BreakerState, get_redis_circuit_breaker
from app.database.session import engine


class ComponentHealth(BaseModel):
    """Health status of an individual subsystem component."""
    status: str  # "healthy", "degraded", "unavailable", "disabled"
    latency_ms: Optional[float] = None
    message: str
    details: Optional[Dict[str, Any]] = None


class HealthStatusResponse(BaseModel):
    """Overall system health diagnostics."""
    status: str  # "healthy", "degraded", "unavailable"
    environment: str
    project_name: str
    version: str
    timestamp_utc: str
    components: Dict[str, ComponentHealth]


async def check_database_health() -> ComponentHealth:
    """Evaluate PostgreSQL connectivity via asyncpg engine."""
    start_time = datetime.now(timezone.utc)
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        latency = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
        return ComponentHealth(
            status="healthy",
            latency_ms=round(latency, 2),
            message="PostgreSQL connection responsive.",
        )
    except Exception as e:
        return ComponentHealth(
            status="unavailable",
            message=f"PostgreSQL connection failed: {type(e).__name__} (Verify Docker or local service)",
            details={"error": str(e)},
        )


async def check_redis_health() -> ComponentHealth:
    """Evaluate Redis cache and background broker connectivity bounded by circuit breaker."""
    settings = get_settings()
    breaker = get_redis_circuit_breaker()

    if not breaker.can_attempt():
        return ComponentHealth(
            status="unavailable",
            message=f"Redis circuit breaker {breaker.state.value} (in cooldown). Limits operate per-process.",
            details={"circuit_breaker": breaker.state.value},
        )

    start_time = datetime.now(timezone.utc)
    try:
        client = aioredis.from_url(
            settings.redis_url,
            socket_connect_timeout=max(1.5, settings.REDIS_SOCKET_CONNECT_TIMEOUT),
            socket_timeout=max(1.5, settings.REDIS_SOCKET_TIMEOUT),
        )
        ping_response = await asyncio.wait_for(client.ping(), timeout=2.0)
        await client.aclose()
        breaker.record_success()

        latency = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
        if ping_response:
            return ComponentHealth(
                status="healthy",
                latency_ms=round(latency, 2),
                message="Redis responsive.",
            )
        return ComponentHealth(
            status="degraded",
            message="Redis ping returned unexpected response.",
        )
    except Exception as e:
        breaker.record_failure(e)
        return ComponentHealth(
            status="unavailable",
            message=f"Redis connection failed: {type(e).__name__} (Verify Docker or local service)",
            details={"error": str(e)},
        )


async def check_celery_workers_health() -> ComponentHealth:
    """Evaluate Celery worker mesh responsiveness and active nodes concurrently."""
    settings = get_settings()
    breaker = get_redis_circuit_breaker()

    if settings.CELERY_TASK_ALWAYS_EAGER or settings.TASK_DISPATCHER == "inline":
        return ComponentHealth(
            status="healthy",
            message="Celery operating in eager/inline mode (in-process).",
            details={"eager": True, "dispatcher": settings.TASK_DISPATCHER},
        )

    if breaker.state == BreakerState.OPEN:
        return ComponentHealth(
            status="unavailable",
            message="Celery broker unreachable (Redis circuit breaker OPEN).",
            details={"circuit_breaker": "OPEN"},
        )

    def _sync_ping():
        from app.workers.celery_app import celery_app
        return celery_app.control.ping(timeout=0.8)

    try:
        responses = await asyncio.wait_for(asyncio.to_thread(_sync_ping), timeout=3.0)
        if responses:
            worker_nodes = [list(r.keys())[0] for r in responses if r]
            return ComponentHealth(
                status="healthy",
                message=f"Celery worker mesh online ({len(worker_nodes)} active node(s)).",
                details={"workers": worker_nodes},
            )
        return ComponentHealth(
            status="degraded",
            message="Celery worker mesh unresponsive or no workers currently online.",
            details={"active_nodes": 0},
        )
    except Exception as exc:
        return ComponentHealth(
            status="unavailable",
            message=f"Celery inspection failed: {type(exc).__name__}",
            details={"error": str(exc)},
        )


def check_evidence_storage_health() -> ComponentHealth:
    """Evaluate accessibility and isolation of evidence storage."""
    settings = get_settings()
    try:
        evidence_dir = Path(settings.TTI_EVIDENCE_STORAGE_PATH).resolve()
        evidence_dir.mkdir(parents=True, exist_ok=True)
        probe_file = evidence_dir / ".health_probe"
        probe_file.write_text("probe", encoding="utf-8")
        probe_file.unlink()

        return ComponentHealth(
            status="healthy",
            message="Evidence storage directory verified and writable.",
            details={"path": str(evidence_dir)},
        )
    except Exception as e:
        return ComponentHealth(
            status="unavailable",
            message=f"Evidence storage directory error: {str(e)}",
        )


async def check_detection_engine_health() -> ComponentHealth:
    """Evaluate threat detection rules engine status."""
    try:
        from app.services.detection_service import ThreatDetectionService
        service = ThreatDetectionService()
        engine = await service.get_active_engine()
        is_prod = os.getenv("TTI_ENV", "development").lower() == "production"

        if engine.is_degraded:
            status = "degraded"
            msg = f"Detection engine running in degraded mode ({engine.rules_loaded} rules active)."
        elif engine.rules_loaded == 0 or (is_prod and engine.reviewed_rules_loaded == 0):
            status = "degraded"
            msg = "No reviewed detection rules active in current environment."
        else:
            status = "healthy"
            msg = f"Detection engine operational ({engine.rules_loaded} active rules, {engine.reviewed_rules_loaded} reviewed)."

        return ComponentHealth(
            status=status,
            message=msg,
            details={
                "rules_loaded": engine.rules_loaded,
                "reviewed_rules_loaded": engine.reviewed_rules_loaded,
                "is_degraded": engine.is_degraded,
            },
        )
    except Exception as exc:
        return ComponentHealth(
            status="unavailable",
            message=f"Detection engine check failed: {type(exc).__name__}",
            details={"error": str(exc)},
        )


async def check_mtproto_collector_health() -> ComponentHealth:
    """Evaluate MTProto collector and Telegram connection health."""
    try:
        from app.services.mtproto_collector import get_mtproto_collector

        collector = get_mtproto_collector()
        if collector.connector is not None:
            connector_health = await collector.connector.health_check()
        else:
            from app.connectors.telegram.mtproto import MTProtoTelegramConnector

            connector_health = await MTProtoTelegramConnector().health_check()

        status = connector_health.status.value
        return ComponentHealth(
            status=status,
            message=connector_health.message,
            details={
                "collector_status": collector.stats.get("status"),
                "cycles_completed": collector.stats.get("cycles_completed", 0),
                "authenticated": (connector_health.metadata or {}).get("authenticated", False),
                "telethon_installed": (connector_health.metadata or {}).get("telethon_installed", False),
            },
        )
    except Exception as exc:  # noqa: BLE001
        return ComponentHealth(
            status="unavailable",
            message=f"MTProto health check failed: {type(exc).__name__}",
        )


async def get_system_health() -> HealthStatusResponse:
    """Aggregate health diagnostics across all system components concurrently."""
    settings = get_settings()

    # Static provider inventory (no network probes) so /health stays < 150 ms.
    try:
        from app.integrations.registry import list_integrations

        integrations_summary = [
            {
                "provider": r.provider,
                "credential_available": r.credential_available,
                "configured": r.configured,
                "enabled": r.enabled,
                "backend_integration": r.backend_integration,
            }
            for r in await list_integrations(probe=False)
        ]
    except Exception:  # noqa: BLE001 - inventory must never break health
        integrations_summary = []

    # Run network and async probes concurrently
    db_health, redis_health, celery_health, engine_health, mtproto_health = await asyncio.gather(
        check_database_health(),
        check_redis_health(),
        check_celery_workers_health(),
        check_detection_engine_health(),
        check_mtproto_collector_health(),
    )
    storage_health = check_evidence_storage_health()

    connectors_health = ComponentHealth(
        status="disabled",
        message="Phase 1 Baseline: Ingestion connectors operate in safe inert stub mode.",
        details={
            "telegram_active": settings.TTI_TELEGRAM_CONNECTOR_ACTIVE,
            "darkweb_active": settings.TTI_DARKWEB_CONNECTOR_ACTIVE,
            "live_collection": "disabled_by_policy",
        },
    )

    # Determine overall status
    is_healthy = db_health.status == "healthy" and redis_health.status == "healthy"
    overall_status = "healthy" if is_healthy else "degraded"

    return HealthStatusResponse(
        status=overall_status,
        environment=settings.TTI_ENV,
        project_name=settings.TTI_PROJECT_NAME,
        version="0.1.0",
        timestamp_utc=datetime.now(timezone.utc).isoformat(),
        components={
            "database": db_health,
            "redis": redis_health,
            "celery_workers": celery_health,
            "evidence_storage": storage_health,
            "connectors": connectors_health,
            "detection_engine": engine_health,
            "mtproto_collector": mtproto_health,
            "integrations": ComponentHealth(
                status="healthy",
                message="External API integration inventory (credential/configuration state only).",
                details={"providers": integrations_summary},
            ),
        },
    )
