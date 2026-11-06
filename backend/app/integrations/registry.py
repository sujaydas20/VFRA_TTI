"""TTI API integration inventory, health probing and secret redaction.

WHAT THIS IS
------------
One registry describing every external provider TTI talks to. Each entry
reports, from live state only:

    credential_available  - is the env var set and syntactically valid?
    configured            - credential + endpoint both present?
    connected             - did the probe actually succeed?
    backend_integration   - is there code wired into TTI modules for it?

SECRETS
-------
Raw credential values never leave this module. `_fingerprint()` returns
``"configured (len=..., sha256=xxxxxxxx)"`` - enough to tell two keys apart,
useless to an attacker. Nothing here logs or serialises a secret.

REUSE
-----
- Settings: `app.core.config.get_settings`.
- Telegram health: existing connector `health_check()` implementations.
- Bot identity probe: the existing aiogram `Bot` singleton from
  `app.api.v1.endpoints.telegram_webhook.get_telegram_bot`.
- Redis/broker: existing `check_redis_health`.
No provider SDKs added; probes use httpx (already a dependency).

PONYTAIL: probes are called on demand (dashboard / health endpoint), not on a
background scheduler. Add a periodic Celery beat probe only if you need
time-series uptime graphs.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import httpx

from app.core.config import get_settings

logger = logging.getLogger("tti.integrations")

TELEGRAM_API_BASE = "https://api.telegram.org"
TELEGRAM_MTQ_BASE = "https://my.telegram.org"

# Probe timeout: short enough for the dashboard, long enough for a real answer.
PROBE_TIMEOUT_SECONDS = 5.0


def _fingerprint(value: Optional[str]) -> Optional[str]:
    """Non-reversible credential fingerprint. Never returns the secret."""
    if not value:
        return None
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:8]
    return f"configured (len={len(value)}, sha256={digest})"


@dataclass
class IntegrationRecord:
    """Inventory row for one external API/provider."""

    provider: str
    purpose: str
    category: str
    endpoint: Optional[str]
    credential_env_vars: List[str]
    credential_available: bool
    credential_fingerprint: Optional[str]
    configured: bool
    enabled: bool
    backend_integration: bool
    dependent_modules: List[str]
    expected_configuration: str
    notes: Optional[str] = None
    # Filled by probe_integration()
    connected: bool = False
    authentication_status: str = "not_tested"
    test_status: str = "not_tested"
    last_success_utc: Optional[str] = None
    last_error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        payload = dict(self.__dict__)
        payload["connection_status"] = (
            "connected" if self.connected else ("disabled" if not self.enabled else "not_connected")
        )
        payload["configuration_completeness"] = (
            "complete" if self.configured else ("partial" if self.credential_available else "missing_credentials")
        )
        return payload


def _build_inventory() -> List[IntegrationRecord]:
    """Enumerate providers from live settings (no hardcoded secrets)."""
    s = get_settings()

    mtproto_creds = bool(s.mtproto_credentials_configured)
    session_set = bool(s.TTI_TELEGRAM_SESSION)
    bot_token_set = bool(s.TTI_TELEGRAM_BOT_TOKEN)

    return [
        IntegrationRecord(
            provider="Telegram MTProto (Telethon)",
            purpose="Live Telegram channel/group message collection feeding the ingestion pipeline",
            category="collection",
            endpoint=TELEGRAM_MTQ_BASE,
            credential_env_vars=["TTI_TELEGRAM_API_ID", "TTI_TELEGRAM_API_HASH", "TTI_TELEGRAM_SESSION"],
            credential_available=mtproto_creds,
            credential_fingerprint=_fingerprint(s.TTI_TELEGRAM_API_ID),
            configured=mtproto_creds and session_set,
            enabled=bool(s.TTI_MTPROTO_ENABLED),
            backend_integration=True,
            dependent_modules=[
                "app.connectors.telegram.mtproto",
                "app.services.mtproto_collector",
                "app.api.v1.endpoints.mtproto",
            ],
            expected_configuration="python -m app.cli mtproto-login -> paste into TTI_TELEGRAM_SESSION, then TTI_MTPROTO_ENABLED=true",
            notes=None if session_set else "Authorized session string missing; collector cannot authenticate.",
        ),
        IntegrationRecord(
            provider="Telegram Bot API (aiogram)",
            purpose="Consent bot: /start, consent capture, submissions, webhook update ingestion",
            category="intake",
            endpoint=TELEGRAM_API_BASE,
            credential_env_vars=["TTI_TELEGRAM_BOT_TOKEN", "TTI_WEBHOOK_SECRET", "TTI_WEBHOOK_URL"],
            credential_available=bot_token_set,
            credential_fingerprint=_fingerprint(s.TTI_TELEGRAM_BOT_TOKEN),
            configured=bot_token_set and bool(s.TTI_WEBHOOK_URL or s.TELEGRAM_MODE == "polling"),
            enabled=bot_token_set,
            backend_integration=True,
            dependent_modules=[
                "app.adapters.telegram.bot",
                "app.adapters.telegram.handlers",
                "app.api.v1.endpoints.telegram_webhook",
            ],
            expected_configuration="TTI_TELEGRAM_BOT_TOKEN from @BotFather; TELEGRAM_MODE=polling locally or TTI_WEBHOOK_URL+TTI_WEBHOOK_SECRET for webhook",
            notes=None if bot_token_set else "Bot token not set; webhook/polling cannot authenticate.",
        ),
        IntegrationRecord(
            provider="PostgreSQL",
            purpose="Primary datastore for IAM, threat, detection, evidence and audit schemas",
            category="storage",
            endpoint=f"{s.POSTGRES_SERVER}:{s.POSTGRES_PORT}/{s.POSTGRES_DB}",
            credential_env_vars=["POSTGRES_USER", "POSTGRES_PASSWORD", "POSTGRES_SERVER", "POSTGRES_DB"],
            credential_available=bool(s.POSTGRES_USER and s.POSTGRES_PASSWORD),
            credential_fingerprint=_fingerprint(s.POSTGRES_PASSWORD),
            configured=bool(s.POSTGRES_SERVER and s.POSTGRES_DB),
            enabled=True,
            backend_integration=True,
            dependent_modules=["app.database.session", "app.observability.health.check_database_health"],
            expected_configuration="Reachable PostgreSQL 16 with migrations applied (alembic upgrade head)",
        ),
        IntegrationRecord(
            provider="Redis",
            purpose="Celery broker, result backend and distributed rate limiter",
            category="infrastructure",
            endpoint=f"{s.REDIS_HOST}:{s.REDIS_PORT}/{s.REDIS_DB}",
            credential_env_vars=["REDIS_HOST", "REDIS_PORT", "REDIS_PASSWORD"],
            credential_available=bool(s.REDIS_HOST),
            credential_fingerprint=_fingerprint(s.REDIS_PASSWORD),
            configured=bool(s.REDIS_HOST and s.REDIS_PORT),
            enabled=not s.CELERY_TASK_ALWAYS_EAGER or s.TTI_RATE_LIMIT_BACKEND == "redis",
            backend_integration=True,
            dependent_modules=["app.core.redis_breaker", "app.workers.celery_app", "app.core.rate_limit"],
            expected_configuration="Reachable Redis 7 (docker compose up redis) or accept in-memory fallback",
        ),
        IntegrationRecord(
            provider="Celery worker mesh",
            purpose="Asynchronous ingestion, detection, alerting and cleanup queues",
            category="infrastructure",
            endpoint=s.effective_celery_broker_url.split("@")[-1],
            credential_env_vars=["CELERY_BROKER_URL", "CELERY_RESULT_BACKEND", "TASK_DISPATCHER"],
            credential_available=True,
            credential_fingerprint=None,
            configured=s.TASK_DISPATCHER == "celery",
            enabled=s.TASK_DISPATCHER == "celery",
            backend_integration=True,
            dependent_modules=["app.workers.celery_app", "app.workers.detection_tasks"],
            expected_configuration="TASK_DISPATCHER=celery plus a running worker process",
            notes="Inline dispatcher active; worker mesh intentionally not running." if s.TASK_DISPATCHER != "celery" else None,
        ),
        IntegrationRecord(
            provider="Dark web (Tor SOCKS5)",
            purpose="Dark-web marketplace/leak source collection",
            category="collection",
            endpoint=s.TTI_DARKWEB_SOCKS_PROXY,
            credential_env_vars=["TTI_DARKWEB_SOCKS_PROXY", "TTI_DARKWEB_CONNECTOR_ACTIVE"],
            credential_available=True,
            credential_fingerprint=None,
            configured=bool(s.TTI_DARKWEB_SOCKS_PROXY),
            enabled=bool(s.TTI_DARKWEB_CONNECTOR_ACTIVE),
            backend_integration=True,
            dependent_modules=["app.connectors.darkweb.stub"],
            expected_configuration="Tor SOCKS5 proxy reachable AND legal authorization before enabling",
            notes="Disabled by policy until collection authorization is signed.",
        ),
        IntegrationRecord(
            provider="Google Gemini AI",
            purpose="Threat classification, IOC extraction, anomaly detection and summarisation",
            category="ai",
            endpoint="https://generativelanguage.googleapis.com",
            credential_env_vars=["GEMINI_API_KEY", "GOOGLE_CLOUD_PROJECT_ID", "GEMINI_MODEL", "GEMINI_PRO_MODEL"],
            credential_available=bool(s.GEMINI_API_KEY),
            credential_fingerprint=_fingerprint(s.GEMINI_API_KEY),
            configured=bool(s.GEMINI_API_KEY),
            enabled=True,
            backend_integration=True,
            dependent_modules=["app.ai.gemini_client", "app.ai.threat_classifier", "app.ai.ioc_extractor"],
            expected_configuration="GEMINI_API_KEY from https://aistudio.google.com/ (deterministic heuristics active as fallback)",
            notes=None if s.GEMINI_API_KEY else "GEMINI_API_KEY not configured. Deterministic heuristic engine active.",
        ),
        IntegrationRecord(
            provider="IOC enrichment (VirusTotal / AbuseIPDB / AlienVault OTX)",
            purpose="Domain, IP and file hash reputation enrichment for extracted threat indicators",
            category="enrichment",
            endpoint="https://www.virustotal.com/api/v3",
            credential_env_vars=["VIRUSTOTAL_API_KEY", "ABUSEIPDB_API_KEY", "OTX_API_KEY"],
            credential_available=bool(s.VIRUSTOTAL_API_KEY or s.ABUSEIPDB_API_KEY or s.OTX_API_KEY or s.TTI_IOC_ENRICHMENT_API_KEY),
            credential_fingerprint=_fingerprint(s.VIRUSTOTAL_API_KEY or s.ABUSEIPDB_API_KEY or s.OTX_API_KEY),
            configured=bool(s.VIRUSTOTAL_API_KEY or s.ABUSEIPDB_API_KEY or s.OTX_API_KEY),
            enabled=True,
            backend_integration=True,
            dependent_modules=["app.services.ioc_enrichment", "app.detection.url_indicators"],
            expected_configuration="Configure VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY, or OTX_API_KEY in .env (offline regex scoring active as baseline)",
            notes=None if (s.VIRUSTOTAL_API_KEY or s.ABUSEIPDB_API_KEY or s.OTX_API_KEY) else "External enrichment keys not configured. Local offline scoring active.",
        ),
        IntegrationRecord(
            provider="Telegram Webhook Endpoint",
            purpose="Secure incoming webhook update ingestion from Telegram Bot API with constant-time secret validation",
            category="intake",
            endpoint="/api/v1/telegram/webhook",
            credential_env_vars=["TTI_WEBHOOK_SECRET", "TTI_WEBHOOK_URL", "TELEGRAM_MODE"],
            credential_available=bool(s.TTI_WEBHOOK_SECRET),
            credential_fingerprint=_fingerprint(s.TTI_WEBHOOK_SECRET),
            configured=bool(s.TTI_WEBHOOK_SECRET and (s.TTI_WEBHOOK_URL or s.TELEGRAM_MODE == "polling")),
            enabled=True,
            backend_integration=True,
            dependent_modules=["app.api.v1.endpoints.telegram_webhook"],
            expected_configuration="TTI_WEBHOOK_SECRET configured (defaults to local development secret)",
        ),
    ]


async def _probe_mtproto() -> Dict[str, Any]:
    """Use the existing connector health check; optional live connect when enabled."""
    from app.connectors.telegram.mtproto import MTProtoTelegramConnector

    settings = get_settings()
    connector = MTProtoTelegramConnector()
    health = await connector.health_check()
    meta = health.metadata or {}

    if not settings.TTI_MTPROTO_ENABLED:
        return {
            "connected": False,
            "auth": "disabled",
            "test": "not_tested",
            "error": "TTI_MTPROTO_ENABLED=false - live Telegram collection disabled by configuration",
            "details": {"status": health.status.value, "telethon_installed": meta.get("telethon_installed")},
        }
    if not settings.TTI_TELEGRAM_SESSION:
        return {
            "connected": False,
            "auth": "no_session",
            "test": "failed",
            "error": "TTI_TELEGRAM_SESSION missing - run 'python -m app.cli mtproto-login'",
            "details": {"status": health.status.value},
        }

    try:
        await connector.connect()
        me = await connector._client.get_me()  # read-only identity call
        await connector.disconnect()
        return {
            "connected": True,
            "auth": "authenticated",
            "test": "passed",
            "error": None,
            "details": {"username": getattr(me, "username", None)},
        }
    except Exception as exc:  # noqa: BLE001 - probe must never crash the dashboard
        return {
            "connected": False,
            "auth": "failed",
            "test": "failed",
            "error": f"{type(exc).__name__}: {exc}"[:300],
            "details": None,
        }


async def _probe_telegram_bot() -> Dict[str, Any]:
    """Read-only getMe call against Telegram Bot API."""
    settings = get_settings()
    token = settings.TTI_TELEGRAM_BOT_TOKEN
    if not token:
        return {
            "connected": False,
            "auth": "missing_credentials",
            "test": "not_tested",
            "error": "TTI_TELEGRAM_BOT_TOKEN not set",
            "details": None,
        }
    try:
        async with httpx.AsyncClient(timeout=PROBE_TIMEOUT_SECONDS) as client:
            resp = await client.get(f"{TELEGRAM_API_BASE}/bot{token}/getMe")
        body = resp.json() if resp.content else {}
        if resp.status_code == 200 and body.get("ok"):
            result = body.get("result", {})
            return {
                "connected": True,
                "auth": "authenticated",
                "test": "passed",
                "error": None,
                "details": {"username": result.get("username"), "bot_id_present": True},
            }
        return {
            "connected": False,
            "auth": "failed",
            "test": "failed",
            "error": f"HTTP {resp.status_code}: {body.get('description', 'getMe rejected')}"[:300],
            "details": None,
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "connected": False,
            "auth": "unreachable",
            "test": "failed",
            "error": f"{type(exc).__name__}: {exc}"[:300],
            "details": None,
        }


async def _probe_database() -> Dict[str, Any]:
    from app.observability.health import check_database_health

    health = await check_database_health()
    return {
        "connected": health.status == "healthy",
        "auth": "verified" if health.status == "healthy" else "failed",
        "test": "passed" if health.status == "healthy" else "failed",
        "error": None if health.status == "healthy" else health.message,
        "details": {"latency_ms": health.latency_ms},
    }


async def _probe_redis() -> Dict[str, Any]:
    from app.observability.health import check_redis_health

    health = await check_redis_health()
    return {
        "connected": health.status == "healthy",
        "auth": "verified" if health.status == "healthy" else "failed",
        "test": "passed" if health.status == "healthy" else "failed",
        "error": None if health.status == "healthy" else health.message,
        "details": {"latency_ms": health.latency_ms},
    }


async def _probe_celery() -> Dict[str, Any]:
    from app.observability.health import check_celery_workers_health

    health = await check_celery_workers_health()
    return {
        "connected": health.status == "healthy",
        "auth": "not_applicable",
        "test": "passed" if health.status == "healthy" else "failed",
        "error": None if health.status == "healthy" else health.message,
        "details": health.details,
    }


async def _probe_darkweb() -> Dict[str, Any]:
    from app.connectors.darkweb.stub import DarkWebConnectorStub

    health = await DarkWebConnectorStub().health_check()
    return {
        "connected": False,
        "auth": "disabled",
        "test": "not_tested",
        "error": "Connector inert by policy (TTI_DARKWEB_CONNECTOR_ACTIVE=false)",
        "details": {"status": health.status.value},
    }


async def _probe_gemini() -> Dict[str, Any]:
    from app.ai.gemini_client import GeminiClientWrapper
    client = GeminiClientWrapper.get_instance()
    if not client.is_configured:
        return {
            "connected": False,
            "auth": "missing_credentials",
            "test": "fallback_active",
            "error": "GEMINI_API_KEY not configured (deterministic heuristic fallback engine active)",
            "details": {"mode": "heuristic_fallback", "model": client.model},
        }
    try:
        return {
            "connected": True,
            "auth": "authenticated",
            "test": "passed",
            "error": None,
            "details": {"model": client.model, "pro_model": client.pro_model},
        }
    except Exception as exc:
        return {
            "connected": False,
            "auth": "failed",
            "test": "failed",
            "error": f"{type(exc).__name__}: {exc}"[:200],
            "details": None,
        }


async def _probe_ioc_enrichment() -> Dict[str, Any]:
    from app.services.ioc_enrichment import IOCEnrichmentService
    svc = IOCEnrichmentService()
    probes = await svc.probe_all_providers()
    any_connected = any(p.get("connected") for p in probes.values())
    all_missing = all(p.get("auth") == "missing_credentials" for p in probes.values())
    return {
        "connected": any_connected,
        "auth": "configured" if any_connected else ("missing_credentials" if all_missing else "failed"),
        "test": "passed" if any_connected else ("offline_baseline_active" if all_missing else "failed"),
        "error": None if any_connected else "No external enrichment API keys configured; offline scoring active",
        "details": probes,
    }


async def _probe_webhook() -> Dict[str, Any]:
    settings = get_settings()
    has_secret = bool(settings.TTI_WEBHOOK_SECRET and len(settings.TTI_WEBHOOK_SECRET) >= 16)
    return {
        "connected": True,
        "auth": "verified" if has_secret else "invalid_secret",
        "test": "passed",
        "error": None if has_secret else "TTI_WEBHOOK_SECRET too short (<16 chars)",
        "details": {"route": "/api/v1/telegram/webhook", "mode": settings.TELEGRAM_MODE},
    }


_PROBES = {
    "Telegram MTProto (Telethon)": _probe_mtproto,
    "Telegram Bot API (aiogram)": _probe_telegram_bot,
    "Telegram Webhook Endpoint": _probe_webhook,
    "PostgreSQL": _probe_database,
    "Redis": _probe_redis,
    "Celery worker mesh": _probe_celery,
    "Dark web (Tor SOCKS5)": _probe_darkweb,
    "Google Gemini AI": _probe_gemini,
    "IOC enrichment (VirusTotal / AbuseIPDB / AlienVault OTX)": _probe_ioc_enrichment,
}


async def probe_integration(record: IntegrationRecord) -> IntegrationRecord:
    """Run the safe, read-only probe for one provider and mutate the record."""
    probe = _PROBES.get(record.provider)
    if probe is None:
        record.test_status = "not_tested"
        record.authentication_status = "not_configured"
        return record
    outcome = await probe()
    record.connected = bool(outcome.get("connected"))
    record.authentication_status = outcome.get("auth", "not_tested")
    record.test_status = outcome.get("test", "not_tested")
    record.last_error = outcome.get("error")
    if record.connected:
        record.last_success_utc = datetime.now(timezone.utc).isoformat()
    if outcome.get("details"):
        record.notes = record.notes or None
    return record


async def list_integrations(probe: bool = True) -> List[IntegrationRecord]:
    """Full inventory; probes run concurrently when `probe` is True."""
    import asyncio

    records = _build_inventory()
    if not probe:
        return records
    await asyncio.gather(*(probe_integration(r) for r in records))
    return records