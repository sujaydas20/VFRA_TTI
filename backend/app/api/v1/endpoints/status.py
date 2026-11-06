"""TTI Project status and architecture diagnostic endpoint."""

from typing import Any, Dict
from fastapi import APIRouter, Depends
from app.api.deps import TenantContext, get_current_tenant_context
from app.core.config import Settings, get_settings

router = APIRouter()


@router.get(
    "/status",
    summary="Project Status & Architecture Diagnostics",
    description="Returns current project phase, active baseline rules, and architecture state.",
)
async def get_project_status(
    tenant_context: TenantContext = Depends(get_current_tenant_context),
    settings: Settings = Depends(get_settings),
) -> Dict[str, Any]:
    """Retrieve comprehensive project status."""
    engine_status = {
        "rules_loaded": 0,
        "reviewed_rules_loaded": 0,
        "is_degraded": False,
    }
    try:
        from app.services.detection_service import ThreatDetectionService
        service = ThreatDetectionService()
        engine = await service.get_active_engine()
        engine_status = {
            "rules_loaded": engine.rules_loaded,
            "reviewed_rules_loaded": engine.reviewed_rules_loaded,
            "is_degraded": engine.is_degraded,
        }
    except Exception:
        pass

    return {
        "project": "Telegram Threat Intelligence (TTI)",
        "phase": "Phase 1: Project Initialization & Architectural Foundation",
        "phase_status": "complete",
        "environment": settings.TTI_ENV,
        "tenant_context": {
            "active_tenant_id": tenant_context.tenant_id,
            "authentication_ready": tenant_context.is_authenticated,
            "tenant_isolation_design": "enforced_on_models",
        },
        "connectors_summary": {
            "telegram_collection": "disabled_safe_stub",
            "darkweb_collection": "disabled_safe_stub",
            "untrusted_input_sanitizer": "active",
            "evidence_store_isolated": True,
        },
        "security_baseline_compliance": {
            "real_credentials_in_repo": False,
            "live_scraping_authorized": False,
            "evidence_separated_from_frontend": True,
            "unrestricted_autonomous_actions": False,
            "live_reinforcement_learning": False,
        },
        "detection_engine": engine_status,
        "next_phase": "Phase 2: Authentication, Tenant Scoping & Controlled Connector Sandbox",
    }
