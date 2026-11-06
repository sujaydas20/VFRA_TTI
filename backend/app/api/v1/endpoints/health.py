"""Health check API endpoint."""

from fastapi import APIRouter
from app.observability.health import HealthStatusResponse, get_system_health
from app.observability.metrics import metrics_store

router = APIRouter()


@router.get(
    "/health",
    response_model=HealthStatusResponse,
    summary="System and Subsystem Health Diagnostic",
    description="Returns aggregate health status and individual checks for PostgreSQL, Redis, and storage.",
)
async def check_health() -> HealthStatusResponse:
    """Evaluate and report system health."""
    metrics_store.health_checks_total += 1
    return await get_system_health()
