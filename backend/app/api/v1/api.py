"""Aggregated API v1 router for TTI."""

from fastapi import APIRouter
from app.api.v1.endpoints import (
    alerts,
    auth,
    cases,
    connectors,
    detections,
    health,
    integrations,
    jobs,
    mtproto,
    organizations,
    status,
    telegram_webhook,
    threat,
)

api_router = APIRouter()

api_router.include_router(health.router, tags=["Health"])
api_router.include_router(status.router, tags=["Status"])
api_router.include_router(connectors.router, tags=["Connectors"])
api_router.include_router(mtproto.router)
api_router.include_router(auth.router)
api_router.include_router(organizations.router)
api_router.include_router(threat.router)
api_router.include_router(cases.router)
api_router.include_router(jobs.router)
api_router.include_router(detections.router)
api_router.include_router(alerts.router)
api_router.include_router(integrations.router)
api_router.include_router(telegram_webhook.router, prefix="/telegram", tags=["Telegram"])
