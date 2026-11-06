"""Connector registration and health status endpoints."""

from typing import Dict, List
from fastapi import APIRouter
from app.connectors.base import ConnectorHealth
from app.connectors.telegram.stub import TelegramConnectorStub
from app.connectors.darkweb.stub import DarkWebConnectorStub

router = APIRouter()

# Instantiate connector stubs
telegram_stub = TelegramConnectorStub()
darkweb_stub = DarkWebConnectorStub()


@router.get(
    "/connectors",
    response_model=List[ConnectorHealth],
    summary="List Registered Connectors",
    description="Returns diagnostic status for all modular intelligence connectors.",
)
async def list_connectors() -> List[ConnectorHealth]:
    """Retrieve diagnostic health reports from all registered connectors."""
    tg_health = await telegram_stub.health_check()
    dw_health = await darkweb_stub.health_check()
    return [tg_health, dw_health]
