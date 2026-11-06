"""Modular data source connectors for TTI."""

from app.connectors.base import BaseConnector, ConnectorHealth, ConnectorStatus
from app.connectors.telegram.stub import TelegramConnectorStub
from app.connectors.telegram.mtproto import MTProtoTelegramConnector
from app.connectors.darkweb.stub import DarkWebConnectorStub

__all__ = [
    "BaseConnector",
    "ConnectorHealth",
    "ConnectorStatus",
    "TelegramConnectorStub",
    "MTProtoTelegramConnector",
    "DarkWebConnectorStub",
]
