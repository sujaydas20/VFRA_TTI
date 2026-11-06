"""Dark-web connector package for TTI."""
from app.connectors.darkweb.interface import DarkWebConnectorInterface
from app.connectors.darkweb.stub import DarkWebConnectorStub
from app.connectors.darkweb.models import DarkWebPagePayload, DarkWebThreadItem

__all__ = [
    "DarkWebConnectorInterface",
    "DarkWebConnectorStub",
    "DarkWebPagePayload",
    "DarkWebThreadItem",
]
