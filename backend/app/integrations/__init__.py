"""Centralised external API/integration registry.

Single source of truth for "which provider credentials exist, where they are
used, and are they working". Reuses the existing settings object, connector
health checks and observability probes; adds no new HTTP client frameworks.
"""

from app.integrations.registry import (
    IntegrationRecord,
    list_integrations,
    probe_integration,
)

__all__ = ["IntegrationRecord", "list_integrations", "probe_integration"]