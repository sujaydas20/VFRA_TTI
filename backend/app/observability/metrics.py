"""Basic observability metrics baseline."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict


@dataclass
class SystemMetrics:
    """In-memory telemetry counters for Phase 1 baseline."""
    requests_total: int = 0
    health_checks_total: int = 0
    sanitization_runs_total: int = 0
    started_at_utc: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


metrics_store = SystemMetrics()
