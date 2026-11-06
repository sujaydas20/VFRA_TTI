"""Intelligence report generation interface."""

from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Dict, List
from pydantic import BaseModel, Field


class ThreatReport(BaseModel):
    """Generated threat intelligence dossier or periodic summary."""
    tenant_id: str
    report_id: str
    report_title: str
    time_window_start_utc: datetime
    time_window_end_utc: datetime
    total_threads_analyzed: int
    high_priority_threats_count: int
    executive_summary: str
    generated_at_utc: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ReportGeneratorInterface(ABC):
    """Abstract interface for intelligence reporting."""

    @abstractmethod
    async def generate_tenant_report(
        self,
        tenant_id: str,
        title: str,
        parameters: Dict[str, Any],
    ) -> ThreatReport:
        """Generate a tenant-isolated threat intelligence report."""
        pass
