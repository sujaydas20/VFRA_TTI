"""Abstract interface for threat intelligence AI analysis.

GOVERNANCE & NON-NEGOTIABLE RULE:
Unrestricted autonomous actions are strictly prohibited. In Phase 1, this interface
defines the contract for future deterministic classification, NER (Named Entity Recognition),
and threat summarization with human-in-the-loop oversight.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List
from pydantic import BaseModel


class AnalysisResult(BaseModel):
    """Structured output of threat intelligence analysis."""
    tenant_id: str
    thread_id: str
    threat_category: str
    confidence_score: float
    extracted_iocs: List[Dict[str, str]]
    executive_summary: str
    requires_human_review: bool = True  # Mandatory safety baseline


class AIAnalysisEngineInterface(ABC):
    """Interface for pluggable AI/LLM analysis providers."""

    @abstractmethod
    async def analyze_thread(
        self,
        tenant_id: str,
        thread_id: str,
        sanitized_content: str,
    ) -> AnalysisResult:
        """Analyze sanitized thread content and extract threat indicators."""
        pass
