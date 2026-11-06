"""Ingestion data models and normalized payload schemas."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class RawIngestEnvelope(BaseModel):
    """Untrusted raw payload submitted for ingestion."""
    tenant_id: str
    source_type: str  # "telegram" | "darkweb"
    source_reference: str  # channel username or onion URL
    raw_payload: Dict[str, Any]
    captured_at_utc: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class NormalizedIntelligenceItem(BaseModel):
    """
    Standardized, sanitized intelligence item ready for persistence and analysis.
    All untrusted content has been processed through InputSanitizer.
    """
    tenant_id: str
    source_type: str
    external_id: str
    title: str
    sanitized_text: str
    content_sha256: str
    author_identifier: Optional[str] = None
    captured_at_utc: datetime
    sanitization_applied: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
