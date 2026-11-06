"""Evidence domain models and integrity verification structures."""

from datetime import datetime, timezone
from typing import Optional
from pydantic import BaseModel, Field


class EvidenceRecord(BaseModel):
    """Metadata describing a stored cryptographic evidence artifact."""
    tenant_id: str
    artifact_id: str
    source_type: str
    content_sha256: str
    relative_path: str
    byte_size: int
    stored_at_utc: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    is_tamper_verified: bool = False


class EvidenceIntegrityReport(BaseModel):
    """Result of an evidence integrity check."""
    artifact_id: str
    tenant_id: str
    expected_sha256: str
    computed_sha256: Optional[str] = None
    is_valid: bool
    verified_at_utc: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    notes: str = ""
