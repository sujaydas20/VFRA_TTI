"""Declarative model for failed system jobs and dead-letter queue records."""

from datetime import datetime, timezone
import uuid
from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID

from app.database.base import Base


class SystemJobRecord(Base):
    """Tracks failed background worker tasks, retries, and dead-letter records.

    INVARIANT: NEVER stores task arguments, payload data, or message content.
    Only cryptographic hashes of arguments (args_hash) and sanitized exception classes are recorded.
    """

    __tablename__ = "system_jobs"
    __table_args__ = {"schema": "app"}

    job_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(
        UUID(as_uuid=True),
        ForeignKey("iam.tenant_organizations.tenant_id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    task_name = Column(String(128), nullable=False, index=True)
    queue_name = Column(String(64), nullable=False, index=True)
    args_hash = Column(String(64), nullable=False, index=True)
    error_class = Column(String(128), nullable=False)
    sanitized_error_message = Column(Text, nullable=False)
    attempt_count = Column(Integer, nullable=False, default=1)
    status = Column(String(32), nullable=False, default="FAILED", index=True)
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    failed_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
