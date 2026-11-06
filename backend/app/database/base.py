"""SQLAlchemy declarative base and multi-tenancy mixin architecture."""

from datetime import datetime, timezone
import uuid
from sqlalchemy import DateTime, String, func
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, declared_attr, mapped_column


class Base(DeclarativeBase):
    """Root declarative base for all SQLAlchemy entities."""
    pass


class TenantAwareModel:
    """
    Architectural mixin enforcing tenant isolation across all client-owned entities.

    NON-NEGOTIABLE ARCHITECTURAL RULE:
    Every intelligence artifact, thread, analysis result, alert, and report must inherit
    from TenantAwareModel. Direct cross-tenant querying without tenant_id predicate
    filtering is strictly prohibited.
    """

    @declared_attr
    def tenant_id(cls) -> Mapped[uuid.UUID]:
        return mapped_column(
            PG_UUID(as_uuid=True),
            nullable=False,
            index=True,
            comment="Enforces strict tenant isolation for client-owned data",
        )

    @declared_attr
    def created_at(cls) -> Mapped[datetime]:
        return mapped_column(
            DateTime(timezone=True),
            server_default=func.now(),
            default=lambda: datetime.now(timezone.utc),
            nullable=False,
        )

    @declared_attr
    def updated_at(cls) -> Mapped[datetime]:
        return mapped_column(
            DateTime(timezone=True),
            server_default=func.now(),
            onupdate=lambda: datetime.now(timezone.utc),
            default=lambda: datetime.now(timezone.utc),
            nullable=False,
        )
