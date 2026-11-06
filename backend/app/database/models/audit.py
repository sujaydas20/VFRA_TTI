"""Audit event models for compliance and access tracking.

Includes:
- AuditEvent: Release 0 prototype model (public.audit_events)
- AuditEventRecord: Canonical Phase 1 append-only audit ledger (audit.audit_event_records per DEC-17)
"""

from datetime import datetime, timezone
import uuid
from typing import Optional
from sqlalchemy import JSON, DateTime, ForeignKey, String, func
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column
from app.database.base import Base, TenantAwareModel


class AuditEvent(Base, TenantAwareModel):
    """
    Immutable audit log entry recording actions, tenant contexts, and security events.
    (Release 0 prototype model in public schema).
    """

    __tablename__ = "audit_events"

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    actor_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    action: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    resource_type: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    resource_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    client_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    event_metadata: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    def __repr__(self) -> str:
        return f"<AuditEvent id={self.id} action={self.action} tenant_id={self.tenant_id}>"


class AuditEventRecord(Base):
    """
    Canonical append-only audit ledger for security-sensitive operations.

    Canonical Reference:
    - Requirements: AC-REQ-001 through AC-REQ-006, NFR-OBS-001, NFR-OBS-003
    - Decisions: DEC-17 (Minimal IAM audit ledger pulled forward to Phase 1)
    - Physical Schema: audit.audit_event_records (docs/architecture/gate_4b_3a/physical_schema_design.md#61)

    LIMITATION NOTICE (DEC-17):
    This relational audit table provides application-level accountability and tamper evidence
    against standard application queries. However, ordinary database rows are NOT inherently
    tamper-proof against database superusers or privileged database operators without external
    WORM storage or RFC 3161 cryptographic timestamp sealing.
    """

    __tablename__ = "audit_event_records"
    __table_args__ = (
        {"schema": "audit"},
    )

    audit_event_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    tenant_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("iam.tenant_organizations.tenant_id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        comment="Tenant scope; NULL for system-level or unauthenticated events",
    )
    user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("iam.user_profiles.user_id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        comment="Acting user; NULL for anonymous or automated system operations",
    )
    action_type: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
        comment="Lifecycle or security action: MEMBERSHIP_CREATE, MEMBERSHIP_REVOKE, LOGIN, etc.",
    )
    target_identifier_hash: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
        comment="SHA-256 digest of sensitive target observable (zero cleartext)",
    )
    client_ip_address: Mapped[Optional[str]] = mapped_column(
        String(45),
        nullable=True,
        comment="Client network address (IPv4 or IPv6)",
    )
    correlation_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        nullable=False,
        default=uuid.uuid4,
        comment="Cross-service tracing correlation identifier",
    )
    details: Mapped[Optional[dict]] = mapped_column(
        JSON,
        nullable=True,
        comment="Structured context details (state transitions, nonces, etc.)",
    )
    event_timestamp_utc: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )

    def __repr__(self) -> str:
        return f"<AuditEventRecord id={self.audit_event_id} action='{self.action_type}' tenant={self.tenant_id} user={self.user_id}>"
