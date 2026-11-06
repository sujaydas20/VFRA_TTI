"""Initial schema: tenants, collected_threads, raw_artifacts, audit_events

Revision ID: 0001_initial_schema
Revises: 
Create Date: 2026-10-28 12:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "0001_initial_schema"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Tenants table
    op.create_table(
        "tenants",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("slug", sa.String(length=100), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_tenants_slug", "tenants", ["slug"], unique=True)

    # 2. Collected threads table (Enforcing tenant_id)
    op.create_table(
        "collected_threads",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("source_type", sa.String(length=50), nullable=False),
        sa.Column("external_id", sa.String(length=255), nullable=False),
        sa.Column("title", sa.String(length=500), nullable=False),
        sa.Column("sanitization_status", sa.String(length=50), server_default="pending", nullable=False),
        sa.Column("raw_evidence_sha256", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_collected_threads_tenant_id", "collected_threads", ["tenant_id"])
    op.create_index("ix_collected_threads_source_type", "collected_threads", ["source_type"])
    op.create_index("ix_collected_threads_external_id", "collected_threads", ["external_id"])

    # 3. Raw artifacts table (Isolated evidence references)
    op.create_table(
        "raw_artifacts",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("thread_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("source_type", sa.String(length=50), nullable=False),
        sa.Column("content_sha256", sa.String(length=64), nullable=False),
        sa.Column("storage_relative_path", sa.Text(), nullable=False),
        sa.Column("byte_size", sa.Integer(), nullable=False),
        sa.Column("mime_type", sa.String(length=100), server_default="application/json", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["thread_id"], ["collected_threads.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_raw_artifacts_tenant_id", "raw_artifacts", ["tenant_id"])
    op.create_index("ix_raw_artifacts_thread_id", "raw_artifacts", ["thread_id"])
    op.create_index("ix_raw_artifacts_content_sha256", "raw_artifacts", ["content_sha256"])

    # 4. Audit events table
    op.create_table(
        "audit_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("actor_id", sa.String(length=255), nullable=True),
        sa.Column("action", sa.String(length=100), nullable=False),
        sa.Column("resource_type", sa.String(length=100), nullable=False),
        sa.Column("resource_id", sa.String(length=255), nullable=True),
        sa.Column("client_ip", sa.String(length=45), nullable=True),
        sa.Column("event_metadata", postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_audit_events_tenant_id", "audit_events", ["tenant_id"])
    op.create_index("ix_audit_events_action", "audit_events", ["action"])
    op.create_index("ix_audit_events_resource_type", "audit_events", ["resource_type"])


def downgrade() -> None:
    op.drop_table("audit_events")
    op.drop_table("raw_artifacts")
    op.drop_table("collected_threads")
    op.drop_table("tenants")
