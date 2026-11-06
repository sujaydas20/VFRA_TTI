"""Phase 1: System Jobs and Dead-Letter Queue Architecture

Revision ID: 0007_phase1_system_jobs
Revises: 0006_phase5_case_management
Create Date: 2026-10-31

Canonical Reference:
- Physical Schema Design: Background Worker Mesh & Dead-Letter Auditing
- Requirements: Zero-Content Invariant on Worker Failures
- Security: Tenant RLS on app.system_jobs
"""

from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "0007_phase1_system_jobs"
down_revision: Union[str, None] = "0006_phase5_case_management"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Create app.system_jobs
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS app.system_jobs (
            job_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id UUID REFERENCES iam.tenant_organizations(tenant_id) ON DELETE CASCADE,
            task_name VARCHAR(128) NOT NULL,
            queue_name VARCHAR(64) NOT NULL,
            args_hash VARCHAR(64) NOT NULL,
            error_class VARCHAR(128) NOT NULL,
            sanitized_error_message TEXT NOT NULL,
            attempt_count INT NOT NULL DEFAULT 1,
            status VARCHAR(32) NOT NULL DEFAULT 'FAILED',
            created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            failed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        """
    )

    # 2. Indexes
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_system_jobs_tenant ON app.system_jobs(tenant_id);
        """
    )
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_system_jobs_task_name ON app.system_jobs(task_name);
        """
    )
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_system_jobs_queue_name ON app.system_jobs(queue_name);
        """
    )
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_system_jobs_status ON app.system_jobs(status);
        """
    )
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_system_jobs_args_hash ON app.system_jobs(args_hash);
        """
    )

    # 3. Row-Level Security
    op.execute(
        """
        ALTER TABLE app.system_jobs ENABLE ROW LEVEL SECURITY;
        """
    )
    op.execute(
        """
        CREATE POLICY rls_system_jobs_tenant_isolation ON app.system_jobs
            FOR ALL
            USING (
                tenant_id IS NULL OR 
                tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
            );
        """
    )

    # 4. Grant access to tti_app_role
    op.execute(
        """
        GRANT SELECT, INSERT, UPDATE, DELETE ON app.system_jobs TO tti_app_role;
        """
    )


def downgrade() -> None:
    op.execute(
        """
        DROP TABLE IF EXISTS app.system_jobs CASCADE;
        """
    )
