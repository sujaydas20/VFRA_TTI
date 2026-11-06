"""Phase 0: Database primitives - extensions, schemas, and security roles

Revision ID: 0002_phase0_schemas_and_roles
Revises: 0001_initial_schema
Create Date: 2026-10-29 12:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "0002_phase0_schemas_and_roles"
down_revision: Union[str, None] = "0001_initial_schema"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. PostgreSQL Extensions
    # Required for UUID generation, cryptographic hashing, and trigram text search
    op.execute('CREATE EXTENSION IF NOT EXISTS "uuid-ossp";')
    op.execute('CREATE EXTENSION IF NOT EXISTS "pgcrypto";')
    op.execute('CREATE EXTENSION IF NOT EXISTS "pg_trgm";')

    # 2. Schema Namespaces (Partitioned Topography per Gate 4B.3A)
    # iam: Identity & Access Management (Tenants, Users, Roles)
    # threat: Shared Global Telemetry (Connectors, Channels, Messages)
    # evidence: Vault Metadata & Tier 1 Raw Evidence
    # app: Tenant Workspaces & Case Data (RLS Protected)
    # audit: Append-Only Compliance & Security Ledger
    op.execute("CREATE SCHEMA IF NOT EXISTS iam;")
    op.execute("CREATE SCHEMA IF NOT EXISTS threat;")
    op.execute("CREATE SCHEMA IF NOT EXISTS evidence;")
    op.execute("CREATE SCHEMA IF NOT EXISTS app;")
    op.execute("CREATE SCHEMA IF NOT EXISTS audit;")

    # 3. Security Roles (Idempotent Definition with Least-Privilege Semantics)
    # tti_admin_role: DDL and schema management role
    # tti_app_role: Application runtime role - explicitly NOSUPERUSER and NOBYPASSRLS
    op.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tti_admin_role') THEN
                BEGIN
                    CREATE ROLE tti_admin_role WITH NOLOGIN;
                EXCEPTION WHEN insufficient_privilege THEN
                    RAISE NOTICE 'Insufficient privilege to create role tti_admin_role; skipping';
                END;
            END IF;

            IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tti_app_role') THEN
                BEGIN
                    CREATE ROLE tti_app_role WITH NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
                EXCEPTION WHEN insufficient_privilege THEN
                    RAISE NOTICE 'Insufficient privilege to create role tti_app_role; skipping';
                END;
            END IF;
        END $$;
        """
    )

    # 4. Schema Permissions
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tti_admin_role') THEN
                GRANT USAGE, CREATE ON SCHEMA iam, threat, evidence, app, audit TO tti_admin_role;
            END IF;
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tti_app_role') THEN
                GRANT USAGE ON SCHEMA iam, threat, evidence, app, audit TO tti_app_role;
            END IF;
        END $$;
        """
    )


def downgrade() -> None:
    # 1. Revoke Schema Permissions
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tti_app_role') THEN
                REVOKE USAGE ON SCHEMA iam, threat, evidence, app, audit FROM tti_app_role;
            END IF;
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tti_admin_role') THEN
                REVOKE USAGE, CREATE ON SCHEMA iam, threat, evidence, app, audit FROM tti_admin_role;
            END IF;
        END $$;
        """
    )

    # 2. Drop Roles Idempotently
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tti_app_role') THEN
                BEGIN
                    DROP ROLE tti_app_role;
                EXCEPTION WHEN others THEN
                    RAISE NOTICE 'Could not drop role tti_app_role; skipping';
                END;
            END IF;
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tti_admin_role') THEN
                BEGIN
                    DROP ROLE tti_admin_role;
                EXCEPTION WHEN others THEN
                    RAISE NOTICE 'Could not drop role tti_admin_role; skipping';
                END;
            END IF;
        END $$;
        """
    )

    # 3. Drop Domain Schemas (Public schema and prototype tables remain untouched)
    for schema_name in ["audit", "app", "evidence", "threat", "iam"]:
        op.execute(
            f"""
            DO $$
            BEGIN
                EXECUTE 'DROP SCHEMA IF EXISTS {schema_name} RESTRICT;';
            EXCEPTION WHEN insufficient_privilege THEN
                RAISE NOTICE 'Insufficient privilege to drop schema {schema_name}; skipping';
            END $$;
            """
        )

    # 4. Drop Phase 0 Extensions (uuid-ossp and pgcrypto retained for prototype compatibility)
    op.execute(
        """
        DO $$
        BEGIN
            DROP EXTENSION IF EXISTS "pg_trgm";
        EXCEPTION WHEN insufficient_privilege THEN
            RAISE NOTICE 'Insufficient privilege to drop extension pg_trgm; leaving installed';
        END $$;
        """
    )
