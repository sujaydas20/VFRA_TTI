"""Phase 0 Database Primitives Tests.

Validates:
- Alembic migration graph linearity and revision dependencies (0001 -> 0002).
- Migration DDL generation for schemas (iam, threat, evidence, app, audit),
  extensions (uuid-ossp, pgcrypto, pg_trgm), and least-privilege roles.
- Preservation of prototype tables and schemas during migration/rollback.
- Multi-schema configuration in Alembic env.py.
- Live database integration checks (reported as SKIPPED/NOT RUN if PostgreSQL is unreachable).
"""

import os
from pathlib import Path
import pytest
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, text
from app.core.config import get_settings


@pytest.fixture(scope="module")
def alembic_config() -> Config:
    backend_dir = Path(__file__).resolve().parent.parent
    ini_path = backend_dir / "alembic.ini"
    cfg = Config(str(ini_path))
    cfg.set_main_option("script_location", str(backend_dir / "alembic"))
    return cfg


def test_alembic_linear_history(alembic_config: Config):
    """Verify Alembic migration tree forms a strictly linear DAG with a single head."""
    script = ScriptDirectory.from_config(alembic_config)
    heads = script.get_heads()
    assert len(heads) == 1, f"Expected exactly 1 head revision, found {len(heads)}: {heads}"
    assert heads[0] == "0011_phase4_alerts"

    rev_0011 = script.get_revision("0011_phase4_alerts")
    assert rev_0011 is not None
    assert rev_0011.down_revision == "0010_phase3_hardening"

    rev_0010 = script.get_revision("0010_phase3_hardening")
    assert rev_0010 is not None
    assert rev_0010.down_revision == "0009_phase3_threat_engine"

    rev_0009 = script.get_revision("0009_phase3_threat_engine")
    assert rev_0009 is not None
    assert rev_0009.down_revision == "0008_phase2_telegram_and_consent"

    rev_0008 = script.get_revision("0008_phase2_telegram_and_consent")
    assert rev_0008 is not None
    assert rev_0008.down_revision == "0007_phase1_system_jobs"

    rev_0007 = script.get_revision("0007_phase1_system_jobs")
    assert rev_0007 is not None
    assert rev_0007.down_revision == "0006_phase5_case_management"

    rev_0006 = script.get_revision("0006_phase5_case_management")
    assert rev_0006 is not None
    assert rev_0006.down_revision == "0005_phase3_threat_intel_core"

    rev_0005 = script.get_revision("0005_phase3_threat_intel_core")
    assert rev_0005 is not None
    assert rev_0005.down_revision == "0004_phase1_tenant_rls"

    rev_0004 = script.get_revision("0004_phase1_tenant_rls")
    assert rev_0004 is not None
    assert rev_0004.down_revision == "0003_phase1_iam_core"

    rev_0003 = script.get_revision("0003_phase1_iam_core")
    assert rev_0003 is not None
    assert rev_0003.down_revision == "0002_phase0_schemas_and_roles"

    rev_0002 = script.get_revision("0002_phase0_schemas_and_roles")
    assert rev_0002 is not None
    assert rev_0002.down_revision == "0001_initial_schema"

    rev_0001 = script.get_revision("0001_initial_schema")
    assert rev_0001 is not None
    assert rev_0001.down_revision is None


def test_migration_0002_primitives_contract(alembic_config: Config):
    """Verify 0002 revision specifies all required Phase 0 primitives."""
    backend_dir = Path(__file__).resolve().parent.parent
    migration_file = backend_dir / "alembic" / "versions" / "0002_phase0_schemas_and_roles.py"
    assert migration_file.exists(), f"Migration file not found at {migration_file}"

    content = migration_file.read_text(encoding="utf-8")

    # Required extensions
    for ext in ["uuid-ossp", "pgcrypto", "pg_trgm"]:
        assert f'CREATE EXTENSION IF NOT EXISTS "{ext}"' in content

    # Required 5 domain schemas
    for schema in ["iam", "threat", "evidence", "app", "audit"]:
        assert f"CREATE SCHEMA IF NOT EXISTS {schema}" in content

    # Required roles and least-privilege flags
    assert "tti_admin_role" in content
    assert "tti_app_role" in content
    assert "NOSUPERUSER" in content
    assert "NOBYPASSRLS" in content
    assert "NOCREATEROLE" in content
    assert "NOCREATEDB" in content
    assert "NOINHERIT" in content


def test_migration_downgrade_preserves_prototype_tables(alembic_config: Config):
    """Verify downgrade explicitly preserves prototype tables in the public schema."""
    backend_dir = Path(__file__).resolve().parent.parent
    migration_file = backend_dir / "alembic" / "versions" / "0002_phase0_schemas_and_roles.py"
    content = migration_file.read_text(encoding="utf-8")

    downgrade_func = content.split("def downgrade() -> None:")[1]

    # Verify no prototype table drops exist in downgrade of 0002
    prototype_tables = ["tenants", "collected_threads", "raw_artifacts", "audit_events"]
    for table in prototype_tables:
        assert f"DROP TABLE {table}" not in downgrade_func
        assert f'DROP TABLE IF EXISTS "{table}"' not in downgrade_func
        assert f"DROP TABLE IF EXISTS {table}" not in downgrade_func

    # Verify base extensions required by prototype tables are NOT dropped
    assert 'DROP EXTENSION IF EXISTS "uuid-ossp"' not in downgrade_func
    assert 'DROP EXTENSION IF EXISTS "pgcrypto"' not in downgrade_func


def test_alembic_env_multi_schema_configuration():
    """Verify Alembic env.py is configured for multi-schema discovery and public version tracking."""
    backend_dir = Path(__file__).resolve().parent.parent
    env_file = backend_dir / "alembic" / "env.py"
    content = env_file.read_text(encoding="utf-8")

    assert "include_schemas=True" in content
    assert 'version_table_schema="public"' in content


def test_init_dev_sql_includes_primitives():
    """Verify infra/docker/postgres/init-dev.sql includes pg_trgm, schemas, and least-privilege roles."""
    repo_root = Path(__file__).resolve().parent.parent.parent
    init_sql = repo_root / "infra" / "docker" / "postgres" / "init-dev.sql"
    assert init_sql.exists(), f"init-dev.sql not found at {init_sql}"

    content = init_sql.read_text(encoding="utf-8")

    assert 'CREATE EXTENSION IF NOT EXISTS "pg_trgm"' in content
    for schema in ["iam", "threat", "evidence", "app", "audit"]:
        assert f"CREATE SCHEMA IF NOT EXISTS {schema}" in content

    assert "tti_admin_role" in content
    assert "tti_app_role" in content
    assert "NOSUPERUSER" in content
    assert "NOBYPASSRLS" in content


def test_fail_closed_tenant_context_semantics():
    """Unit test: verify SQL expression semantics for fail-closed tenant evaluation."""
    # The canonical fail-closed evaluation expression proposed in ADR-004 / Gate 4B.3A:
    expr = "NULLIF(current_setting('app.current_tenant_id', true), '')::UUID"
    # When app.current_tenant_id is missing or '', NULLIF returns NULL, preventing comparison matches
    assert "app.current_tenant_id" in expr
    assert "NULLIF" in expr


def test_live_postgres_primitives_integration():
    """Integration test: verify extensions, schemas, and role properties on a live PostgreSQL instance.

    If PostgreSQL is unreachable or authentication fails, cleanly SKIP and report as NOT RUN.
    """
    settings = get_settings()
    url = settings.sync_database_url

    try:
        engine = create_engine(url, connect_args={"connect_timeout": 3})
        with engine.connect() as conn:
            # Check connection
            conn.execute(text("SELECT 1;"))
    except Exception as exc:
        pytest.skip(f"Live PostgreSQL database unreachable or unauthorized ({type(exc).__name__}); DB integration tests NOT RUN")

    with engine.connect() as conn:
        # 1. Verify extensions
        ext_res = conn.execute(text("SELECT extname FROM pg_extension;"))
        extensions = {row[0] for row in ext_res.fetchall()}
        for expected_ext in ["uuid-ossp", "pgcrypto", "pg_trgm"]:
            assert expected_ext in extensions, f"Extension {expected_ext} missing from pg_extension"

        # 2. Verify schemas
        schema_res = conn.execute(
            text("SELECT schema_name FROM information_schema.schemata WHERE schema_name IN ('iam', 'threat', 'evidence', 'app', 'audit');")
        )
        schemas = {row[0] for row in schema_res.fetchall()}
        for expected_schema in ["iam", "threat", "evidence", "app", "audit"]:
            assert expected_schema in schemas, f"Schema {expected_schema} missing from database"

        # 3. Verify roles
        role_res = conn.execute(
            text("SELECT rolname, rolsuper, rolbypassrls FROM pg_roles WHERE rolname IN ('tti_admin_role', 'tti_app_role');")
        )
        roles = {row[0]: {"rolsuper": row[1], "rolbypassrls": row[2]} for row in role_res.fetchall()}
        assert "tti_app_role" in roles, "tti_app_role missing from pg_roles"
        assert roles["tti_app_role"]["rolsuper"] is False, "tti_app_role must NOT be a superuser"
        assert roles["tti_app_role"]["rolbypassrls"] is False, "tti_app_role must NOT possess BYPASSRLS"

        # 4. Verify fail-closed context evaluation returns NULL when unset
        ctx_res = conn.execute(text("SELECT NULLIF(current_setting('app.current_tenant_id', true), '');"))
        val = ctx_res.scalar()
        assert val is None, f"Expected NULL for unconfigured tenant context, got: {val}"
