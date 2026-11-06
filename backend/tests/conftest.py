"""Pytest fixtures and test harness configuration."""

import os

# Ensure test environment uses test database and test configuration
os.environ["TTI_ENV"] = "test"
os.environ["POSTGRES_DB"] = "tti_test"
os.environ["TTI_RATE_LIMIT_BACKEND"] = "memory"
os.environ["TASK_DISPATCHER"] = "inline"
os.environ["TTI_RATE_LIMIT_LOGIN_IP_LIMIT"] = "10000"
os.environ["TTI_MTPROTO_ENABLED"] = "false"
os.environ["TTI_TELEGRAM_SESSION"] = ""
os.environ["TTI_WEBHOOK_SECRET"] = "tti_dev_secret_token_1234567890_min32chars"

from app.core.config import get_settings
get_settings.cache_clear()

import tempfile
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine, text

from app.adapters.queue.inline_dispatcher import InlineTaskDispatcher
from app.evidence.storage import LocalEvidenceStore
from app.main import app
from alembic.config import Config
from pathlib import Path


@pytest.fixture
def alembic_config() -> Config:
    """Fixture providing configured Alembic Config object."""
    backend_dir = Path(__file__).resolve().parent.parent
    ini_path = backend_dir / "alembic.ini"
    cfg = Config(str(ini_path))
    cfg.set_main_option("script_location", str(backend_dir / "alembic"))
    return cfg


@pytest.fixture(scope="session", autouse=True)
def clean_and_seed_test_database():
    """Ensure baseline test tenants exist and test database is clean."""
    settings = get_settings()
    engine = create_engine(settings.sync_database_url)
    try:
        with engine.begin() as conn:
            conn.execute(
                text("""
                TRUNCATE iam.user_profiles, iam.tenant_organizations, 
                         app.investigative_cases, app.case_message_associations, 
                         app.case_notes, threat.source_messages, threat.source_channels, 
                         app.system_jobs, app.deletion_requests, app.consent_records, 
                         app.telegram_subjects, app.webhook_updates, app.consented_submissions,
                         app.alerts, app.analyst_feedback,
                         audit.audit_event_records CASCADE;

                INSERT INTO iam.tenant_organizations (tenant_id, organization_name, market_profile, account_status)
                VALUES 
                    ('00000000-0000-0000-0000-000000000001', 'Test Default Tenant', 'LAW_ENFORCEMENT', 'ACTIVE'),
                    ('ffffffff-ffff-ffff-ffff-ffffffffffff', 'Test Alternate Tenant', 'LAW_ENFORCEMENT', 'ACTIVE')
                ON CONFLICT (tenant_id) DO UPDATE SET account_status = 'ACTIVE';

                UPDATE threat.keyword_rules SET is_reviewed = false;
                """)
            )
    except Exception as exc:
        print(f"Warning during test database initialization: {exc}")
    finally:
        engine.dispose()


@pytest.fixture(scope="session")
def test_tenant_id() -> str:
    """Standard test tenant UUIDv4."""
    return "00000000-0000-0000-0000-000000000001"


@pytest.fixture(scope="session")
def alternate_tenant_id() -> str:
    """Alternative tenant UUIDv4 to test isolation barriers."""
    return "ffffffff-ffff-ffff-ffff-ffffffffffff"


@pytest_asyncio.fixture
async def async_client() -> AsyncClient:
    """Provide an asynchronous HTTP test client bound to the FastAPI application."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        yield client


@pytest.fixture
def temp_evidence_store(tmp_path) -> LocalEvidenceStore:
    """Provide an isolated temporary evidence storage engine for test execution."""
    return LocalEvidenceStore(base_path=str(tmp_path / "evidence_isolated"))


@pytest.fixture
def inline_dispatcher() -> InlineTaskDispatcher:
    """Provide a clean in-memory task dispatcher for testing."""
    dispatcher = InlineTaskDispatcher()
    yield dispatcher
    dispatcher.clear()
