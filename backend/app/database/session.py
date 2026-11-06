"""Asynchronous database session management."""

from typing import AsyncGenerator
import uuid
from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool
from app.core.config import get_settings

settings = get_settings()

if settings.TTI_ENV.lower() in ("test", "testing"):
    engine = create_async_engine(
        settings.async_database_url,
        echo=settings.TTI_LOG_LEVEL.upper() == "DEBUG",
        poolclass=NullPool,
    )
else:
    engine = create_async_engine(
        settings.async_database_url,
        echo=settings.TTI_LOG_LEVEL.upper() == "DEBUG",
        pool_pre_ping=True,
        pool_size=10,
        max_overflow=20,
    )

async_session_factory = async_sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
    expire_on_commit=False,
    class_=AsyncSession,
)


async def set_transaction_tenant_context(session: AsyncSession, tenant_id: uuid.UUID) -> None:
    """
    Set transaction-local tenant context for PostgreSQL Row-Level Security (RLS) (SEC-AUDIT-06).

    Uses `SET LOCAL` so the parameter automatically expires upon transaction commit or
    rollback, preventing connection-pool context leakage across re-used pooled connections.
    """
    if not isinstance(tenant_id, uuid.UUID):
        tenant_id = uuid.UUID(str(tenant_id))

    await session.execute(
        text("SELECT set_config('app.current_tenant_id', :tenant_id, true);"),
        {"tenant_id": str(tenant_id)},
    )


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Provide a transactional asynchronous database session scope."""
    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()
