"""Main FastAPI application entry point for TTI."""

from contextlib import asynccontextmanager
from typing import AsyncGenerator
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from app.api.v1.api import api_router
from app.core.config import get_settings
from app.core.errors import TTIBaseException, http_exception_from_domain
from app.core.logging import setup_logging
from app.observability.metrics import metrics_store

logger = setup_logging()
settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifecycle hooks for startup and graceful shutdown."""
    logger.info("Initializing TTI (Telegram Threat Intelligence) backend...")
    logger.info("Environment: %s", settings.TTI_ENV)
    logger.info("Tenant isolation baseline: active")

    # MTProto background collector (live Telegram collection; disabled by default)
    collector = None
    try:
        from app.services.mtproto_collector import get_mtproto_collector

        collector = get_mtproto_collector()
        await collector.start()
    except Exception as exc:  # noqa: BLE001 - startup must never crash the API
        logger.error("MTProto collector failed to start: %s", type(exc).__name__)

    yield

    if collector is not None:
        try:
            await collector.stop()
        except Exception as exc:  # noqa: BLE001
            logger.error("MTProto collector shutdown error: %s", type(exc).__name__)
    logger.info("Shutting down TTI backend...")


def create_application() -> FastAPI:
    """FastAPI application factory."""
    app = FastAPI(
        title=settings.TTI_PROJECT_NAME,
        version="0.1.0",
        description="Modular threat intelligence platform for Telegram thread analysis and dark-web telemetry.",
        openapi_url=f"{settings.TTI_API_V1_STR}/openapi.json",
        docs_url=f"{settings.TTI_API_V1_STR}/docs",
        redoc_url=f"{settings.TTI_API_V1_STR}/redoc",
        lifespan=lifespan,
    )

    # Hardened CORS configuration with explicit methods and headers
    if settings.TTI_BACKEND_CORS_ORIGINS:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=[str(origin).rstrip("/") for origin in settings.TTI_BACKEND_CORS_ORIGINS],
            allow_credentials=True,
            allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
            allow_headers=["Authorization", "Content-Type", "X-Tenant-ID", "X-Correlation-ID", "Accept"],
        )

    # Telemetry and logging middleware
    @app.middleware("http")
    async def track_metrics_middleware(request: Request, call_next):
        metrics_store.requests_total += 1
        response = await call_next(request)
        return response

    # Global domain exception handler
    @app.exception_handler(TTIBaseException)
    async def domain_exception_handler(request: Request, exc: TTIBaseException):
        http_exc = http_exception_from_domain(exc)
        return JSONResponse(
            status_code=http_exc.status_code,
            content=http_exc.detail,
        )

    @app.exception_handler(ValueError)
    async def value_error_handler(request: Request, exc: ValueError):
        exc_str = str(exc)
        if "4096" in exc_str and "exceeds" in exc_str:
            return JSONResponse(
                status_code=422,
                content={"detail": [{"msg": exc_str, "type": "value_error.max_length"}]},
            )
        return JSONResponse(
            status_code=400,
            content={"detail": exc_str},
        )

    # Mount API routes under /api/v1
    app.include_router(api_router, prefix=settings.TTI_API_V1_STR)

    @app.get("/", tags=["Root"])
    async def root():
        return {
            "project": settings.TTI_PROJECT_NAME,
            "version": "0.1.0",
            "docs": f"{settings.TTI_API_V1_STR}/docs",
            "health": f"{settings.TTI_API_V1_STR}/health",
        }

    return app


app = create_application()
