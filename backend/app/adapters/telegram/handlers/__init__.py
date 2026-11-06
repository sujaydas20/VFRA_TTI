"""Telegram bot handler router aggregation."""

from aiogram import Router
from app.adapters.telegram.handlers.onboarding import router as onboarding_router
from app.adapters.telegram.handlers.consent_handlers import router as consent_router
from app.adapters.telegram.handlers.submission_handlers import router as submission_router


def get_main_router() -> Router:
    """Return unified router with all command and callback handlers attached."""
    main_router = Router(name="main_tti_router")
    main_router.include_router(onboarding_router)
    main_router.include_router(consent_router)
    main_router.include_router(submission_router)
    return main_router


__all__ = ["get_main_router"]

