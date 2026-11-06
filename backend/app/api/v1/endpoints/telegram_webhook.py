"""FastAPI webhook endpoint for Telegram Bot API updates.

Guarantees:
- Constant-time validation of X-Telegram-Bot-Api-Secret-Token (403 on mismatch).
- Strict update_id deduplication via app.webhook_updates (ON CONFLICT DO NOTHING).
- Allowed update types restriction: message, callback_query, my_chat_member.
- Zero raw content or bot tokens in structured logs.
"""

import hashlib
import json
import logging
import secrets
from typing import Any, Dict

from aiogram import Bot, Dispatcher
from aiogram.types import Update
from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response, status
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.telegram.bot import create_bot, create_dispatcher
from app.api import deps
from app.core.config import Settings, get_settings
from app.database.session import get_db

logger = logging.getLogger("tti.telegram.webhook")

router = APIRouter()

ALLOWED_UPDATE_TYPES = {"message", "callback_query", "my_chat_member"}

# Singleton Bot and Dispatcher instances for FastAPI runtime
_bot_instance: Bot | None = None
_dispatcher_instance: Dispatcher | None = None


def get_telegram_bot() -> Bot:
    """Return shared Bot instance, creating a fresh instance in test environments to avoid event-loop closure."""
    global _bot_instance
    if _bot_instance is None or get_settings().TTI_ENV in ("test", "testing"):
        _bot_instance = create_bot()
    return _bot_instance


def get_telegram_dispatcher() -> Dispatcher:
    """Return shared Dispatcher instance."""
    global _dispatcher_instance
    if _dispatcher_instance is None:
        _dispatcher_instance = create_dispatcher()
    return _dispatcher_instance


@router.post("/webhook", status_code=status.HTTP_200_OK)
async def handle_telegram_webhook(
    request: Request,
    x_telegram_bot_api_secret_token: str | None = Header(None, alias="X-Telegram-Bot-Api-Secret-Token"),
    db: AsyncSession = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> Dict[str, Any]:
    """Ingest, verify, deduplicate, and process Telegram webhook updates."""
    # 1. Constant-time secret token verification
    if not x_telegram_bot_api_secret_token or not secrets.compare_digest(
        x_telegram_bot_api_secret_token, settings.TTI_WEBHOOK_SECRET
    ):
        logger.warning("Rejected webhook request with invalid or missing secret token")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "Forbidden", "message": "Invalid or missing webhook secret token"},
        )

    # 2. Parse request payload
    try:
        payload_bytes = await request.body()
        payload_json = json.loads(payload_bytes.decode("utf-8"))
        update_obj = Update.model_validate(payload_json)
    except Exception as exc:
        logger.warning("Failed to parse incoming webhook payload as aiogram Update", exc_info=False)
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "UnprocessableEntity", "message": "Malformed update payload"},
        )

    # 3. Restrict allowed update types
    update_type = update_obj.event_type
    if update_type not in ALLOWED_UPDATE_TYPES:
        logger.info(f"Ignored update type outside allowed set: {update_type}")
        return {"status": "ignored", "reason": f"update_type_{update_type}_not_in_allowed_set"}

    # 4. Atomic deduplication by update_id in app.webhook_updates
    payload_hash = hashlib.sha256(payload_bytes).hexdigest()
    dedupe_query = text(
        """
        INSERT INTO app.webhook_updates (update_id, update_type, payload_hash, status)
        VALUES (:update_id, :update_type, :payload_hash, 'received')
        ON CONFLICT (update_id) DO NOTHING
        RETURNING update_id;
        """
    )
    result = await db.execute(
        dedupe_query,
        {
            "update_id": update_obj.update_id,
            "update_type": update_type,
            "payload_hash": payload_hash,
        },
    )
    inserted_row = result.scalar_one_or_none()
    await db.commit()

    if not inserted_row:
        # Duplicate update_id: return 200 OK immediately and ignore
        logger.info(f"Duplicate update_id {update_obj.update_id} received and discarded")
        return {"status": "ok", "message": "duplicate_update_ignored", "update_id": update_obj.update_id}

    # 5. Dispatch update through aiogram pipeline
    bot = get_telegram_bot()
    dispatcher = get_telegram_dispatcher()

    try:
        await dispatcher.feed_update(bot=bot, update=update_obj)
        # Mark update as processed
        mark_query = text(
            "UPDATE app.webhook_updates SET status = 'processed', processed_at = CURRENT_TIMESTAMP WHERE update_id = :update_id"
        )
        await db.execute(mark_query, {"update_id": update_obj.update_id})
        await db.commit()
    except Exception as exc:
        logger.error(f"Error processing update_id {update_obj.update_id}: {exc}", exc_info=True)
        mark_err = text(
            "UPDATE app.webhook_updates SET status = 'failed' WHERE update_id = :update_id"
        )
        await db.execute(mark_err, {"update_id": update_obj.update_id})
        await db.commit()
        # Still return 200 to Telegram so it does not endlessly redeliver a failing update
        return {"status": "error_handled", "update_id": update_obj.update_id}

    return {"status": "ok", "update_id": update_obj.update_id}
