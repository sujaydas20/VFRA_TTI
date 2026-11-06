"""Polling runner for local development and offline environments on Windows.

Guarantees:
- Runs without requiring a public HTTPS tunnel or domain.
- Reuses the identical Dispatcher, outer middlewares, and handlers as webhook mode.
- Explicitly drops pending updates and sets allowed_updates filter.
- Safe shutdown on SIGINT / KeyboardInterrupt.
"""

import asyncio
import logging
import sys

from app.adapters.telegram.bot import create_bot, create_dispatcher
from app.core.config import get_settings

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("tti.telegram.polling")


async def run_polling() -> None:
    """Initialize bot and start long polling with the unified dispatcher."""
    settings = get_settings()
    logger.info("Starting TTI Telegram Bot in POLLING mode...")

    if not settings.TTI_TELEGRAM_BOT_TOKEN:
        logger.warning(
            "TTI_TELEGRAM_BOT_TOKEN is not set in environment or .env! "
            "Please configure your bot token from @BotFather."
        )
        return

    bot = create_bot()
    dp = create_dispatcher()

    try:
        # Delete any active webhook before switching to polling
        logger.info("Ensuring active webhook is cleared before polling...")
        await bot.delete_webhook(drop_pending_updates=False)

        bot_info = await bot.get_me()
        logger.info(f"Bot connected successfully as @{bot_info.username} (ID: {bot_info.id})")

        logger.info("Listening for updates (message, callback_query, my_chat_member)...")
        await dp.start_polling(
            bot,
            allowed_updates=["message", "callback_query", "my_chat_member"],
        )
    except asyncio.CancelledError:
        logger.info("Polling runner received cancellation request.")
    finally:
        await bot.session.close()
        logger.info("Bot session closed cleanly.")


def main() -> None:
    """Entry point for python -m app.adapters.telegram.polling."""
    try:
        asyncio.run(run_polling())
    except (KeyboardInterrupt, SystemExit):
        logger.info("Polling process stopped.")


if __name__ == "__main__":
    main()

