"""Onboarding and informational bot handlers: /start, /help, /privacy."""

from aiogram import Router
from aiogram.filters import CommandStart, Command
from aiogram.types import Message

from app.services.consent_service import get_active_consent_policy

router = Router(name="onboarding_router")


@router.message(CommandStart())
async def handle_start(message: Message) -> None:
    """Provide clear onboarding, summarizing what the bot does and does NOT do."""
    welcome_text = (
        "<b>🛡️ Telegram Threat Intelligence &amp; Behaviour Analytics Platform (TTI)</b>\n\n"
        "Welcome! TTI is a consent-governed system designed to assist security analysts "
        "and individuals in detecting fraud, scam patterns, and cyber extortion.\n\n"
        "<b>Strict Privacy Guarantees:</b>\n"
        "• <b>No Hidden Surveillance:</b> We do not scrape private chats or groups.\n"
        "• <b>Full Consent Control:</b> Nothing is analyzed without your explicit, revocable consent.\n"
        "• <b>Zero Persistence:</b> Messages from unconsented users in groups are dropped immediately.\n\n"
        "<b>Getting Started:</b>\n"
        "/consent - Review and configure your granular analysis permissions\n"
        "/privacy - Read our data protection and retention policies\n"
        "/submit - Submit a suspicious text or scam link for analysis\n"
        "/help - View the complete command directory"
    )
    await message.answer(welcome_text)


@router.message(Command("help"))
async def handle_help(message: Message) -> None:
    """Display comprehensive directory of bot commands."""
    help_text = (
        "<b>📋 TTI Platform Command Catalog</b>\n\n"
        "<b>Consent &amp; Privacy:</b>\n"
        "/consent - View and toggle your granular analysis permissions\n"
        "/privacy - View data handling, legal basis, and retention charter\n"
        "/revoke - Revoke your active permissions at any time\n"
        "/export - Export your personal telemetry and consent history\n"
        "/delete_me - Permanently erase all data and identity records\n\n"
        "<b>Threat Analysis (Consented Only):</b>\n"
        "/submit &lt;text&gt; - Submit a message, link, or scam attempt for screening\n"
        "/analyse - Trigger in-depth threat and scam classification\n"
        "/myactivity - View your own communication and activity baselines\n"
        "/myalerts - View detected threats and security indicators\n\n"
        "<i>Need assistance? Use /privacy to review our non-negotiable security principles.</i>"
    )
    await message.answer(help_text)


@router.message(Command("privacy"))
async def handle_privacy(message: Message) -> None:
    """Display detailed privacy, legal basis, and retention details."""
    policy = get_active_consent_policy()
    privacy_text = (
        f"<b>🔒 TTI Privacy &amp; Data Protection Charter (v{policy['version']})</b>\n\n"
        "<b>1. Purpose of Processing:</b>\n"
        f"{policy['purpose']}\n\n"
        "<b>2. Strict Data Minimization:</b>\n"
        "• Telegram User IDs are never stored in plaintext (encrypted with AES-256 and indexed via HMAC).\n"
        "• Unconsented messages are dropped in memory at ingestion (zero disk/DB rows).\n"
        "• No external AI API calls are made; all processing is local.\n\n"
        "<b>3. Retention &amp; Revocation:</b>\n"
        "• When you invoke /revoke, future analysis stops instantly and past telemetry is deleted under your configured retention mode.\n"
        "• Invoking /delete_me executes irreversible erasure across all tables.\n\n"
        "<b>4. Your Rights:</b>\n"
        "You hold statutory rights to access (/export), rectify/toggle (/consent), revoke (/revoke), and erase (/delete_me)."
    )
    await message.answer(privacy_text)

