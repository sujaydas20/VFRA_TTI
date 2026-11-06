"""Consent lifecycle handlers: /consent, /revoke, /delete_me, /export."""

import json
from aiogram import F, Router
from aiogram.filters import Command
from aiogram.types import CallbackQuery, InlineKeyboardButton, InlineKeyboardMarkup, Message

from app.database.session import async_session_factory
from app.services.consent_service import (
    ALL_PERMITTED_CATEGORIES,
    ConsentService,
    get_active_consent_policy,
    get_default_permissions,
)

router = Router(name="consent_router")

# Human-readable labels for granular permissions
PERMISSION_LABELS = {
    "message_analysis": "Message Analysis (/submit)",
    "keyword_detection": "Keyword Threat Detection",
    "nlp_analysis": "Multilingual NLP & Entities",
    "activity_analytics": "Activity Baselines",
    "timeline": "Threat Chronology & Timeline",
    "reports": "Forensic Case Reporting",
    "approved_group_context": "Approved Group Monitoring",
}


def build_consent_keyboard(
    permissions: dict[str, bool],
    version: str,
) -> InlineKeyboardMarkup:
    """Build inline keyboard allowing subject to toggle permissions and explicitly confirm."""
    buttons = []
    for cat in ALL_PERMITTED_CATEGORIES:
        is_enabled = permissions.get(cat, False)
        icon = "✅" if is_enabled else "❌"
        label = f"{icon} {PERMISSION_LABELS.get(cat, cat)}"
        buttons.append([
            InlineKeyboardButton(
                text=label,
                callback_data=f"toggle_perm:{cat}",
            )
        ])

    # Confirmation action row
    buttons.append([
        InlineKeyboardButton(
            text=f"💾 Confirm & Save Consent (v{version})",
            callback_data="confirm_consent",
        )
    ])
    return InlineKeyboardMarkup(inline_keyboard=buttons)


@router.message(Command("consent"))
async def handle_consent_menu(message: Message, consent_service: ConsentService) -> None:
    """Display current consent status with interactive toggles."""
    if not message.from_user:
        return

    policy = get_active_consent_policy()
    async with async_session_factory() as session:
        consent = await consent_service.get_active_consent(session, message.from_user.id)
        current_perms = consent.permitted_categories if consent else get_default_permissions()

    kb = build_consent_keyboard(current_perms, policy["version"])
    status_text = (
        f"<b>⚙️ Consent &amp; Privacy Dashboard (Policy v{policy['version']})</b>\n\n"
        f"<b>Purpose:</b> {policy['purpose']}\n\n"
        "All permissions default strictly to <b>OFF</b>.\n"
        "Tap any item to toggle it ON or OFF, then click <b>Confirm &amp; Save</b>.\n\n"
        "<i>Note: You can revoke these permissions at any time with /revoke.</i>"
    )
    await message.answer(status_text, reply_markup=kb)


@router.callback_query(F.data.startswith("toggle_perm:"))
async def handle_toggle_permission(
    callback: CallbackQuery,
    consent_service: ConsentService,
) -> None:
    """Toggle a granular permission and update the message markup in-place."""
    if not callback.from_user or not callback.message or not isinstance(callback.message, Message):
        return

    cat_to_toggle = callback.data.split(":", 1)[1]
    if cat_to_toggle not in ALL_PERMITTED_CATEGORIES:
        await callback.answer("Invalid permission category.", show_alert=True)
        return

    policy = get_active_consent_policy()
    async with async_session_factory() as session:
        consent = await consent_service.get_active_consent(session, callback.from_user.id)
        current_perms = consent.permitted_categories.copy() if consent else get_default_permissions()
        
        # Invert the selected category
        current_perms[cat_to_toggle] = not current_perms.get(cat_to_toggle, False)
        
        # Save updated draft/permission
        await consent_service.grant_permissions(
            session=session,
            telegram_user_id=callback.from_user.id,
            permissions_update=current_perms,
        )
        await session.commit()

    # Refresh keyboard
    kb = build_consent_keyboard(current_perms, policy["version"])
    await callback.message.edit_reply_markup(reply_markup=kb)
    status_msg = "Enabled" if current_perms[cat_to_toggle] else "Disabled"
    await callback.answer(f"{PERMISSION_LABELS.get(cat_to_toggle, cat_to_toggle)}: {status_msg}")


@router.callback_query(F.data == "confirm_consent")
async def handle_confirm_consent(
    callback: CallbackQuery,
    consent_service: ConsentService,
) -> None:
    """Record explicit confirmation timestamp and close the consent dialogue."""
    if not callback.from_user or not callback.message or not isinstance(callback.message, Message):
        return

    policy = get_active_consent_policy()
    async with async_session_factory() as session:
        consent = await consent_service.get_active_consent(session, callback.from_user.id)
        current_perms = consent.permitted_categories if consent else get_default_permissions()
        
        # Explicit confirmation
        record = await consent_service.grant_permissions(
            session=session,
            telegram_user_id=callback.from_user.id,
            permissions_update=current_perms,
        )
        await session.commit()

    active_count = sum(1 for v in current_perms.values() if v)
    ack_text = (
        f"<b>✅ Consent Successfully Confirmed &amp; Stored</b>\n\n"
        f"• <b>Policy Version:</b> v{policy['version']}\n"
        f"• <b>Active Permissions:</b> {active_count} of {len(ALL_PERMITTED_CATEGORIES)}\n"
        f"• <b>Timestamp (UTC):</b> {record.granted_at.isoformat() if record.granted_at else 'N/A'}\n\n"
        "Your consent preferences are now active. You may use /submit or /privacy."
    )
    await callback.message.edit_text(ack_text)
    await callback.answer("Consent successfully confirmed!")


@router.message(Command("revoke"))
async def handle_revoke_menu(message: Message, consent_service: ConsentService) -> None:
    """Prompt user to revoke individual permissions or execute total revocation."""
    if not message.from_user:
        return

    kb = InlineKeyboardMarkup(
        inline_keyboard=[
            [
                InlineKeyboardButton(
                    text="🛑 Revoke ALL Permissions",
                    callback_data="confirm_revoke_all",
                )
            ],
            [
                InlineKeyboardButton(
                    text="⚙️ Adjust Permissions Individually",
                    callback_data="open_consent_menu",
                )
            ],
        ]
    )
    revoke_prompt = (
        "<b>⚠️ Revocation Center</b>\n\n"
        "Revoking consent immediately halts all future analysis. "
        "Any telemetry or unanalyzed submissions linked to revoked permissions "
        "will be handled according to your retention policy (immediate purge by default).\n\n"
        "Choose an action below:"
    )
    await message.answer(revoke_prompt, reply_markup=kb)


@router.callback_query(F.data == "confirm_revoke_all")
async def handle_confirm_revoke_all(
    callback: CallbackQuery,
    consent_service: ConsentService,
) -> None:
    """Execute total revocation across all permissions."""
    if not callback.from_user or not callback.message or not isinstance(callback.message, Message):
        return

    async with async_session_factory() as session:
        await consent_service.revoke_consent(session, callback.from_user.id)
        await session.commit()

    revoked_text = (
        "<b>🛑 All Permissions Revoked</b>\n\n"
        "All analytical permissions have been disabled. "
        "Processing of your messages has stopped immediately, and active submissions have been purged.\n\n"
        "To re-enable features at any time, run /consent."
    )
    await callback.message.edit_text(revoked_text)
    await callback.answer("All permissions revoked.")


@router.callback_query(F.data == "open_consent_menu")
async def handle_open_consent_from_callback(
    callback: CallbackQuery,
    consent_service: ConsentService,
) -> None:
    """Redirect back to interactive /consent menu."""
    if not callback.from_user or not callback.message or not isinstance(callback.message, Message):
        return

    policy = get_active_consent_policy()
    async with async_session_factory() as session:
        consent = await consent_service.get_active_consent(session, callback.from_user.id)
        current_perms = consent.permitted_categories if consent else get_default_permissions()

    kb = build_consent_keyboard(current_perms, policy["version"])
    await callback.message.edit_text(
        f"<b>⚙️ Consent &amp; Privacy Dashboard (Policy v{policy['version']})</b>\n\n"
        "Toggle your permissions below:",
        reply_markup=kb,
    )


@router.message(Command("delete_me"))
async def handle_delete_me_prompt(message: Message) -> None:
    """Two-step irreversible erasure confirmation dialog."""
    kb = InlineKeyboardMarkup(
        inline_keyboard=[
            [
                InlineKeyboardButton(
                    text="🗑️ Yes, Permanently Delete My Data",
                    callback_data="confirm_delete_me",
                )
            ],
            [
                InlineKeyboardButton(
                    text="❌ Cancel",
                    callback_data="cancel_delete_me",
                )
            ],
        ]
    )
    prompt_text = (
        "<b>⚠️ Permanent Subject Erasure Confirmation</b>\n\n"
        "This action is <b>irreversible</b>:\n"
        "• Your pseudonymized subject identity will be erased.\n"
        "• All consent records and personal submissions will be purged from the database.\n"
        "• The system retains only a non-reversible HMAC-SHA256 audit proof that the erasure occurred.\n\n"
        "Are you certain you wish to proceed?"
    )
    await message.answer(prompt_text, reply_markup=kb)


@router.callback_query(F.data == "confirm_delete_me")
async def handle_confirm_delete_me(
    callback: CallbackQuery,
    consent_service: ConsentService,
) -> None:
    """Execute complete subject erasure."""
    if not callback.from_user or not callback.message or not isinstance(callback.message, Message):
        return

    async with async_session_factory() as session:
        result = await consent_service.execute_deletion(session, callback.from_user.id)
        await session.commit()

    counts = result.get("deleted_counts", {})
    ack_text = (
        "<b>🗑️ Data Successfully Erased</b>\n\n"
        "All data linked to your identity has been permanently removed.\n"
        f"• Submissions deleted: {counts.get('submissions', 0)}\n"
        f"• Consent records purged: {counts.get('consent_records', 0)}\n\n"
        "Thank you for using TTI. If you message the bot in the future, you will be onboarded as a brand new subject."
    )
    await callback.message.edit_text(ack_text)
    await callback.answer("Data deleted.")


@router.callback_query(F.data == "cancel_delete_me")
async def handle_cancel_delete_me(callback: CallbackQuery) -> None:
    """Cancel erasure request."""
    if callback.message and isinstance(callback.message, Message):
        await callback.message.edit_text("Erasure request cancelled. Your current settings remain active.")
    await callback.answer("Cancelled.")


@router.message(Command("export"))
async def handle_export_data(message: Message, consent_service: ConsentService) -> None:
    """Export subject data formatted as clean JSON in private chat."""
    if not message.from_user:
        return

    async with async_session_factory() as session:
        export_payload = await consent_service.export_user_data(session, message.from_user.id)

    formatted_json = json.dumps(export_payload, indent=2)
    # Format inside HTML pre tags, truncating if over Telegram 4096 character limit
    if len(formatted_json) > 3800:
        formatted_json = formatted_json[:3800] + "\n... [truncated]"

    export_text = (
        "<b>📦 Personal Telemetry &amp; Consent Export</b>\n\n"
        f"<pre>{formatted_json}</pre>"
    )
    await message.answer(export_text)

