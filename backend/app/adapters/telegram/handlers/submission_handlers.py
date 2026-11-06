from pathlib import Path
"""Submission and analytical feature handlers: /submit, /analyse, /myactivity, /myalerts."""

import hashlib
from aiogram import Router
from aiogram.filters import Command
from aiogram.types import Message

from app.database.models.consent import ConsentedSubmissionRecord
from app.database.session import async_session_factory
from app.ingestion.sanitizer import InputSanitizer
from app.services.consent_service import ConsentService

router = Router(name="submission_router")


@router.message(Command("submit"))
async def handle_submit_message(message: Message, consent_service: ConsentService) -> None:
    """Accept pasted or forwarded text for screening, gated strictly on message_analysis consent."""
    if not message.from_user:
        return

    chat_type = message.chat.type if message.chat else "private"
    async with async_session_factory() as session:
        has_consent = await consent_service.check_permission(
            session=session,
            telegram_user_id=message.from_user.id,
            permission="message_analysis",
            chat_type=chat_type,
        )

        if not has_consent:
            await message.answer(
                "<b>⛔ Consent Required</b>\n\n"
                "To submit messages for fraud and threat screening, you must first enable "
                "the <b>Message Analysis</b> permission.\n\n"
                "Please run /consent to configure your permissions."
            )
            return

        # Extract text: either following command `/submit <text>` or forwarded content
        raw_text = ""
        if message.text:
            parts = message.text.split(maxsplit=1)
            if len(parts) > 1:
                raw_text = parts[1].strip()
        elif message.caption:
            raw_text = message.caption.strip()

        if not raw_text:
            await message.answer(
                "<b>ℹ️ How to Submit</b>\n\n"
                "Provide text after the command or reply to a message:\n"
                "<code>/submit Suspicious payment link: hxxps://scam-domain[.]xyz/pay</code>"
            )
            return

        if len(raw_text) > 4096:
            await message.answer(
                "⚠️ Message exceeds the maximum allowed length of 4096 characters. Please submit a shorter excerpt."
            )
            return

        # Sanitize input untrusted text
        sanitized_text, applied_actions = InputSanitizer.sanitize_text(raw_text)
        content_hash = hashlib.sha256(sanitized_text.encode("utf-8")).hexdigest()

        # Subject record lookup
        subject = await consent_service.get_or_create_subject(session, message.from_user.id)

        # Persist to consented submissions
        submission = ConsentedSubmissionRecord(
            tenant_id=subject.tenant_id,
            subject_id=subject.id,
            submission_hash=content_hash,
            sanitized_text=sanitized_text,
            detected_language="en",  # Default baseline; updated by NLP engine in Phase 5
        )
        session.add(submission)
        await session.commit()

    ack_text = (
        "<b>📥 Submission Acknowledged &amp; Stored</b>\n\n"
        f"• <b>Reference Hash:</b> <code>{content_hash[:16]}...</code>\n"
        f"• <b>Sanitizations Applied:</b> {len(applied_actions)}\n"
        "• <b>Retention:</b> Linked to your active consent profile.\n\n"
        "Your submission has been securely ingested into the screening queue."
    )
    await message.answer(ack_text)


@router.message(Command("analyse"))
async def handle_analyse(message: Message, consent_service: ConsentService) -> None:
    """Analyze submitted text against deterministic threat detection rules."""
    if not message.from_user:
        return

    chat_type = message.chat.type if message.chat else "private"
    async with async_session_factory() as session:
        has_consent = await consent_service.check_permission(
            session=session,
            telegram_user_id=message.from_user.id,
            permission="message_analysis",
            chat_type=chat_type,
        )

        if not has_consent:
            await message.answer(
                "<b>⛔ Consent Required</b>\n\n"
                "Deep threat analysis requires active <b>Message Analysis</b> consent.\n"
                "Run /consent to grant this permission."
            )
            return

        raw_text = ""
        if message.text:
            parts = message.text.split(maxsplit=1)
            if len(parts) > 1:
                raw_text = parts[1].strip()
        if not raw_text and message.reply_to_message:
            raw_text = message.reply_to_message.text or message.reply_to_message.caption or ""

        if not raw_text:
            await message.answer(
                "<b>🔬 How to Analyse a Message</b>\n\n"
                "Provide text after the command or reply to a message:\n"
                "<code>/analyse Sir aapka KYC expire ho gaya, click to update</code>"
            )
            return

        if len(raw_text) > 4096:
            await message.answer(
                "⚠️ Message exceeds the maximum allowed length of 4096 characters. Please analyze a shorter excerpt."
            )
            return

        import os
        from app.services.detection_service import ThreatDetectionService
        detection_service = ThreatDetectionService()
        engine = await detection_service.get_active_engine(session=session)

        # Fail-closed guard: when no reviewed rules are loaded, or engine is degraded
        is_prod = os.getenv("TTI_ENV", "development").lower() == "production"
        if engine.rules_loaded == 0 or (is_prod and engine.reviewed_rules_loaded == 0) or engine.is_degraded:
            await message.answer(
                "⚠️ Threat analysis is currently unavailable (rules engine offline or no reviewed rules loaded)."
            )
            return

        subject = await consent_service.get_or_create_subject(session, message.from_user.id)

        results = engine.analyze_message(
            raw_text=raw_text,
            tenant_id=subject.tenant_id,
            message_id=str(message.message_id),
            subject_id=subject.id,
        )

    if not results:
        await message.answer(
            "<b>✅ No Obvious Threat Detected</b>\n\n"
            "Our rules engine found no matching scam indicators in the submitted text.\n\n"
            "<b>Important:</b> Absence of indicators does not mean this message is safe. Always exercise caution and never share OTPs, PINs, or credentials."
        )
        return

    lines = ["<b>🚨 Threat Detection Analysis</b>\n"]
    for res in results:
        lines.append(f"• <b>Category:</b> {res.category.replace('_', ' ').title()}")
        lines.append(f"• <b>Severity:</b> <code>{res.severity}</code>")
        lines.append(f"• <b>Rule Confidence:</b> {res.rule_confidence:.2f} <i>(uncalibrated)</i>")
        lines.append(f"• <b>Findings:</b> {res.explanation}\n")

    advisory_path = Path("backend/templates/safety_advisory.txt")
    if not advisory_path.exists():
        advisory_path = Path("templates/safety_advisory.txt")
    if advisory_path.exists():
        advisory_text = advisory_path.read_text(encoding="utf-8").strip()
    else:
        advisory_text = (
            "• Never share OTP, UPI PIN, or bank passwords with anyone.\n"
            "• Banks and official agencies will never ask for credentials via message.\n"
            "• <b>National Cyber Crime Helpline:</b> Call <b>1930</b>\n"
            "• <b>Official Reporting Portal:</b> https://cybercrime.gov.in"
        )
    lines.append("<b>🛡️ Safety Advisory &amp; Support:</b>\n" + advisory_text)

    await message.answer("\n".join(lines))


@router.message(Command("myactivity"))
async def handle_myactivity(message: Message, consent_service: ConsentService) -> None:
    """Gated on activity_analytics; reports honest status without fake output."""
    if not message.from_user:
        return

    chat_type = message.chat.type if message.chat else "private"
    async with async_session_factory() as session:
        has_consent = await consent_service.check_permission(
            session=session,
            telegram_user_id=message.from_user.id,
            permission="activity_analytics",
            chat_type=chat_type,
        )

    if not has_consent:
        await message.answer(
            "<b>⛔ Consent Required</b>\n\n"
            "Viewing personal activity baselines requires active <b>Activity Baselines</b> consent.\n"
            "Run /consent to configure your permissions."
        )
        return

    await message.answer(
        "<b>📊 Behaviour Analytics Baseline (Phase 2 Status)</b>\n\n"
        "Your consent is verified! The statistical anomaly calculation and communication "
        "baseline engine arrives in <b>Phase 6 (Behaviour Analytics)</b>.\n\n"
        "We never calculate activity baselines without this active permission."
    )


@router.message(Command("myalerts"))
async def handle_myalerts(message: Message, consent_service: ConsentService) -> None:
    """Gated on reports/alerts; reports honest status without fake output."""
    if not message.from_user:
        return

    chat_type = message.chat.type if message.chat else "private"
    async with async_session_factory() as session:
        has_consent = await consent_service.check_permission(
            session=session,
            telegram_user_id=message.from_user.id,
            permission="reports",
            chat_type=chat_type,
        )

    if not has_consent:
        await message.answer(
            "<b>⛔ Consent Required</b>\n\n"
            "Viewing security alerts requires active <b>Forensic Case Reporting</b> consent.\n"
            "Run /consent to enable it."
        )
        return

    await message.answer(
        "<b>🔔 Security Alerts Workbench (Phase 4 Live)</b>\n\n"
        "Analyst alert triage and priority dispatch are now live in the "
        "<b>TTI Console (Alerts section)</b>.\n\n"
        "Subject-facing alert delivery to this chat arrives in a later phase."
    )
