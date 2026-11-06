"""Integration registry: credential discovery, probe safety, no-secret guarantees."""

import asyncio
import contextlib

import pytest

import pytest


@contextlib.contextmanager
def _temporary_settings(**overrides):
    """Set env overrides, clear the settings cache, restore state after."""
    import os

    from app.core.config import get_settings

    originals = {k: os.environ.get(k) for k in overrides}
    try:
        for key, value in overrides.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        get_settings.cache_clear()
        yield get_settings()
    finally:
        for key, value in originals.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        get_settings.cache_clear()

from app.integrations.registry import _fingerprint, list_integrations
def test_registry_never_exposes_secrets():
    """Serialised inventory must not contain raw credential values - fingerprints only."""
    with _temporary_settings(
        TTI_TELEGRAM_BOT_TOKEN="123456:AAFAKE-SECRET-SHOULD-NEVER-LEAK",
        TTI_TELEGRAM_API_ID="34891529",
        TTI_TELEGRAM_API_HASH="0123456789abcdef0123456789abcdef",
    ):
        rows = asyncio.run(list_integrations(probe=False))
        all_text = str(rows)
        assert "AAFAKE-SECRET-SHOULD-NEVER-LEAK" not in all_text
        assert "0123456789abcdef0123456789abcdef" not in all_text
        assert "34891529" not in all_text  # even api_id is fingerprinted
        assert "sha256=" in all_text  # fingerprints present instead


def test_fingerprint_is_irreversible_and_reports_length():
    fp = _fingerprint("super-secret-token-value")
    assert fp is not None
    assert "super-secret-token-value" not in fp
    assert "len=" in fp
    assert "sha256=" in fp
    assert _fingerprint("") is None
    assert _fingerprint(None) is None


def test_inventory_has_expected_providers():
    with _temporary_settings(TTI_TELEGRAM_API_ID="", TTI_MTPROTO_ENABLED="false"):
        records = asyncio.run(list_integrations(probe=False))
    providers = {r.provider for r in records}
    assert "Telegram MTProto (Telethon)" in providers
    assert "Telegram Bot API (aiogram)" in providers
    assert "PostgreSQL" in providers
    assert "Redis" in providers
    assert "Celery worker mesh" in providers
    assert all("credential_fingerprint" in r.__dict__ for r in records)

    mtproto = next(r for r in records if r.provider == "Telegram MTProto (Telethon)")
    assert mtproto.credential_available is False
    assert mtproto.backend_integration is True


def test_disabled_mtproto_probe_never_connects():
    """With TTI_MTPROTO_ENABLED=false the probe must not attempt a Telegram connection."""
    with _temporary_settings(TTI_MTPROTO_ENABLED="false", TTI_TELEGRAM_SESSION=""):
        from app.integrations.registry import _build_inventory, probe_integration

        record = next(r for r in _build_inventory() if r.provider == "Telegram MTProto (Telethon)")
        probed = asyncio.run(probe_integration(record))
        assert probed.connected is False
        assert probed.authentication_status == "disabled"
        assert probed.last_error is not None