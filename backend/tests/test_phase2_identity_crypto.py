"""Tests for cryptographic identity protection at rest."""

import pytest
from app.core.identity_crypto import (
    hash_telegram_user_id,
    encrypt_telegram_user_id,
    decrypt_telegram_user_id,
)


def test_telegram_user_id_crypto_roundtrip():
    """Encrypted Telegram user ID must cleanly decrypt back to original integer."""
    user_id = 9876543210
    encrypted = encrypt_telegram_user_id(user_id)
    assert isinstance(encrypted, str)
    assert str(user_id) not in encrypted  # Plaintext never appears in ciphertext

    decrypted = decrypt_telegram_user_id(encrypted)
    assert decrypted == user_id


def test_blind_indexing_determinism():
    """Blind index HMAC-SHA256 must be deterministic for identical input and key."""
    user_id = 123456789
    hash1 = hash_telegram_user_id(user_id)
    hash2 = hash_telegram_user_id(user_id)
    assert hash1 == hash2
    assert len(hash1) == 64

    # Different users produce different hashes
    other_hash = hash_telegram_user_id(987654321)
    assert hash1 != other_hash

