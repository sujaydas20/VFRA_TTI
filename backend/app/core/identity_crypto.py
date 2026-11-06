"""Cryptographic primitives for subject identity pseudonymization and encryption at rest.

Guarantees:
- Telegram User IDs are never stored in plaintext in database records.
- Indexed lookups use a keyed HMAC-SHA256 (blind index).
- Reversible values use Fernet (AES-128-CBC + HMAC-SHA256) authenticated encryption.
"""

import hmac
import hashlib
from typing import Optional
from cryptography.fernet import Fernet
from app.core.config import get_settings


def hash_telegram_user_id(telegram_user_id: int | str, pepper: Optional[str] = None) -> str:
    """Compute keyed HMAC-SHA256 blind index hash for a Telegram user ID."""
    settings = get_settings()
    active_pepper = (pepper or settings.TTI_ID_PEPPER).encode("utf-8")
    user_bytes = str(telegram_user_id).strip().encode("utf-8")
    return hmac.new(key=active_pepper, msg=user_bytes, digestmod=hashlib.sha256).hexdigest()


def encrypt_telegram_user_id(telegram_user_id: int | str, key: Optional[bytes] = None) -> str:
    """Encrypt a Telegram user ID using authenticated Fernet encryption."""
    settings = get_settings()
    active_key = key or settings.effective_encryption_key
    fernet = Fernet(active_key)
    encrypted_bytes = fernet.encrypt(str(telegram_user_id).encode("utf-8"))
    return encrypted_bytes.decode("utf-8")


def decrypt_telegram_user_id(encrypted_token: str, key: Optional[bytes] = None) -> int:
    """Decrypt an encrypted Telegram user ID back to its native integer value."""
    settings = get_settings()
    active_key = key or settings.effective_encryption_key
    fernet = Fernet(active_key)
    decrypted_bytes = fernet.decrypt(encrypted_token.encode("utf-8"))
    return int(decrypted_bytes.decode("utf-8"))

