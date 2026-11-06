"""Security baseline, tenant context primitives, and cryptographic token management.

Provides:
- Argon2id password hashing and constant-time verification (ADR-007).
- Signed, short-lived JWT token generation and validation with environment-managed keys.
- Backward-compatible TenantContext header extraction for unauthenticated endpoints.
"""

from datetime import datetime, timedelta, timezone
import secrets
from typing import Any, Dict, Optional
from uuid import UUID
import argon2
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from fastapi import Header, HTTPException, status
import jwt

from app.core.config import get_settings

# Initialized with Argon2id type
_hasher = PasswordHasher(
    time_cost=2,
    memory_cost=65536,
    parallelism=1,
    hash_len=32,
    type=argon2.Type.ID,
)


def hash_password(password: str) -> str:
    """Hash password using Argon2id with recommended memory and time hardness."""
    if not password:
        raise ValueError("Password cannot be empty.")
    return _hasher.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password against Argon2id hash with constant-time comparison."""
    if not plain_password or not hashed_password:
        return False
    try:
        return _hasher.verify(hashed_password, plain_password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def create_access_token(
    subject: str,
    active_tenant_id: str,
    session_id: str,
    expires_delta: Optional[timedelta] = None,
    extra_claims: Optional[Dict[str, Any]] = None,
) -> str:
    """
    Issue a signed, short-lived JWT access token using TTI_SECRET_KEY.

    Claims:
    - sub: user_id (string UUID)
    - tid: active_tenant_id (string UUID)
    - sid: session_id (string UUID)
    - exp: expiration timestamp (UTC)
    - iat: issued-at timestamp (UTC)
    """
    settings = get_settings()
    now = datetime.now(timezone.utc)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=settings.TTI_ACCESS_TOKEN_EXPIRE_MINUTES)

    payload: Dict[str, Any] = {
        "sub": str(subject),
        "tid": str(active_tenant_id),
        "sid": str(session_id),
        "jti": secrets.token_hex(16),
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
        "iss": "tti-backend",
    }
    if extra_claims:
        payload.update(extra_claims)

    token = jwt.encode(payload, settings.TTI_SECRET_KEY, algorithm=settings.TTI_TOKEN_ALGORITHM)
    return token


def decode_access_token(token: str) -> Dict[str, Any]:
    """
    Decode and cryptographically verify a JWT access token.

    Raises HTTPException 401 on expired, invalid signature, or malformed tokens.
    """
    settings = get_settings()
    try:
        payload = jwt.decode(
            token,
            settings.TTI_SECRET_KEY,
            algorithms=[settings.TTI_TOKEN_ALGORITHM],
            issuer="tti-backend",
            options={"require": ["sub", "tid", "sid", "exp", "iat"]},
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="TOKEN_EXPIRED: Authentication token has expired.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="TOKEN_INVALID: Invalid authentication token.",
            headers={"WWW-Authenticate": "Bearer"},
        )


class TenantContext:
    """Represents the validated tenant identity associated with the current execution context."""

    def __init__(self, tenant_id: str, is_authenticated: bool = False):
        self.tenant_id = tenant_id
        self.is_authenticated = is_authenticated

    def __repr__(self) -> str:
        return f"<TenantContext tenant_id={self.tenant_id} is_authenticated={self.is_authenticated}>"


def get_current_tenant_context(
    x_tenant_id: Optional[str] = Header(None, alias="X-Tenant-ID"),
) -> TenantContext:
    """
    Extract and validate tenant context from request headers (prototype / unauthenticated endpoints).

    For protected routes, use `get_tenant_security_context` from `app.api.deps`.
    """
    settings = get_settings()
    target_tenant = x_tenant_id or settings.TTI_DEFAULT_TENANT_ID

    try:
        uuid_obj = UUID(target_tenant)
        normalized_tenant_id = str(uuid_obj)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid X-Tenant-ID header format. Must be a valid UUIDv4.",
        )

    return TenantContext(
        tenant_id=normalized_tenant_id,
        is_authenticated=False,
    )
