"""Custom exception hierarchy and domain errors for TTI."""

from typing import Any, Dict, Optional
from fastapi import HTTPException, status


class TTIBaseException(Exception):
    """Base exception for all domain-specific TTI errors."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}


class TenantAccessError(TTIBaseException):
    """Raised when tenant context is invalid, missing, or unauthorized."""
    pass


class ConnectorNotConfiguredError(TTIBaseException):
    """Raised when an operation is requested on an inactive or unconfigured connector."""
    pass


class InputSanitizationError(TTIBaseException):
    """Raised when untrusted input fails security screening."""
    pass


class EvidenceIntegrityError(TTIBaseException):
    """Raised when cryptographic evidence hash check fails."""
    pass


class DatabaseConnectionError(TTIBaseException):
    """Raised when database connectivity fails."""
    pass


class ConsentRequiredError(TTIBaseException):
    """Raised when an analytical operation is attempted without active, valid consent."""
    pass


class WebhookVerificationError(TTIBaseException):
    """Raised when a webhook update fails secret-token or source validation."""
    pass


class ConsentVersionMismatchError(TTIBaseException):
    """Raised when a consent record belongs to an outdated consent version."""
    pass


def http_exception_from_domain(exc: TTIBaseException) -> HTTPException:
    """Map domain exceptions to corresponding FastAPI HTTPExceptions."""
    if isinstance(exc, TenantAccessError):
        return HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "TenantAccessError", "message": exc.message, "details": exc.details},
        )
    if isinstance(exc, ConnectorNotConfiguredError):
        return HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "ConnectorNotConfiguredError", "message": exc.message, "details": exc.details},
        )
    if isinstance(exc, InputSanitizationError):
        return HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail={"error": "InputSanitizationError", "message": exc.message, "details": exc.details},
        )
    if isinstance(exc, EvidenceIntegrityError):
        return HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"error": "EvidenceIntegrityError", "message": exc.message, "details": exc.details},
        )
    if isinstance(exc, (ConsentRequiredError, WebhookVerificationError)):
        return HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": exc.__class__.__name__, "message": exc.message, "details": exc.details},
        )
    if isinstance(exc, ConsentVersionMismatchError):
        return HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"error": "ConsentVersionMismatchError", "message": exc.message, "details": exc.details},
        )
    return HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail={"error": "InternalServerError", "message": exc.message, "details": exc.details},
    )
