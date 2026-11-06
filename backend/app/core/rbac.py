"""Role-Based Access Control (RBAC) static permission mapping (Release 1).

Canonical Reference:
- Requirements: AC-REQ-001, AC-REQ-003, AC-REQ-004
- Decisions: DEC-14 (Static Code RBAC for Release 1; relational role_permissions deferred to Release 2)
"""

from typing import Dict, Set
from fastapi import HTTPException, status

# Canonical Permission Tokens
PERM_ORG_READ = "org:read"
PERM_ORG_MANAGE = "org:manage"
PERM_USER_READ = "user:read"
PERM_USER_MANAGE = "user:manage"
PERM_ROLE_READ = "role:read"

PERM_CASE_CREATE = "case:create"
PERM_CASE_READ = "case:read"
PERM_CASE_UPDATE = "case:update"
PERM_CASE_DELETE = "case:delete"
PERM_CASE_NOTE_CREATE = "case:note_create"
PERM_CASE_MESSAGE_PIN = "case:message_pin"

PERM_SEARCH_QUERY = "search:query"
PERM_THREAD_READ = "thread:read"
PERM_INGEST_SUBMIT = "ingest:submit"
PERM_INGEST_READ = "ingest:read"

PERM_ALERT_READ = "alert:read"
PERM_ALERT_TRIAGE = "alert:triage"
PERM_ALERT_ASSIGN = "alert:assign"

PERM_REPORT_GENERATE = "report:generate"
PERM_REPORT_SEAL = "report:seal"
PERM_REPORT_DOWNLOAD = "report:download"

PERM_CREDIT_READ = "credit:read"
PERM_CREDIT_DEDUCT = "credit:deduct"
PERM_CREDIT_MANAGE = "credit:manage"

PERM_AUDIT_READ = "audit:read"
PERM_AUDIT_WRITE = "audit:write"

# Canonical Role Definitions (iam.roles)
ROLE_TENANT_ADMIN = "TENANT_ADMIN"
ROLE_INVESTIGATOR_LEAD = "INVESTIGATOR_LEAD"
ROLE_INVESTIGATOR = "INVESTIGATOR"
ROLE_READ_ONLY_ANALYST = "READ_ONLY_ANALYST"

CANONICAL_ROLES = {
    ROLE_TENANT_ADMIN,
    ROLE_INVESTIGATOR_LEAD,
    ROLE_INVESTIGATOR,
    ROLE_READ_ONLY_ANALYST,
}

# Static Role -> Permission Set Map (DEC-14: O(1) in-memory resolution)
ROLE_PERMISSIONS_MAP: Dict[str, Set[str]] = {
    ROLE_TENANT_ADMIN: {
        PERM_ORG_READ,
        PERM_ORG_MANAGE,
        PERM_USER_READ,
        PERM_USER_MANAGE,
        PERM_ROLE_READ,
        PERM_CASE_READ,
        PERM_SEARCH_QUERY,
        PERM_THREAD_READ,
        PERM_INGEST_SUBMIT,
        PERM_INGEST_READ,
        PERM_REPORT_DOWNLOAD,
        PERM_CREDIT_READ,
        PERM_CREDIT_MANAGE,
        PERM_AUDIT_READ,
        PERM_ALERT_READ,
        PERM_ALERT_TRIAGE,
        PERM_ALERT_ASSIGN,
    },
    ROLE_INVESTIGATOR_LEAD: {
        PERM_ORG_READ,
        PERM_USER_READ,
        PERM_ROLE_READ,
        PERM_CASE_CREATE,
        PERM_CASE_READ,
        PERM_CASE_UPDATE,
        PERM_CASE_DELETE,
        PERM_CASE_NOTE_CREATE,
        PERM_CASE_MESSAGE_PIN,
        PERM_SEARCH_QUERY,
        PERM_THREAD_READ,
        PERM_INGEST_SUBMIT,
        PERM_INGEST_READ,
        PERM_REPORT_GENERATE,
        PERM_REPORT_SEAL,
        PERM_REPORT_DOWNLOAD,
        PERM_CREDIT_READ,
        PERM_CREDIT_DEDUCT,
        PERM_AUDIT_READ,
        PERM_ALERT_READ,
        PERM_ALERT_TRIAGE,
        PERM_ALERT_ASSIGN,
    },
    ROLE_INVESTIGATOR: {
        PERM_ORG_READ,
        PERM_CASE_CREATE,
        PERM_CASE_READ,
        PERM_CASE_UPDATE,
        PERM_CASE_NOTE_CREATE,
        PERM_CASE_MESSAGE_PIN,
        PERM_SEARCH_QUERY,
        PERM_THREAD_READ,
        PERM_INGEST_SUBMIT,
        PERM_INGEST_READ,
        PERM_REPORT_GENERATE,
        PERM_REPORT_DOWNLOAD,
        PERM_CREDIT_READ,
        PERM_CREDIT_DEDUCT,
        PERM_ALERT_READ,
        PERM_ALERT_TRIAGE,
    },
    ROLE_READ_ONLY_ANALYST: {
        PERM_ORG_READ,
        PERM_CASE_READ,
        PERM_SEARCH_QUERY,
        PERM_THREAD_READ,
        PERM_INGEST_READ,
        PERM_REPORT_DOWNLOAD,
        PERM_ALERT_READ,
    },
}


def get_role_permissions(role: str) -> Set[str]:
    """Retrieve the permission set granted to a role."""
    return ROLE_PERMISSIONS_MAP.get(role, set()).copy()


def has_permission(role: str, permission: str) -> bool:
    """Check if a given role possesses the specified permission."""
    permissions = ROLE_PERMISSIONS_MAP.get(role, set())
    return permission in permissions


def require_permission(role: str, permission: str) -> None:
    """Enforce permission requirement; raises HTTP 403 Forbidden on failure."""
    if not has_permission(role, permission):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Operation not permitted. Required permission: '{permission}'.",
        )


def validate_self_elevation_attempt(current_role: str, requested_role: str) -> None:
    """
    Enforce invariant: a user cannot elevate their own role (Scenario 6 / AC-REQ-003).
    A user cannot assign or promote anyone to a role higher than what their role permits.
    """
    if requested_role not in CANONICAL_ROLES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid target role: '{requested_role}'.",
        )

    # TENANT_ADMIN can manage roles up to TENANT_ADMIN within their tenant.
    # Non-admins cannot manage or promote roles at all.
    if current_role != ROLE_TENANT_ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Non-administrative users cannot assign or elevate roles.",
        )
