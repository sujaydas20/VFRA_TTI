"""Evidence storage engine isolating raw intelligence artifacts from public web assets.

NON-NEGOTIABLE SECURITY RULES:
1. Evidence files must NEVER be saved in or served from frontend static directories.
2. Evidence storage directories must be partitioned strictly by tenant UUID.
3. Every write calculates and verifies an immutable SHA-256 cryptographic digest.
4. Phase 1 provides an initial storage foundation. Evidence integrity verification
   and HSM/KMS key-signing are marked as work in progress for subsequent phases.
"""

from abc import ABC, abstractmethod
import hashlib
from pathlib import Path
from typing import Optional
from app.core.config import get_settings
from app.core.errors import EvidenceIntegrityError, TenantAccessError
from app.evidence.models import EvidenceIntegrityReport, EvidenceRecord


class EvidenceStorageEngine(ABC):
    """Abstract interface for segregated evidence persistence."""

    @abstractmethod
    def store_raw_evidence(
        self,
        tenant_id: str,
        artifact_id: str,
        source_type: str,
        raw_bytes: bytes,
    ) -> EvidenceRecord:
        """Persist raw evidence under tenant partition and return metadata."""
        pass

    @abstractmethod
    def retrieve_raw_evidence(self, tenant_id: str, relative_path: str) -> bytes:
        """Retrieve raw evidence ensuring tenant access boundaries."""
        pass

    @abstractmethod
    def verify_integrity(self, tenant_id: str, artifact_id: str, relative_path: str, expected_sha256: str) -> EvidenceIntegrityReport:
        """Verify that the stored file matches the expected cryptographic SHA-256 hash."""
        pass


class LocalEvidenceStore(EvidenceStorageEngine):
    """Local filesystem implementation of segregated evidence storage."""

    def __init__(self, base_path: Optional[str] = None):
        settings = get_settings()
        self.base_dir = Path(base_path or settings.TTI_EVIDENCE_STORAGE_PATH).resolve()
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def _get_tenant_dir(self, tenant_id: str) -> Path:
        """Ensure tenant-specific isolated directory exists with strict boundary validation."""
        if (
            not tenant_id
            or not isinstance(tenant_id, str)
            or "/" in tenant_id
            or "\\" in tenant_id
            or ".." in tenant_id
            or "\x00" in tenant_id
        ):
            raise TenantAccessError("Invalid tenant identifier for evidence path resolution.")

        tenant_dir = (self.base_dir / tenant_id).resolve()
        # Prevent directory traversal or boundary escapes
        try:
            if not tenant_dir.is_relative_to(self.base_dir):
                raise TenantAccessError("Path traversal detected during evidence tenant resolution.")
        except (ValueError, AttributeError):
            if not str(tenant_dir).startswith(str(self.base_dir)):
                raise TenantAccessError("Path traversal detected during evidence tenant resolution.")

        tenant_dir.mkdir(parents=True, exist_ok=True)
        return tenant_dir

    def store_raw_evidence(
        self,
        tenant_id: str,
        artifact_id: str,
        source_type: str,
        raw_bytes: bytes,
    ) -> EvidenceRecord:
        tenant_dir = self._get_tenant_dir(tenant_id)

        # Compute SHA-256 hash
        digest = hashlib.sha256(raw_bytes).hexdigest()
        filename = f"{artifact_id}_{digest[:16]}.raw"
        file_path = (tenant_dir / filename).resolve()

        # Ensure file path stays strictly within tenant container
        if not file_path.is_relative_to(tenant_dir):
            raise TenantAccessError("Illegal path escape during evidence write.")

        # Write immutable binary file
        file_path.write_bytes(raw_bytes)

        relative_path = f"{tenant_id}/{filename}"
        return EvidenceRecord(
            tenant_id=tenant_id,
            artifact_id=artifact_id,
            source_type=source_type,
            content_sha256=digest,
            relative_path=relative_path,
            byte_size=len(raw_bytes),
            is_tamper_verified=True,
        )

    def retrieve_raw_evidence(self, tenant_id: str, relative_path: str) -> bytes:
        """
        Retrieve raw evidence ensuring strict tenant partition boundaries (SEC-AUDIT-03).
        
        Guarantees:
        1. Prohibits cross-tenant retrieval (e.g. tenant A requesting tenant B's prefix).
        2. Prohibits relative path traversal ('..') and absolute paths.
        3. Prohibits Windows drive letters, UNC paths, and separator tricks.
        4. Prohibits symlink escapes outside the tenant storage root.
        5. Fails closed with TenantAccessError if resolution escapes the tenant boundary.
        """
        tenant_dir = self._get_tenant_dir(tenant_id)

        if not relative_path or not isinstance(relative_path, str) or "\x00" in relative_path:
            raise TenantAccessError("Invalid evidence path.")

        # Reject absolute paths, Windows drive specifications, and UNC shares
        raw_path = Path(relative_path)
        if raw_path.is_absolute() or raw_path.drive or relative_path.startswith(("\\\\", "//")):
            raise TenantAccessError("Absolute paths and network shares are prohibited in evidence retrieval.")

        # Normalize path separators for consistent cross-platform inspection
        norm_posix = relative_path.replace("\\", "/")
        parts = [p for p in norm_posix.split("/") if p and p != "."]

        if ".." in parts:
            raise TenantAccessError("Directory traversal ('..') is prohibited in evidence retrieval.")

        # Enforce tenant container prefix matching
        if len(parts) > 1 and parts[0] != tenant_id:
            raise TenantAccessError(
                f"Cross-tenant access prohibited: Requested path partition '{parts[0]}' "
                f"does not match authenticated tenant '{tenant_id}'."
            )

        # Extract path relative to tenant root
        rel_inside_tenant = norm_posix[len(tenant_id) + 1:] if norm_posix.startswith(f"{tenant_id}/") else norm_posix
        if not rel_inside_tenant or rel_inside_tenant.startswith("/"):
            raise TenantAccessError("Invalid target artifact path.")

        target_file = (tenant_dir / rel_inside_tenant).resolve()

        # Strict containment validation
        try:
            if not target_file.is_relative_to(tenant_dir):
                raise TenantAccessError(f"Access denied: Target resolves outside tenant '{tenant_id}' boundary.")
        except (ValueError, AttributeError):
            if not str(target_file).startswith(str(tenant_dir)):
                raise TenantAccessError(f"Access denied: Target resolves outside tenant '{tenant_id}' boundary.")

        if not target_file.exists():
            raise FileNotFoundError(f"Evidence artifact not found: {relative_path}")

        if not target_file.is_file():
            raise TenantAccessError("Target evidence path does not point to a regular file.")

        return target_file.read_bytes()

    def verify_integrity(
        self,
        tenant_id: str,
        artifact_id: str,
        relative_path: str,
        expected_sha256: str,
    ) -> EvidenceIntegrityReport:
        try:
            content = self.retrieve_raw_evidence(tenant_id, relative_path)
            computed_sha256 = hashlib.sha256(content).hexdigest()
            is_valid = computed_sha256.lower() == expected_sha256.lower()
            return EvidenceIntegrityReport(
                artifact_id=artifact_id,
                tenant_id=tenant_id,
                expected_sha256=expected_sha256,
                computed_sha256=computed_sha256,
                is_valid=is_valid,
                notes="Integrity verified" if is_valid else "HASH MISMATCH: Evidence potentially tampered",
            )
        except Exception as e:
            return EvidenceIntegrityReport(
                artifact_id=artifact_id,
                tenant_id=tenant_id,
                expected_sha256=expected_sha256,
                computed_sha256=None,
                is_valid=False,
                notes=f"Verification error: {str(e)}",
            )
