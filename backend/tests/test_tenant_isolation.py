"""Tests for multi-tenant isolation, evidence partitioning, and integrity verification."""

import pytest
from httpx import AsyncClient
from app.core.errors import TenantAccessError
from app.evidence.storage import LocalEvidenceStore


@pytest.mark.asyncio
async def test_invalid_tenant_header_rejected(async_client: AsyncClient):
    """Verify malformed non-UUID tenant header is strictly rejected."""
    response = await async_client.get(
        "/api/v1/status",
        headers={"X-Tenant-ID": "malicious' OR 1=1 --"},
    )
    assert response.status_code == 400
    assert "Invalid X-Tenant-ID header format" in response.json()["detail"]


@pytest.mark.asyncio
async def test_valid_tenant_header_accepted(async_client: AsyncClient, test_tenant_id: str):
    """Verify valid UUIDv4 tenant header is properly parsed into context."""
    response = await async_client.get(
        "/api/v1/status",
        headers={"X-Tenant-ID": test_tenant_id},
    )
    assert response.status_code == 200
    assert response.json()["tenant_context"]["active_tenant_id"] == test_tenant_id


def test_evidence_store_tenant_partitioning(
    temp_evidence_store: LocalEvidenceStore,
    test_tenant_id: str,
    alternate_tenant_id: str,
):
    """Verify evidence files are physically partitioned by tenant ID and checksum-verified."""
    payload_a = b"Sensitive threat evidence for Tenant A"
    payload_b = b"Unrelated threat evidence for Tenant B"

    record_a = temp_evidence_store.store_raw_evidence(
        tenant_id=test_tenant_id,
        artifact_id="art_001",
        source_type="telegram",
        raw_bytes=payload_a,
    )

    record_b = temp_evidence_store.store_raw_evidence(
        tenant_id=alternate_tenant_id,
        artifact_id="art_002",
        source_type="darkweb",
        raw_bytes=payload_b,
    )

    # Check path isolation
    assert record_a.relative_path.startswith(f"{test_tenant_id}/")
    assert record_b.relative_path.startswith(f"{alternate_tenant_id}/")

    # Verify integrity report
    report_valid = temp_evidence_store.verify_integrity(
        tenant_id=test_tenant_id,
        artifact_id="art_001",
        relative_path=record_a.relative_path,
        expected_sha256=record_a.content_sha256,
    )
    assert report_valid.is_valid is True

    # Verify tampering detection
    tampered_report = temp_evidence_store.verify_integrity(
        tenant_id=test_tenant_id,
        artifact_id="art_001",
        relative_path=record_a.relative_path,
        expected_sha256="0" * 64,  # Intentional bogus hash
    )
    assert tampered_report.is_valid is False
    assert "HASH MISMATCH" in tampered_report.notes


def test_evidence_store_prevents_directory_traversal(
    temp_evidence_store: LocalEvidenceStore,
):
    """Verify directory traversal attempts in tenant ID are blocked."""
    with pytest.raises(TenantAccessError):
        temp_evidence_store.store_raw_evidence(
            tenant_id="../../etc",
            artifact_id="evil",
            source_type="telegram",
            raw_bytes=b"exploit",
        )


def test_cross_tenant_evidence_retrieval_prohibited(
    temp_evidence_store: LocalEvidenceStore,
    test_tenant_id: str,
    alternate_tenant_id: str,
):
    """Regression test for SEC-AUDIT-03: Cross-tenant path resolution must fail closed."""
    secret_payload = b"Confidential victim evidence payload"
    record = temp_evidence_store.store_raw_evidence(
        tenant_id=alternate_tenant_id,
        artifact_id="victim_art_001",
        source_type="telegram",
        raw_bytes=secret_payload,
    )

    # Attacker tenant attempts to retrieve victim's artifact
    with pytest.raises(TenantAccessError) as exc_info:
        temp_evidence_store.retrieve_raw_evidence(
            tenant_id=test_tenant_id,
            relative_path=record.relative_path,
        )
    assert "Cross-tenant access prohibited" in str(exc_info.value)


def test_evidence_retrieval_path_traversal_and_separators(
    temp_evidence_store: LocalEvidenceStore,
    test_tenant_id: str,
):
    """Verify path traversal, absolute paths, and separator tricks are blocked."""
    traversal_paths = [
        f"{test_tenant_id}/../../etc/passwd",
        f"{test_tenant_id}/..\\..\\windows\\system32",
        "../../shadow",
        "..\\..\\boot.ini",
        "/etc/shadow",
        "C:\\Windows\\System32\\cmd.exe",
        "\\\\network_share\\evil.raw",
        f"{test_tenant_id}/subdir/../../outside.raw",
    ]

    for evil_path in traversal_paths:
        with pytest.raises(TenantAccessError):
            temp_evidence_store.retrieve_raw_evidence(
                tenant_id=test_tenant_id,
                relative_path=evil_path,
            )


def test_valid_same_tenant_evidence_read_and_missing_artifact(
    temp_evidence_store: LocalEvidenceStore,
    test_tenant_id: str,
):
    """Verify legitimate same-tenant reads succeed, and missing artifacts raise FileNotFoundError."""
    payload = b"Legitimate threat evidence for authorized tenant"
    record = temp_evidence_store.store_raw_evidence(
        tenant_id=test_tenant_id,
        artifact_id="legit_001",
        source_type="telegram",
        raw_bytes=payload,
    )

    # 1. Valid read succeeds
    retrieved = temp_evidence_store.retrieve_raw_evidence(
        tenant_id=test_tenant_id,
        relative_path=record.relative_path,
    )
    assert retrieved == payload

    # 2. Missing artifact inside valid tenant partition raises FileNotFoundError
    with pytest.raises(FileNotFoundError):
        temp_evidence_store.retrieve_raw_evidence(
            tenant_id=test_tenant_id,
            relative_path=f"{test_tenant_id}/non_existent_file.raw",
        )


def test_symlink_escape_rejected_where_supported(
    temp_evidence_store: LocalEvidenceStore,
    test_tenant_id: str,
    tmp_path,
):
    """Verify symlinks pointing outside tenant boundary are rejected."""
    outside_file = tmp_path / "outside_secret.txt"
    outside_file.write_bytes(b"Outside host secret")

    tenant_dir = temp_evidence_store._get_tenant_dir(test_tenant_id)
    symlink_path = tenant_dir / "symlink_escape.raw"

    try:
        symlink_path.symlink_to(outside_file)
    except (OSError, NotImplementedError):
        pytest.skip("Symlink creation not permitted or supported in current environment")

    with pytest.raises(TenantAccessError):
        temp_evidence_store.retrieve_raw_evidence(
            tenant_id=test_tenant_id,
            relative_path=f"{test_tenant_id}/symlink_escape.raw",
        )
