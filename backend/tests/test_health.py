"""Tests for health, status, and diagnostic API endpoints."""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_root_endpoint(async_client: AsyncClient):
    """Verify root discovery endpoint responds with project metadata."""
    response = await async_client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert "Telegram Threat Intelligence" in data["project"]
    assert data["health"] == "/api/v1/health"


@pytest.mark.asyncio
async def test_health_check_endpoint(async_client: AsyncClient):
    """Verify GET /api/v1/health returns structured diagnostic payload."""
    response = await async_client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()

    # Health contract assertions
    assert "status" in data
    assert data["status"] in ("healthy", "degraded", "unavailable")
    assert data["project_name"] == "Telegram Threat Intelligence (TTI)"
    assert "components" in data
    assert "database" in data["components"]
    assert "redis" in data["components"]
    assert "evidence_storage" in data["components"]
    assert "connectors" in data["components"]

    # Verify storage component is healthy (directory created and verified)
    assert data["components"]["evidence_storage"]["status"] == "healthy"

    # Verify connectors reflect safe inert stub mode
    assert data["components"]["connectors"]["status"] == "disabled"
    assert data["components"]["connectors"]["details"]["live_collection"] == "disabled_by_policy"


@pytest.mark.asyncio
async def test_status_endpoint(async_client: AsyncClient, test_tenant_id: str):
    """Verify GET /api/v1/status reports architectural phase and compliance boundaries."""
    response = await async_client.get(
        "/api/v1/status",
        headers={"X-Tenant-ID": test_tenant_id},
    )
    assert response.status_code == 200
    data = response.json()
    assert "Phase 1" in data["phase"]
    assert data["tenant_context"]["active_tenant_id"] == test_tenant_id
    assert data["security_baseline_compliance"]["live_scraping_authorized"] is False
    assert data["security_baseline_compliance"]["unrestricted_autonomous_actions"] is False
