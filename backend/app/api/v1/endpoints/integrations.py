"""API integration inventory and health dashboard endpoints.

Exposes the provider inventory built by `app.integrations.registry`.
Secrets are never serialised: only `credential_fingerprint` (length + truncated
SHA-256) and boolean availability flags are returned.
"""

from typing import Any, Dict, List

from fastapi import APIRouter, Query

from app.integrations.registry import list_integrations

router = APIRouter(prefix="/integrations", tags=["Integrations"])


@router.get(
    "",
    summary="API integration inventory with live connection probes",
    description=(
        "Returns every configured external API/provider with credential availability, "
        "connection status, authentication status, test result and dependent modules. "
        "No secret values are ever returned."
    ),
)
async def get_integrations(
    probe: bool = Query(True, description="Omit probes to read static configuration only (fast, no network)."),
) -> Dict[str, Any]:
    """Inventory of all TTI external integrations."""
    records: List[Any] = await list_integrations(probe=probe)
    payload = [r.to_dict() for r in records]
    return {
        "total": len(payload),
        "connected": sum(1 for r in payload if r["connected"]),
        "missing_credentials": sum(1 for r in payload if not r["credential_available"]),
        "failed": sum(1 for r in payload if r["test_status"] == "failed"),
        "integrations": payload,
    }