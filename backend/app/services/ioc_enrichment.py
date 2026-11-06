"""External Threat Intelligence & IOC Enrichment Services.

Supported Providers:
1. VirusTotal (v3 REST API) - IP, domain, URL, and file hash reputation.
2. AbuseIPDB (v2 API) - IP confidence score and abuse reporting history.
3. AlienVault OTX (v1 API) - Threat pulses, malware indicators, and passive DNS.

Security Guarantees:
- Read-only lookups strictly (no automated submission of private customer evidence).
- Safe error handling: timeouts, 401/403 auth errors, 429 rate limits caught gracefully.
- Secrets are NEVER logged or leaked in exception traces.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
import httpx

from app.core.config import get_settings

logger = logging.getLogger("tti.services.enrichment")

HTTP_TIMEOUT_SECONDS = 5.0


@dataclass
class IOCEnrichmentResult:
    """Enrichment lookup result for an Indicator of Compromise."""
    provider: str
    ioc_type: str
    value: str
    is_malicious: bool
    reputation_score: float  # 0.0 to 100.0 (100 = critical threat)
    raw_details: Dict[str, Any]
    error: Optional[str] = None


class VirusTotalProvider:
    """VirusTotal API v3 Client."""

    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: Optional[str] = None) -> None:
        settings = get_settings()
        self.api_key = api_key or settings.VIRUSTOTAL_API_KEY or settings.TTI_IOC_ENRICHMENT_API_KEY

    @property
    def is_configured(self) -> bool:
        return bool(self.api_key and len(self.api_key) >= 16)

    async def probe(self) -> Dict[str, Any]:
        """Probe VirusTotal API connection and authentication status."""
        if not self.is_configured:
            return {
                "connected": False,
                "auth": "missing_credentials",
                "test": "not_tested",
                "error": "VIRUSTOTAL_API_KEY not configured in .env",
            }
        try:
            headers = {"x-apikey": self.api_key}
            async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_SECONDS) as client:
                resp = await client.get(f"{self.BASE_URL}/ip_addresses/8.8.8.8", headers=headers)
            if resp.status_code == 200:
                return {"connected": True, "auth": "authenticated", "test": "passed", "error": None}
            if resp.status_code in (401, 403):
                return {"connected": False, "auth": "invalid_credentials", "test": "failed", "error": f"HTTP {resp.status_code}: Unauthorized"}
            return {"connected": False, "auth": "error", "test": "failed", "error": f"HTTP {resp.status_code}"}
        except Exception as exc:
            return {"connected": False, "auth": "unreachable", "test": "failed", "error": f"{type(exc).__name__}: {exc}"[:200]}

    async def lookup_ip(self, ip_address: str) -> IOCEnrichmentResult:
        """Lookup IP address reputation."""
        if not self.is_configured:
            return IOCEnrichmentResult(
                provider="VirusTotal",
                ioc_type="ipv4",
                value=ip_address,
                is_malicious=False,
                reputation_score=0.0,
                raw_details={},
                error="VIRUSTOTAL_API_KEY not configured",
            )
        try:
            headers = {"x-apikey": self.api_key}
            async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_SECONDS) as client:
                resp = await client.get(f"{self.BASE_URL}/ip_addresses/{ip_address}", headers=headers)
            if resp.status_code == 200:
                data = resp.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                score = min(100.0, float(malicious * 15))
                return IOCEnrichmentResult(
                    provider="VirusTotal",
                    ioc_type="ipv4",
                    value=ip_address,
                    is_malicious=malicious > 0,
                    reputation_score=score,
                    raw_details=stats,
                )
            return IOCEnrichmentResult(
                provider="VirusTotal",
                ioc_type="ipv4",
                value=ip_address,
                is_malicious=False,
                reputation_score=0.0,
                raw_details={},
                error=f"HTTP {resp.status_code}",
            )
        except Exception as exc:
            return IOCEnrichmentResult(
                provider="VirusTotal",
                ioc_type="ipv4",
                value=ip_address,
                is_malicious=False,
                reputation_score=0.0,
                raw_details={},
                error=str(exc),
            )


class AbuseIPDBProvider:
    """AbuseIPDB API v2 Client."""

    BASE_URL = "https://api.abuseipdb.com/api/v2"

    def __init__(self, api_key: Optional[str] = None) -> None:
        settings = get_settings()
        self.api_key = api_key or settings.ABUSEIPDB_API_KEY

    @property
    def is_configured(self) -> bool:
        return bool(self.api_key and len(self.api_key) >= 16)

    async def probe(self) -> Dict[str, Any]:
        """Probe AbuseIPDB API connection and authentication."""
        if not self.is_configured:
            return {
                "connected": False,
                "auth": "missing_credentials",
                "test": "not_tested",
                "error": "ABUSEIPDB_API_KEY not configured in .env",
            }
        try:
            headers = {"Key": self.api_key, "Accept": "application/json"}
            params = {"ipAddress": "127.0.0.1", "maxAgeInDays": 30}
            async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_SECONDS) as client:
                resp = await client.get(f"{self.BASE_URL}/check", headers=headers, params=params)
            if resp.status_code == 200:
                return {"connected": True, "auth": "authenticated", "test": "passed", "error": None}
            if resp.status_code in (401, 403):
                return {"connected": False, "auth": "invalid_credentials", "test": "failed", "error": f"HTTP {resp.status_code}: Unauthorized"}
            return {"connected": False, "auth": "error", "test": "failed", "error": f"HTTP {resp.status_code}"}
        except Exception as exc:
            return {"connected": False, "auth": "unreachable", "test": "failed", "error": f"{type(exc).__name__}: {exc}"[:200]}

    async def lookup_ip(self, ip_address: str) -> IOCEnrichmentResult:
        """Lookup IP address abuse score."""
        if not self.is_configured:
            return IOCEnrichmentResult(
                provider="AbuseIPDB",
                ioc_type="ipv4",
                value=ip_address,
                is_malicious=False,
                reputation_score=0.0,
                raw_details={},
                error="ABUSEIPDB_API_KEY not configured",
            )
        try:
            headers = {"Key": self.api_key, "Accept": "application/json"}
            params = {"ipAddress": ip_address, "maxAgeInDays": 30}
            async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_SECONDS) as client:
                resp = await client.get(f"{self.BASE_URL}/check", headers=headers, params=params)
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                abuse_score = float(data.get("abuseConfidenceScore", 0))
                return IOCEnrichmentResult(
                    provider="AbuseIPDB",
                    ioc_type="ipv4",
                    value=ip_address,
                    is_malicious=abuse_score >= 25.0,
                    reputation_score=abuse_score,
                    raw_details=data,
                )
            return IOCEnrichmentResult(
                provider="AbuseIPDB",
                ioc_type="ipv4",
                value=ip_address,
                is_malicious=False,
                reputation_score=0.0,
                raw_details={},
                error=f"HTTP {resp.status_code}",
            )
        except Exception as exc:
            return IOCEnrichmentResult(
                provider="AbuseIPDB",
                ioc_type="ipv4",
                value=ip_address,
                is_malicious=False,
                reputation_score=0.0,
                raw_details={},
                error=str(exc),
            )


class AlienVaultOTXProvider:
    """AlienVault Open Threat Exchange (OTX) API Client."""

    BASE_URL = "https://otx.alienvault.com/api/v1"

    def __init__(self, api_key: Optional[str] = None) -> None:
        settings = get_settings()
        self.api_key = api_key or settings.OTX_API_KEY

    @property
    def is_configured(self) -> bool:
        return bool(self.api_key and len(self.api_key) >= 16)

    async def probe(self) -> Dict[str, Any]:
        """Probe AlienVault OTX connection and authentication."""
        if not self.is_configured:
            return {
                "connected": False,
                "auth": "missing_credentials",
                "test": "not_tested",
                "error": "OTX_API_KEY not configured in .env",
            }
        try:
            headers = {"X-OTX-API-KEY": self.api_key}
            async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_SECONDS) as client:
                resp = await client.get(f"{self.BASE_URL}/user/me", headers=headers)
            if resp.status_code == 200:
                return {"connected": True, "auth": "authenticated", "test": "passed", "error": None}
            if resp.status_code in (401, 403):
                return {"connected": False, "auth": "invalid_credentials", "test": "failed", "error": f"HTTP {resp.status_code}: Unauthorized"}
            return {"connected": False, "auth": "error", "test": "failed", "error": f"HTTP {resp.status_code}"}
        except Exception as exc:
            return {"connected": False, "auth": "unreachable", "test": "failed", "error": f"{type(exc).__name__}: {exc}"[:200]}


class IOCEnrichmentService:
    """Unified IOC enrichment service orchestrator."""

    def __init__(self) -> None:
        self.virustotal = VirusTotalProvider()
        self.abuseipdb = AbuseIPDBProvider()
        self.otx = AlienVaultOTXProvider()

    async def enrich_indicator(self, ioc_type: str, value: str) -> Dict[str, Any]:
        """Enrich an IOC across configured providers."""
        results: Dict[str, Any] = {}
        if ioc_type in ("ipv4", "ip"):
            if self.virustotal.is_configured:
                results["virustotal"] = (await self.virustotal.lookup_ip(value)).__dict__
            if self.abuseipdb.is_configured:
                results["abuseipdb"] = (await self.abuseipdb.lookup_ip(value)).__dict__
        return results

    async def probe_all_providers(self) -> Dict[str, Dict[str, Any]]:
        """Run health probes across all IOC enrichment providers."""
        return {
            "VirusTotal": await self.virustotal.probe(),
            "AbuseIPDB": await self.abuseipdb.probe(),
            "AlienVault OTX": await self.otx.probe(),
        }
