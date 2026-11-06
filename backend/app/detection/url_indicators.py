"""Offline URL extraction and heuristic indicator analysis.

STRICT INVARIANTS:
- Absolutely zero network requests (no DNS, no HTTP/TLS, no socket operations).
- Safe, defanged storage for indicators.
- Official domain allowlist suppresses brand-lookalike alerts ONLY.
  It never suppresses shorteners, IP hosts, or APK downloads.
"""

from functools import lru_cache
from pathlib import Path
import re
import urllib.parse
from typing import Any, Dict, List, Optional, Set, Tuple
import yaml

from app.detection.masking import mask_sensitive_data

# Suspicious top level domains frequently associated with phishing / fraud
SUSPICIOUS_TLDS: Set[str] = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "buzz", "icu",
    "club", "work", "click", "vip", "fit", "link", "online", "live"
}

# Known URL shorteners
SHORTENERS: Set[str] = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "shorturl.at", "ow.ly", "rebrand.ly"
}

# Suspicious executable extensions
SUSPICIOUS_EXTENSIONS: Set[str] = {
    "apk", "exe", "bat", "cmd", "scr", "vbs", "msi", "ps1"
}

# Brand keywords often spoofed in India
FINANCIAL_BRAND_KEYWORDS: Set[str] = {
    "sbi", "hdfc", "icici", "pnb", "axis", "kotak", "bob", "paytm", "phonepe", "gpay",
    "kisan", "yojana", "electricity", "bsnl", "airtel", "jio", "fedex", "bluedart"
}

# URL matching regex covering standard and defanged URLs
URL_PATTERN = re.compile(
    r"(?:hxxps?|https?):\/\/[^\s/$.?#].[^\s]*|"
    r"\b[a-zA-Z0-9.-]+\[\.\][a-zA-Z]{2,}(?:\/[^\s]*)?|"
    r"\b[a-zA-Z0-9.-]+\.(?:xyz|top|tk|ml|ga|cf|gq|buzz|icu|club|work|click|apk|bank\.in|fin\.in)(?:\/[^\s]*)?",
    re.IGNORECASE,
)

IP_HOST_PATTERN = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


@lru_cache(maxsize=1)
def load_official_allowlist(allowlist_path: Optional[Path] = None) -> Tuple[Set[str], Set[str]]:
    """Load official domains allowlist from YAML.
    
    Returns:
        (allowed_suffixes, allowed_domains)
    """
    if allowlist_path is None:
        allowlist_path = Path("backend/rules/allowlists/official_domains.yaml")
        if not allowlist_path.exists():
            allowlist_path = Path("rules/allowlists/official_domains.yaml")

    allowed_suffixes: Set[str] = set()
    allowed_domains: Set[str] = set()

    if allowlist_path and allowlist_path.exists():
        try:
            with open(allowlist_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
                if isinstance(data, dict):
                    if "tld_suffixes" in data and isinstance(data["tld_suffixes"], list):
                        for item in data["tld_suffixes"]:
                            if isinstance(item, dict) and item.get("is_reviewed", False):
                                s = item.get("suffix", "").lower().strip()
                                if s:
                                    allowed_suffixes.add(s)
                    if "domains" in data and isinstance(data["domains"], list):
                        for item in data["domains"]:
                            if isinstance(item, dict) and item.get("is_reviewed", False):
                                d = item.get("domain", "").lower().strip()
                                if d:
                                    allowed_domains.add(d)
        except Exception:
            pass

    return allowed_suffixes, allowed_domains


def is_official_domain(hostname: str, allowlist: Optional[Tuple[Set[str], Set[str]]] = None) -> bool:
    """Check if hostname matches official allowlist at exact label boundaries.
    
    Match is on exact domain or true subdomain, never substring.
    """
    if not hostname:
        return False

    clean_host = hostname.lower().strip(".")
    if allowlist is not None:
        allowed_suffixes, allowed_domains = allowlist
    else:
        allowed_suffixes, allowed_domains = load_official_allowlist()

    # 1. Match allowed suffixes (e.g. .bank.in, .gov.in)
    for s in allowed_suffixes:
        if clean_host == s or clean_host.endswith(f".{s}"):
            return True

    # 2. Match exact allowed domains or true subdomains
    for d in allowed_domains:
        if clean_host == d or clean_host.endswith(f".{d}"):
            return True

    return False


def defang_url(url: str) -> str:
    """Defang URL so it cannot be clicked or auto-resolved."""
    defanged = url.replace("http://", "hxxp://").replace("https://", "hxxps://")
    parts = defanged.split("/", 3)
    if len(parts) >= 3:
        host = parts[2].replace(".", "[.]")
        defanged = f"{parts[0]}//{host}" + ("/" + parts[3] if len(parts) > 3 else "")
    else:
        defanged = defanged.replace(".", "[.]")
    return defanged


def refang_for_parsing(url: str) -> str:
    """Refang URL in-memory strictly for parsing structure."""
    clean = url.replace("hxxps://", "https://").replace("hxxp://", "http://")
    clean = clean.replace("[.]", ".")
    if not clean.startswith(("http://", "https://")):
        clean = "http://" + clean
    return clean


class URLIndicatorDetector:
    """Extracts and evaluates static indicators for URLs without network calls."""

    @classmethod
    def analyze_text(cls, text: str) -> List[Dict[str, Any]]:
        """Find all URLs in text and compute heuristic flags. Returns indicator payloads."""
        results: List[Dict[str, Any]] = []
        matches = URL_PATTERN.findall(text)
        seen_domains: Set[str] = set()

        for raw_match in matches:
            refanged = refang_for_parsing(raw_match)
            try:
                parsed = urllib.parse.urlparse(refanged)
            except Exception:
                continue

            hostname = (parsed.hostname or "").lower().strip(".")
            if not hostname or hostname in seen_domains:
                continue
            seen_domains.add(hostname)

            flags: List[str] = []

            # Check if originally defanged
            if "hxxp" in raw_match.lower() or "[.]" in raw_match:
                flags.append("defanged_indicator")

            # Check for raw IP address as host
            if IP_HOST_PATTERN.match(hostname):
                flags.append("ip_host")

            # Check for punycode/IDN
            if "xn--" in hostname:
                flags.append("punycode_idn")

            # Check for URL shortener
            if hostname in SHORTENERS:
                flags.append("url_shortener")

            # Check for suspicious TLD
            tld = hostname.split(".")[-1]
            if tld in SUSPICIOUS_TLDS:
                flags.append("suspicious_tld")

            # Check for executable/script extension in path or query
            path_lower = parsed.path.lower()
            for ext in SUSPICIOUS_EXTENSIONS:
                if path_lower.endswith(f".{ext}") or f".{ext}?" in path_lower:
                    flags.append(f"suspicious_file_{ext}")

            # Check for brand lookalike / typosquatting:
            # Allowlist suppresses brand lookalike alerts ONLY; never other indicators
            official = is_official_domain(hostname)
            if not official:
                for brand in FINANCIAL_BRAND_KEYWORDS:
                    if brand in hostname:
                        flags.append(f"brand_lookalike_{brand}")

            # Defang URL with query strings and fragments completely stripped
            scheme = "hxxps" if refanged.startswith("https") else "hxxp"
            clean_path = parsed.path if parsed.path else ""
            defanged = f"{scheme}://{hostname.replace('.', '[.]')}{clean_path}"
            masked_defanged = mask_sensitive_data(defanged)

            results.append({
                "defanged_url": masked_defanged,
                "domain": hostname,
                "indicator_flags": flags,
            })

        return results
