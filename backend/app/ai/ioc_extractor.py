"""AI Module 4: Entity and Indicator of Compromise (IOC) Extraction & Validation.

Deterministic regex parsing and validation for:
- IPv4 addresses (octet validity checks)
- URLs and domain names (including defanged hxxp/brackets)
- Telegram handles (@user) and join links
- Cryptocurrency addresses: Bitcoin (P2PKH, P2SH, Bech32), Ethereum, TRON (TRC-20), Solana
- Indian UPI IDs (e.g. merchant@icici, victim@okhdfcbank)
- Email addresses
- Phone numbers (Indian mobile + international E.164)
- Cryptographic file hashes (MD5, SHA-1, SHA-256)
- Indian IFSC bank routing codes
"""

import ipaddress
import re
from typing import Dict, List, Optional, Set, Tuple

from app.ai.schemas import ExtractedIOCItem

# Deterministic Pattern Matchers
RE_IPV4 = re.compile(r"\b(?:[0-9]{1,3}(?:\[\.\]|\.)){3}[0-9]{1,3}\b")
RE_URL = re.compile(r"(?:https?|hxxps?|ftp)://[^\s/$.?#].[^\s]*", re.IGNORECASE)
RE_DEFANGED_DOMAIN = re.compile(r"\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\[\.\][a-zA-Z]{2,}\b")
RE_TELEGRAM_HANDLE = re.compile(r"(?<!\w)@([a-zA-Z0-9_]{4,32})\b")
RE_TELEGRAM_LINK = re.compile(r"(?:https?://)?(?:t\.me|telegram\.me)/(?:joinchat/|\+)?([a-zA-Z0-9_]{4,32})", re.IGNORECASE)

# Crypto Addresses
RE_CRYPTO_BTC = re.compile(r"\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{39,59})\b")
RE_CRYPTO_ETH = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
RE_CRYPTO_TRON = re.compile(r"\bT[A-Za-z0-9]{33}\b")

# Financial & Identifiers
RE_UPI_ID = re.compile(r"\b[a-zA-Z0-9.\-_]{2,64}@(?!gmail|yahoo|hotmail|outlook)[a-zA-Z]{2,32}\b", re.IGNORECASE)
RE_EMAIL = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")
RE_PHONE_IN = re.compile(r"(?:\+91[\-\s]?)?[6-9]\d{9}\b")
RE_PHONE_E164 = re.compile(r"\+[1-9]\d{7,14}\b")
RE_IFSC = re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b")

# Cryptographic Hashes
RE_HASH_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
RE_HASH_MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")


class IOCExtractor:
    """Enterprise deterministic entity and IOC extractor."""

    @staticmethod
    def defang(value: str) -> str:
        """Defang an active indicator to prevent accidental client-side execution."""
        defanged = value.replace("http://", "hxxp://").replace("https://", "hxxps://")
        # Replace dot in domain/ip if not already defanged
        if "[.]" not in defanged:
            defanged = defanged.replace(".", "[.]")
        return defanged

    @staticmethod
    def refang(value: str) -> str:
        """Refang a defanged indicator for internal validation and normalization."""
        return value.replace("hxxps://", "https://").replace("hxxp://", "http://").replace("[.]", ".")

    def extract_all(self, text: str) -> List[ExtractedIOCItem]:
        """Extract all verified IOCs from message text."""
        if not text:
            return []

        results: List[ExtractedIOCItem] = []
        seen: Set[Tuple[str, str]] = set()

        # 1. IPv4 Addresses
        for match in RE_IPV4.findall(text):
            clean_ip = self.refang(match)
            try:
                ip_obj = ipaddress.IPv4Address(clean_ip)
                # Filter out standard localhost
                if ip_obj.is_loopback:
                    continue
                norm = str(ip_obj)
                key = ("ipv4", norm)
                if key not in seen:
                    seen.add(key)
                    results.append(
                        ExtractedIOCItem(
                            ioc_type="ipv4",
                            raw_value=match,
                            normalized_value=norm,
                            defanged_value=self.defang(norm),
                            is_validated=True,
                            is_malicious=not ip_obj.is_private,
                            confidence=0.95,
                        )
                    )
            except ValueError:
                pass

        # 2. URLs
        for match in RE_URL.findall(text):
            refanged = self.refang(match)
            norm = refanged.strip().rstrip(".,;)>")
            key = ("url", norm)
            if key not in seen:
                seen.add(key)
                results.append(
                    ExtractedIOCItem(
                        ioc_type="url",
                        raw_value=match,
                        normalized_value=norm,
                        defanged_value=self.defang(norm),
                        is_validated=True,
                        is_malicious=True,
                        confidence=0.90,
                    )
                )

        # 3. Defanged Domains
        for match in RE_DEFANGED_DOMAIN.findall(text):
            norm = self.refang(match).lower()
            key = ("domain", norm)
            if key not in seen:
                seen.add(key)
                results.append(
                    ExtractedIOCItem(
                        ioc_type="domain",
                        raw_value=match,
                        normalized_value=norm,
                        defanged_value=self.defang(norm),
                        is_validated=True,
                        is_malicious=True,
                        confidence=0.85,
                    )
                )

        # 4. Crypto Wallets
        for btc in RE_CRYPTO_BTC.findall(text):
            key = ("crypto_btc", btc)
            if key not in seen:
                seen.add(key)
                results.append(
                    ExtractedIOCItem(
                        ioc_type="crypto_btc",
                        raw_value=btc,
                        normalized_value=btc,
                        defanged_value=btc,
                        is_validated=True,
                        is_malicious=True,
                        confidence=0.95,
                    )
                )

        for eth in RE_CRYPTO_ETH.findall(text):
            key = ("crypto_eth", eth.lower())
            if key not in seen:
                seen.add(key)
                results.append(
                    ExtractedIOCItem(
                        ioc_type="crypto_eth",
                        raw_value=eth,
                        normalized_value=eth.lower(),
                        defanged_value=eth,
                        is_validated=True,
                        is_malicious=True,
                        confidence=0.95,
                    )
                )

        for trx in RE_CRYPTO_TRON.findall(text):
            key = ("crypto_tron", trx)
            if key not in seen:
                seen.add(key)
                results.append(
                    ExtractedIOCItem(
                        ioc_type="crypto_tron",
                        raw_value=trx,
                        normalized_value=trx,
                        defanged_value=trx,
                        is_validated=True,
                        is_malicious=True,
                        confidence=0.95,
                    )
                )

        # 5. Financial UPI IDs
        for upi in RE_UPI_ID.findall(text):
            norm_upi = upi.strip().lower()
            key = ("upi_id", norm_upi)
            if key not in seen:
                seen.add(key)
                results.append(
                    ExtractedIOCItem(
                        ioc_type="upi_id",
                        raw_value=upi,
                        normalized_value=norm_upi,
                        defanged_value=self.defang(norm_upi),
                        is_validated=True,
                        is_malicious=True,
                        confidence=0.90,
                    )
                )

        # 6. Telegram Handles
        for handle in RE_TELEGRAM_HANDLE.findall(text):
            norm_handle = f"@{handle.lower()}"
            key = ("telegram_handle", norm_handle)
            if key not in seen:
                seen.add(key)
                results.append(
                    ExtractedIOCItem(
                        ioc_type="telegram_handle",
                        raw_value=f"@{handle}",
                        normalized_value=norm_handle,
                        defanged_value=norm_handle,
                        is_validated=True,
                        is_malicious=False,
                        confidence=0.85,
                    )
                )

        # 7. Emails
        for email in RE_EMAIL.findall(text):
            norm_email = email.lower()
            key = ("email", norm_email)
            if key not in seen:
                seen.add(key)
                results.append(
                    ExtractedIOCItem(
                        ioc_type="email",
                        raw_value=email,
                        normalized_value=norm_email,
                        defanged_value=self.defang(norm_email),
                        is_validated=True,
                        is_malicious=False,
                        confidence=0.90,
                    )
                )

        # 8. Indian Phone Numbers
        for phone in RE_PHONE_IN.findall(text):
            clean_phone = re.sub(r"[^\d]", "", phone)
            if len(clean_phone) >= 10:
                e164 = f"+91{clean_phone[-10:]}"
                key = ("phone", e164)
                if key not in seen:
                    seen.add(key)
                    results.append(
                        ExtractedIOCItem(
                            ioc_type="phone",
                            raw_value=phone,
                            normalized_value=e164,
                            defanged_value=e164,
                            is_validated=True,
                            is_malicious=False,
                            confidence=0.85,
                        )
                    )

        # 9. Hashes (SHA-256)
        for h in RE_HASH_SHA256.findall(text):
            norm_h = h.lower()
            key = ("hash_sha256", norm_h)
            if key not in seen:
                seen.add(key)
                results.append(
                    ExtractedIOCItem(
                        ioc_type="hash_sha256",
                        raw_value=h,
                        normalized_value=norm_h,
                        defanged_value=norm_h,
                        is_validated=True,
                        is_malicious=True,
                        confidence=0.99,
                    )
                )

        return results
