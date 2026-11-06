"""Phase 3 Test Suite: Threat Detection Rules Engine, Normalizer, Masking, Stance & URL Indicators."""

import os
from pathlib import Path
import re
import socket
import time
from unittest.mock import patch
import uuid
import pytest

from app.detection.detectors import (
    EntityDetector,
    KeywordDetector,
    PhraseDetector,
    ReDoSChecker,
    RegexDetector,
    RuleExecutionTimeoutError,
    RuleMatch,
)
from app.detection.engine import (
    ENGINE_VERSION,
    MAX_MESSAGE_LENGTH,
    ThreatDetectionEngine,
)
from app.detection.masking import (
    extract_masked_excerpt,
    mask_sensitive_data,
    passes_luhn,
)
from app.detection.normalizer import TextNormalizer
from app.detection.scoring import calculate_rule_confidence, resolve_severity
from app.detection.stance import StanceClassifier
from app.detection.url_indicators import (
    URLIndicatorDetector,
    defang_url,
    is_official_domain,
)


def test_text_normalizer_multilingual_and_defanging():
    """Verify Devanagari numerals, zero-width chars, acronyms, and defanging."""
    raw = "Sir aapka K Y C expire ho gaya, click hxxp://sbi-rewards-claim[.]xyz/update"
    norm = TextNormalizer.normalize(raw)
    assert "KYC" in norm.text
    assert "http://sbi-rewards-claim.xyz/update" in norm.text

    # Devanagari digits conversion ०-९ -> 0-9
    devanagari_num = "१२३४५६"
    norm_dev = TextNormalizer.normalize(devanagari_num)
    assert "123456" in norm_dev.text

    # Offset mapping accuracy
    raw_span_start, raw_span_end = norm.get_raw_span(norm.text.find("KYC"), norm.text.find("KYC") + 3)
    assert raw[raw_span_start:raw_span_end] == "K Y C"


def test_luhn_algorithm():
    """Verify Luhn card number verification."""
    assert passes_luhn("4532015112830366") is True
    assert passes_luhn("453201511283037") is False
    assert passes_luhn("12345") is False


def test_sensitive_masking_independent_corpus():
    """Verify masking across independent synthetic corpus of sensitive entities."""
    corpus = [
        # Passwords & PINs (full redaction)
        ("Admin password: SecretPass123! for system access", "[PASSWORD_REDACTED]", "SecretPass123!"),
        ("तुमचा पासवर्ड: MySecret999 कोणालाही सांगू नका", "[PASSWORD_REDACTED]", "MySecret999"),
        ("Enter UPI PIN: 8492 to authorize payment", "[PIN_REDACTED]", "8492"),
        ("आपका एमपिन: 6721 किसी को न बताएं", "[PIN_REDACTED]", "6721"),
        ("ATM card security code CVV: 482", "[CVV_REDACTED]", "482"),
        ("Card details: CVC 914", "[CVV_REDACTED]", "914"),

        # OTPs (full redaction)
        ("Your one-time password OTP is 984512 valid for 10 mins", "[OTP_REDACTED]", "984512"),
        ("बैंक सत्यापन कोड 458912 प्राप्त हुआ", "[OTP_REDACTED]", "458912"),

        # Indian Phone Numbers (full redaction, keep NO digits)
        ("Call manager at +91-9876543210 immediately", "[PHONE_REDACTED]", "9876543210"),
        ("Helpline number 09823456789 par sampark karein", "[PHONE_REDACTED]", "09823456789"),
        ("कृपया 87654 32109 या क्रमांकावर संपर्क करा", "[PHONE_REDACTED]", "87654 32109"),

        # Telegram handles (full redaction)
        ("Contact recruiter on Telegram @scam_agent_99 for tasks", "[HANDLE_REDACTED]", "@scam_agent_99"),

        # Email & UPI IDs
        ("Send confirmation to fraudster@phishing-portal.com now", "[EMAIL_REDACTED]@phishing-portal.com", "fraudster@"),
        ("Transfer 500 to payment.support@okhdfcbank via GPay", "***@okhdfcbank", "payment.support"),
        ("Pay to merchant@ybl immediately", "***@ybl", "merchant"),

        # Payment Cards (retain only last 4 digits)
        ("Card 4532-0151-1283-0366 was debited", "XXXX-XXXX-XXXX-0366", "4532-0151-1283"),

        # Bank Account Numbers (retain only last 4 digits)
        ("Bank A/c 50100234567890 credited with Rs 5000", "XXXXXX7890", "5010023456"),
        ("आपके खाता संख्या 123456789012 से राशि कटी", "XXXXXX9012", "12345678"),

        # Aadhaar & PAN (retain only last 4 chars)
        ("Aadhaar number 1234 5678 9012 registered", "XXXX-XXXX-9012", "1234 5678"),
        ("PAN card ABCDE1234F updated", "XXXXXX234F", "ABCDE"),
    ]

    for raw, expected_token, forbidden_substring in corpus:
        masked = mask_sensitive_data(raw)
        assert expected_token in masked, f"Expected '{expected_token}' in masked text: '{masked}'"
        assert forbidden_substring not in masked, f"Forbidden substring '{forbidden_substring}' leaked in: '{masked}'"


def test_devanagari_digits_masking():
    """Verify sensitive numbers containing Devanagari numerals are masked cleanly."""
    raw_hindi_phone = "अधिकारी से ९८७६५४३२१० पर बात करें"
    masked = mask_sensitive_data(raw_hindi_phone)
    assert "[PHONE_REDACTED]" in masked
    assert "९८७६५४३२१०" not in masked

    raw_hindi_otp = "आपका ओटीपी १२३४५६ है"
    masked_otp = mask_sensitive_data(raw_hindi_otp)
    assert "[OTP_REDACTED]" in masked_otp
    assert "१२३४५६" not in masked_otp


def test_excerpt_length_and_masking():
    """Verify excerpt bounding <= 120 chars with sensitive redaction."""
    long_text = "A" * 300 + " OTP: 456789 " + "B" * 300
    start, end, excerpt = extract_masked_excerpt(long_text, 301, 312, max_length=120)
    assert len(excerpt) <= 160  # max 120 + redaction token expansion
    assert "456789" not in excerpt
    assert "[OTP_REDACTED]" in excerpt


def test_stance_classifier_multilingual():
    """Verify stance classification across all 4 target languages."""
    # Warning
    assert StanceClassifier.classify("Never share your OTP or passwords with anyone") == "warning"
    assert StanceClassifier.classify("सावधान: किसी को भी ओटीपी मत बताना") == "warning"
    assert StanceClassifier.classify("सतर्क राहा! कोणालाही बँकेचा पिन सांगू नका") == "warning"
    assert StanceClassifier.classify("Kisi ko bhi OTP mat batana, bank kabhi nahi maangta") == "warning"

    # Potentially Facilitating (renamed from facilitating)
    assert StanceClassifier.classify("Click here immediately to update your blocked account") == "potentially_facilitating"
    assert StanceClassifier.classify("खाता 24 घंटे में ब्लॉक हो जाएगा तुरंत क्लिक करें") == "potentially_facilitating"
    assert StanceClassifier.classify("खाते ब्लॉक होईल त्वरित खालील लिंकवर क्लिक करा") == "potentially_facilitating"
    assert StanceClassifier.classify("Guaranteed 300% returns in 7 days on crypto arbitrage") == "potentially_facilitating"

    # Reporting
    assert StanceClassifier.classify("I lost 45,000 rupees yesterday when a caller pretending to be FedEx") == "reporting"
    assert StanceClassifier.classify("कल मेरे खाते से 30,000 रुपये कट गए जब एक फर्जी कॉल आया") == "reporting"
    assert StanceClassifier.classify("माझ्या खात्यातून 25000 रुपये कपात झाले फसवणूक झाली") == "reporting"

    # Discussing
    assert StanceClassifier.classify("In our cybersecurity class today, we analyzed how phishing kits work") == "discussing"
    assert StanceClassifier.classify("सायबर सेलमध्ये 1930 वर तक्रार कशी नोंदवायची?") == "discussing"

    # None (only when no detections)
    assert StanceClassifier.classify("Meeting 5 baje hai, doc bhej do", has_detections=False) == "none"

    # Unclear (detections exist but stance intent is unclassified or conflicting)
    assert StanceClassifier.classify("Suspicious string without clear intent", has_detections=True) == "unclear"


def test_url_allowlist_boundaries_and_spoofing():
    """Verify official domain allowlist strictly matches on label boundaries and rejects spoofing."""
    test_allowlist = (
        {"bank.in", "fin.in", "gov.in", "nic.in"},
        {"sbi.co.in", "onlinesbi.sbi", "hdfcbank.com", "cybercrime.gov.in", "pmkisan.gov.in"}
    )

    # With reviewed allowlist: Official domains and subdomains -> Allowed
    assert is_official_domain("sbi.co.in", allowlist=test_allowlist) is True
    assert is_official_domain("retail.onlinesbi.sbi", allowlist=test_allowlist) is True
    assert is_official_domain("netbanking.hdfcbank.com", allowlist=test_allowlist) is True
    assert is_official_domain("cybercrime.gov.in", allowlist=test_allowlist) is True
    assert is_official_domain("pmkisan.gov.in", allowlist=test_allowlist) is True
    assert is_official_domain("pnb.bank.in", allowlist=test_allowlist) is True  # .bank.in TLD
    assert is_official_domain("portal.fin.in", allowlist=test_allowlist) is True  # .fin.in TLD

    # Deceptive lookalikes & substrings -> NOT allowed
    assert is_official_domain("sbi.co.in.evil.xyz", allowlist=test_allowlist) is False
    assert is_official_domain("evil.com", allowlist=test_allowlist) is False
    assert is_official_domain("sbi-update-kyc.top", allowlist=test_allowlist) is False
    assert is_official_domain("hdfc-reward-claim.xyz", allowlist=test_allowlist) is False
    assert is_official_domain("fake-pmkisan.online", allowlist=test_allowlist) is False
    assert is_official_domain("xn--sb-e9s.co.in", allowlist=test_allowlist) is False  # punycode lookalike

    # When all YAML entries are unreviewed (default repo state):
    assert is_official_domain("sbi.co.in") is False


def test_url_indicator_strips_query_string_and_fragments():
    """Verify query strings and URL fragments are completely stripped from stored defanged URLs."""
    raw = "Phishing link: https://evil-bank.com/login?phone=9876543210&otp=123456&email=victim@target.com#confirm_step"
    indicators = URLIndicatorDetector.analyze_text(raw)
    assert len(indicators) == 1
    stored = indicators[0]["defanged_url"]
    assert stored == "hxxps://evil-bank[.]com/login"
    assert "9876543210" not in stored
    assert "123456" not in stored
    assert "victim@target.com" not in stored
    assert "?" not in stored
    assert "#" not in stored


def test_allowlist_suppresses_only_brand_lookalike():
    """Verify reviewed allowlist suppresses ONLY brand_lookalike, never APK, shorteners, or IP hosts."""
    test_allowlist = ({"bank.in"}, {"sbi.co.in", "bit.ly"})

    # 1. Official domain with APK still triggers suspicious_file_apk
    with patch("app.detection.url_indicators.load_official_allowlist", return_value=test_allowlist):
        indicators = URLIndicatorDetector.analyze_text("Download from https://sbi.co.in/app.apk")
        assert len(indicators) == 1
        flags = indicators[0]["indicator_flags"]
        assert "brand_lookalike_sbi" not in flags  # Suppressed!
        assert "suspicious_file_apk" in flags      # NOT suppressed!

    # 2. Shortener with official name still triggers url_shortener
    with patch("app.detection.url_indicators.load_official_allowlist", return_value=test_allowlist):
        indicators = URLIndicatorDetector.analyze_text("Link: https://bit.ly/sbi_claim")
        assert len(indicators) == 1
        flags = indicators[0]["indicator_flags"]
        assert "url_shortener" in flags            # NOT suppressed!


def test_entity_validity_ifsc_and_upi():
    """Verify IFSC code and UPI VPA entity pattern validation."""
    rule_ifsc = {
        "rule_id": "test_ifsc",
        "category": "banking_fraud",
        "rule_type": "entity",
        "pattern_payload": {"entity_type": "ifsc"},
        "is_enabled": True,
        "is_reviewed": True,
    }
    detector_ifsc = EntityDetector(rule_ifsc)
    norm_valid_ifsc = TextNormalizer.normalize("Transfer to SBIN0001234 or HDFC0000456")
    matches = detector_ifsc.match(norm_valid_ifsc)
    assert len(matches) == 2

    norm_invalid_ifsc = TextNormalizer.normalize("Invalid codes: SBIN1001234 and SBI00012")
    assert len(detector_ifsc.match(norm_invalid_ifsc)) == 0

    rule_upi = {
        "rule_id": "test_upi",
        "category": "upi_fraud",
        "rule_type": "entity",
        "pattern_payload": {"entity_type": "upi"},
        "is_enabled": True,
        "is_reviewed": True,
    }
    detector_upi = EntityDetector(rule_upi)
    norm_valid_upi = TextNormalizer.normalize("Pay to merchant@okhdfcbank or fraudster@paytm")
    matches_upi = detector_upi.match(norm_valid_upi)
    assert len(matches_upi) == 2

    norm_invalid_upi = TextNormalizer.normalize("Not upi: user@unknownbank or user@@paytm or user@")
    assert len(detector_upi.match(norm_invalid_upi)) == 0


def test_severity_matrix_calculation():
    """Verify severity resolution based on stance, rule severities, and URL indicators."""
    assert resolve_severity(["HIGH"], "potentially_facilitating", indicator_count=0) in ("HIGH", "CRITICAL")
    assert resolve_severity(["HIGH"], "warning", indicator_count=0) == "LOW"
    assert resolve_severity(["HIGH"], "discussing", indicator_count=0) == "INFO"
    assert resolve_severity(["LOW"], "potentially_facilitating", indicator_count=1) == "MEDIUM"


def test_url_indicator_detector_offline_zero_network():
    """Verify URL indicator detection runs strictly offline with zero socket calls."""
    with patch.object(socket, "socket", side_effect=RuntimeError("Network access forbidden")), \
         patch("app.detection.url_indicators.load_official_allowlist", return_value=(set(), {"sbi.co.in"})):
        indicators = URLIndicatorDetector.analyze_text(
            "Claim prize at hxxps://sbi-rewards-claim[.]xyz/bonus.apk or visit http://192.168.1.1/pay or https://sbi.co.in/legit"
        )

    assert len(indicators) >= 2
    domains = [ind["domain"] for ind in indicators]
    assert "sbi-rewards-claim.xyz" in domains
    assert "192.168.1.1" in domains
    assert "sbi.co.in" in domains

    # Spoofed domain gets brand_lookalike
    sbi_spoof = [ind for ind in indicators if ind["domain"] == "sbi-rewards-claim.xyz"][0]
    assert "brand_lookalike_sbi" in sbi_spoof["indicator_flags"]
    assert "suspicious_file_apk" in sbi_spoof["indicator_flags"]

    # Official domain does NOT get brand_lookalike
    sbi_official = [ind for ind in indicators if ind["domain"] == "sbi.co.in"][0]
    assert "brand_lookalike_sbi" not in sbi_official["indicator_flags"]


def test_redos_checker():
    """Verify ReDoS checker rejects vulnerable nested quantifiers."""
    safe_pattern = r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"
    assert ReDoSChecker.is_safe(safe_pattern) is True

    unsafe_pattern = r"(a+)+"
    assert ReDoSChecker.is_safe(unsafe_pattern) is False


def test_hard_message_length_cap():
    """Verify engine rejects inputs exceeding MAX_MESSAGE_LENGTH = 4096."""
    engine = ThreatDetectionEngine([])
    oversized = "A" * (MAX_MESSAGE_LENGTH + 1)
    with pytest.raises(ValueError, match="exceeds maximum allowed limit of 4096 characters"):
        engine.analyze_message(oversized, tenant_id=uuid.uuid4(), message_id="oversized_test")


def test_rule_execution_timeout_and_degraded_fallback():
    """Verify rule timeouts increment counter, mark execution degraded, and route to human review."""
    class SlowDetector:
        rule_id = "test_slow_rule"
        category = "phishing"

        def match(self, norm_text):
            raise RuleExecutionTimeoutError("test_slow_rule", timeout_seconds=0.05)

    engine = ThreatDetectionEngine([])
    engine.detectors.append(SlowDetector())

    # Add a normal detector that hits
    engine.detectors.append(KeywordDetector({
        "rule_id": "fast_hit",
        "category": "phishing",
        "pattern_payload": {"keywords": ["urgent"]},
    }))

    results = engine.analyze_message(
        "urgent verification required",
        tenant_id=uuid.uuid4(),
        message_id="timeout_test"
    )

    assert len(results) == 1
    res = results[0]
    assert res.is_degraded is True
    assert res.stance == "unclear"  # Routed to human review
    assert "DEGRADED_EXECUTION_TIMEOUT" in res.explanation
    assert engine.rule_timeout_counts["test_slow_rule"] == 1


def test_open_closed_extensibility():
    """Verify engine can register custom detectors via protocol without modifying core engine."""
    class CustomCryptoDetector:
        def __init__(self):
            self.rule_id = "custom_crypto_wallet"
            self.category = "crypto_drainer"
            self.weight = 2.0
            self.severity = "CRITICAL"
            self.explanation = "Detected custom crypto wallet pattern"
            self.taxonomy_version = "2026.03.1"

        def match(self, norm_text):
            if "0x" in norm_text.text:
                return [
                    RuleMatch(
                        rule_id=self.rule_id,
                        category=self.category,
                        weight=self.weight,
                        severity=self.severity,
                        explanation=self.explanation,
                        span_start=0,
                        span_end=4,
                        masked_excerpt="0x123...",
                        taxonomy_version=self.taxonomy_version,
                    )
                ]
            return []

    engine = ThreatDetectionEngine([])
    engine.detectors.append(CustomCryptoDetector())

    results = engine.analyze_message(
        "Send gas to 0x71C... immediately",
        tenant_id=uuid.uuid4(),
        message_id="ext_test"
    )
    assert len(results) == 1
    assert results[0].category == "crypto_drainer"
    assert results[0].severity == "CRITICAL"


def test_production_rule_review_gate(monkeypatch):
    """Verify unreviewed rules are excluded when TTI_ENV=production."""
    rules = [
        {
            "rule_id": "rule_reviewed",
            "category": "phishing",
            "rule_type": "keyword",
            "is_enabled": True,
            "is_reviewed": True,
            "pattern_payload": {"keywords": ["testphish"]},
        },
        {
            "rule_id": "rule_unreviewed",
            "category": "phishing",
            "rule_type": "keyword",
            "is_enabled": True,
            "is_reviewed": False,
            "pattern_payload": {"keywords": ["unreviewedphish"]},
        },
    ]

    monkeypatch.setenv("TTI_ENV", "development")
    engine_dev = ThreatDetectionEngine(rules)
    assert len(engine_dev.detectors) == 2

    monkeypatch.setenv("TTI_ENV", "production")
    engine_prod = ThreatDetectionEngine(rules)
    assert len(engine_prod.detectors) == 1
    assert engine_prod.detectors[0].rule_id == "rule_reviewed"

    # With all rules in repo currently is_reviewed=False, production engine loads 0 rules
    from app.detection.taxonomy_loader import load_taxonomy_from_directory
    tax_dir = Path("backend/rules/taxonomy") if Path("backend/rules/taxonomy").exists() else Path("rules/taxonomy")
    _, repo_rules = load_taxonomy_from_directory(tax_dir)
    engine_repo_prod = ThreatDetectionEngine(repo_rules)
    assert len(engine_repo_prod.detectors) == 0
    assert engine_repo_prod.reviewed_rules_loaded == 0
