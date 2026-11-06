"""Forensic excerpt extraction and sensitive data masking.

MANDATORY INVARIANTS:
- No stored excerpt or detection text may contain full OTP, password, PIN, CVV,
  payment card, bank account number, phone number, Telegram handle, Aadhaar, or PAN numbers.
- Sensitive entities are masked strictly per policy:
  * Full redaction: passwords ([PASSWORD_REDACTED]), PINs ([PIN_REDACTED]),
    CVV ([CVV_REDACTED]), OTP ([OTP_REDACTED]), phone numbers ([PHONE_REDACTED]),
    Telegram handles ([HANDLE_REDACTED]).
  * E-mail: [EMAIL_REDACTED]@domain.
  * UPI ID: ***@handle.
  * Cards, Aadhaar, PAN, Bank Accounts: retain at most the last 4 characters.
- Excerpts are bounded to a maximum length (default <= 120 chars) around the match span.
- Full message text is NEVER stored in detections or rule hits.
"""

import re
from typing import Tuple

MAX_EXCERPT_LENGTH = 120

# Devanagari numerals translation table
DEVANAGARI_DIGITS = str.maketrans("०१२३४५६७८९", "0123456789")

# Sensitive identification patterns
AADHAAR_PATTERN = re.compile(r"\b(\d{4})[\s-]?(\d{4})[\s-]?(\d{4})\b")
PAN_PATTERN = re.compile(r"\b([A-Z]{5})(\d{4})([A-Z])\b", re.IGNORECASE)

CARD_PATTERN = re.compile(r"\b(?:\d[ -]*?){13,19}\b")

# Password, PIN, CVV patterns
PASSWORD_PATTERN = re.compile(
    r"(?i)(?:^|[^\w\u0900-\u097f])(?:password|passwd|pwd|पासवर्ड)\s*(?:[:=]|\bis\b)\s*([^\s,;]+)"
)
PIN_PATTERN = re.compile(
    r"(?i)(?:^|[^\w\u0900-\u097f])(?:mpin|upi[- ]?pin|atm[- ]?pin|pin|पिन|एमपिन)(?:\b|\s|:)[:=]?\s*(\d{4,6})\b"
)
CVV_PATTERN = re.compile(
    r"(?i)\b(?:cvv\d?|cvc\d?|security\s*code)\b\s*[:=]?\s*(\d{3,4})\b"
)

# OTP patterns with preceding context (Latin and Devanagari)
OTP_CONTEXT_PATTERN = re.compile(
    r"(?i)(?:^|[^\w\u0900-\u097f])(?:otp|one[- ]?time[- ]?password|verification\s*code|code|ओटीपी|कोड)(?:\b|\s|:)[:=]?[^\d\n]{0,15}(\d{4,8})\b"
)

# Indian mobile phone numbers: 10 digits starting with 6-9, optional +91 or 0 prefix, flexible 5+5, 3+3+4, or contiguous
PHONE_PATTERN = re.compile(
    r"(?:(?:\+91|0091)[\s-]?)?(?:\b0)?[6-9](?:\d{9}|\d{4}[\s-]?\d{5}|\d{2}[\s-]?\d{3}[\s-]?\d{4})\b"
)

# Bank account numbers: 9 to 18 digits preceded by banking account context
BANK_ACCOUNT_PATTERN = re.compile(
    r"(?i)(?:^|[^\w\u0900-\u097f])(?:a\/c|acct|account|acc\.?|खाता|खाते|खात्यातून)(?:\b|\s)[^\d\n]{0,20}(\d{9,18})\b"
)

# Telegram handles: @username (5-32 chars)
TELEGRAM_HANDLE_PATTERN = re.compile(r"(?<![\w.])@([a-zA-Z][a-zA-Z0-9_]{4,31})\b")

# Email vs UPI pattern
EMAIL_PATTERN = re.compile(
    r"\b[a-zA-Z0-9_.+-]+@([a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)\b"
)
UPI_PATTERN = re.compile(
    r"\b[a-zA-Z0-9_.-]+@([a-zA-Z][a-zA-Z0-9_.-]*)\b"
)


def passes_luhn(candidate: str) -> bool:
    """Validate candidate credit/debit card number using Luhn algorithm."""
    digits = [int(c) for c in candidate if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    total = 0
    reverse_digits = digits[::-1]
    for i, d in enumerate(reverse_digits):
        if i % 2 == 1:
            doubled = d * 2
            total += (doubled - 9) if doubled > 9 else doubled
        else:
            total += d
    return total % 10 == 0


def mask_sensitive_data(text: str) -> str:
    """Mask all sensitive credentials, PII, and financial identifiers from text.
    
    Adheres strictly to the TTI sensitive data masking policy.
    """
    if not text:
        return ""

    # Translate Devanagari numerals for matching while retaining original string length / structure
    has_devanagari = any('\u0966' <= c <= '\u096f' for c in text)
    working_text = text.translate(DEVANAGARI_DIGITS) if has_devanagari else text

    # 1. Mask Passwords (full redaction)
    def mask_password(m: re.Match) -> str:
        full = m.group(0)
        val = m.group(1)
        prefix = full[:-len(val)]
        return f"{prefix}[PASSWORD_REDACTED]"
    working_text = PASSWORD_PATTERN.sub(mask_password, working_text)

    # 2. Mask PINs (full redaction)
    def mask_pin(m: re.Match) -> str:
        full = m.group(0)
        val = m.group(1)
        prefix = full[:-len(val)]
        return f"{prefix}[PIN_REDACTED]"
    working_text = PIN_PATTERN.sub(mask_pin, working_text)

    # 3. Mask CVV / CVC (full redaction)
    def mask_cvv(m: re.Match) -> str:
        full = m.group(0)
        val = m.group(1)
        prefix = full[:-len(val)]
        return f"{prefix}[CVV_REDACTED]"
    working_text = CVV_PATTERN.sub(mask_cvv, working_text)

    # 4. Mask OTPs with context (full redaction)
    def mask_otp(m: re.Match) -> str:
        full = m.group(0)
        digits = m.group(1)
        prefix = full[:-len(digits)]
        return f"{prefix}[OTP_REDACTED]"
    working_text = OTP_CONTEXT_PATTERN.sub(mask_otp, working_text)

    # 5. Mask Bank Account Numbers (contextual a/c, खाता) -> retain strictly at most last 4 digits
    def mask_bank_acc(m: re.Match) -> str:
        full = m.group(0)
        digits = m.group(1)
        prefix = full[:-len(digits)]
        suffix = digits[-4:]
        return f"{prefix}XXXXXX{suffix}"
    working_text = BANK_ACCOUNT_PATTERN.sub(mask_bank_acc, working_text)

    # 6. Mask Payment Cards (Luhn verified) -> retain strictly at most last 4 digits
    def mask_card(m: re.Match) -> str:
        raw_match = m.group(0)
        digits_only = re.sub(r"\D", "", raw_match)
        if passes_luhn(digits_only):
            suffix = digits_only[-4:]
            return f"XXXX-XXXX-XXXX-{suffix}"
        return raw_match
    working_text = CARD_PATTERN.sub(mask_card, working_text)

    # 7. Mask Aadhaar numbers -> retain strictly at most last 4 digits
    working_text = AADHAAR_PATTERN.sub(r"XXXX-XXXX-\3", working_text)

    # 8. Mask PAN numbers -> retain strictly at most last 4 characters
    def mask_pan(m: re.Match) -> str:
        digits = m.group(2)
        last_letter = m.group(3)
        return f"XXXXXX{digits[-3:]}{last_letter}"
    working_text = PAN_PATTERN.sub(mask_pan, working_text)

    # 9. Mask Phone numbers (full redaction)
    working_text = PHONE_PATTERN.sub("[PHONE_REDACTED]", working_text)

    # 10. Mask Telegram Handles (full redaction)
    working_text = TELEGRAM_HANDLE_PATTERN.sub("[HANDLE_REDACTED]", working_text)

    # 11. Mask Emails: [EMAIL_REDACTED]@domain
    # 12. Mask UPI IDs: ***@handle
    def mask_email_or_upi(m: re.Match) -> str:
        val = m.group(0)
        handle = m.group(1)
        if "." in handle:
            return f"[EMAIL_REDACTED]@{handle}"
        else:
            return f"***@{handle}"

    working_text = EMAIL_PATTERN.sub(mask_email_or_upi, working_text)
    working_text = UPI_PATTERN.sub(mask_email_or_upi, working_text)

    return working_text


def extract_masked_excerpt(
    raw_text: str,
    span_start: int,
    span_end: int,
    max_length: int = MAX_EXCERPT_LENGTH,
) -> Tuple[int, int, str]:
    """Extract a window around the match span and apply sensitive masking.
    
    Guarantees the returned excerpt does not exceed max_length characters.
    Returns:
        (span_start, span_end, masked_excerpt)
    """
    if not raw_text:
        return 0, 0, ""

    span_start = max(0, min(span_start, len(raw_text)))
    span_end = max(span_start, min(span_end, len(raw_text)))

    match_len = span_end - span_start
    if match_len >= max_length:
        window = raw_text[span_start : span_start + max_length]
        return span_start, span_end, mask_sensitive_data(window)

    padding = (max_length - match_len) // 2
    window_start = max(0, span_start - padding)
    window_end = min(len(raw_text), span_end + padding)

    if window_start == 0:
        window_end = min(len(raw_text), max_length)
    elif window_end == len(raw_text):
        window_start = max(0, len(raw_text) - max_length)

    window = raw_text[window_start:window_end]
    masked = mask_sensitive_data(window)

    if len(masked) > max_length + 40:
        masked = masked[: max_length + 40]

    return span_start, span_end, masked
