"""AI Module 1 & 3: Message Understanding, Preprocessing, Multilingual & Contextual Triage.

Capabilities:
- Text normalization (NFKC, invisible character stripping, whitespace normalization)
- Script & language identification (English, Hindi/Hinglish, Russian, Arabic, Devanagari)
- Slang, acronym, and emoji contextual interpretation
- Evasion and obfuscation detection (leetspeak, hyphens, dots, zero-width chars)
- Relevance triage (filters trivial greetings, bot commands, and pure noise to preserve token budget)
"""

from dataclasses import dataclass
import re
import unicodedata
from typing import Dict, List, Optional, Set, Tuple


@dataclass
class MessageUnderstandingResult:
    normalized_text: str
    detected_scripts: List[str]
    is_multilingual: bool
    is_relevant_for_ai: bool
    relevance_reason: str
    detected_slang: Dict[str, str]
    obfuscation_detected: bool
    token_estimate: int


# Common trivial chatter and noise
RE_TRIVIAL_NOISE = re.compile(
    r"^(hi|hello|hey|gm|gn|good morning|good night|ok|okay|k|nice|thanks|thx|cool|\?|\!|lol|lmao|yes|no|done|\+1)$",
    re.IGNORECASE,
)
RE_BOT_COMMAND = re.compile(r"^/[a-zA-Z0-9_]+(?:\s+.*)?$")

# Devanagari Unicode block (Hindi, Marathi, Nepali)
RE_DEVANAGARI = re.compile(r"[\u0900-\u097F]")
# Cyrillic Unicode block (Russian, etc.)
RE_CYRILLIC = re.compile(r"[\u0400-\u04FF]")
# Arabic Unicode block
RE_ARABIC = re.compile(r"[\u0600-\u06FF]")

# Obfuscation patterns
RE_LEETSPEAK = re.compile(r"\b[a-zA-Z0-9]*[0-9@\$!][a-zA-Z0-9]*\b")
RE_HYPHENATED_WORDS = re.compile(r"\b[a-zA-Z](?:[-._][a-zA-Z]){2,}\b")


class MessageUnderstandingEngine:
    """Enterprise text normalization, multilingual detection, and relevance triage engine."""

    def __init__(self):
        self.slang_glossary = {
            "mule": "Proxy bank account used for laundering illicit proceeds",
            "mule account": "Account rented/bought to receive fraudulent UPI or bank transfers",
            "cashing out": "Converting illicit bank balances to cash, USDT, or gold",
            "fullz": "Complete stolen victim identity (name, SSN/Aadhaar, DOB, card number, CVV)",
            "otp bot": "Telegram/IVR service designed to trick victims into revealing 2FA codes",
            "bank logs": "Active online banking credentials with session cookies",
            "sim swap": "Hijacking telecom identity to intercept 2FA SMS",
            "wh/cc": "Warehouse / Credit card stolen dumps",
            "drop": "Physical drop address or intermediate delivery point for illicit goods",
            "trc20": "TRON blockchain token commonly used in cybercrime payouts",
            "usdt": "Tether cryptocurrency often favored for cross-border fraud settlements",
            "dhamaka": "Hinglish term often used in scam promotions for massive guaranteed returns",
            "khata": "Hinglish term for bank account or passbook used in mule operations",
            "paisa": "Hinglish term for money/funds",
            "aadhar dump": "Bulk exfiltrated Indian National Identity records",
            "aadhaar dump": "Bulk exfiltrated Indian National Identity records",
            "pancard dump": "Bulk exfiltrated Permanent Account Number tax records",
            "apk mod": "Modified Android application carrying spyware, stealer, or SMS forwarder",
            "rat": "Remote Access Trojan",
            "fud": "Fully Undetectable malware payload designed to evade antivirus engines",
        }

    def normalize_text(self, text: str) -> str:
        """
        Normalize text:
        1. Unicode NFKC normalization
        2. Remove zero-width characters and control characters
        3. Normalize repeated whitespace
        """
        if not text:
            return ""

        # NFKC Normalization
        normalized = unicodedata.normalize("NFKC", text)

        # Strip zero-width spaces (\u200b, \u200c, \u200d, \ufeff)
        normalized = re.sub(r"[\u200b-\u200d\ufeff]", "", normalized)

        # Collapse whitespace
        normalized = re.sub(r"\s+", " ", normalized).strip()
        return normalized

    def identify_scripts(self, text: str) -> List[str]:
        """Detect scripts present in the text."""
        scripts: List[str] = []
        if re.search(r"[a-zA-Z]", text):
            scripts.append("Latin")
        if RE_DEVANAGARI.search(text):
            scripts.append("Devanagari (Hindi/Regional)")
        if RE_CYRILLIC.search(text):
            scripts.append("Cyrillic (Russian)")
        if RE_ARABIC.search(text):
            scripts.append("Arabic")
        return scripts

    def detect_obfuscation(self, text: str) -> bool:
        """Detect deliberate obfuscation attempts such as spaced/hyphenated words or leetspeak."""
        if RE_HYPHENATED_WORDS.search(text):
            return True
        # Check for spaced out words e.g. "l e a k"
        if re.search(r"\b[a-zA-Z]\s+[a-zA-Z]\s+[a-zA-Z]\s+[a-zA-Z]\b", text):
            return True
        return False

    def check_relevance(self, normalized_text: str) -> Tuple[bool, str]:
        """
        Determine if the message contains substantive content worthy of LLM token spend.
        Filters out pure bot greetings, trivial single words, and spam.
        """
        if not normalized_text or len(normalized_text) < 3:
            return False, "Message is too short (< 3 characters)"

        if RE_TRIVIAL_NOISE.match(normalized_text.strip()):
            return False, "Trivial conversational noise/greeting"

        if RE_BOT_COMMAND.match(normalized_text.strip()):
            return False, "Automated Telegram bot command"

        # High priority if contains indicators (URLs, @handles, numbers, crypto, or fraud keywords)
        if any(marker in normalized_text.lower() for marker in [
            "http", "t.me", "@", "bank", "pay", "upi", "leak", "pass", "account",
            "crypto", "trx", "btc", "eth", "usdt", "hack", "dump", "otp", "police"
        ]):
            return True, "Contains high-value threat keywords or indicators"

        if len(normalized_text.split()) >= 4:
            return True, "Substantive multi-word message text"

        return False, "Low-substance conversational chatter"

    def process(self, raw_text: str) -> MessageUnderstandingResult:
        """Execute full message understanding pipeline."""
        normalized = self.normalize_text(raw_text)
        scripts = self.identify_scripts(normalized)
        is_multilingual = len(scripts) > 1 or any(s != "Latin" for s in scripts)
        is_relevant, reason = self.check_relevance(normalized)
        obfuscation = self.detect_obfuscation(normalized)

        # Detect slang
        detected_slang: Dict[str, str] = {}
        norm_lower = normalized.lower()
        for term, meaning in self.slang_glossary.items():
            if term in norm_lower:
                detected_slang[term] = meaning

        # Force relevance if slang is present
        if detected_slang and not is_relevant:
            is_relevant = True
            reason = f"Contains criminal slang indicators ({', '.join(detected_slang.keys())})"

        token_estimate = max(1, len(normalized.split()) * 2)

        return MessageUnderstandingResult(
            normalized_text=normalized,
            detected_scripts=scripts,
            is_multilingual=is_multilingual,
            is_relevant_for_ai=is_relevant,
            relevance_reason=reason,
            detected_slang=detected_slang,
            obfuscation_detected=obfuscation,
            token_estimate=token_estimate,
        )
