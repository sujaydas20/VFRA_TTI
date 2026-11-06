"""Python Core Keyword Detection Engine (Normal & Advanced Threat Analysis).

Provides:
1. Normal Keyword Detection (pure Python algorithms, no AI calls):
   - Usernames, emails, phone numbers, URLs, domains
   - Normal vocabulary frequency analysis, n-grams
   - Frequently occurring keywords and repeated phrases
   - Commonly used social engineering / spam terms

2. Advanced Threat Keyword Detection:
   - Cybercrime, dark web, malware, ransomware, data leak, fraud terms
   - Threat-related emojis and emoji-word combinations
   - Context-dependent illicit expressions

3. Triage & Filtering Layer:
   - First-line defense to filter benign chatter
   - Decides whether to escalate to Google Gemini AI
"""

from collections import Counter
from dataclasses import dataclass, field
import hashlib
import re
from typing import Any, Dict, List, Optional, Set, Tuple
import unicodedata

# -----------------------------------------------------------------------------
# Compiled Regular Expressions for Normal Extraction
# -----------------------------------------------------------------------------
RE_USERNAME = re.compile(r"(?<!\w)@([a-zA-Z0-9_]{3,32})\b")
RE_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")
RE_PHONE_INTL = re.compile(r"\+[1-9]\d{7,14}\b")
RE_PHONE_DOMESTIC = re.compile(r"\b(?:\+91|91)?[6-9]\d{9}\b")
RE_URL = re.compile(r"(?:https?|ftp|hxxps?|hXXp)://[^\s/$.?#].[^\s]*", re.IGNORECASE)
RE_DOMAIN = re.compile(
    r"\b(?:[a-zA-Z0-9-]+\.)+(?:com|org|net|io|in|ru|cn|cc|to|xyz|top|biz|info|me|co|app|live)\b",
    re.IGNORECASE,
)

# -----------------------------------------------------------------------------
# Predefined Dictionaries & Knowledge Bases
# -----------------------------------------------------------------------------

# Commonly used suspicious / spam / social engineering terms (Normal Detection)
COMMON_SUSPICIOUS_TERMS: Set[str] = {
    "urgent", "act fast", "limited offer", "limited time", "pm me", "dm me",
    "contact inbox", "inbox me", "guaranteed profit", "free money", "easy cash",
    "secret deal", "work from home", "no risk", "exclusive offer", "click here",
    "join now", "discount", "free access", "giveaway", "winner", "congratulations",
    "claim now", "special price", "fast delivery", "instant bonus",
}

# Stop words to filter during frequency analysis
STOP_WORDS: Set[str] = {
    "the", "a", "an", "and", "or", "but", "in", "on", "at", "to", "for", "of",
    "with", "by", "from", "up", "about", "into", "over", "after", "is", "are",
    "was", "were", "be", "been", "being", "have", "has", "had", "do", "does",
    "did", "will", "would", "shall", "should", "may", "might", "must", "can",
    "could", "i", "you", "he", "she", "it", "we", "they", "me", "him", "her",
    "us", "them", "my", "your", "his", "its", "our", "their", "this", "that",
    "these", "those", "hai", "ka", "ki", "ke", "ko", "se", "me", "par", "bhi",
    "aur", "toh", "ye", "woh", "kya", "kyu", "karo", "karna", "hoga", "tha",
}

# Advanced Threat Categories and Terminology
THREAT_LEXICONS: Dict[str, Set[str]] = {
    "MALWARE_RANSOMWARE": {
        "rat", "remote access trojan", "stealer", "infostealer", "redline",
        "lumma", "vidar", "raccoon", "crypter", "fud", "fud crypter", "payload",
        "ransomware", "decryptor", "keylogger", "botnet", "botnet builder",
        "shellcode", "exploit kit", "malicious apk", "mod apk", "dropper",
        "loader", "rootkit", "c2", "command and control",
    },
    "DATA_LEAKS_CREDENTIALS": {
        "leak", "database leak", "databreed", "database dump", "sql dump",
        "combo list", "combolist", "fullz", "plaintext", "aadhaar dump",
        "aadhaar leak", "pan dump", "voter dump", "voter id dump", "passport dump",
        "kyc dump", "otp bot", "otp bypass", "session dump", "tdata", "stealer log",
        "credentials dump", "breached db",
    },
    "BANKING_FINANCIAL_FRAUD": {
        "mule account", "mule bank", "bank logs", "netbanking logs", "cloned card",
        "cvv", "cvv dump", "bin dump", "cashout", "cashing out", "hawala",
        "counterfeit currency", "fake currency", "cheque bounce", "carding",
        "carder", "pos cashout", "atm clone",
    },
    "UPI_PHISHING_SCAMS": {
        "upi fraud", "fake payment screenshot", "fake paytm", "fake gpay",
        "upi mandate", "cashback scam", "phishing link", "fake banking portal",
        "kyc suspension", "kyc update", "task scam", "telegram task", "crypto doubling",
        "loan app harassment", "instant loan hack",
    },
    "DARK_WEB_CYBERCRIME": {
        "darknet", "dark web", "onion link", "tor browser", "escrow service",
        "bulletproof hosting", "hacker for hire", "hire hacker", "doxxing",
        "sim swap", "sim swapping", "call spoofing", "sms bomber", "ddos attack",
    },
}

# Threat-related emojis
THREAT_EMOJIS: Dict[str, str] = {
    "💰": "Money bag (illicit cashout / funds)",
    "💳": "Credit card (carding / stolen CVV / bank logs)",
    "🤫": "Shushing face (clandestine / private deal)",
    "🐀": "Rat (Remote Access Trojan / snitch)",
    "💣": "Bomb (database dump / destructive exploit)",
    "💉": "Syringe (code injection / malware payload)",
    "💀": "Skull (lethal / destructive malware)",
    "⚡️": "High voltage (fast cashout / blitz raid)",
    "🚨": "Police siren (urgent law enforcement / scam alert)",
    "💵": "Dollar banknote (illicit payout / cash)",
    "🤑": "Money-mouth (high profit scam lure)",
    "🔓": "Unlocked (cracked software / bypass tool)",
    "📦": "Package (shipped contraband / log package)",
    "🛒": "Shopping cart (dark market checkout / accounts for sale)",
    "⚠️": "Warning (threat advisory / fake alert)",
    "🔥": "Fire (hot dump / fresh credentials)",
    "🧨": "Firecracker (exploit drop)",
    "🏴‍☠️": "Pirate flag (cybercrime / illicit syndicate)",
}

# Emoji + Keyword combinations indicating high-probability threat operations
EMOJI_WORD_COMBOS: List[Tuple[str, str, str]] = [
    ("💳", "cvv", "Carding / Stolen Credit Card CVV Operation"),
    ("💳", "dump", "Stolen Bank Card Track Dump"),
    ("💳", "card", "Card Cloning Operation"),
    ("💳", "fullz", "Full Stolen Identity with Financial Data"),
    ("💰", "mule", "Mule Bank Account Money Laundering"),
    ("💰", "cashout", "Illicit Funds Cashout Network"),
    ("💰", "usdt", "Cryptocurrency Laundering / Cashout"),
    ("🤫", "deal", "Clandestine Cybercrime Transaction"),
    ("🤫", "private", "Private Illicit Syndicate Access"),
    ("💣", "leak", "Explosive Database Leak / Breach Drop"),
    ("💣", "dump", "Mass Database Exfiltration"),
    ("🚨", "kyc", "Urgent Fake KYC Phishing Trap"),
    ("🚨", "urgent", "Urgent Social Engineering Pressure"),
    ("🐀", "rat", "Remote Access Trojan Distribution"),
    ("🐀", "fud", "Fully Undetectable Trojan Distribution"),
    ("🔓", "bypass", "Security Control / OTP Bypass Script"),
    ("🛒", "logs", "Stolen Account Logs Marketplace"),
    ("📦", "accounts", "Bulk Stolen Accounts Delivery"),
]


# -----------------------------------------------------------------------------
# Data Models
# -----------------------------------------------------------------------------

@dataclass
class NormalKeywordResult:
    """Findings from Python core normal processing."""
    usernames: List[str] = field(default_factory=list)
    emails: List[str] = field(default_factory=list)
    phone_numbers: List[str] = field(default_factory=list)
    urls: List[str] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    top_keywords: List[Tuple[str, int]] = field(default_factory=list)
    common_suspicious_terms: List[str] = field(default_factory=list)
    repeated_phrases: List[str] = field(default_factory=list)
    is_repeated_message: bool = False
    message_hash: str = ""


@dataclass
class ThreatKeywordResult:
    """Findings from Python core advanced threat detection."""
    threat_terms_found: List[Dict[str, str]] = field(default_factory=list)  # [{"category": ..., "term": ...}]
    matched_categories: List[str] = field(default_factory=list)
    threat_emojis_found: List[Dict[str, str]] = field(default_factory=list)  # [{"emoji": ..., "meaning": ...}]
    emoji_word_combos_found: List[str] = field(default_factory=list)
    suspicious_expressions: List[str] = field(default_factory=list)
    threat_score: int = 0
    preliminary_severity: str = "INFO"  # INFO, LOW, MEDIUM, HIGH, CRITICAL
    requires_ai_analysis: bool = False
    triage_reason: str = "Normal message content"


@dataclass
class UnifiedKeywordDetectionResult:
    """Consolidated result of both normal and threat detection."""
    normal: NormalKeywordResult
    threat: ThreatKeywordResult
    all_extracted_keywords: List[str] = field(default_factory=list)
    summary: str = ""


# -----------------------------------------------------------------------------
# Core Engine Implementation
# -----------------------------------------------------------------------------

class KeywordDetectionEngine:
    """
    Unified Python Core Detection Engine for TTI.
    Performs high-throughput rule-based triage without calling external AI APIs.
    """

    def __init__(self, recent_message_window_size: int = 500):
        # LRU cache of recent message hashes for repeat/spam detection
        self._recent_hashes: Set[str] = set()
        self._hash_order: List[str] = []
        self._max_history = recent_message_window_size

    def _normalize_text(self, text: str) -> str:
        """Normalize Unicode and clean excessive whitespace."""
        if not text:
            return ""
        norm = unicodedata.normalize("NFKC", text)
        return " ".join(norm.split())

    def detect_normal_keywords(self, text: str) -> NormalKeywordResult:
        """
        Pure Python core algorithm:
        Extracts normal words, phrases, names/usernames, emails, phones, URLs,
        frequently occurring keywords, and repeated messages.
        """
        clean_text = self._normalize_text(text)
        lower_text = clean_text.lower()
        res = NormalKeywordResult()

        if not clean_text:
            return res

        # 1. Usernames (@handle)
        usernames = RE_USERNAME.findall(clean_text)
        res.usernames = sorted(list(set(usernames)))

        # 2. Email addresses
        emails = RE_EMAIL.findall(clean_text)
        res.emails = sorted(list(set(emails)))

        # 3. Phone numbers (international & domestic)
        phones = RE_PHONE_INTL.findall(clean_text) + RE_PHONE_DOMESTIC.findall(clean_text)
        res.phone_numbers = sorted(list(set(phones)))

        # 4. URLs
        urls = RE_URL.findall(clean_text)
        res.urls = sorted(list(set(urls)))

        # 5. Domains
        domains = RE_DOMAIN.findall(clean_text)
        res.domains = sorted(list(set(domains)))

        # 6. Common suspicious / social engineering terms
        matched_suspicious = []
        for term in COMMON_SUSPICIOUS_TERMS:
            if re.search(rf"\b{re.escape(term)}\b", lower_text):
                matched_suspicious.append(term)
        res.common_suspicious_terms = sorted(matched_suspicious)

        # 7. Word & phrase frequencies (tokenization & n-grams)
        words = re.findall(r"\b[a-zA-Z]{3,25}\b", lower_text)
        filtered_words = [w for w in words if w not in STOP_WORDS]
        word_counts = Counter(filtered_words)
        res.top_keywords = word_counts.most_common(10)

        # 8. Repeated phrases detection (3-grams occurring >= 2 times in the same text)
        if len(words) >= 6:
            trigrams = [" ".join(words[i:i + 3]) for i in range(len(words) - 2)]
            trigram_counts = Counter(trigrams)
            res.repeated_phrases = [phrase for phrase, count in trigram_counts.items() if count >= 2]

        # 9. Message hash & repetition across recent stream
        msg_hash = hashlib.sha256(clean_text.encode("utf-8")).hexdigest()
        res.message_hash = msg_hash
        if msg_hash in self._recent_hashes:
            res.is_repeated_message = True
        else:
            self._record_hash(msg_hash)

        return res

    def _record_hash(self, msg_hash: str) -> None:
        """Maintain bounded hash history."""
        if len(self._hash_order) >= self._max_history:
            oldest = self._hash_order.pop(0)
            self._recent_hashes.discard(oldest)
        self._recent_hashes.add(msg_hash)
        self._hash_order.append(msg_hash)

    def detect_advanced_threat_keywords(self, text: str) -> ThreatKeywordResult:
        """
        Pure Python core advanced threat detection:
        Identifies cybercrime terms, malware, data leaks, phishing, fraud,
        threat emojis, emoji-word combinations, and contextual expressions.
        """
        clean_text = self._normalize_text(text)
        lower_text = clean_text.lower()
        res = ThreatKeywordResult()

        if not clean_text:
            return res

        score = 0
        matched_categories_set = set()

        # 1. Check Threat Lexicons across categories
        for category, terms in THREAT_LEXICONS.items():
            for term in terms:
                # Word boundary match
                pattern = rf"\b{re.escape(term)}\b"
                if re.search(pattern, lower_text):
                    res.threat_terms_found.append({"category": category, "term": term})
                    matched_categories_set.add(category)
                    score += 20

        res.matched_categories = sorted(list(matched_categories_set))

        # 2. Check Threat-Related Emojis
        for emoji_char, meaning in THREAT_EMOJIS.items():
            if emoji_char in clean_text:
                res.threat_emojis_found.append({"emoji": emoji_char, "meaning": meaning})
                score += 10

        # 3. Check Emoji + Word Combinations
        for emoji_char, word, desc in EMOJI_WORD_COMBOS:
            if emoji_char in clean_text and re.search(rf"\b{re.escape(word)}\b", lower_text):
                res.emoji_word_combos_found.append(f"{emoji_char} + '{word}': {desc}")
                score += 30

        # 4. Context-Dependent Suspicious Expressions
        context_patterns = [
            (r"\bfresh dump\b", "Fresh data dump announcement"),
            (r"\bmule account (?:ready|available|needed)\b", "Mule account solicitation"),
            (r"\bdm for (?:rates|fullz|logs|otp|bin)\b", "Direct message solicitations for contraband"),
            (r"\bguaranteed cashout\b", "Guaranteed cashout lure"),
            (r"\botp (?:bot|bypass|script)\b", "Automated OTP interception / bypass tool"),
            (r"\bfullz with pin\b", "High-value complete identity package with PIN"),
            (r"\bbank logs with (?:balance|cookies)\b", "Compromised netbanking sessions"),
            (r"\bfud (?:payload|crypter|rat)\b", "Fully Undetectable malware delivery"),
            (r"\baadhaar (?:dump|database|leak)\b", "Aadhaar national identity database exfiltration"),
        ]
        for pattern, desc in context_patterns:
            if re.search(pattern, lower_text):
                res.suspicious_expressions.append(desc)
                score += 35

        # 5. Compute Severity & AI Escalation Triage
        res.threat_score = min(score, 100)

        if score >= 60 or len(res.emoji_word_combos_found) > 0 or len(res.suspicious_expressions) > 0:
            res.preliminary_severity = "CRITICAL" if score >= 80 else "HIGH"
            res.requires_ai_analysis = True
            res.triage_reason = (
                f"High-confidence threat indicators detected ({len(res.threat_terms_found)} terms, "
                f"{len(res.emoji_word_combos_found)} emoji combos, {len(res.suspicious_expressions)} expressions)"
            )
        elif score >= 25 or len(res.threat_terms_found) > 0:
            res.preliminary_severity = "MEDIUM"
            res.requires_ai_analysis = True
            res.triage_reason = (
                f"Moderate threat indicators detected ({len(res.threat_terms_found)} threat terms)"
            )
        elif score > 0:
            res.preliminary_severity = "LOW"
            res.requires_ai_analysis = False  # Keep at Python layer to save tokens
            res.triage_reason = "Isolated threat keyword or emoji without malicious context"
        else:
            res.preliminary_severity = "INFO"
            res.requires_ai_analysis = False
            res.triage_reason = "Benign or normal conversational content"

        return res

    def analyze(self, text: str) -> UnifiedKeywordDetectionResult:
        """
        Execute full unified keyword analysis:
        Runs normal keyword extraction followed by advanced threat analysis.
        """
        normal_res = self.detect_normal_keywords(text)
        threat_res = self.detect_advanced_threat_keywords(text)

        # Aggregate all extracted keywords for easy display/indexing
        all_kw: List[str] = []
        for kw, _ in normal_res.top_keywords:
            all_kw.append(kw)
        for term in normal_res.common_suspicious_terms:
            all_kw.append(term)
        for t in threat_res.threat_terms_found:
            all_kw.append(t["term"])

        # Deduplicate while preserving order
        seen = set()
        dedup_kw = []
        for k in all_kw:
            kl = k.lower()
            if kl not in seen:
                seen.add(kl)
                dedup_kw.append(k)

        summary_parts = []
        if threat_res.requires_ai_analysis:
            summary_parts.append(f"Threat Flagged [{threat_res.preliminary_severity}]: {threat_res.triage_reason}")
        else:
            summary_parts.append(f"Normal Content [{threat_res.preliminary_severity}]: {threat_res.triage_reason}")

        if normal_res.usernames:
            summary_parts.append(f"Usernames: {', '.join(normal_res.usernames)}")
        if normal_res.emails:
            summary_parts.append(f"Emails: {', '.join(normal_res.emails)}")
        if normal_res.phone_numbers:
            summary_parts.append(f"Phones: {', '.join(normal_res.phone_numbers)}")
        if normal_res.urls:
            summary_parts.append(f"URLs: {len(normal_res.urls)}")
        if normal_res.is_repeated_message:
            summary_parts.append("Duplicate/Repeated Broadcast Detected")

        return UnifiedKeywordDetectionResult(
            normal=normal_res,
            threat=threat_res,
            all_extracted_keywords=dedup_kw,
            summary=" | ".join(summary_parts),
        )

