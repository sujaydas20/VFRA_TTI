"""Untrusted input sanitization engine.

NON-NEGOTIABLE ARCHITECTURAL RULE:
Every incoming message from Telegram and scraped page from the dark web must be
treated as completely untrusted input. Content may contain exploits, embedded scripts,
null bytes, ANSI escape sequences, or malicious URI schemes intended to exploit
downstream storage, search indexes, or analysts' browsers.
"""

import html
import re
import unicodedata
from typing import List, Tuple

# Compiled patterns for sanitization
SCRIPT_PATTERN = re.compile(r"<\s*script[^>]*>.*?<\s*/\s*script\s*>", re.IGNORECASE | re.DOTALL)
DANGEROUS_TAGS_PATTERN = re.compile(
    r"<\s*(iframe|object|embed|applet|meta|link|base|style)[^>]*>.*?<\s*/\s*\1\s*>",
    re.IGNORECASE | re.DOTALL,
)
NULL_BYTE_PATTERN = re.compile(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]")
ANSI_ESCAPE_PATTERN = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
DANGEROUS_SCHEME_PATTERN = re.compile(
    r"(javascript|vbscript|data|file):", re.IGNORECASE
)


class InputSanitizer:
    """Sanitizes raw untrusted text and payloads from external intelligence sources."""

    MAX_TEXT_LENGTH = 1_000_000  # 1MB max raw text length protection

    @classmethod
    def sanitize_text(cls, raw_content: str) -> Tuple[str, List[str]]:
        """
        Sanitize an untrusted string.
        Returns:
            Tuple of (sanitized_string, list_of_applied_sanitizations)
        """
        if not raw_content:
            return "", []

        applied_actions: List[str] = []
        text = raw_content

        # 1. Truncate if exceeds extreme boundary
        if len(text) > cls.MAX_TEXT_LENGTH:
            text = text[: cls.MAX_TEXT_LENGTH]
            applied_actions.append(f"truncated_to_{cls.MAX_TEXT_LENGTH}_chars")

        # 2. Normalize Unicode (NFC representation)
        normalized = unicodedata.normalize("NFC", text)
        if normalized != text:
            text = normalized
            applied_actions.append("unicode_nfc_normalized")

        # 3. Strip ANSI terminal escape sequences first before control bytes
        if ANSI_ESCAPE_PATTERN.search(text):
            text = ANSI_ESCAPE_PATTERN.sub("", text)
            applied_actions.append("stripped_ansi_escapes")

        # 4. Strip null bytes and non-printable control characters
        if NULL_BYTE_PATTERN.search(text):
            text = NULL_BYTE_PATTERN.sub("", text)
            applied_actions.append("stripped_control_and_null_bytes")

        # 5. Neutralize script blocks
        if SCRIPT_PATTERN.search(text):
            text = SCRIPT_PATTERN.sub("[REDACTED_SCRIPT_BLOCK]", text)
            applied_actions.append("redacted_script_block")

        # 6. Neutralize dangerous embedding tags (iframe, embed, object)
        if DANGEROUS_TAGS_PATTERN.search(text):
            text = DANGEROUS_TAGS_PATTERN.sub("[REDACTED_EMBED_BLOCK]", text)
            applied_actions.append("redacted_embed_block")

        # 7. Defang dangerous URI schemes (neutralize protocol and colon)
        if DANGEROUS_SCHEME_PATTERN.search(text):
            text = DANGEROUS_SCHEME_PATTERN.sub(r"defanged-\1-blocked:", text)
            applied_actions.append("defanged_malicious_uri_scheme")

        # 8. Escape residual HTML markup for safe display
        text_escaped = html.escape(text, quote=False)
        if text_escaped != text:
            text = text_escaped
            applied_actions.append("escaped_html_entities")

        return text.strip(), applied_actions
