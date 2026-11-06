"""Text normalization and character offset mapping for multilingual threat detection.

Handles:
- Devanagari script normalization (NFC, digit conversion ०-९ -> 0-9, ZWJ/ZWNJ removal).
- URL defanging restoration (hxxp -> http, [.] -> .).
- Spaced acronym normalization ("O T P" -> "OTP", "K Y C" -> "KYC").
- Accurate character offset mapping from normalized back to raw input.
"""

import re
import unicodedata
from typing import List, Tuple

# Devanagari digits to ASCII digits
DEVANAGARI_DIGITS = {
    "\u0966": "0",
    "\u0967": "1",
    "\u0968": "2",
    "\u0969": "3",
    "\u096a": "4",
    "\u096b": "5",
    "\u096c": "6",
    "\u096d": "7",
    "\u096e": "8",
    "\u096f": "9",
}

# Zero width characters to strip
ZERO_WIDTH_CHARS = {"\u200b", "\u200c", "\u200d", "\ufeff"}

# Common spaced acronyms used in fraud attempts
SPACED_ACRONYMS = [
    (re.compile(r"\bO\s+T\s+P\b", re.IGNORECASE), "OTP"),
    (re.compile(r"\bK\s+Y\s+C\b", re.IGNORECASE), "KYC"),
    (re.compile(r"\bU\s+P\s+I\b", re.IGNORECASE), "UPI"),
    (re.compile(r"\bP\s+I\s+N\b", re.IGNORECASE), "PIN"),
    (re.compile(r"\bS\s+B\s+I\b", re.IGNORECASE), "SBI"),
]


class NormalizedText:
    """Represents normalized text with character mapping back to raw text."""

    def __init__(self, raw_text: str, text: str, char_map: List[int]):
        self.raw_text = raw_text
        self.text = text
        self.char_map = char_map

    def get_raw_span(self, norm_start: int, norm_end: int) -> Tuple[int, int]:
        """Convert normalized [norm_start, norm_end) into raw text span [raw_start, raw_end)."""
        if not self.char_map:
            return 0, 0
        
        safe_start = max(0, min(norm_start, len(self.char_map) - 1))
        safe_end_idx = max(0, min(norm_end - 1, len(self.char_map) - 1))
        
        raw_start = self.char_map[safe_start]
        # raw_end is at least raw_start + 1
        raw_end = self.char_map[safe_end_idx] + 1
        if raw_end < raw_start:
            raw_end = raw_start + (norm_end - norm_start)
        raw_end = min(raw_end, len(self.raw_text))
        return raw_start, raw_end

    def get_raw_excerpt(self, norm_start: int, norm_end: int) -> str:
        """Extract the raw substring corresponding to a normalized span."""
        raw_start, raw_end = self.get_raw_span(norm_start, norm_end)
        return self.raw_text[raw_start:raw_end]


class TextNormalizer:
    """Normalizes multilingual text for deterministic threat rule matching."""

    @classmethod
    def normalize(cls, raw_text: str) -> NormalizedText:
        """Normalize raw text while building a character index map."""
        if not raw_text:
            return NormalizedText("", "", [])

        # 1. Unicode NFC normalization
        nfc_text = unicodedata.normalize("NFC", raw_text)
        
        # Build initial 1-1 map (or identity map for raw_text)
        # To be completely safe with NFC differences, iterate characters
        norm_chars: List[str] = []
        char_map: List[int] = []

        raw_idx = 0
        for char in raw_text:
            # Handle zero-width characters
            if char in ZERO_WIDTH_CHARS:
                raw_idx += 1
                continue

            # Convert Devanagari digits
            if char in DEVANAGARI_DIGITS:
                norm_chars.append(DEVANAGARI_DIGITS[char])
                char_map.append(raw_idx)
            else:
                norm_chars.append(char)
                char_map.append(raw_idx)
            raw_idx += 1

        intermediate_text = "".join(norm_chars)

        # 2. Defanged URL restoration in normalized view (hxxp -> http, [.] -> .)
        # We replace defanged markers while keeping char_map aligned
        defanged_text = intermediate_text
        # Handle [.]
        dot_offset = 0
        while True:
            pos = defanged_text.find("[.]", dot_offset)
            if pos == -1:
                break
            # Replace [.] (3 chars) with . (1 char)
            orig_raw_idx = char_map[pos]
            defanged_text = defanged_text[:pos] + "." + defanged_text[pos + 3:]
            char_map = char_map[:pos] + [orig_raw_idx] + char_map[pos + 3:]
            dot_offset = pos + 1

        # Handle hxxp -> http
        hxxp_offset = 0
        while True:
            pos = defanged_text.lower().find("hxxp", hxxp_offset)
            if pos == -1:
                break
            orig_raw_idx = char_map[pos]
            defanged_text = defanged_text[:pos] + "http" + defanged_text[pos + 4:]
            char_map = char_map[:pos] + [orig_raw_idx] * 4 + char_map[pos + 4:]
            hxxp_offset = pos + 4

        # 3. Spaced acronym normalization (e.g. O T P -> OTP)
        for pattern, replacement in SPACED_ACRONYMS:
            while True:
                match = pattern.search(defanged_text)
                if not match:
                    break
                start, end = match.start(), match.end()
                raw_start = char_map[start]
                raw_end = char_map[end - 1]
                replacement_map = [raw_start] * (len(replacement) - 1) + [raw_end]
                defanged_text = defanged_text[:start] + replacement + defanged_text[end:]
                char_map = (
                    char_map[:start]
                    + replacement_map
                    + char_map[end:]
                )

        return NormalizedText(
            raw_text=raw_text,
            text=defanged_text,
            char_map=char_map,
        )
