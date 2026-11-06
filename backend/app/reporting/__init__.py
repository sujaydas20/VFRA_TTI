"""TTI Reporting & Canonicalization Module.

Provides RFC 8785 JSON Canonicalization Scheme (JCS) encoding,
manifest domain validation, and duplicate-key-rejecting JSON parsing.
"""

from .canonicalization import (
    CanonicalizationError,
    DuplicateKeyError,
    FloatDomainError,
    IntegerDomainError,
    LoneSurrogateError,
    NumericDomainError,
    canonicalize_json,
    canonicalize_manifest,
    parse_json_reject_duplicates,
)

__all__ = [
    "canonicalize_json",
    "canonicalize_manifest",
    "parse_json_reject_duplicates",
    "CanonicalizationError",
    "NumericDomainError",
    "FloatDomainError",
    "IntegerDomainError",
    "DuplicateKeyError",
    "LoneSurrogateError",
]
