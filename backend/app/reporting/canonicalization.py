"""RFC 8785 JSON Canonicalization Scheme (JCS) & TTI Manifest Domain Engine.

Conforms strictly to RFC 8785 (JSON Canonicalization Scheme) with zero third-party dependencies.
Distinguishes generic RFC 8785 JCS encoding from TTI forensic manifest domain validation.
"""

from __future__ import annotations

import hashlib
import json
import math
from typing import Any, Dict, List, Tuple, Union


# ==============================================================================
# Domain Exceptions
# ==============================================================================

class CanonicalizationError(ValueError):
    """Base exception for all canonicalization and validation errors."""
    pass


class NumericDomainError(CanonicalizationError):
    """Raised when a numeric value violates representation domain rules."""
    pass


class FloatDomainError(NumericDomainError):
    """Raised when a float is NaN, Infinite, or prohibited in manifests."""
    pass


class IntegerDomainError(NumericDomainError):
    """Raised when an integer exceeds IEEE 754 safe integer limits."""
    pass


class DuplicateKeyError(CanonicalizationError):
    """Raised when a JSON object contains duplicate keys during parsing."""
    pass


class LoneSurrogateError(CanonicalizationError):
    """Raised when a lone surrogate Unicode character is encountered."""
    pass


# ==============================================================================
# ECMAScript §7.1.12.1 / RFC 8785 §3.2.2.3 Number Serialization
# ==============================================================================

def serialize_float_ecmascript(val: float) -> str:
    """Serializes an IEEE 754 double-precision float according to ECMA-262 §7.1.12.1.
    
    Adheres strictly to RFC 8785 §3.2.2.3 and Appendix B:
    - NaN and +/-Infinity raise FloatDomainError.
    - +0.0 and -0.0 serialize as '0'.
    - Negative values serialize with leading '-' followed by positive representation.
    - Uses shortest decimal representation that round-trips to the same IEEE 754 double.
    - Switches between fixed decimal and exponential notation based on magnitude thresholds:
        - k <= n <= 21: fixed decimal with trailing zero padding.
        - 0 < n <= k: fixed decimal with '.' placed after n digits.
        - -6 < n <= 0: fixed decimal '0.' with -n leading zeros before digits.
        - Otherwise (n <= -6 or n > 21): exponential notation with lowercase 'e' and '+/-'.
    """
    if math.isnan(val) or math.isinf(val):
        raise FloatDomainError(f"Float value {val} is not representable in JSON (NaN or Infinity)")

    # ECMA-262: if x is +0 or -0, return "0"
    if val == 0.0:
        return "0"

    sign = ""
    if val < 0.0:
        sign = "-"
        val = -val

    # Python's repr(float) uses David Gay's dtoa (same as V8/ECMAScript),
    # producing the shortest round-tripping decimal representation.
    s = repr(val)
    if "e" in s:
        mantissa_str, exp_str = s.split("e")
        exp = int(exp_str)
    else:
        mantissa_str = s
        exp = 0

    if "." in mantissa_str:
        integer_part, frac_part = mantissa_str.split(".")
    else:
        integer_part, frac_part = mantissa_str, ""

    if integer_part == "0":
        # e.g., 0.002 -> frac_part = "002"
        frac_stripped = frac_part.lstrip("0")
        leading_zeros = len(frac_part) - len(frac_stripped)
        digits = frac_stripped
        # First significant digit is at 10^(-(leading_zeros + 1) + exp)
        # n - 1 = -(leading_zeros + 1) + exp  =>  n = -leading_zeros + exp
        n = -leading_zeros + exp
    else:
        frac_stripped = frac_part.rstrip("0")
        digits = integer_part + frac_stripped
        n = len(integer_part) + exp

    k = len(digits)

    # ECMA-262 §7.1.12.1 rules:
    # 1. If k <= n <= 21:
    if k <= n <= 21:
        out = digits + ("0" * (n - k))
    # 2. If 0 < n <= k:
    elif 0 < n <= k:
        if n == k:
            out = digits
        else:
            out = digits[:n] + "." + digits[n:]
    # 3. If -6 < n <= 0:
    elif -6 < n <= 0:
        out = "0." + ("0" * (-n)) + digits
    # 4. Otherwise (n <= -6 or n > 21):
    else:
        if k == 1:
            base = digits
        else:
            base = digits[0] + "." + digits[1:]
        exponent = n - 1
        if exponent > 0:
            exp_formatted = f"+{exponent}"
        else:
            exp_formatted = str(exponent)
        out = f"{base}e{exp_formatted}"

    return sign + out


# ==============================================================================
# RFC 8785 §3.2.2.2 String Escaping & Validation
# ==============================================================================

def canonicalize_string(s: str) -> bytes:
    """Escapes strings conforming strictly to RFC 8785 §3.2.2.2.
    
    Rules:
    - Quotation mark (") escaped as \\"
    - Reverse solidus (\\) escaped as \\\\
    - Characters U+0000..U+001F escaped using lower-case hex \\u00xx,
      except:
        - Backspace (U+0008) -> \\b
        - Tab (U+0009) -> \\t
        - Line feed (U+000A) -> \\n
        - Form feed (U+000C) -> \\f
        - Carriage return (U+000D) -> \\r
    - Solidus (/) MUST NOT be escaped.
    - All other characters emitted as literal UTF-8 octets.
    - Rejects lone surrogate characters (U+D800 to U+DFFF).
    """
    out: List[bytes] = [b'"']
    for char in s:
        code = ord(char)
        if 0xD800 <= code <= 0xDFFF:
            raise LoneSurrogateError(
                f"Lone surrogate character U+{code:04X} detected in string"
            )
        if char == '"':
            out.append(b'\\"')
        elif char == '\\':
            out.append(b'\\\\')
        elif char == '\b':
            out.append(b'\\b')
        elif char == '\t':
            out.append(b'\\t')
        elif char == '\n':
            out.append(b'\\n')
        elif char == '\f':
            out.append(b'\\f')
        elif char == '\r':
            out.append(b'\\r')
        elif code < 0x20:
            out.append(f"\\u{code:04x}".encode("ascii"))
        else:
            out.append(char.encode("utf-8"))
    out.append(b'"')
    return b"".join(out)


# ==============================================================================
# Generic RFC 8785 JCS Canonicalization
# ==============================================================================

def canonicalize_json(val: Any) -> bytes:
    """Serializes arbitrary JSON-serializable Python data into canonical RFC 8785 UTF-8 bytes.
    
    Conforming to RFC 8785 (JSON Canonicalization Scheme / JCS):
    - null -> b"null"
    - bool -> b"true" / b"false"
    - int -> decimal ASCII within IEEE 754 safe integer range (-2^53 + 1 to 2^53 - 1)
    - float -> ECMAScript §7.1.12.1 formatting via serialize_float_ecmascript()
    - str -> RFC 8785 §3.2.2.2 escaping
    - list/tuple -> comma-separated items enclosed in square brackets
    - dict -> keys sorted by UTF-16 code units (key.encode('utf-16-be')), colon/comma separated
    - Rejects lone surrogates, invalid types, and non-finite floats.
    - Produces exact canonical bytes terminating with no trailing newline.
    """
    if val is None:
        return b"null"
    elif isinstance(val, bool):
        # Must be checked before int (bool is a subclass of int in Python)
        return b"true" if val else b"false"
    elif isinstance(val, int):
        # Enforce IEEE 754 safe integer limits (-2^53 + 1 to 2^53 - 1)
        if not (-9007199254740991 <= val <= 9007199254740991):
            raise IntegerDomainError(
                f"Integer {val} exceeds IEEE 754 safe integer range [-9007199254740991, 9007199254740991]"
            )
        return str(val).encode("ascii")
    elif isinstance(val, float):
        return serialize_float_ecmascript(val).encode("ascii")
    elif isinstance(val, str):
        return canonicalize_string(val)
    elif isinstance(val, (list, tuple)):
        items = [canonicalize_json(item) for item in val]
        return b"[" + b",".join(items) + b"]"
    elif isinstance(val, dict):
        # RFC 8785 §3.2.3: Keys MUST be sorted according to UTF-16 code units
        for k in val.keys():
            if not isinstance(k, str):
                raise TypeError(f"Dictionary keys must be strings, got {type(k).__name__}")
            for ch in k:
                if 0xD800 <= ord(ch) <= 0xDFFF:
                    raise LoneSurrogateError(
                        f"Lone surrogate U+{ord(ch):04X} detected in dictionary key '{k}'"
                    )

        sorted_keys = sorted(val.keys(), key=lambda k: k.encode("utf-16-be"))
        entries: List[bytes] = []
        for k in sorted_keys:
            k_bytes = canonicalize_string(k)
            v_bytes = canonicalize_json(val[k])
            entries.append(k_bytes + b":" + v_bytes)
        return b"{" + b",".join(entries) + b"}"
    else:
        raise TypeError(f"Object of type {type(val).__name__} is not JSON serializable")


# ==============================================================================
# TTI Forensic Manifest Validation & Canonicalization
# ==============================================================================

def validate_manifest_domain(val: Any, path: str = "$") -> None:
    """Recursively validates that data conforms to TTI forensic manifest domain rules.
    
    Rules:
    - Numeric values MUST be non-negative safe integers: 0 <= n <= 2^53 - 1.
    - Floating-point numbers are STRICTLY PROHIBITED in manifests (raises NumericDomainError).
    - Negative integers are PROHIBITED in manifests (raises NumericDomainError).
    - Lone surrogate characters in strings or keys are REJECTED (raises LoneSurrogateError).
    - Keys must be strings.
    - No silent coercion.
    """
    if val is None:
        return
    elif isinstance(val, bool):
        # Booleans are permitted
        return
    elif isinstance(val, int):
        if val < 0:
            raise NumericDomainError(
                f"Negative integer {val} not permitted in TTI manifest schema at {path}"
            )
        if val > 9007199254740991:
            raise NumericDomainError(
                f"Integer {val} exceeds safe integer limit (2^53 - 1 = 9007199254740991) at {path}"
            )
        return
    elif isinstance(val, float):
        raise NumericDomainError(
            f"Floating-point numbers are prohibited in TTI manifest schema at {path}"
        )
    elif isinstance(val, str):
        for idx, ch in enumerate(val):
            if 0xD800 <= ord(ch) <= 0xDFFF:
                raise LoneSurrogateError(
                    f"Lone surrogate U+{ord(ch):04X} detected in manifest string at {path}[{idx}]"
                )
        return
    elif isinstance(val, (list, tuple)):
        for idx, item in enumerate(val):
            validate_manifest_domain(item, f"{path}[{idx}]")
        return
    elif isinstance(val, dict):
        for k, v in val.items():
            if not isinstance(k, str):
                raise TypeError(
                    f"Manifest keys must be strings, got {type(k).__name__} at {path}"
                )
            for idx, ch in enumerate(k):
                if 0xD800 <= ord(ch) <= 0xDFFF:
                    raise LoneSurrogateError(
                        f"Lone surrogate U+{ord(ch):04X} detected in manifest key '{k}' at {path}"
                    )
            validate_manifest_domain(v, f"{path}.{k}")
        return
    else:
        raise TypeError(
            f"Unsupported data type in manifest schema: {type(val).__name__} at {path}"
        )


def canonicalize_manifest(payload: Dict[str, Any]) -> Tuple[bytes, str]:
    """Validates TTI forensic manifest domain and returns (canonical_bytes, sha256_hexdigest).
    
    Enforces:
    - payload must be a dictionary.
    - Manifest numbers MUST be non-negative safe integers (0 <= n <= 2^53 - 1).
    - Floats are strictly prohibited in the manifest numeric domain.
    - Lone surrogate characters are rejected.
    - Output canonical bytes have NO trailing newline.
    - SHA-256 is computed over the exact canonical octets.
    """
    if not isinstance(payload, dict):
        raise TypeError(f"Manifest payload must be a dict, got {type(payload).__name__}")

    validate_manifest_domain(payload)
    canonical_bytes = canonicalize_json(payload)
    manifest_sha256 = hashlib.sha256(canonical_bytes).hexdigest()
    return canonical_bytes, manifest_sha256


# ==============================================================================
# Duplicate-Key Rejecting JSON Parser
# ==============================================================================

def _check_no_lone_surrogates(val: Any) -> None:
    """Recursively validates that parsed JSON contains no lone surrogate characters."""
    if isinstance(val, str):
        for ch in val:
            if 0xD800 <= ord(ch) <= 0xDFFF:
                raise LoneSurrogateError(
                    f"Lone surrogate U+{ord(ch):04X} detected in JSON string"
                )
    elif isinstance(val, list):
        for item in val:
            _check_no_lone_surrogates(item)
    elif isinstance(val, dict):
        for k, v in val.items():
            if isinstance(k, str):
                for ch in k:
                    if 0xD800 <= ord(ch) <= 0xDFFF:
                        raise LoneSurrogateError(
                            f"Lone surrogate U+{ord(ch):04X} detected in JSON object key"
                        )
            _check_no_lone_surrogates(v)


def parse_json_reject_duplicates(raw_data: Union[bytes, str]) -> Any:
    """Parses JSON data (bytes or str), strictly rejecting duplicate keys and lone surrogates.
    
    Args:
        raw_data: Input JSON bytes (UTF-8 encoded) or Unicode string.
        
    Returns:
        The deserialized JSON Python object.
        
    Raises:
        DuplicateKeyError: If any object in the JSON contains duplicate keys.
        LoneSurrogateError: If parsed text contains lone surrogate characters.
        TypeError: If raw_data is neither bytes nor str.
        ValueError / json.JSONDecodeError: If raw_data is not valid JSON.
    """
    if isinstance(raw_data, bytes):
        try:
            text = raw_data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError(f"Invalid UTF-8 encoding in JSON input: {exc}") from exc
    elif isinstance(raw_data, str):
        text = raw_data
    else:
        raise TypeError(f"Expected bytes or str, got {type(raw_data).__name__}")

    def _pair_hook(pairs: List[Tuple[Any, Any]]) -> Dict[Any, Any]:
        obj: Dict[Any, Any] = {}
        for k, v in pairs:
            if k in obj:
                raise DuplicateKeyError(f"Duplicate key encountered in JSON object: {k!r}")
            obj[k] = v
        return obj

    parsed = json.loads(text, object_pairs_hook=_pair_hook)
    _check_no_lone_surrogates(parsed)
    return parsed
