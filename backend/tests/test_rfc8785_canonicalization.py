"""Comprehensive Conformance Test Suite for RFC 8785 Canonicalization & TTI Manifest Engine.

Tests:
1. Official RFC 8785 / Cyberphone Reference Vectors.
2. RFC 8785 Appendix B Number Serialization Samples.
3. Non-BMP UTF-16 Code-Unit Key Ordering (surrogate pair vs BMP).
4. String Escaping & Literal UTF-8 Preservation.
5. Numeric Boundaries & Zero (-0.0 vs +0.0, IEEE 754 safe integers).
6. Nulls, Booleans & Nested Structures.
7. Realistic TTI Forensic Manifest.
8. Negative Tests: Duplicate Keys, Lone Surrogates, Floats in Manifest, Out-of-Range Ints, Malformed JSON.
9. Determinism and Zero Trailing Newline.
"""

import hashlib
import json
import math
import pytest

try:
    from app.reporting.canonicalization import (
        CanonicalizationError,
        DuplicateKeyError,
        FloatDomainError,
        IntegerDomainError,
        LoneSurrogateError,
        NumericDomainError,
        canonicalize_json,
        canonicalize_manifest,
        parse_json_reject_duplicates,
        serialize_float_ecmascript,
    )
except ImportError:
    from backend.app.reporting.canonicalization import (
        CanonicalizationError,
        DuplicateKeyError,
        FloatDomainError,
        IntegerDomainError,
        LoneSurrogateError,
        NumericDomainError,
        canonicalize_json,
        canonicalize_manifest,
        parse_json_reject_duplicates,
        serialize_float_ecmascript,
    )


# ==============================================================================
# 1. Official RFC 8785 / Cyberphone Reference Vectors
# ==============================================================================

class TestCyberphoneReferenceVectors:
    """Tests corresponding to Anders Rundgren's reference implementation test corpus."""

    def test_cyberphone_values_vector(self):
        """Tests the standard values.json test vector from cyberphone/json-canonicalization."""
        input_data = {
            "numbers": [333333333.33333329, 1e30, 4.50, 2e-3, 1e-27],
            "string": "\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"/",
            "literals": [None, True, False],
        }
        expected_output = (
            b'{"literals":[null,true,false],'
            b'"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],'
            b'"string":"\xe2\x82\xac$\\u000f\\nA\'B\\"\\\\\\\\\\"/"}'
        )
        canonical = canonicalize_json(input_data)
        assert canonical == expected_output
        assert not canonical.endswith(b"\n")

    def test_array_preservation_with_nested_objects(self):
        """Arrays preserve item order; objects inside arrays are sorted by keys."""
        input_data = [
            {"z": 1, "a": 2},
            {"k": [None, {"b": 3, "a": 4}]},
        ]
        expected = b'[{"a":2,"z":1},{"k":[null,{"a":4,"b":3}]}]'
        assert canonicalize_json(input_data) == expected

    def test_empty_containers(self):
        """Empty dicts, arrays, and strings encode to minimal forms."""
        assert canonicalize_json({}) == b"{}"
        assert canonicalize_json([]) == b"[]"
        assert canonicalize_json("") == b'""'


# ==============================================================================
# 2. RFC 8785 Appendix B Number Serialization Samples
# ==============================================================================

class TestAppendixBNumberSerialization:
    """Validates adherence to Table 1 in RFC 8785 Appendix B."""

    @pytest.mark.parametrize(
        "val, expected",
        [
            (0.0, "0"),
            (-0.0, "0"),
            (5e-324, "5e-324"),
            (-5e-324, "-5e-324"),
            (1.7976931348623157e308, "1.7976931348623157e+308"),
            (-1.7976931348623157e308, "-1.7976931348623157e+308"),
            (9007199254740992.0, "9007199254740992"),
            (-9007199254740992.0, "-9007199254740992"),
            (1e23, "1e+23"),
            (999999999999999700000.0, "999999999999999700000"),
            (999999999999999900000.0, "999999999999999900000"),
            # Fixed vs Exponential transition boundaries
            (1e20, "100000000000000000000"),  # 21 digits -> fixed
            (1e21, "1e+21"),                   # 22 digits -> exponential
            (1e-5, "0.00001"),                  # -6 < n <= 0 -> fixed
            (1e-6, "0.000001"),                 # -6 < n <= 0 -> fixed
            (1e-7, "1e-7"),                     # n <= -6 -> exponential
            (1.23e-7, "1.23e-7"),
            (1.23e25, "1.23e+25"),
        ],
    )
    def test_float_ecmascript_serialization(self, val: float, expected: str):
        serialized = serialize_float_ecmascript(val)
        assert serialized == expected
        # Ensure canonicalize_json produces exact ASCII bytes
        assert canonicalize_json(val) == expected.encode("ascii")


# ==============================================================================
# 3. UTF-16 Code-Unit Key Ordering (Non-BMP Characters)
# ==============================================================================

class TestUTF16KeyOrdering:
    """Verifies that object keys are sorted by UTF-16 code units per RFC 8785 §3.2.3."""

    def test_vector_cv01_surrogate_ordering(self):
        """Test Vector CV-01: \\U00010437 (surrogate 0xD801) must sort BEFORE \\uffff (0xFFFF)."""
        input_data = {"\uffff": 1, "\U00010437": 2}
        expected = b'{"\xf0\x90\x90\xb7":2,"\xef\xbf\xbf":1}'
        expected_sha256 = "e450b1c4411b44889453a58b394bd740d515ea169706731fa99d1f6c283b9142"

        # Demonstrate standard Python sort would fail this requirement:
        assert sorted(["\uffff", "\U00010437"]) == ["\uffff", "\U00010437"]

        # JCS canonicalization correctly reverses them according to UTF-16 code units:
        canonical = canonicalize_json(input_data)
        assert canonical == expected
        assert hashlib.sha256(canonical).hexdigest() == expected_sha256

    def test_mixed_bmp_and_astral_keys(self):
        """Orders mixed ASCII, BMP, and supplementary (astral) plane characters."""
        # UTF-16 code units:
        # "a": 0x0061
        # "z": 0x007A
        # "\u00e9": 0x00E9
        # "\u4e16": 0x4E16
        # "\U00010000": 0xD800, 0xDC00
        # "\U0001f600": 0xD83D, 0xDE00
        # "\uffff": 0xFFFF
        keys_dict = {
            "\uffff": "high_bmp",
            "z": "ascii_z",
            "\U0001f600": "emoji_face",
            "\u4e16": "cjk_char",
            "\U00010000": "linear_b",
            "a": "ascii_a",
            "\u00e9": "latin_e_acute",
        }
        canonical = canonicalize_json(keys_dict)
        parsed = json.loads(canonical.decode("utf-8"))
        actual_order = list(parsed.keys())
        expected_order = [
            "a",
            "z",
            "\u00e9",
            "\u4e16",
            "\U00010000",
            "\U0001f600",
            "\uffff",
        ]
        assert actual_order == expected_order


# ==============================================================================
# 4. String Escaping & UTF-8 Preservation
# ==============================================================================

class TestStringEscaping:
    """Verifies RFC 8785 §3.2.2.2 string escaping rules."""

    def test_vector_cv02_string_escaping(self):
        """Test Vector CV-02: String escaping and multi-byte UTF-8 preservation."""
        input_data = {"count": 42, "text": "Hello \"World\"! \n \t \\ / 🛡️ ñ 日本語"}
        expected = (
            b'{"count":42,"text":"Hello \\"World\\"! \\n \\t \\\\ / '
            b'\xf0\x9f\x9b\xa1\xef\xb8\x8f \xc3\xb1 \xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e"}'
        )
        expected_sha256 = "35d9fd06f1663eb10e981e6e7d1150f874a549e59bcf565b786e5c7c3b93f442"

        canonical = canonicalize_json(input_data)
        assert canonical == expected
        assert hashlib.sha256(canonical).hexdigest() == expected_sha256

    def test_control_character_escapes(self):
        """Verifies special short escapes (b, t, n, f, r) and generic \\u00xx for control chars."""
        # Short escapes
        assert canonicalize_json("\b") == b'"\\b"'
        assert canonicalize_json("\t") == b'"\\t"'
        assert canonicalize_json("\n") == b'"\\n"'
        assert canonicalize_json("\f") == b'"\\f"'
        assert canonicalize_json("\r") == b'"\\r"'
        # Generic \\u00xx lower-case hex
        assert canonicalize_json("\x00") == b'"\\u0000"'
        assert canonicalize_json("\x01") == b'"\\u0001"'
        assert canonicalize_json("\x1f") == b'"\\u001f"'
        # Solidus must NOT be escaped
        assert canonicalize_json("/") == b'"/"'
        assert canonicalize_json("a/b/c") == b'"a/b/c"'
        # Quotes and backslashes
        assert canonicalize_json('"') == b'"\\""'
        assert canonicalize_json("\\") == b'"\\\\"'


# ==============================================================================
# 5. Numeric Boundaries & Zero
# ==============================================================================

class TestNumericBoundaries:
    """Verifies integer limits, negative values, and zero."""

    def test_vector_cv03_numeric_boundaries(self):
        """Test Vector CV-03: Max safe integer, negative integer, and zero."""
        input_data = {
            "max_safe_int": 9007199254740991,
            "negative": -12345,
            "zero": 0,
        }
        expected = b'{"max_safe_int":9007199254740991,"negative":-12345,"zero":0}'
        expected_sha256 = "b20332c1158764b2b34fafd3b307cc1a809c0a977182d25bcaa7075e29292f06"

        canonical = canonicalize_json(input_data)
        assert canonical == expected
        assert hashlib.sha256(canonical).hexdigest() == expected_sha256

    def test_safe_integer_boundaries(self):
        """Tests the exact IEEE 754 safe integer limits."""
        # Min safe int: -(2^53 - 1)
        assert canonicalize_json(-9007199254740991) == b"-9007199254740991"
        # Max safe int: 2^53 - 1
        assert canonicalize_json(9007199254740991) == b"9007199254740991"


# ==============================================================================
# 6. Nulls, Booleans & Nested Structures
# ==============================================================================

class TestNullsBooleansNested:
    """Verifies nulls, booleans, and nested structures."""

    def test_vector_cv04_nulls_booleans(self):
        """Test Vector CV-04: Null, booleans, empty list, and nested objects."""
        input_data = {
            "active": True,
            "archived": False,
            "empty_list": [],
            "nested": {"a": None, "b": [1, 2, 3]},
        }
        expected = b'{"active":true,"archived":false,"empty_list":[],"nested":{"a":null,"b":[1,2,3]}}'
        expected_sha256 = "621f62bfa3535fda7b794da66912e813820c7a38756a64708295e81ff6902eea"

        canonical = canonicalize_json(input_data)
        assert canonical == expected
        assert hashlib.sha256(canonical).hexdigest() == expected_sha256


# ==============================================================================
# 7. Realistic TTI Forensic Manifest Vector
# ==============================================================================

class TestTTIForensicManifest:
    """Verifies the authoritative TTI forensic manifest vector CV-05."""

    def test_vector_cv05_forensic_manifest(self):
        """Test Vector CV-05: Authoritative 735-byte forensic manifest."""
        manifest = {
            "schema_version": "1.0",
            "report_package_id": "11111111-1111-1111-1111-111111111111",
            "tenant_id": "22222222-2222-2222-2222-222222222222",
            "case_id": "33333333-3333-3333-3333-333333333333",
            "package_title": "Operation Nightshade Threat Evidence",
            "created_at_utc": "2026-10-30T02:00:00Z",
            "total_artifacts": 2,
            "total_uncompressed_bytes": 10240,
            "artifacts": [
                {
                    "archive_relative_path": "evidence/channel_meta.json",
                    "artifact_type": "RAW_JSON",
                    "file_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    "uncompressed_bytes": 4096,
                },
                {
                    "archive_relative_path": "evidence/screenshot_001.png",
                    "artifact_type": "SCREENSHOT_PNG",
                    "file_sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                    "uncompressed_bytes": 6144,
                },
            ],
        }
        expected_sha256 = "1da753d02c5245c69d50a5bdae369cdd050d26b0e8857bc877cfb4a5408d8ded"

        canonical_bytes, manifest_sha256 = canonicalize_manifest(manifest)

        assert len(canonical_bytes) == 730
        assert not canonical_bytes.endswith(b"\n")
        assert canonical_bytes.endswith(b"}")
        assert manifest_sha256 == expected_sha256
        assert hashlib.sha256(canonical_bytes).hexdigest() == expected_sha256


# ==============================================================================
# 8. Negative Tests (Robustness & Rejection)
# ==============================================================================

class TestNegativeRejections:
    """Verifies strict rejection of invalid inputs, duplicate keys, surrogates, and domain violations."""

    def test_duplicate_key_rejected_in_json_parser(self):
        """Rejects objects with duplicate keys."""
        with pytest.raises(DuplicateKeyError, match="Duplicate key encountered"):
            parse_json_reject_duplicates(b'{"key": 1, "key": 2}')

    def test_nested_duplicate_key_rejected(self):
        """Rejects nested objects containing duplicate keys."""
        with pytest.raises(DuplicateKeyError, match="Duplicate key encountered"):
            parse_json_reject_duplicates(b'{"outer": {"nested": 1, "nested": 2}}')

    def test_lone_surrogate_rejected_in_string(self):
        """Rejects strings containing lone surrogate code points."""
        with pytest.raises(LoneSurrogateError, match="Lone surrogate character"):
            canonicalize_json({"key": "\ud800"})

    def test_lone_surrogate_rejected_in_dict_key(self):
        """Rejects dictionary keys containing lone surrogate code points."""
        with pytest.raises(LoneSurrogateError, match="Lone surrogate"):
            canonicalize_json({"\ud800": "val"})

    def test_lone_surrogate_rejected_in_parser(self):
        """Rejects JSON strings containing escaped lone surrogate characters."""
        with pytest.raises(LoneSurrogateError, match="Lone surrogate"):
            parse_json_reject_duplicates('{"key": "\\ud800"}')

    def test_non_finite_floats_rejected(self):
        """Rejects NaN, +Infinity, -Infinity per RFC 8785."""
        with pytest.raises(FloatDomainError, match="NaN or Infinity"):
            canonicalize_json(float("nan"))
        with pytest.raises(FloatDomainError, match="NaN or Infinity"):
            canonicalize_json(float("inf"))
        with pytest.raises(FloatDomainError, match="NaN or Infinity"):
            canonicalize_json(float("-inf"))

    def test_integer_exceeding_ieee754_safe_range_rejected(self):
        """Rejects integers outside [-2^53 + 1, 2^53 - 1] in canonicalize_json."""
        with pytest.raises(IntegerDomainError, match="exceeds IEEE 754 safe integer range"):
            canonicalize_json(9007199254740992)
        with pytest.raises(IntegerDomainError, match="exceeds IEEE 754 safe integer range"):
            canonicalize_json(-9007199254740992)

    def test_floats_strictly_prohibited_in_manifest(self):
        """Manifest validation strictly rejects floats."""
        with pytest.raises(NumericDomainError, match="Floating-point numbers are prohibited"):
            canonicalize_manifest({"total_bytes": 1024.5})

    def test_negative_integers_prohibited_in_manifest(self):
        """Manifest validation rejects negative integers."""
        with pytest.raises(NumericDomainError, match="Negative integer"):
            canonicalize_manifest({"uncompressed_bytes": -1})

    def test_integer_above_max_safe_prohibited_in_manifest(self):
        """Manifest validation rejects integers > 2^53 - 1."""
        with pytest.raises(NumericDomainError, match="exceeds safe integer limit"):
            canonicalize_manifest({"total_bytes": 9007199254740992})

    def test_malformed_json_syntax_rejected(self):
        """Rejects malformed JSON syntax."""
        with pytest.raises(json.JSONDecodeError):
            parse_json_reject_duplicates(b'{"unclosed":')
        with pytest.raises(json.JSONDecodeError):
            parse_json_reject_duplicates(b"not valid json")

    def test_non_string_dictionary_keys_rejected(self):
        """Non-string dictionary keys must raise TypeError."""
        with pytest.raises(TypeError, match="Dictionary keys must be strings"):
            canonicalize_json({123: "number_key"})

    def test_manifest_requires_dictionary(self):
        """canonicalize_manifest requires a dict."""
        with pytest.raises(TypeError, match="Manifest payload must be a dict"):
            canonicalize_manifest(["not", "a", "dict"])

    def test_unsupported_python_types_rejected(self):
        """Sets or custom classes raise TypeError."""
        with pytest.raises(TypeError, match="not JSON serializable"):
            canonicalize_json({1, 2, 3})


# ==============================================================================
# 9. Determinism and Zero Trailing Newline
# ==============================================================================

class TestDeterminismAndFraming:
    """Verifies bit-for-bit repeatability across thousands of iterations and framing rules."""

    def test_zero_trailing_newline_guaranteed(self):
        """Asserts that neither canonicalize_json nor canonicalize_manifest append newlines."""
        obj = {"a": 1, "b": [2, 3], "c": {"d": "hello"}}
        canonical = canonicalize_json(obj)
        assert not canonical.endswith(b"\n")
        assert not canonical.endswith(b"\r")
        assert canonical.endswith(b"}")

        manifest = {"version": 1, "count": 10}
        c_bytes, c_hash = canonicalize_manifest(manifest)
        assert not c_bytes.endswith(b"\n")
        assert not c_bytes.endswith(b"\r")
        assert c_bytes.endswith(b"}")
        assert hashlib.sha256(c_bytes).hexdigest() == c_hash

    def test_deterministic_output_across_iterations(self):
        """Ensures identical bytes and hashes across 1,000 serializations."""
        data = {
            "z": 100,
            "m": [None, True, False, 42, "text", {"nested": "value"}],
            "a": "first",
            "\u00e9": "accent",
            "\U0001f512": "lock",
        }
        first_bytes = canonicalize_json(data)
        first_hash = hashlib.sha256(first_bytes).hexdigest()

        for _ in range(1000):
            res_bytes = canonicalize_json(data)
            assert res_bytes == first_bytes
            assert hashlib.sha256(res_bytes).hexdigest() == first_hash
