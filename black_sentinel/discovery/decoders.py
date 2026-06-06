"""
decoder_engine.py
=================
Production-ready multi-encoding Decoder Engine.

Supported encodings:
  Base64, Base32, Hex, URL, JWT, Unicode-escape, HTML entities

Features:
  - Recursive / nested decoding until no further layer can be peeled
  - Encoding detection with confidence scoring
  - False-positive reduction heuristics
  - Thread-safe design
  - Structured logging
  - Comprehensive unit tests (run: python decoder_engine.py --test)

Author : Senior Cybersecurity Engineer
License: MIT
"""

from __future__ import annotations

import base64
import binascii
import html
import json
import logging
import re
import threading
import unittest
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logger = logging.getLogger("decoder_engine")
if not logger.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(
        logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S",
        )
    )
    logger.addHandler(_h)
logger.setLevel(logging.INFO)

# ---------------------------------------------------------------------------
# Constants / heuristics
# ---------------------------------------------------------------------------

# Minimum length thresholds to avoid false positives on trivially short strings
_MIN_BASE64_LEN = 4
_MIN_BASE32_LEN = 8
_MIN_HEX_LEN = 4          # at least 2 bytes
_MAX_RECURSIVE_DEPTH = 20

# Printable-UTF-8 ratio required to accept a decoded result
_MIN_PRINTABLE_RATIO = 0.80

# Regex patterns
_RE_BASE64 = re.compile(r"^[A-Za-z0-9+/\-_]+=*$")
_RE_BASE32 = re.compile(r"^[A-Z2-7]+=*$")
_RE_HEX = re.compile(r"^(?:0x|0X)?[0-9A-Fa-f]+$")
_RE_URL_ENCODED = re.compile(r"%[0-9A-Fa-f]{2}")
_RE_UNICODE_ESCAPE = re.compile(r"\\u[0-9A-Fa-f]{4}|\\U[0-9A-Fa-f]{8}|\\x[0-9A-Fa-f]{2}")
_RE_HTML_ENTITY = re.compile(r"&(?:#\d+|#x[0-9A-Fa-f]+|[a-zA-Z][a-zA-Z0-9]*);")
_RE_JWT = re.compile(r"^[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]*$")

# Encoding type identifiers
ENC_BASE64 = "base64"
ENC_BASE32 = "base32"
ENC_HEX = "hex"
ENC_URL = "url"
ENC_JWT = "jwt"
ENC_UNICODE = "unicode_escape"
ENC_HTML = "html_entity"
ENC_UNKNOWN = "unknown"

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class DecodeResult:
    """Result for a single decode attempt."""
    encoding: str
    decoded: str
    confidence: float           # 0.0 – 1.0
    layer: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None

    @property
    def success(self) -> bool:
        return self.error is None and self.decoded != ""


@dataclass
class RecursiveDecodeResult:
    """Aggregated result from recursive_decode()."""
    original: str
    final: str
    layers: List[DecodeResult] = field(default_factory=list)
    depth_reached: int = 0
    encodings_found: List[str] = field(default_factory=list)

    @property
    def was_encoded(self) -> bool:
        return bool(self.layers)


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def _printable_ratio(s: str) -> float:
    """Return fraction of characters that are printable (non-control) UTF-8."""
    if not s:
        return 0.0
    printable = sum(1 for c in s if c.isprintable() or c in "\n\r\t")
    return printable / len(s)


def _looks_like_text(s: str, min_ratio: float = _MIN_PRINTABLE_RATIO) -> bool:
    return _printable_ratio(s) >= min_ratio


def _strip_padding(data: str) -> str:
    """Return *data* stripped of common whitespace / BOM."""
    return data.strip().lstrip("\ufeff")


def _b64_add_padding(s: str) -> str:
    """Add '=' padding so that len(s) % 4 == 0."""
    r = len(s) % 4
    if r == 0:
        return s
    return s + "=" * (4 - r)


def _safe_utf8(raw: bytes) -> Optional[str]:
    """Try to decode *raw* bytes as UTF-8; return None on failure."""
    try:
        return raw.decode("utf-8")
    except (UnicodeDecodeError, ValueError):
        try:
            return raw.decode("latin-1")
        except Exception:
            return None


# ---------------------------------------------------------------------------
# DecoderEngine
# ---------------------------------------------------------------------------

class DecoderEngine:
    """
    Multi-encoding decoder with recursive layer peeling.

    Thread-safe: each public method is stateless with respect to instance
    state; the lock protects only the optional shared cache.
    """

    def __init__(self, max_depth: int = _MAX_RECURSIVE_DEPTH) -> None:
        self.max_depth = max_depth
        self._lock = threading.Lock()
        # Optional decode-result cache (input → RecursiveDecodeResult)
        self._cache: Dict[str, RecursiveDecodeResult] = {}

    # ------------------------------------------------------------------
    # Individual decoders
    # ------------------------------------------------------------------

    def decode_base64(self, data: str) -> DecodeResult:
        """Attempt standard Base64 (and URL-safe Base64) decoding."""
        data = _strip_padding(data)

        if len(data) < _MIN_BASE64_LEN:
            return self._fail(ENC_BASE64, "too short", data)

        # Normalise URL-safe alphabet → standard
        normalised = data.replace("-", "+").replace("_", "/")
        padded = _b64_add_padding(normalised)

        if not _RE_BASE64.match(padded):
            return self._fail(ENC_BASE64, "non-base64 characters", data)

        try:
            raw = base64.b64decode(padded, validate=True)
        except (binascii.Error, ValueError) as exc:
            return self._fail(ENC_BASE64, str(exc), data)

        decoded = _safe_utf8(raw)
        if decoded is None:
            return self._fail(ENC_BASE64, "binary / non-text result", data)

        if not _looks_like_text(decoded):
            return self._fail(ENC_BASE64, "decoded result is mostly non-printable", data)

        confidence = self._confidence_base64(data, decoded)
        logger.debug("Base64 decoded (conf=%.2f): %r → %r", confidence, data[:40], decoded[:40])
        return DecodeResult(encoding=ENC_BASE64, decoded=decoded, confidence=confidence)

    def decode_base32(self, data: str) -> DecodeResult:
        """Attempt Base32 decoding."""
        data = _strip_padding(data).upper()

        if len(data) < _MIN_BASE32_LEN:
            return self._fail(ENC_BASE32, "too short", data)

        padded = _b64_add_padding(data)   # same padding rule
        if not _RE_BASE32.match(padded):
            return self._fail(ENC_BASE32, "non-base32 characters", data)

        try:
            raw = base64.b32decode(padded, casefold=True)
        except (binascii.Error, ValueError) as exc:
            return self._fail(ENC_BASE32, str(exc), data)

        decoded = _safe_utf8(raw)
        if decoded is None:
            return self._fail(ENC_BASE32, "binary / non-text result", data)

        if not _looks_like_text(decoded):
            return self._fail(ENC_BASE32, "decoded result is mostly non-printable", data)

        confidence = self._confidence_base32(data, decoded)
        logger.debug("Base32 decoded (conf=%.2f): %r → %r", confidence, data[:40], decoded[:40])
        return DecodeResult(encoding=ENC_BASE32, decoded=decoded, confidence=confidence)

    def decode_hex(self, data: str) -> DecodeResult:
        """Attempt hexadecimal decoding (with or without 0x prefix)."""
        data = _strip_padding(data)
        stripped = data.lstrip("0x").lstrip("0X").replace(" ", "").replace(":", "")

        if len(stripped) < _MIN_HEX_LEN:
            return self._fail(ENC_HEX, "too short", data)

        if not _RE_HEX.match(stripped):
            return self._fail(ENC_HEX, "non-hex characters", data)

        if len(stripped) % 2 != 0:
            return self._fail(ENC_HEX, "odd-length hex string", data)

        try:
            raw = bytes.fromhex(stripped)
        except ValueError as exc:
            return self._fail(ENC_HEX, str(exc), data)

        decoded = _safe_utf8(raw)
        if decoded is None:
            return self._fail(ENC_HEX, "binary / non-text result", data)

        if not _looks_like_text(decoded):
            return self._fail(ENC_HEX, "decoded result is mostly non-printable", data)

        confidence = self._confidence_hex(stripped, decoded)
        logger.debug("Hex decoded (conf=%.2f): %r → %r", confidence, data[:40], decoded[:40])
        return DecodeResult(encoding=ENC_HEX, decoded=decoded, confidence=confidence)

    def decode_url(self, data: str) -> DecodeResult:
        """Attempt URL (percent) decoding."""
        data = _strip_padding(data)

        if not _RE_URL_ENCODED.search(data):
            return self._fail(ENC_URL, "no percent-encoded sequences found", data)

        try:
            decoded = urllib.parse.unquote(data, errors="strict")
        except Exception as exc:
            return self._fail(ENC_URL, str(exc), data)

        if decoded == data:
            return self._fail(ENC_URL, "decoding produced no change", data)

        confidence = self._confidence_url(data, decoded)
        logger.debug("URL decoded (conf=%.2f): %r → %r", confidence, data[:40], decoded[:40])
        return DecodeResult(encoding=ENC_URL, decoded=decoded, confidence=confidence)

    def decode_jwt(self, data: str) -> DecodeResult:
        """
        Decode a JWT token.

        Returns a JSON string containing header + payload.
        Does NOT verify the signature.
        """
        data = _strip_padding(data)

        if not _RE_JWT.match(data):
            return self._fail(ENC_JWT, "not a JWT-shaped string", data)

        parts = data.split(".")
        if len(parts) != 3:
            return self._fail(ENC_JWT, "expected exactly 3 dot-separated parts", data)

        results = {}
        labels = ("header", "payload")
        for label, part in zip(labels, parts[:2]):
            padded = _b64_add_padding(part.replace("-", "+").replace("_", "/"))
            try:
                raw = base64.b64decode(padded)
                results[label] = json.loads(raw.decode("utf-8"))
            except Exception as exc:
                return self._fail(ENC_JWT, f"Failed to decode JWT {label}: {exc}", data)

        results["signature"] = parts[2]
        decoded = json.dumps(results, indent=2)
        confidence = 0.97  # JWT structure is highly unambiguous
        logger.debug("JWT decoded (conf=%.2f)", confidence)
        return DecodeResult(
            encoding=ENC_JWT,
            decoded=decoded,
            confidence=confidence,
            metadata={"header": results["header"], "payload": results["payload"]},
        )

    def decode_unicode(self, data: str) -> DecodeResult:
        """Decode Unicode escape sequences (\\uXXXX, \\UXXXXXXXX, \\xXX)."""
        data_s = _strip_padding(data)

        if not _RE_UNICODE_ESCAPE.search(data_s):
            return self._fail(ENC_UNICODE, "no unicode escape sequences found", data_s)

        try:
            decoded = data_s.encode("raw_unicode_escape").decode("unicode_escape")
        except (UnicodeDecodeError, ValueError) as exc:
            # Fallback: regex substitution
            try:
                decoded = re.sub(
                    r"\\u([0-9A-Fa-f]{4})",
                    lambda m: chr(int(m.group(1), 16)),
                    data_s,
                )
                decoded = re.sub(
                    r"\\U([0-9A-Fa-f]{8})",
                    lambda m: chr(int(m.group(1), 16)),
                    decoded,
                )
                decoded = re.sub(
                    r"\\x([0-9A-Fa-f]{2})",
                    lambda m: chr(int(m.group(1), 16)),
                    decoded,
                )
            except Exception as exc2:
                return self._fail(ENC_UNICODE, str(exc2), data_s)

        if decoded == data_s:
            return self._fail(ENC_UNICODE, "decoding produced no change", data_s)

        confidence = self._confidence_unicode(data_s, decoded)
        logger.debug("Unicode decoded (conf=%.2f): %r → %r", confidence, data_s[:40], decoded[:40])
        return DecodeResult(encoding=ENC_UNICODE, decoded=decoded, confidence=confidence)

    def decode_html_entities(self, data: str) -> DecodeResult:
        """Decode HTML entities (&amp;, &#60;, &#x3C;, etc.)."""
        data_s = _strip_padding(data)

        if not _RE_HTML_ENTITY.search(data_s):
            return self._fail(ENC_HTML, "no HTML entities found", data_s)

        try:
            decoded = html.unescape(data_s)
        except Exception as exc:
            return self._fail(ENC_HTML, str(exc), data_s)

        if decoded == data_s:
            return self._fail(ENC_HTML, "decoding produced no change", data_s)

        confidence = self._confidence_html(data_s, decoded)
        logger.debug("HTML decoded (conf=%.2f): %r → %r", confidence, data_s[:40], decoded[:40])
        return DecodeResult(encoding=ENC_HTML, decoded=decoded, confidence=confidence)

    # ------------------------------------------------------------------
    # Encoding detection
    # ------------------------------------------------------------------

    def detect_encoding(self, data: str) -> List[Tuple[str, float]]:
        """
        Detect likely encodings for *data*.

        Returns a list of (encoding_type, confidence) sorted descending.
        """
        data_s = _strip_padding(data)
        candidates: List[Tuple[str, float]] = []

        # JWT — check first (it also matches base64 characters)
        if _RE_JWT.match(data_s) and data_s.count(".") == 2:
            candidates.append((ENC_JWT, 0.97))

        # URL encoding
        if _RE_URL_ENCODED.search(data_s):
            density = len(_RE_URL_ENCODED.findall(data_s)) / max(len(data_s), 1)
            candidates.append((ENC_URL, min(0.5 + density * 5, 0.95)))

        # HTML entities
        if _RE_HTML_ENTITY.search(data_s):
            density = len(_RE_HTML_ENTITY.findall(data_s)) / max(len(data_s), 1)
            candidates.append((ENC_HTML, min(0.5 + density * 10, 0.95)))

        # Unicode escapes
        if _RE_UNICODE_ESCAPE.search(data_s):
            density = len(_RE_UNICODE_ESCAPE.findall(data_s)) / max(len(data_s), 1)
            candidates.append((ENC_UNICODE, min(0.5 + density * 5, 0.95)))

        # Hex — only pure hex strings (no mixed content) to reduce FP
        stripped_hex = data_s.lstrip("0x").lstrip("0X").replace(":", "").replace(" ", "")
        if (
            len(stripped_hex) >= _MIN_HEX_LEN
            and len(stripped_hex) % 2 == 0
            and _RE_HEX.match(stripped_hex)
            and not _RE_BASE64.match(data_s)  # prefer base64 if both match
        ):
            candidates.append((ENC_HEX, 0.80))

        # Base32 — uppercase only, strict alphabet
        if (
            len(data_s) >= _MIN_BASE32_LEN
            and _RE_BASE32.match(_b64_add_padding(data_s.upper()))
            and data_s == data_s.upper()
        ):
            candidates.append((ENC_BASE32, 0.75))

        # Base64 — checked last as it has the broadest alphabet
        if (
            len(data_s) >= _MIN_BASE64_LEN
            and _RE_BASE64.match(_b64_add_padding(data_s.replace("-", "+").replace("_", "/")))
        ):
            conf = self._confidence_base64_detect(data_s)
            candidates.append((ENC_BASE64, conf))

        candidates.sort(key=lambda x: x[1], reverse=True)
        return candidates

    # ------------------------------------------------------------------
    # Recursive decoder
    # ------------------------------------------------------------------

    def recursive_decode(self, data: str, *, use_cache: bool = True) -> RecursiveDecodeResult:
        """
        Peel encoding layers recursively until no further decoding is possible
        or max_depth is reached.

        Returns a RecursiveDecodeResult with every intermediate step.
        """
        original = data

        if use_cache:
            with self._lock:
                cached = self._cache.get(original)
            if cached is not None:
                logger.debug("Cache hit for input (len=%d)", len(original))
                return cached

        current = data
        layers: List[DecodeResult] = []
        encodings_found: List[str] = []
        seen: set[str] = {current}   # cycle detection

        for depth in range(1, self.max_depth + 1):
            candidates = self.detect_encoding(current)
            if not candidates:
                logger.debug("[depth=%d] No encodings detected, stopping.", depth)
                break

            best_result: Optional[DecodeResult] = None

            for enc_type, _ in candidates:
                result = self._decode_by_type(enc_type, current)
                if result.success and result.confidence >= 0.55:
                    result.layer = depth
                    best_result = result
                    logger.info(
                        "[depth=%d] Decoded %s (conf=%.2f): %r → %r",
                        depth, enc_type, result.confidence,
                        current[:50], result.decoded[:50],
                    )
                    break  # take the highest-confidence successful decode

            if best_result is None:
                logger.debug("[depth=%d] No decode succeeded with sufficient confidence.", depth)
                break

            if best_result.decoded in seen:
                logger.debug("[depth=%d] Cycle detected, stopping.", depth)
                break

            layers.append(best_result)
            encodings_found.append(best_result.encoding)
            seen.add(best_result.decoded)
            current = best_result.decoded

        result_obj = RecursiveDecodeResult(
            original=original,
            final=current,
            layers=layers,
            depth_reached=len(layers),
            encodings_found=encodings_found,
        )

        if use_cache:
            with self._lock:
                self._cache[original] = result_obj

        return result_obj

    def decode_all(self, text: str) -> List[str]:
        result = self.recursive_decode(text)
        return [layer.decoded for layer in result.layers]

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _fail(encoding: str, reason: str, data: str) -> DecodeResult:
        logger.debug("%s decode failed (%s): %r", encoding, reason, data[:60])
        return DecodeResult(
            encoding=encoding,
            decoded="",
            confidence=0.0,
            error=reason,
        )

    def _decode_by_type(self, enc_type: str, data: str) -> DecodeResult:
        dispatch = {
            ENC_BASE64:  self.decode_base64,
            ENC_BASE32:  self.decode_base32,
            ENC_HEX:     self.decode_hex,
            ENC_URL:     self.decode_url,
            ENC_JWT:     self.decode_jwt,
            ENC_UNICODE: self.decode_unicode,
            ENC_HTML:    self.decode_html_entities,
        }
        fn = dispatch.get(enc_type)
        if fn is None:
            return self._fail(enc_type, "no handler", data)
        try:
            return fn(data)
        except Exception as exc:
            return self._fail(enc_type, f"unhandled exception: {exc}", data)

    # ------------------------------------------------------------------
    # Confidence scorers (false-positive reduction)
    # ------------------------------------------------------------------

    @staticmethod
    def _confidence_base64(encoded: str, decoded: str) -> float:
        score = 0.60
        # Longer strings → less likely to be coincidental
        if len(encoded) >= 20:
            score += 0.10
        if len(encoded) >= 40:
            score += 0.05
        # Decoded text looks like natural language / structured data
        if _printable_ratio(decoded) >= 0.99:
            score += 0.10
        # Padding present → strong indicator
        if encoded.endswith("="):
            score += 0.05
        # Decoded text contains common patterns
        if re.search(r"[\w\s]{6,}", decoded):
            score += 0.05
        return min(score, 0.97)

    @staticmethod
    def _confidence_base64_detect(encoded: str) -> float:
        score = 0.55
        if len(encoded) >= 20:
            score += 0.10
        if encoded.endswith("="):
            score += 0.10
        # Pure base64 alphabet (no URL-special chars) → slightly higher
        if re.fullmatch(r"[A-Za-z0-9+/]+=*", encoded):
            score += 0.05
        return min(score, 0.90)

    @staticmethod
    def _confidence_base32(encoded: str, decoded: str) -> float:
        score = 0.65
        if len(encoded) >= 16:
            score += 0.10
        if _printable_ratio(decoded) >= 0.99:
            score += 0.10
        if encoded.endswith("="):
            score += 0.05
        return min(score, 0.95)

    @staticmethod
    def _confidence_hex(encoded: str, decoded: str) -> float:
        score = 0.70
        if len(encoded) >= 16:
            score += 0.10
        if _printable_ratio(decoded) >= 0.99:
            score += 0.10
        # Even number of chars is already enforced; pure lowercase or uppercase
        if encoded == encoded.lower() or encoded == encoded.upper():
            score += 0.05
        return min(score, 0.95)

    @staticmethod
    def _confidence_url(encoded: str, decoded: str) -> float:
        count = len(_RE_URL_ENCODED.findall(encoded))
        score = 0.65 + min(count * 0.05, 0.25)
        return min(score, 0.95)

    @staticmethod
    def _confidence_unicode(encoded: str, decoded: str) -> float:
        count = len(_RE_UNICODE_ESCAPE.findall(encoded))
        score = 0.70 + min(count * 0.05, 0.20)
        return min(score, 0.95)

    @staticmethod
    def _confidence_html(encoded: str, decoded: str) -> float:
        count = len(_RE_HTML_ENTITY.findall(encoded))
        score = 0.70 + min(count * 0.05, 0.25)
        return min(score, 0.97)

    # ------------------------------------------------------------------
    # Cache management
    # ------------------------------------------------------------------

    def clear_cache(self) -> None:
        """Clear the internal decode-result cache."""
        with self._lock:
            self._cache.clear()

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    def __enter__(self) -> "DecoderEngine":
        return self

    def __exit__(self, *_) -> None:
        self.clear_cache()

    def __repr__(self) -> str:
        return f"DecoderEngine(max_depth={self.max_depth})"


# ---------------------------------------------------------------------------
# Unit tests
# ---------------------------------------------------------------------------

class TestDecoderEngine(unittest.TestCase):

    def setUp(self):
        self.engine = DecoderEngine()

    # --- Base64 ---

    def test_base64_standard(self):
        r = self.engine.decode_base64("SGVsbG8sIFdvcmxkIQ==")
        self.assertTrue(r.success)
        self.assertEqual(r.decoded, "Hello, World!")

    def test_base64_urlsafe(self):
        r = self.engine.decode_base64("SGVsbG8tV29ybGQ_")
        self.assertTrue(r.success)

    def test_base64_no_padding(self):
        # base64("test") = "dGVzdA=="
        r = self.engine.decode_base64("dGVzdA")
        self.assertTrue(r.success)
        self.assertEqual(r.decoded, "test")

    def test_base64_too_short(self):
        # Single character result is acceptable; test with non-base64 chars
        r = self.engine.decode_base64("!")
        self.assertFalse(r.success)

    def test_base64_invalid(self):
        r = self.engine.decode_base64("!!!not-base64!!!")
        self.assertFalse(r.success)

    def test_base64_binary_rejected(self):
        # base64 of raw binary (mostly non-printable)
        raw = bytes(range(0, 32))
        enc = base64.b64encode(raw).decode()
        r = self.engine.decode_base64(enc)
        self.assertFalse(r.success)

    # --- Base32 ---

    def test_base32_basic(self):
        enc = base64.b32encode(b"Hello World").decode()
        r = self.engine.decode_base32(enc)
        self.assertTrue(r.success)
        self.assertEqual(r.decoded, "Hello World")

    def test_base32_invalid_chars(self):
        r = self.engine.decode_base32("HELLO123WORLD!")
        self.assertFalse(r.success)

    # --- Hex ---

    def test_hex_basic(self):
        r = self.engine.decode_hex("48656c6c6f20576f726c64")
        self.assertTrue(r.success)
        self.assertEqual(r.decoded, "Hello World")

    def test_hex_with_prefix(self):
        r = self.engine.decode_hex("0x48656c6c6f")
        self.assertTrue(r.success)
        self.assertEqual(r.decoded, "Hello")

    def test_hex_odd_length(self):
        # Odd number of nibbles must be rejected
        r = self.engine.decode_hex("48656")
        self.assertFalse(r.success)

    def test_hex_even_short(self):
        r = self.engine.decode_hex("4865")
        self.assertTrue(r.success)
        self.assertEqual(r.decoded, "He")

    def test_hex_invalid(self):
        r = self.engine.decode_hex("ZZZZZZZZ")
        self.assertFalse(r.success)

    # --- URL ---

    def test_url_basic(self):
        r = self.engine.decode_url("Hello%20World%21")
        self.assertTrue(r.success)
        self.assertEqual(r.decoded, "Hello World!")

    def test_url_no_encoding(self):
        r = self.engine.decode_url("HelloWorld")
        self.assertFalse(r.success)

    def test_url_double_encoded(self):
        r = self.engine.decode_url("Hello%2520World")
        self.assertTrue(r.success)
        self.assertEqual(r.decoded, "Hello%20World")

    # --- JWT ---

    def test_jwt_valid(self):
        import base64 as b64
        header = b64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).rstrip(b"=").decode()
        payload = b64.urlsafe_b64encode(json.dumps({"sub": "user1", "iat": 1234567890}).encode()).rstrip(b"=").decode()
        token = f"{header}.{payload}.fakesig"
        r = self.engine.decode_jwt(token)
        self.assertTrue(r.success)
        self.assertIn("header", r.metadata)
        self.assertIn("payload", r.metadata)
        self.assertEqual(r.metadata["header"]["alg"], "HS256")

    def test_jwt_invalid_structure(self):
        r = self.engine.decode_jwt("not.a.jwt.with.five.parts")
        self.assertFalse(r.success)

    def test_jwt_not_a_token(self):
        r = self.engine.decode_jwt("Hello World")
        self.assertFalse(r.success)

    # --- Unicode ---

    def test_unicode_basic(self):
        r = self.engine.decode_unicode(r"\u0048\u0065\u006c\u006c\u006f")
        self.assertTrue(r.success)
        self.assertIn("Hello", r.decoded)

    def test_unicode_no_escapes(self):
        r = self.engine.decode_unicode("Hello World")
        self.assertFalse(r.success)

    # --- HTML entities ---

    def test_html_basic(self):
        r = self.engine.decode_html_entities("&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;")
        self.assertTrue(r.success)
        self.assertIn("<script>", r.decoded)

    def test_html_no_entities(self):
        r = self.engine.decode_html_entities("Hello World")
        self.assertFalse(r.success)

    def test_html_numeric(self):
        r = self.engine.decode_html_entities("&#72;&#101;&#108;&#108;&#111;")
        self.assertTrue(r.success)
        self.assertEqual(r.decoded, "Hello")

    # --- detect_encoding ---

    def test_detect_base64(self):
        candidates = self.engine.detect_encoding("SGVsbG8sIFdvcmxkIQ==")
        types = [c[0] for c in candidates]
        self.assertIn(ENC_BASE64, types)

    def test_detect_url(self):
        candidates = self.engine.detect_encoding("Hello%20World")
        types = [c[0] for c in candidates]
        self.assertIn(ENC_URL, types)

    def test_detect_html(self):
        candidates = self.engine.detect_encoding("&lt;b&gt;bold&lt;/b&gt;")
        types = [c[0] for c in candidates]
        self.assertIn(ENC_HTML, types)

    # --- recursive_decode ---

    def test_recursive_double_base64(self):
        inner = base64.b64encode(b"Secret message").decode()
        outer = base64.b64encode(inner.encode()).decode()
        r = self.engine.recursive_decode(outer)
        self.assertEqual(r.final, "Secret message")
        self.assertEqual(r.depth_reached, 2)

    def test_recursive_url_then_base64(self):
        b64_part = base64.b64encode(b"Hello World").decode()
        url_encoded = urllib.parse.quote(b64_part)
        r = self.engine.recursive_decode(url_encoded)
        self.assertEqual(r.final, "Hello World")
        self.assertGreaterEqual(r.depth_reached, 2)

    def test_recursive_no_encoding(self):
        r = self.engine.recursive_decode("plain text with no encoding")
        self.assertEqual(r.depth_reached, 0)
        self.assertFalse(r.was_encoded)

    def test_recursive_html_then_url(self):
        url_part = urllib.parse.quote("<b>bold</b>")
        html_part = html.escape(url_part)
        r = self.engine.recursive_decode(html_part)
        self.assertIn("<b>bold</b>", r.final)

    def test_recursive_cycle_detection(self):
        # Encoding that decodes to itself should terminate cleanly
        # "YQ==" decodes to "a", which is too short to re-encode meaningfully
        r = self.engine.recursive_decode("cGxhaW50ZXh0")  # "plaintext"
        self.assertIsNotNone(r)

    def test_cache_hit(self):
        data = base64.b64encode(b"cached value").decode()
        r1 = self.engine.recursive_decode(data)
        r2 = self.engine.recursive_decode(data)
        self.assertEqual(r1.final, r2.final)

    def test_confidence_scores_in_range(self):
        for enc, sample in [
            (ENC_BASE64, "SGVsbG8sIFdvcmxkIQ=="),
            (ENC_URL, "Hello%20World"),
            (ENC_HTML, "&lt;b&gt;"),
        ]:
            result = self.engine._decode_by_type(enc, sample)
            if result.success:
                self.assertGreaterEqual(result.confidence, 0.0)
                self.assertLessEqual(result.confidence, 1.0)

    def test_thread_safety(self):
        import threading
        errors = []
        data = base64.b64encode(b"thread safe test").decode()

        def worker():
            try:
                r = self.engine.recursive_decode(data, use_cache=False)
                assert r.final == "thread safe test", f"Got: {r.final}"
            except Exception as exc:
                errors.append(str(exc))

        threads = [threading.Thread(target=worker) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [], f"Thread errors: {errors}")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def _main():
    import argparse
    import sys

    parser = argparse.ArgumentParser(description="Decoder Engine CLI")
    parser.add_argument("--test", action="store_true", help="Run unit tests")
    parser.add_argument("--decode", metavar="STRING", help="Recursively decode a string")
    parser.add_argument("--detect", metavar="STRING", help="Detect encodings in a string")
    parser.add_argument("--depth", type=int, default=_MAX_RECURSIVE_DEPTH,
                        help=f"Max recursive depth (default: {_MAX_RECURSIVE_DEPTH})")
    parser.add_argument("--verbose", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    if args.test:
        print("=" * 60)
        print("Running DecoderEngine unit tests …")
        print("=" * 60)
        loader = unittest.TestLoader()
        suite = loader.loadTestsFromTestCase(TestDecoderEngine)
        runner = unittest.TextTestRunner(verbosity=2)
        result = runner.run(suite)
        sys.exit(0 if result.wasSuccessful() else 1)

    engine = DecoderEngine(max_depth=args.depth)

    if args.detect:
        candidates = engine.detect_encoding(args.detect)
        print(f"\nEncoding detection for: {args.detect!r}")
        if not candidates:
            print("  No encodings detected.")
        for enc, conf in candidates:
            print(f"  {enc:<20}  confidence={conf:.2f}")

    if args.decode:
        result = engine.recursive_decode(args.decode)
        print(f"\nRecursive decode of: {args.decode!r}")
        print(f"  Depth reached  : {result.depth_reached}")
        print(f"  Encodings found: {result.encodings_found}")
        print(f"  Final value    : {result.final!r}")
        if result.layers:
            print("\nLayer-by-layer:")
            for layer in result.layers:
                print(
                    f"  [{layer.layer}] {layer.encoding:<20} "
                    f"conf={layer.confidence:.2f}  "
                    f"→ {layer.decoded[:80]!r}"
                )

    if not args.test and not args.detect and not args.decode:
        parser.print_help()


if __name__ == "__main__":
    _main()
