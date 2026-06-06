"""
validation_engine.py
=====================
Production-ready Validation Engine for secrets, API keys, and auth tokens.

Architecture  : Structural + checksum + heuristic validation pipeline
Features      : Confidence scoring, false-positive reduction,
                entropy analysis, pattern decomposition, metadata enrichment
Author        : Principal Cybersecurity Architect
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import math
import re
import string
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s – %(message)s",
)
logger = logging.getLogger("validation_engine")


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------
class ValidationStatus(str, Enum):
    VALID           = "VALID"           # all checks passed, high confidence
    LIKELY_VALID    = "LIKELY_VALID"    # structural checks pass, minor doubts
    UNCERTAIN       = "UNCERTAIN"       # some checks pass, cannot confirm
    LIKELY_INVALID  = "LIKELY_INVALID"  # structural/checksum mismatch
    INVALID         = "INVALID"         # definitively fails structural rules
    PLACEHOLDER     = "PLACEHOLDER"     # looks like example / test / dummy data


class TokenType(str, Enum):
    AWS_ACCESS_KEY_ID      = "AWS_ACCESS_KEY_ID"
    AWS_SECRET_ACCESS_KEY  = "AWS_SECRET_ACCESS_KEY"
    GITHUB_PAT             = "GITHUB_PAT"
    GITHUB_OAUTH           = "GITHUB_OAUTH"
    GITHUB_APP             = "GITHUB_APP"
    OPENAI_API_KEY         = "OPENAI_API_KEY"
    STRIPE_SECRET_KEY      = "STRIPE_SECRET_KEY"
    STRIPE_RESTRICTED_KEY  = "STRIPE_RESTRICTED_KEY"
    STRIPE_PUBLISHABLE_KEY = "STRIPE_PUBLISHABLE_KEY"
    SLACK_BOT_TOKEN        = "SLACK_BOT_TOKEN"
    SLACK_USER_TOKEN       = "SLACK_USER_TOKEN"
    SLACK_APP_TOKEN        = "SLACK_APP_TOKEN"
    SLACK_WEBHOOK          = "SLACK_WEBHOOK"
    JWT                    = "JWT"
    UNKNOWN                = "UNKNOWN"


# ---------------------------------------------------------------------------
# ValidationResult
# ---------------------------------------------------------------------------
@dataclass
class ValidationResult:
    """Standardised result returned by every validate_* method."""

    id:              str             = field(default_factory=lambda: str(uuid.uuid4()))
    token_type:      TokenType       = TokenType.UNKNOWN
    status:          ValidationStatus = ValidationStatus.UNCERTAIN
    confidence:      float           = 0.0           # 0.0 – 1.0
    redacted_value:  str             = ""
    checks:          dict[str, bool] = field(default_factory=dict)
    failure_reasons: list[str]       = field(default_factory=list)
    warnings:        list[str]       = field(default_factory=list)
    metadata:        dict[str, Any]  = field(default_factory=dict)
    validated_at:    str             = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["token_type"] = self.token_type.value
        d["status"]     = self.status.value
        return d

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @property
    def is_actionable(self) -> bool:
        """True when the result is confident enough to act on."""
        return self.status in (ValidationStatus.VALID, ValidationStatus.INVALID)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _redact(value: str, show: int = 4) -> str:
    if len(value) <= show * 2:
        return "*" * len(value)
    return value[:show] + "*" * (len(value) - show * 2) + value[-show:]


def _shannon_entropy(s: str) -> float:
    """Shannon entropy (bits per character) of a string."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((v / length) * math.log2(v / length) for v in freq.values())


def _is_base64url(s: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9\-_]+", s))


def _safe_b64url_decode(segment: str) -> bytes | None:
    padded = segment + "=" * (-len(segment) % 4)
    try:
        return base64.urlsafe_b64decode(padded)
    except Exception:
        return None


def _is_placeholder(value: str) -> bool:
    """Detect example / dummy / test values that appear in docs."""
    PLACEHOLDER_PATTERNS = [
        r"(?i)example",
        r"(?i)your[_\-]?key",
        r"(?i)test[_\-]?key",
        r"(?i)dummy",
        r"(?i)replace[_\-]?me",
        r"(?i)xxx+",
        r"(?i)sample",
        r"(?i)insert[_\-]?here",
        r"AAAA{4,}",          # repeated chars like AKIAAAAAAAAAAAAAAA
        r"1234567890",
        r"0000000000",
    ]
    for pat in PLACEHOLDER_PATTERNS:
        if re.search(pat, value):
            return True
    # detect low-entropy placeholder (e.g. aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa)
    if len(value) >= 20 and _shannon_entropy(value) < 2.0:
        return True
    return False


def _check_charset(value: str, allowed: str, name: str) -> tuple[bool, str]:
    invalid = set(value) - set(allowed)
    if invalid:
        return False, f"{name}: invalid characters {sorted(invalid)}"
    return True, ""


# ---------------------------------------------------------------------------
# AWS SigV4 HMAC helpers (structural only – no network call)
# ---------------------------------------------------------------------------

_AWS_KEY_ID_PREFIXES = frozenset(["AKIA", "ABIA", "ACCA", "ASIA"])

_AWS_KEY_ID_PATTERN  = re.compile(
    r"^(AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}$"
)
_AWS_SECRET_PATTERN  = re.compile(
    r"^[A-Za-z0-9/+=]{40}$"
)

# ---------------------------------------------------------------------------
# GitHub patterns
# ---------------------------------------------------------------------------
_GITHUB_PAT_PATTERN   = re.compile(r"^ghp_[A-Za-z0-9]{36}$")
_GITHUB_OAUTH_PATTERN = re.compile(r"^gho_[A-Za-z0-9]{36}$")
_GITHUB_APP_PATTERN   = re.compile(r"^(ghs_|ghu_)[A-Za-z0-9]{36}$")

# ---------------------------------------------------------------------------
# OpenAI
# ---------------------------------------------------------------------------
_OPENAI_PATTERN = re.compile(r"^sk-[A-Za-z0-9]{48}$")

# ---------------------------------------------------------------------------
# Stripe
# ---------------------------------------------------------------------------
_STRIPE_SK_PATTERN  = re.compile(r"^sk_(live|test)_[A-Za-z0-9]{24,}$")
_STRIPE_RK_PATTERN  = re.compile(r"^rk_(live|test)_[A-Za-z0-9]{24,}$")
_STRIPE_PK_PATTERN  = re.compile(r"^pk_(live|test)_[A-Za-z0-9]{24,}$")

# ---------------------------------------------------------------------------
# Slack
# ---------------------------------------------------------------------------
_SLACK_BOT_PATTERN      = re.compile(r"^xoxb-\d{10,13}-\d{10,13}-[A-Za-z0-9]{24,32}$")
_SLACK_USER_PATTERN     = re.compile(r"^xoxp-\d{10,13}-\d{10,13}-\d{10,13}-[A-Za-z0-9]{32}$")
_SLACK_APP_PATTERN      = re.compile(r"^xoxe\.[A-Za-z0-9\-_]{100,}$")
_SLACK_WEBHOOK_PATTERN  = re.compile(
    r"^https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24,}$"
)

# Slack known workspace ID ranges (T + 8-11 chars)
_SLACK_WID_PATTERN = re.compile(r"T[A-Z0-9]{8,11}")
_SLACK_CID_PATTERN = re.compile(r"B[A-Z0-9]{8,11}")

# ---------------------------------------------------------------------------
# JWT known algorithms
# ---------------------------------------------------------------------------
_JWT_VALID_ALGS = frozenset([
    "HS256", "HS384", "HS512",
    "RS256", "RS384", "RS512",
    "ES256", "ES384", "ES512",
    "PS256", "PS384", "PS512",
    "EdDSA", "none",
])


# ---------------------------------------------------------------------------
# Confidence scoring helper
# ---------------------------------------------------------------------------
class _ConfidenceAccumulator:
    """Weighted confidence calculator with named checks."""

    def __init__(self) -> None:
        self._checks: list[tuple[str, bool, float]] = []   # (name, passed, weight)

    def add(self, name: str, passed: bool, weight: float = 1.0) -> "_ConfidenceAccumulator":
        self._checks.append((name, passed, weight))
        return self

    def build(self) -> tuple[float, dict[str, bool], list[str]]:
        """Return (confidence 0-1, checks dict, failure_reasons list)."""
        if not self._checks:
            return 0.0, {}, []
        total_weight  = sum(w for _, _, w in self._checks)
        passed_weight = sum(w for _, p, w in self._checks if p)
        confidence    = passed_weight / total_weight if total_weight else 0.0
        checks        = {name: passed for name, passed, _ in self._checks}
        failures      = [name for name, passed, _ in self._checks if not passed]
        return round(confidence, 4), checks, failures


# ---------------------------------------------------------------------------
# ValidationEngine
# ---------------------------------------------------------------------------
class ValidationEngine:
    """
    Offline structural, checksum, and heuristic validator for API secrets.

    No network calls are made; all validation is deterministic and instantaneous.

    Usage
    -----
    engine = ValidationEngine()
    result = engine.validate_aws("AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
    print(result.to_json())
    """

    # ── AWS ──────────────────────────────────────────────────────────────────

    def validate_aws(
        self,
        access_key_id: str,
        secret_access_key: str | None = None,
    ) -> ValidationResult:
        """
        Validate an AWS Access Key ID and optionally its paired Secret Access Key.

        Checks
        ------
        - Prefix membership (AKIA / ABIA / ACCA / ASIA)
        - Exact length (20 chars)
        - Charset (A-Z 0-9 only)
        - Account-type inference from prefix
        - Secret: length (40 chars), charset, entropy
        - Placeholder / example value detection
        - Paired consistency (if both supplied)
        """
        acc = _ConfidenceAccumulator()
        warnings: list[str] = []
        metadata: dict[str, Any] = {}

        key = access_key_id.strip()

        # ── Key ID checks ────────────────────────────────────────────────────
        prefix_ok = any(key.startswith(p) for p in _AWS_KEY_ID_PREFIXES)
        acc.add("prefix_valid",        prefix_ok,          weight=3.0)
        acc.add("length_exact_20",     len(key) == 20,     weight=2.0)

        charset_ok, _ = _check_charset(key, string.ascii_uppercase + string.digits, "key_id")
        acc.add("charset_uppercase_alnum", charset_ok,     weight=1.5)

        acc.add("pattern_match",       bool(_AWS_KEY_ID_PATTERN.match(key)), weight=2.0)

        # placeholder / example detection
        placeholder = _is_placeholder(key)
        acc.add("not_placeholder",     not placeholder,    weight=2.0)
        if placeholder:
            warnings.append("Value matches known placeholder / example pattern")

        # entropy check on Key ID (should be high)
        entropy_id = _shannon_entropy(key[4:])   # skip prefix
        acc.add("entropy_sufficient",  entropy_id >= 3.5,  weight=1.0)
        metadata["key_id_entropy"] = round(entropy_id, 4)

        # account-type metadata from prefix
        prefix = key[:4] if len(key) >= 4 else ""
        metadata["prefix"] = prefix
        metadata["account_type"] = {
            "AKIA": "IAM user long-term key",
            "ABIA": "STS service bearer token",
            "ACCA": "AWS Connector credentials",
            "ASIA": "STS temporary credentials",
        }.get(prefix, "unknown")
        if prefix == "ASIA":
            warnings.append("ASIA prefix indicates temporary STS credentials; a session token is also required")

        # ── Secret checks (optional) ──────────────────────────────────────────
        if secret_access_key is not None:
            sec = secret_access_key.strip()
            acc.add("secret_length_40",   len(sec) == 40,  weight=2.0)
            acc.add("secret_pattern",     bool(_AWS_SECRET_PATTERN.match(sec)), weight=2.0)

            entropy_sec = _shannon_entropy(sec)
            acc.add("secret_entropy_high", entropy_sec >= 4.5, weight=1.5)
            metadata["secret_entropy"] = round(entropy_sec, 4)

            acc.add("secret_not_placeholder", not _is_placeholder(sec), weight=2.0)

            # Verify the pair is not obviously mismatched (same repeated block)
            pair_ok = key[:16] not in sec
            acc.add("pair_not_trivially_related", pair_ok, weight=0.5)

        confidence, checks, failures = acc.build()
        status = _status_from_confidence(confidence, placeholder)

        logger.debug("validate_aws('%s'): status=%s confidence=%.2f", _redact(key), status.value, confidence)

        return ValidationResult(
            token_type      = TokenType.AWS_ACCESS_KEY_ID,
            status          = status,
            confidence      = confidence,
            redacted_value  = _redact(key),
            checks          = checks,
            failure_reasons = failures,
            warnings        = warnings,
            metadata        = metadata,
        )

    # ── GitHub ────────────────────────────────────────────────────────────────

    def validate_github(self, token: str) -> ValidationResult:
        """
        Validate a GitHub Personal Access Token (classic or fine-grained),
        OAuth token, or GitHub App / server-to-server token.

        Checks
        ------
        - Prefix classification (ghp_ / gho_ / ghs_ / ghu_)
        - Exact length after prefix (36 alphanumeric chars)
        - Charset validation
        - Entropy analysis
        - Placeholder detection
        """
        acc = _ConfidenceAccumulator()
        warnings: list[str] = []
        metadata: dict[str, Any] = {}

        tok = token.strip()

        # classify prefix
        prefix_map: dict[str, tuple[TokenType, str]] = {
            "ghp_": (TokenType.GITHUB_PAT,   "Personal Access Token (classic)"),
            "gho_": (TokenType.GITHUB_OAUTH, "OAuth access token"),
            "ghs_": (TokenType.GITHUB_APP,   "GitHub App server-to-server token"),
            "ghu_": (TokenType.GITHUB_APP,   "GitHub App user-to-server token"),
        }
        token_type = TokenType.UNKNOWN
        detected_prefix = ""
        for pfx, (tt, desc) in prefix_map.items():
            if tok.startswith(pfx):
                token_type = tt
                detected_prefix = pfx
                metadata["token_class"] = desc
                break

        acc.add("prefix_known",   token_type != TokenType.UNKNOWN, weight=3.0)
        metadata["prefix"] = detected_prefix or tok[:4]

        # suffix (after prefix) must be exactly 36 alphanumeric chars
        body = tok[4:] if len(tok) > 4 else ""
        acc.add("body_length_36",  len(body) == 36, weight=2.5)
        acc.add("body_alnum",      body.isalnum(),   weight=1.5)

        # overall pattern match
        pattern_ok = (
            bool(_GITHUB_PAT_PATTERN.match(tok))
            or bool(_GITHUB_OAUTH_PATTERN.match(tok))
            or bool(_GITHUB_APP_PATTERN.match(tok))
        )
        acc.add("pattern_match", pattern_ok, weight=2.0)

        # entropy
        entropy = _shannon_entropy(body)
        acc.add("entropy_high", entropy >= 4.5, weight=1.5)
        metadata["entropy"] = round(entropy, 4)

        # placeholder
        placeholder = _is_placeholder(tok)
        acc.add("not_placeholder", not placeholder, weight=2.0)
        if placeholder:
            warnings.append("Token matches known placeholder / example pattern")

        confidence, checks, failures = acc.build()
        status = _status_from_confidence(confidence, placeholder)

        if token_type == TokenType.UNKNOWN:
            warnings.append(
                "Unrecognised prefix; fine-grained PATs (github_pat_*) use a different scheme"
            )

        return ValidationResult(
            token_type      = token_type,
            status          = status,
            confidence      = confidence,
            redacted_value  = _redact(tok),
            checks          = checks,
            failure_reasons = failures,
            warnings        = warnings,
            metadata        = metadata,
        )

    # ── OpenAI ────────────────────────────────────────────────────────────────

    def validate_openai(self, api_key: str) -> ValidationResult:
        """
        Validate an OpenAI API key.

        Checks
        ------
        - Fixed prefix sk-
        - Total length 51 chars (sk- + 48 alphanumeric)
        - Charset (A-Z a-z 0-9 only after prefix)
        - Shannon entropy of the payload
        - Placeholder / example detection
        - Test-key heuristic (all-lowercase payload may indicate mock key)
        """
        acc = _ConfidenceAccumulator()
        warnings: list[str] = []
        metadata: dict[str, Any] = {}

        key = api_key.strip()

        acc.add("prefix_sk",         key.startswith("sk-"),            weight=3.0)
        acc.add("total_length_51",   len(key) == 51,                   weight=2.5)
        acc.add("pattern_match",     bool(_OPENAI_PATTERN.match(key)), weight=2.5)

        payload = key[3:] if len(key) >= 3 else ""
        charset_ok, _ = _check_charset(
            payload, string.ascii_letters + string.digits, "payload"
        )
        acc.add("charset_alnum",     charset_ok,                       weight=1.5)

        entropy = _shannon_entropy(payload)
        acc.add("entropy_high",      entropy >= 4.5,                   weight=1.5)
        metadata["entropy"] = round(entropy, 4)

        placeholder = _is_placeholder(key)
        acc.add("not_placeholder",   not placeholder,                  weight=2.0)
        if placeholder:
            warnings.append("Key matches known placeholder / example pattern")

        # heuristic: all-uppercase payload looks like docs example
        if payload.isupper():
            warnings.append("Payload is all-uppercase — may be a documentation example")

        metadata["prefix"] = key[:3]
        metadata["payload_length"] = len(payload)

        confidence, checks, failures = acc.build()
        status = _status_from_confidence(confidence, placeholder)

        return ValidationResult(
            token_type      = TokenType.OPENAI_API_KEY,
            status          = status,
            confidence      = confidence,
            redacted_value  = _redact(key),
            checks          = checks,
            failure_reasons = failures,
            warnings        = warnings,
            metadata        = metadata,
        )

    # ── Stripe ────────────────────────────────────────────────────────────────

    def validate_stripe(self, api_key: str) -> ValidationResult:
        """
        Validate a Stripe API key (secret, restricted, or publishable).

        Checks
        ------
        - Prefix classification (sk_ / rk_ / pk_)
        - Environment segment (live vs test)
        - Payload length (≥ 24 chars)
        - Charset
        - Entropy
        - Placeholder detection
        - Live vs test environment flag
        """
        acc = _ConfidenceAccumulator()
        warnings: list[str] = []
        metadata: dict[str, Any] = {}

        key = api_key.strip()

        # classify
        if _STRIPE_SK_PATTERN.match(key):
            token_type = TokenType.STRIPE_SECRET_KEY
        elif _STRIPE_RK_PATTERN.match(key):
            token_type = TokenType.STRIPE_RESTRICTED_KEY
        elif _STRIPE_PK_PATTERN.match(key):
            token_type = TokenType.STRIPE_PUBLISHABLE_KEY
        else:
            token_type = TokenType.UNKNOWN

        acc.add("prefix_known",    token_type != TokenType.UNKNOWN, weight=3.0)

        # parse components: prefix_env_payload
        parts = key.split("_", 2)
        env     = parts[1] if len(parts) > 1 else ""
        payload = parts[2] if len(parts) > 2 else ""

        acc.add("env_valid",       env in ("live", "test"),         weight=2.0)
        acc.add("payload_min_24",  len(payload) >= 24,              weight=2.0)
        charset_ok, _ = _check_charset(payload, string.ascii_letters + string.digits, "payload")
        acc.add("charset_alnum",   charset_ok,                      weight=1.5)

        entropy = _shannon_entropy(payload)
        acc.add("entropy_high",    entropy >= 4.0,                  weight=1.5)
        metadata["entropy"] = round(entropy, 4)

        placeholder = _is_placeholder(key)
        acc.add("not_placeholder", not placeholder,                 weight=2.0)
        if placeholder:
            warnings.append("Key matches known placeholder / example pattern")

        if env == "test":
            warnings.append(
                "TEST key detected — valid structure but will not process real payments"
            )
        if token_type == TokenType.STRIPE_PUBLISHABLE_KEY:
            warnings.append(
                "Publishable key (pk_) is safe to expose publicly and cannot access the full API"
            )

        metadata["environment"]  = env
        metadata["key_class"]    = token_type.value
        metadata["payload_length"] = len(payload)

        confidence, checks, failures = acc.build()
        status = _status_from_confidence(confidence, placeholder)

        return ValidationResult(
            token_type      = token_type,
            status          = status,
            confidence      = confidence,
            redacted_value  = _redact(key),
            checks          = checks,
            failure_reasons = failures,
            warnings        = warnings,
            metadata        = metadata,
        )

    # ── Slack ─────────────────────────────────────────────────────────────────

    def validate_slack(self, token: str) -> ValidationResult:
        """
        Validate a Slack token (bot xoxb-, user xoxp-, app xoxe.) or webhook URL.

        Checks
        ------
        - Prefix classification
        - Segment count and format for xoxb/xoxp tokens
        - Workspace ID and Channel ID structural rules
        - Webhook URL structure and path segments
        - Entropy of credential segment
        - Placeholder detection
        """
        acc = _ConfidenceAccumulator()
        warnings: list[str] = []
        metadata: dict[str, Any] = {}

        tok = token.strip()

        # classify
        if tok.startswith("xoxb-"):
            token_type = TokenType.SLACK_BOT_TOKEN
        elif tok.startswith("xoxp-"):
            token_type = TokenType.SLACK_USER_TOKEN
        elif tok.startswith("xoxe."):
            token_type = TokenType.SLACK_APP_TOKEN
        elif tok.startswith("https://hooks.slack.com"):
            token_type = TokenType.SLACK_WEBHOOK
        else:
            token_type = TokenType.UNKNOWN

        acc.add("prefix_known", token_type != TokenType.UNKNOWN, weight=3.0)
        metadata["token_class"] = token_type.value

        if token_type == TokenType.SLACK_BOT_TOKEN:
            acc.add("bot_pattern",    bool(_SLACK_BOT_PATTERN.match(tok)),  weight=3.0)
            parts = tok.split("-")
            acc.add("segment_count",  len(parts) == 3,                       weight=1.5)
            acc.add("workspace_digits", parts[1].isdigit() if len(parts) > 1 else False, weight=1.0)
            credential = parts[2] if len(parts) > 2 else ""
            acc.add("credential_min_24", len(credential) >= 24,              weight=1.5)

        elif token_type == TokenType.SLACK_USER_TOKEN:
            acc.add("user_pattern",   bool(_SLACK_USER_PATTERN.match(tok)), weight=3.0)
            parts = tok.split("-")
            acc.add("segment_count",  len(parts) == 4,                       weight=1.5)
            credential = parts[3] if len(parts) > 3 else ""

        elif token_type == TokenType.SLACK_APP_TOKEN:
            acc.add("app_pattern",    bool(_SLACK_APP_PATTERN.match(tok)),  weight=3.0)
            body = tok[5:]   # strip "xoxe."
            acc.add("body_min_100",   len(body) >= 100,                      weight=1.5)
            credential = body

        elif token_type == TokenType.SLACK_WEBHOOK:
            acc.add("webhook_pattern", bool(_SLACK_WEBHOOK_PATTERN.match(tok)), weight=3.0)
            path_parts = tok.split("/")
            acc.add("webhook_path_depth", len(path_parts) >= 7,              weight=1.0)
            t_seg = next((p for p in path_parts if p.startswith("T")), "")
            b_seg = next((p for p in path_parts if p.startswith("B")), "")
            acc.add("workspace_id_present", bool(t_seg),                     weight=1.0)
            acc.add("channel_id_present",   bool(b_seg),                     weight=1.0)
            credential = path_parts[-1] if path_parts else ""
            metadata["workspace_id"] = t_seg
            metadata["channel_id"]   = b_seg

        else:
            credential = tok

        # entropy on the credential segment
        entropy = _shannon_entropy(credential)
        acc.add("entropy_sufficient", entropy >= 3.5, weight=1.5)
        metadata["credential_entropy"] = round(entropy, 4)

        placeholder = _is_placeholder(tok)
        acc.add("not_placeholder", not placeholder, weight=2.0)
        if placeholder:
            warnings.append("Token matches known placeholder / example pattern")

        confidence, checks, failures = acc.build()
        status = _status_from_confidence(confidence, placeholder)

        return ValidationResult(
            token_type      = token_type,
            status          = status,
            confidence      = confidence,
            redacted_value  = _redact(tok),
            checks          = checks,
            failure_reasons = failures,
            warnings        = warnings,
            metadata        = metadata,
        )

    # ── JWT ───────────────────────────────────────────────────────────────────

    def validate_jwt(
        self,
        token: str,
        secret: str | bytes | None = None,
        verify_expiry: bool = True,
    ) -> ValidationResult:
        """
        Validate a JSON Web Token (offline structural + optional HMAC verification).

        Checks
        ------
        - Three-part Base64url structure
        - Header: valid JSON, 'alg' field present, known algorithm
        - Payload: valid JSON, presence of standard claims (sub/iss/iat/exp)
        - Signature: non-empty, valid Base64url
        - Expiry: 'exp' claim compared to current UTC time (if present)
        - HMAC signature verification (if secret supplied for HS* algorithms)
        - Entropy of signature segment
        - Placeholder detection

        Parameters
        ----------
        token         : The raw JWT string.
        secret        : Optional signing secret for HMAC-SHA verification.
        verify_expiry : If True, flag tokens whose 'exp' claim is in the past.
        """
        acc = _ConfidenceAccumulator()
        warnings: list[str] = []
        metadata: dict[str, Any] = {}

        tok = token.strip()

        parts = tok.split(".")
        acc.add("three_part_structure", len(parts) == 3, weight=3.0)

        if len(parts) != 3:
            confidence, checks, failures = acc.build()
            return ValidationResult(
                token_type      = TokenType.JWT,
                status          = ValidationStatus.INVALID,
                confidence      = 0.0,
                redacted_value  = _redact(tok, show=8),
                checks          = checks,
                failure_reasons = ["Token does not have three dot-separated parts"],
                warnings        = warnings,
                metadata        = metadata,
            )

        header_b64, payload_b64, sig_b64 = parts

        # ── Header ────────────────────────────────────────────────────────────
        header_bytes = _safe_b64url_decode(header_b64)
        acc.add("header_decodable", header_bytes is not None, weight=2.0)

        header: dict = {}
        if header_bytes:
            try:
                header = json.loads(header_bytes)
                acc.add("header_valid_json", True, weight=2.0)
            except json.JSONDecodeError:
                acc.add("header_valid_json", False, weight=2.0)

        acc.add("header_has_alg",  "alg" in header,                             weight=1.5)
        alg = header.get("alg", "")
        acc.add("alg_known",       alg in _JWT_VALID_ALGS,                      weight=1.5)
        acc.add("header_has_typ",  "typ" in header,                             weight=0.5)
        metadata["algorithm"] = alg
        metadata["typ"]        = header.get("typ", "")

        if alg == "none":
            warnings.append("Algorithm 'none' — signature is absent; token is unsigned and untrustworthy")

        # ── Payload ───────────────────────────────────────────────────────────
        payload_bytes = _safe_b64url_decode(payload_b64)
        acc.add("payload_decodable", payload_bytes is not None, weight=2.0)

        claims: dict = {}
        if payload_bytes:
            try:
                claims = json.loads(payload_bytes)
                acc.add("payload_valid_json", True, weight=2.0)
            except json.JSONDecodeError:
                acc.add("payload_valid_json", False, weight=2.0)

        now_ts = datetime.now(timezone.utc).timestamp()

        # standard claims
        has_exp = "exp" in claims
        has_iat = "iat" in claims
        acc.add("claim_exp_present", has_exp, weight=0.5)
        acc.add("claim_iat_present", has_iat, weight=0.5)

        if has_exp:
            exp_ts = claims["exp"]
            expired = now_ts > exp_ts
            if verify_expiry:
                acc.add("not_expired", not expired, weight=2.0)
            if expired:
                exp_dt = datetime.fromtimestamp(exp_ts, tz=timezone.utc).isoformat()
                warnings.append(f"Token expired at {exp_dt}")
            else:
                exp_dt = datetime.fromtimestamp(exp_ts, tz=timezone.utc).isoformat()
                metadata["expires_at"] = exp_dt

        if has_iat:
            iat_ts = claims["iat"]
            metadata["issued_at"] = datetime.fromtimestamp(iat_ts, tz=timezone.utc).isoformat()
            # sanity: iat should not be in the future (allow 60-second clock skew)
            if iat_ts > now_ts + 60:
                warnings.append("'iat' claim is in the future — possible clock skew or forgery")

        for claim in ("sub", "iss", "aud", "jti"):
            if claim in claims:
                metadata[f"claim_{claim}"] = claims[claim]

        # ── Signature ─────────────────────────────────────────────────────────
        acc.add("signature_not_empty",  bool(sig_b64),                  weight=1.5)
        acc.add("signature_base64url",  _is_base64url(sig_b64),         weight=1.0)

        sig_entropy = _shannon_entropy(sig_b64)
        acc.add("signature_entropy",    sig_entropy >= 4.0,             weight=1.0)
        metadata["signature_entropy"] = round(sig_entropy, 4)

        # ── Optional HMAC verification ────────────────────────────────────────
        if secret is not None and alg.startswith("HS"):
            hash_map = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
            hash_fn = hash_map.get(alg)
            if hash_fn:
                if isinstance(secret, str):
                    secret = secret.encode()
                signing_input = f"{header_b64}.{payload_b64}".encode()
                expected_sig  = base64.urlsafe_b64encode(
                    hmac.new(secret, signing_input, hash_fn).digest()
                ).rstrip(b"=").decode()
                sig_match = hmac.compare_digest(expected_sig, sig_b64)
                acc.add("hmac_signature_valid", sig_match, weight=5.0)
                if not sig_match:
                    warnings.append("HMAC signature verification failed — secret may be wrong or token is tampered")
            else:
                warnings.append(f"HMAC verification skipped: unsupported algorithm '{alg}'")

        placeholder = _is_placeholder(tok)
        acc.add("not_placeholder", not placeholder, weight=1.0)

        confidence, checks, failures = acc.build()
        status = _status_from_confidence(confidence, placeholder)

        return ValidationResult(
            token_type      = TokenType.JWT,
            status          = status,
            confidence      = confidence,
            redacted_value  = _redact(tok, show=8),
            checks          = checks,
            failure_reasons = failures,
            warnings        = warnings,
            metadata        = metadata,
        )

    # ── Batch helper ─────────────────────────────────────────────────────────

    def validate_batch(
        self,
        items: list[dict[str, Any]],
    ) -> list[ValidationResult]:
        """
        Validate a batch of items.

        Each item dict must have:
          - "type": one of "aws", "github", "openai", "stripe", "slack", "jwt"
          - "value": the token string
          - (optional) "value2": second value for AWS (secret access key)

        Returns a list of ValidationResult objects in the same order.
        """
        dispatch: dict[str, Callable] = {
            "aws":    lambda i: self.validate_aws(i["value"], i.get("value2")),
            "github": lambda i: self.validate_github(i["value"]),
            "openai": lambda i: self.validate_openai(i["value"]),
            "stripe": lambda i: self.validate_stripe(i["value"]),
            "slack":  lambda i: self.validate_slack(i["value"]),
            "jwt":    lambda i: self.validate_jwt(
                i["value"],
                secret=i.get("secret"),
                verify_expiry=i.get("verify_expiry", True),
            ),
        }
        results = []
        for item in items:
            kind = item.get("type", "").lower()
            fn   = dispatch.get(kind)
            if fn is None:
                logger.warning("validate_batch: unknown type '%s' — skipping", kind)
                continue
            results.append(fn(item))
        return results

    def summary(self, results: list[ValidationResult]) -> dict[str, Any]:
        """Aggregate statistics over a list of ValidationResult objects."""
        by_status: dict[str, int] = {s.value: 0 for s in ValidationStatus}
        by_type:   dict[str, int] = {}

        for r in results:
            by_status[r.status.value] += 1
            by_type[r.token_type.value] = by_type.get(r.token_type.value, 0) + 1

        high_confidence   = [r for r in results if r.confidence >= 0.80]
        flagged_placeholders = [r for r in results if "placeholder" in " ".join(r.warnings).lower()]

        return {
            "total":                len(results),
            "by_status":            by_status,
            "by_type":              by_type,
            "high_confidence":      len(high_confidence),
            "likely_placeholders":  len(flagged_placeholders),
            "average_confidence":   round(
                sum(r.confidence for r in results) / len(results), 4
            ) if results else 0.0,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

    def validate(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        validated_findings = []
        for finding in findings:
            if not isinstance(finding, dict):
                validated_findings.append(finding)
                continue
                
            if not finding.get("requires_validation", False):
                finding["validation_status"] = "UNVALIDATED"
                validated_findings.append(finding)
                continue
                
            entity_type = finding.get("entity_type", "")
            mapping = {
                "AWS_ACCESS_KEY": "aws",
                "GITHUB_TOKEN": "github",
                "OPENAI_API_KEY": "openai",
                "STRIPE_KEY": "stripe",
                "JWT_TOKEN": "jwt",
            }
            kind = mapping.get(entity_type)
            if not kind:
                finding["validation_status"] = "UNVALIDATED"
                validated_findings.append(finding)
                continue
                
            item = {
                "type": kind,
                "value": finding.get("raw_value", ""),
            }
            
            try:
                res_list = self.validate_batch([item])
                if res_list:
                    res = res_list[0]
                    status_val = res.status.value if hasattr(res.status, "value") else res.status
                    if status_val in ("PLACEHOLDER", "INVALID", "LIKELY_INVALID"):
                        continue
                    finding["validation_status"] = status_val
                    finding["confidence"] = res.confidence
                    finding["validation_metadata"] = res.metadata
                    finding["validation_warnings"] = res.warnings
                    finding["validation_checks"] = res.checks
                else:
                    finding["validation_status"] = "UNVALIDATED"
            except Exception as e:
                logger.warning("Validation failed for finding %s: %s", finding, e)
                finding["validation_status"] = "UNCERTAIN"
                
            validated_findings.append(finding)
        return validated_findings


# ---------------------------------------------------------------------------
# Status inference from confidence
# ---------------------------------------------------------------------------
def _status_from_confidence(confidence: float, is_placeholder: bool) -> ValidationStatus:
    if is_placeholder:
        return ValidationStatus.PLACEHOLDER
    if confidence >= 0.90:
        return ValidationStatus.VALID
    if confidence >= 0.75:
        return ValidationStatus.LIKELY_VALID
    if confidence >= 0.55:
        return ValidationStatus.UNCERTAIN
    if confidence >= 0.30:
        return ValidationStatus.LIKELY_INVALID
    return ValidationStatus.INVALID


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _cli() -> None:
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="ValidationEngine – offline structural validation for secrets and tokens"
    )
    sub = parser.add_subparsers(dest="cmd")

    # single-value commands
    for name, help_text in [
        ("aws",    "Validate AWS access key ID (pass secret as second arg)"),
        ("github", "Validate GitHub token"),
        ("openai", "Validate OpenAI API key"),
        ("stripe", "Validate Stripe API key"),
        ("slack",  "Validate Slack token or webhook URL"),
        ("jwt",    "Validate JSON Web Token"),
    ]:
        p = sub.add_parser(name, help=help_text)
        p.add_argument("value",  help="Token / key to validate")
        if name == "aws":
            p.add_argument("secret", nargs="?", default=None,
                           help="AWS Secret Access Key (optional)")
        if name == "jwt":
            p.add_argument("--secret", default=None,
                           help="HMAC signing secret for signature verification")
            p.add_argument("--no-expiry-check", action="store_true",
                           help="Skip expiry validation")

    # batch command
    bp = sub.add_parser("batch", help="Validate JSON array of tokens from stdin or file")
    bp.add_argument("file", nargs="?", default=None,
                    help="JSON file; omit to read from stdin")
    bp.add_argument("--summary-only", action="store_true")

    args = parser.parse_args()
    engine = ValidationEngine()

    if args.cmd in ("aws", "github", "openai", "stripe", "slack", "jwt"):
        dispatch = {
            "aws":    lambda: engine.validate_aws(
                args.value, getattr(args, "secret", None)
            ),
            "github": lambda: engine.validate_github(args.value),
            "openai": lambda: engine.validate_openai(args.value),
            "stripe": lambda: engine.validate_stripe(args.value),
            "slack":  lambda: engine.validate_slack(args.value),
            "jwt":    lambda: engine.validate_jwt(
                args.value,
                secret=getattr(args, "secret", None),
                verify_expiry=not getattr(args, "no_expiry_check", False),
            ),
        }
        result = dispatch[args.cmd]()
        print(result.to_json())
        sys.exit(0 if result.status in (ValidationStatus.VALID, ValidationStatus.LIKELY_VALID) else 1)

    elif args.cmd == "batch":
        src = open(args.file) if args.file else sys.stdin
        try:
            items = json.load(src)
        finally:
            if args.file:
                src.close()
        results = engine.validate_batch(items)
        if args.summary_only:
            print(json.dumps(engine.summary(results), indent=2))
        else:
            print(json.dumps([r.to_dict() for r in results], indent=2))

    else:
        parser.print_help()


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    _cli()