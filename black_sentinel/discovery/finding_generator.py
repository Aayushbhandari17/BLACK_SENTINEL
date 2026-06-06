"""
detection_engine.py
====================
Production-ready PII & Secrets Detection Engine

Architecture  : Regex-based multi-pattern scanner
Features      : Confidence scoring, context-aware detection,
                duplicate suppression, severity assignment,
                metadata enrichment
Author        : Principal Cybersecurity Architect
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import mimetypes
import os
import re
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s – %(message)s",
)
logger = logging.getLogger("detection_engine")


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------
class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


class Category(str, Enum):
    PII             = "PII"
    CREDENTIAL      = "CREDENTIAL"
    SECRET          = "SECRET"
    FINANCIAL       = "FINANCIAL"
    IDENTITY        = "IDENTITY"
    CRYPTO          = "CRYPTO"
    AUTHENTICATION  = "AUTHENTICATION"


# ---------------------------------------------------------------------------
# Finding (return object)
# ---------------------------------------------------------------------------
@dataclass
class Finding:
    """Standardised finding returned by every scan method."""

    id:              str      = field(default_factory=lambda: str(uuid.uuid4()))
    rule_id:         str      = ""
    rule_name:       str      = ""
    category:        Category = Category.PII
    severity:        Severity = Severity.MEDIUM
    confidence:      float    = 0.0          # 0.0 – 1.0
    matched_value:   str      = ""
    redacted_value:  str      = ""
    start_offset:    int      = 0
    end_offset:      int      = 0
    line_number:     int      = 0
    column_number:   int      = 0
    context_snippet: str      = ""
    source:          str      = ""           # filename / artifact name
    detected_at:     str      = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    metadata:        dict[str, Any] = field(default_factory=dict)
    tags:            list[str]      = field(default_factory=list)

    # fingerprint used for duplicate suppression
    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(
            f"{self.rule_id}:{self.matched_value}".encode()
        ).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["category"] = self.category.value
        d["severity"]  = self.severity.value
        return d

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


# ---------------------------------------------------------------------------
# Rule definition
# ---------------------------------------------------------------------------
@dataclass
class Rule:
    rule_id:       str
    name:          str
    pattern:       str
    category:      Category
    severity:      Severity
    base_confidence: float         = 0.80
    context_keywords: list[str]    = field(default_factory=list)
    context_boost:    float        = 0.10   # added when context keyword found
    validator:        Any          = None   # optional callable(match_str) -> bool
    tags:             list[str]    = field(default_factory=list)
    description:      str         = ""
    # compiled at engine initialisation
    _compiled: Any = field(default=None, init=False, repr=False)

    def compile(self) -> None:
        self._compiled = re.compile(self.pattern, re.IGNORECASE | re.MULTILINE)


# ---------------------------------------------------------------------------
# Validators (Luhn, Aadhaar checksum, etc.)
# ---------------------------------------------------------------------------

def _luhn_valid(number: str) -> bool:
    """Luhn algorithm for credit-card numbers."""
    digits = [int(c) for c in re.sub(r"\D", "", number)]
    if len(digits) < 13:
        return False
    odd = digits[-1::-2]
    evn = [d * 2 - 9 if d * 2 > 9 else d * 2 for d in digits[-2::-2]]
    return (sum(odd) + sum(evn)) % 10 == 0


def _aadhaar_verhoeff(number: str) -> bool:
    """Verhoeff check-digit for Aadhaar."""
    d_table = [
        [0,1,2,3,4,5,6,7,8,9],
        [1,2,3,4,0,6,7,8,9,5],
        [2,3,4,0,1,7,8,9,5,6],
        [3,4,0,1,2,8,9,5,6,7],
        [4,0,1,2,3,9,5,6,7,8],
        [5,9,8,7,6,0,4,3,2,1],
        [6,5,9,8,7,1,0,4,3,2],
        [7,6,5,9,8,2,1,0,4,3],
        [8,7,6,5,9,3,2,1,0,4],
        [9,8,7,6,5,4,3,2,1,0],
    ]
    p_table = [
        [0,1,2,3,4,5,6,7,8,9],
        [1,5,7,6,2,8,3,0,9,4],
        [5,8,0,3,7,9,6,1,4,2],
        [8,9,1,6,0,4,3,5,2,7],
        [9,4,5,3,1,2,6,8,7,0],
        [4,2,8,6,5,7,3,9,0,1],
        [2,7,9,3,8,0,6,4,1,5],
        [7,0,4,6,9,1,3,2,5,8],
    ]
    inv = [0,4,3,2,1,9,8,7,6,5]
    digits = [int(c) for c in re.sub(r"\s", "", number)]
    c = 0
    for i, d in enumerate(reversed(digits)):
        c = d_table[c][p_table[i % 8][d]]
    return c == 0


def _pan_valid(pan: str) -> bool:
    """Basic structural check: AAAAA9999A."""
    return bool(re.fullmatch(r"[A-Z]{5}[0-9]{4}[A-Z]", pan.upper()))


def _jwt_valid(token: str) -> bool:
    """Check three Base64url-separated parts."""
    parts = token.split(".")
    if len(parts) != 3:
        return False
    try:
        # header must decode to valid JSON
        padded = parts[0] + "=" * (-len(parts[0]) % 4)
        header = json.loads(base64.urlsafe_b64decode(padded))
        return "alg" in header
    except Exception:
        return False


def _ssh_key_valid(key: str) -> bool:
    return "BEGIN" in key and ("PRIVATE KEY" in key or "RSA" in key or "EC" in key)


# ---------------------------------------------------------------------------
# Rule catalogue
# ---------------------------------------------------------------------------
RULES: list[Rule] = [

    # ── Indian Identity ─────────────────────────────────────────────────────
    Rule(
        rule_id="IND-AADHAAR-001",
        name="Aadhaar Number",
        pattern=r"\b([2-9]\d{3}[\s\-]?\d{4}[\s\-]?\d{4})\b",
        category=Category.IDENTITY,
        severity=Severity.CRITICAL,
        base_confidence=0.75,
        context_keywords=["aadhaar", "uid", "uidai", "aadhar", "enrolment"],
        context_boost=0.15,
        validator=lambda m: _aadhaar_verhoeff(re.sub(r"\D", "", m)),
        tags=["india", "government-id", "pii"],
        description="12-digit UIDAI Aadhaar number (Verhoeff validated)",
    ),
    Rule(
        rule_id="IND-PAN-001",
        name="PAN Card Number",
        pattern=r"\b([A-Z]{5}[0-9]{4}[A-Z])\b",
        category=Category.IDENTITY,
        severity=Severity.CRITICAL,
        base_confidence=0.80,
        context_keywords=["pan", "permanent account", "income tax", "it dept"],
        context_boost=0.15,
        validator=lambda m: _pan_valid(m),
        tags=["india", "government-id", "pii", "tax"],
        description="10-char alphanumeric PAN issued by Indian Income Tax Dept",
    ),
    Rule(
        rule_id="IND-PASSPORT-001",
        name="Indian Passport Number",
        pattern=r"\b([A-PR-WYa-pr-wy][1-9]\d\s?\d{4}[1-9])\b",
        category=Category.IDENTITY,
        severity=Severity.CRITICAL,
        base_confidence=0.70,
        context_keywords=["passport", "travel document", "ministry of external"],
        context_boost=0.20,
        tags=["india", "passport", "pii"],
        description="8-character Indian passport number",
    ),
    Rule(
        rule_id="IND-DL-001",
        name="Driving Licence (India)",
        pattern=r"\b([A-Z]{2}[\s\-]?\d{2}[\s\-]?\d{4}[\s\-]?\d{7})\b",
        category=Category.IDENTITY,
        severity=Severity.HIGH,
        base_confidence=0.65,
        context_keywords=["driving licence", "driving license", "dl no", "rto", "vehicle"],
        context_boost=0.20,
        tags=["india", "driving-licence", "pii"],
        description="Indian DL format: ST-YY-NNNNNNN",
    ),

    # ── Contact / PII ────────────────────────────────────────────────────────
    Rule(
        rule_id="PII-EMAIL-001",
        name="Email Address",
        pattern=r"\b([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})\b",
        category=Category.PII,
        severity=Severity.MEDIUM,
        base_confidence=0.95,
        context_keywords=["email", "mail", "contact", "from:", "to:", "reply-to"],
        context_boost=0.04,
        tags=["email", "pii"],
        description="RFC-5322 email address",
    ),
    Rule(
        rule_id="PII-PHONE-IN-001",
        name="Indian Phone Number",
        pattern=r"(?<!\d)(\+?91[\s\-]?)?([6-9]\d{9})(?!\d)",
        category=Category.PII,
        severity=Severity.MEDIUM,
        base_confidence=0.75,
        context_keywords=["phone", "mobile", "contact", "call", "whatsapp", "tel"],
        context_boost=0.15,
        tags=["phone", "india", "pii"],
        description="Indian mobile numbers (starting 6-9, 10 digits)",
    ),
    Rule(
        rule_id="PII-PHONE-INTL-001",
        name="International Phone Number",
        pattern=r"(?<!\d)\+(?:[1-9]\d{6,14})(?!\d)",
        category=Category.PII,
        severity=Severity.LOW,
        base_confidence=0.60,
        context_keywords=["phone", "tel", "call", "fax", "mobile"],
        context_boost=0.20,
        tags=["phone", "pii"],
        description="E.164 international phone numbers",
    ),

    # ── Financial ────────────────────────────────────────────────────────────
    Rule(
        rule_id="FIN-CC-001",
        name="Credit / Debit Card Number",
        pattern=(
            r"\b(?:4[0-9]{12}(?:[0-9]{3})?"          # Visa
            r"|5[1-5][0-9]{14}"                        # MC
            r"|3[47][0-9]{13}"                         # Amex
            r"|3(?:0[0-5]|[68][0-9])[0-9]{11}"        # Diners
            r"|6(?:011|5[0-9]{2})[0-9]{12}"            # Discover
            r"|(?:2131|1800|35\d{3})\d{11})\b"         # JCB
        ),
        category=Category.FINANCIAL,
        severity=Severity.CRITICAL,
        base_confidence=0.80,
        context_keywords=["card", "credit", "debit", "visa", "mastercard", "amex", "payment"],
        context_boost=0.15,
        validator=_luhn_valid,
        tags=["credit-card", "pci-dss", "financial"],
        description="Major card network numbers (Luhn validated)",
    ),
    Rule(
        rule_id="FIN-IBAN-001",
        name="IBAN / Bank Account",
        pattern=r"\b([A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}(?:[A-Z0-9]?){0,16})\b",
        category=Category.FINANCIAL,
        severity=Severity.HIGH,
        base_confidence=0.70,
        context_keywords=["iban", "bank", "account", "swift", "transfer"],
        context_boost=0.20,
        tags=["bank", "iban", "financial"],
        description="IBAN bank account numbers",
    ),
    Rule(
        rule_id="FIN-BANK-IN-001",
        name="Indian Bank Account Number",
        pattern=r"\b(\d{9,18})\b",
        category=Category.FINANCIAL,
        severity=Severity.HIGH,
        base_confidence=0.40,
        context_keywords=["account no", "account number", "savings account",
                          "current account", "ifsc", "neft", "rtgs", "imps"],
        context_boost=0.40,
        tags=["bank", "india", "financial"],
        description="Indian bank account (9-18 digits; requires context keywords)",
    ),

    # ── Cloud Credentials ────────────────────────────────────────────────────
    Rule(
        rule_id="SEC-AWS-KEY-001",
        name="AWS Access Key ID",
        pattern=r"(?<![A-Z0-9])((?:AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16})(?![A-Z0-9])",
        category=Category.CREDENTIAL,
        severity=Severity.CRITICAL,
        base_confidence=0.95,
        context_keywords=["aws", "amazon", "s3", "ec2", "iam", "access_key"],
        context_boost=0.04,
        tags=["aws", "cloud", "secret"],
        description="AWS Access Key ID (AKIA/ABIA/ACCA/ASIA prefix)",
    ),
    Rule(
        rule_id="SEC-AWS-SECRET-001",
        name="AWS Secret Access Key",
        pattern=r"(?i)(?:aws.{0,20})?(?:secret.{0,10}access.{0,10}key|aws_secret)[\"'\s:=]+([A-Za-z0-9/+=]{40})",
        category=Category.CREDENTIAL,
        severity=Severity.CRITICAL,
        base_confidence=0.85,
        context_keywords=["aws", "secret", "access_key"],
        context_boost=0.10,
        tags=["aws", "cloud", "secret"],
        description="AWS Secret Access Key (40-char base64)",
    ),
    Rule(
        rule_id="SEC-AZURE-001",
        name="Azure Storage Key / SAS Token",
        pattern=r"(?i)(?:DefaultEndpointsProtocol|AccountKey=|sig=)[A-Za-z0-9+/=]{20,}",
        category=Category.CREDENTIAL,
        severity=Severity.CRITICAL,
        base_confidence=0.85,
        context_keywords=["azure", "storage", "blob", "connection string"],
        context_boost=0.10,
        tags=["azure", "cloud", "secret"],
        description="Azure storage connection string or SAS token",
    ),
    Rule(
        rule_id="SEC-AZURE-CLIENT-001",
        name="Azure Client Secret",
        pattern=r"(?i)(?:client.?secret|AZURE_CLIENT_SECRET)[\"'\s:=]+([A-Za-z0-9~._\-]{34,})",
        category=Category.CREDENTIAL,
        severity=Severity.CRITICAL,
        base_confidence=0.80,
        context_keywords=["azure", "client_id", "tenant"],
        context_boost=0.15,
        tags=["azure", "cloud", "secret"],
        description="Azure AD client secret",
    ),
    Rule(
        rule_id="SEC-GCP-SA-001",
        name="GCP Service Account Key",
        pattern=r'"type"\s*:\s*"service_account"',
        category=Category.CREDENTIAL,
        severity=Severity.CRITICAL,
        base_confidence=0.95,
        context_keywords=["project_id", "private_key", "client_email"],
        context_boost=0.04,
        tags=["gcp", "cloud", "service-account", "secret"],
        description="GCP service account JSON key file signature",
    ),
    Rule(
        rule_id="SEC-GCP-API-001",
        name="GCP API Key",
        pattern=r"\bAIza[0-9A-Za-z\-_]{35}\b",
        category=Category.CREDENTIAL,
        severity=Severity.CRITICAL,
        base_confidence=0.95,
        context_keywords=["google", "gcp", "maps", "firebase", "api_key"],
        context_boost=0.04,
        tags=["gcp", "google", "api-key", "secret"],
        description="Google / GCP API key (AIza prefix)",
    ),

    # ── Developer Tokens ─────────────────────────────────────────────────────
    Rule(
        rule_id="SEC-GITHUB-PAT-001",
        name="GitHub Personal Access Token",
        pattern=r"\b(ghp_[A-Za-z0-9]{36})\b",
        category=Category.CREDENTIAL,
        severity=Severity.CRITICAL,
        base_confidence=0.97,
        context_keywords=["github", "git", "token", "pat"],
        context_boost=0.02,
        tags=["github", "git", "token", "secret"],
        description="GitHub classic PAT (ghp_ prefix)",
    ),
    Rule(
        rule_id="SEC-GITHUB-OAUTH-001",
        name="GitHub OAuth Token",
        pattern=r"\b(gho_[A-Za-z0-9]{36})\b",
        category=Category.CREDENTIAL,
        severity=Severity.CRITICAL,
        base_confidence=0.97,
        context_keywords=["github", "oauth"],
        context_boost=0.02,
        tags=["github", "oauth", "secret"],
        description="GitHub OAuth token (gho_ prefix)",
    ),
    Rule(
        rule_id="SEC-GITHUB-APP-001",
        name="GitHub App Token",
        pattern=r"\b(ghs_[A-Za-z0-9]{36}|ghu_[A-Za-z0-9]{36})\b",
        category=Category.CREDENTIAL,
        severity=Severity.CRITICAL,
        base_confidence=0.97,
        context_keywords=["github", "app", "installation"],
        context_boost=0.02,
        tags=["github", "app-token", "secret"],
        description="GitHub App / user-to-server tokens",
    ),
    Rule(
        rule_id="SEC-OPENAI-001",
        name="OpenAI API Key",
        pattern=r"\b(sk-[A-Za-z0-9]{48})\b",
        category=Category.CREDENTIAL,
        severity=Severity.CRITICAL,
        base_confidence=0.95,
        context_keywords=["openai", "gpt", "api_key", "chatgpt"],
        context_boost=0.04,
        tags=["openai", "llm", "secret"],
        description="OpenAI API key (sk- prefix, 51 chars)",
    ),
    Rule(
        rule_id="SEC-STRIPE-SK-001",
        name="Stripe Secret Key",
        pattern=r"\b(sk_live_[A-Za-z0-9]{24,})\b",
        category=Category.CREDENTIAL,
        severity=Severity.CRITICAL,
        base_confidence=0.97,
        context_keywords=["stripe", "payment", "billing"],
        context_boost=0.02,
        tags=["stripe", "payment", "secret"],
        description="Stripe live secret key",
    ),
    Rule(
        rule_id="SEC-STRIPE-RK-001",
        name="Stripe Restricted Key",
        pattern=r"\b(rk_live_[A-Za-z0-9]{24,})\b",
        category=Category.CREDENTIAL,
        severity=Severity.HIGH,
        base_confidence=0.95,
        context_keywords=["stripe", "payment"],
        context_boost=0.04,
        tags=["stripe", "payment", "secret"],
        description="Stripe live restricted key",
    ),
    Rule(
        rule_id="SEC-SLACK-TOKEN-001",
        name="Slack Bot / User Token",
        pattern=r"\b(xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,32})\b",
        category=Category.CREDENTIAL,
        severity=Severity.CRITICAL,
        base_confidence=0.95,
        context_keywords=["slack", "bot", "workspace"],
        context_boost=0.04,
        tags=["slack", "token", "secret"],
        description="Slack xoxb/xoxa/xoxp/xoxr/xoxs tokens",
    ),
    Rule(
        rule_id="SEC-SLACK-WEBHOOK-001",
        name="Slack Webhook URL",
        pattern=r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+",
        category=Category.CREDENTIAL,
        severity=Severity.HIGH,
        base_confidence=0.97,
        context_keywords=["slack", "webhook", "notification"],
        context_boost=0.02,
        tags=["slack", "webhook", "secret"],
        description="Slack incoming webhook URL",
    ),

    # ── Authentication Tokens ─────────────────────────────────────────────────
    Rule(
        rule_id="AUTH-JWT-001",
        name="JSON Web Token (JWT)",
        pattern=r"\b(eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+)\b",
        category=Category.AUTHENTICATION,
        severity=Severity.HIGH,
        base_confidence=0.85,
        context_keywords=["authorization", "bearer", "token", "jwt", "auth"],
        context_boost=0.10,
        validator=_jwt_valid,
        tags=["jwt", "auth", "token"],
        description="Base64url-encoded JSON Web Token (three-part)",
    ),

    # ── Cryptographic Keys ────────────────────────────────────────────────────
    Rule(
        rule_id="CRYPTO-SSH-001",
        name="SSH Private Key",
        pattern=r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        category=Category.CRYPTO,
        severity=Severity.CRITICAL,
        base_confidence=0.98,
        context_keywords=["ssh", "private key", "pem", "key"],
        context_boost=0.01,
        validator=lambda m: True,
        tags=["ssh", "private-key", "crypto"],
        description="SSH / PEM private key block header",
    ),
    Rule(
        rule_id="CRYPTO-PGP-001",
        name="PGP Private Key Block",
        pattern=r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
        category=Category.CRYPTO,
        severity=Severity.CRITICAL,
        base_confidence=0.99,
        context_keywords=["pgp", "gpg", "private", "key"],
        context_boost=0.00,
        tags=["pgp", "gpg", "crypto"],
        description="PGP private key block",
    ),
    Rule(
        rule_id="CRYPTO-GENERIC-001",
        name="Generic Private Key",
        pattern=r"-----BEGIN PRIVATE KEY-----",
        category=Category.CRYPTO,
        severity=Severity.CRITICAL,
        base_confidence=0.98,
        context_keywords=["private key", "pem", "tls", "ssl"],
        context_boost=0.01,
        tags=["private-key", "crypto"],
        description="PKCS#8 private key block",
    ),
]


# ---------------------------------------------------------------------------
# Redaction helper
# ---------------------------------------------------------------------------
def _redact(value: str, show_chars: int = 4) -> str:
    """Partially mask a sensitive value."""
    if len(value) <= show_chars * 2:
        return "*" * len(value)
    return value[:show_chars] + "*" * (len(value) - show_chars * 2) + value[-show_chars:]


# ---------------------------------------------------------------------------
# Detection Engine
# ---------------------------------------------------------------------------
class DetectionEngine:
    """
    Regex-based detection engine for PII, secrets, and credentials.

    Usage
    -----
    engine = DetectionEngine()
    findings = engine.scan_text("my email is user@example.com")
    for f in findings:
        print(f.to_json())
    """

    CONTEXT_WINDOW = 80   # chars either side of the match for context snippet
    MAX_FILE_SIZE  = 100 * 1024 * 1024  # 100 MB guard

    def __init__(
        self,
        rules: list[Rule] | None = None,
        min_confidence: float = 0.50,
        deduplicate: bool = True,
    ) -> None:
        self.rules = rules if rules is not None else RULES
        self.min_confidence = min_confidence
        self.deduplicate = deduplicate
        self._compile_rules()
        logger.info(
            "DetectionEngine initialised with %d rules (min_confidence=%.2f)",
            len(self.rules), self.min_confidence,
        )

    # ── internal ────────────────────────────────────────────────────────────

    def _compile_rules(self) -> None:
        for rule in self.rules:
            try:
                rule.compile()
            except re.error as exc:
                logger.error("Failed to compile rule %s: %s", rule.rule_id, exc)

    @staticmethod
    def _line_col(text: str, offset: int) -> tuple[int, int]:
        """Return (1-based line number, 1-based column) for a character offset."""
        lines = text[:offset].split("\n")
        return len(lines), len(lines[-1]) + 1

    def _context_snippet(self, text: str, start: int, end: int) -> str:
        """Extract surrounding text for human-readable context."""
        lo = max(0, start - self.CONTEXT_WINDOW)
        hi = min(len(text), end + self.CONTEXT_WINDOW)
        snippet = text[lo:hi]
        # replace the actual match with a placeholder inside the snippet
        rel_start = start - lo
        rel_end   = end   - lo
        return (
            snippet[:rel_start]
            + "<<<MATCH>>>"
            + snippet[rel_end:]
        )

    def _compute_confidence(
        self, rule: Rule, matched_value: str, surrounding_text: str
    ) -> float:
        confidence = rule.base_confidence

        # validator check
        if rule.validator:
            try:
                if not rule.validator(matched_value):
                    confidence -= 0.30
            except Exception:
                confidence -= 0.10

        # context keyword boost
        lower_ctx = surrounding_text.lower()
        if any(kw.lower() in lower_ctx for kw in rule.context_keywords):
            confidence = min(1.0, confidence + rule.context_boost)

        # penalise very short tokens (likely false positives)
        if len(matched_value) < 6:
            confidence -= 0.15

        return round(max(0.0, min(1.0, confidence)), 4)

    def _scan_text_internal(
        self, text: str, source: str = "<inline>"
    ) -> list[Finding]:
        findings: list[Finding] = []
        seen_fingerprints: set[str] = set()

        for rule in self.rules:
            if rule._compiled is None:
                continue
            for match in rule._compiled.finditer(text):
                # prefer group(1) if the rule uses a capture group, else full match
                try:
                    matched_value = match.group(1)
                except IndexError:
                    matched_value = match.group(0)

                start, end = match.start(), match.end()

                # surrounding context for confidence + snippet
                ctx_lo  = max(0, start - self.CONTEXT_WINDOW)
                ctx_hi  = min(len(text), end + self.CONTEXT_WINDOW)
                surround = text[ctx_lo:ctx_hi]

                confidence = self._compute_confidence(rule, matched_value, surround)
                if confidence < self.min_confidence:
                    continue

                line_no, col_no = self._line_col(text, start)

                finding = Finding(
                    rule_id         = rule.rule_id,
                    rule_name       = rule.name,
                    category        = rule.category,
                    severity        = rule.severity,
                    confidence      = confidence,
                    matched_value   = matched_value,
                    redacted_value  = _redact(matched_value),
                    start_offset    = start,
                    end_offset      = end,
                    line_number     = line_no,
                    column_number   = col_no,
                    context_snippet = self._context_snippet(text, start, end),
                    source          = source,
                    tags            = list(rule.tags),
                    metadata        = {
                        "rule_description": rule.description,
                        "match_length":     len(matched_value),
                        "pattern_id":       rule.rule_id,
                    },
                )

                if self.deduplicate:
                    fp = finding.fingerprint
                    if fp in seen_fingerprints:
                        continue
                    seen_fingerprints.add(fp)

                findings.append(finding)

        return findings

    # ── public API ───────────────────────────────────────────────────────────

    def scan_text(
        self, text: str, source: str = "<inline>"
    ) -> list[Finding]:
        """
        Scan a plain-text string for secrets and PII.

        Parameters
        ----------
        text   : The text content to scan.
        source : Optional label identifying the origin (e.g. filename).

        Returns
        -------
        List of Finding objects sorted by severity then offset.
        """
        if not isinstance(text, str):
            raise TypeError(f"scan_text expects str, got {type(text).__name__}")

        findings = self._scan_text_internal(text, source=source)
        findings.sort(key=lambda f: (
            list(Severity).index(f.severity), f.start_offset
        ))
        logger.info(
            "scan_text('%s'): %d finding(s) from %d char(s)",
            source, len(findings), len(text),
        )
        return findings

    def scan_file(self, path: str | Path) -> list[Finding]:
        """
        Scan a file on disk.

        Supports: plain text, JSON, YAML, TOML, .env, source code, etc.
        Binary files (images, compiled objects) are skipped.

        Parameters
        ----------
        path : Path to the file.

        Returns
        -------
        List of Finding objects.
        """
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {path}")
        if not path.is_file():
            raise ValueError(f"Path is not a regular file: {path}")

        size = path.stat().st_size
        if size > self.MAX_FILE_SIZE:
            raise ValueError(
                f"File too large ({size:,} bytes > {self.MAX_FILE_SIZE:,} bytes limit)"
            )

        mime, _ = mimetypes.guess_type(str(path))
        if mime and mime.startswith(("image/", "video/", "audio/")):
            logger.info("Skipping binary file: %s (%s)", path, mime)
            return []

        encodings = ["utf-8", "utf-8-sig", "latin-1", "cp1252"]
        text: str | None = None
        for enc in encodings:
            try:
                text = path.read_text(encoding=enc)
                break
            except (UnicodeDecodeError, LookupError):
                continue

        if text is None:
            logger.warning("Could not decode file as text: %s", path)
            return []

        findings = self.scan_text(text, source=str(path))
        for f in findings:
            f.metadata["file_size_bytes"] = size
            f.metadata["file_extension"]  = path.suffix.lower()
            f.metadata["mime_type"]        = mime or "unknown"
        return findings

    def scan_artifact(
        self,
        artifact: dict[str, Any] | str | bytes | Path,
        artifact_name: str = "<artifact>",
    ) -> list[Finding]:
        """
        Scan a generic artifact which may be:
          - a dict/list (JSON-serialised then scanned)
          - a bytes blob (decoded as UTF-8 where possible)
          - a str (scanned directly)
          - a Path (delegates to scan_file)
          - a structured object with a __dict__ (serialised)

        Parameters
        ----------
        artifact      : The artifact to scan.
        artifact_name : Human-readable label for the artifact.

        Returns
        -------
        List of Finding objects.
        """
        if isinstance(artifact, Path):
            return self.scan_file(artifact)

        if isinstance(artifact, bytes):
            try:
                text = artifact.decode("utf-8")
            except UnicodeDecodeError:
                try:
                    text = artifact.decode("latin-1")
                except UnicodeDecodeError:
                    logger.warning(
                        "scan_artifact('%s'): bytes could not be decoded", artifact_name
                    )
                    return []

        elif isinstance(artifact, str):
            text = artifact

        elif isinstance(artifact, (dict, list)):
            try:
                text = json.dumps(artifact, default=str, indent=2)
            except (TypeError, ValueError) as exc:
                logger.error("scan_artifact: JSON serialisation failed: %s", exc)
                return []

        elif hasattr(artifact, "__dict__"):
            try:
                text = json.dumps(artifact.__dict__, default=str, indent=2)
            except (TypeError, ValueError) as exc:
                logger.error("scan_artifact: __dict__ serialisation failed: %s", exc)
                return []

        else:
            text = str(artifact)

        findings = self.scan_text(text, source=artifact_name)
        for f in findings:
            f.metadata["artifact_type"] = type(artifact).__name__
            f.metadata["artifact_name"] = artifact_name
        return findings

    # ── convenience ─────────────────────────────────────────────────────────

    def scan_directory(
        self,
        directory: str | Path,
        recursive: bool = True,
        extensions: list[str] | None = None,
    ) -> list[Finding]:
        """
        Walk a directory and scan every eligible file.

        Parameters
        ----------
        directory  : Root directory to scan.
        recursive  : Whether to recurse into sub-directories.
        extensions : Whitelist of file extensions (e.g. ['.py', '.json']).
                     If None, all non-binary files are scanned.
        """
        directory = Path(directory)
        if not directory.is_dir():
            raise NotADirectoryError(f"Not a directory: {directory}")

        all_findings: list[Finding] = []
        glob_pattern = "**/*" if recursive else "*"

        for fp in sorted(directory.glob(glob_pattern)):
            if not fp.is_file():
                continue
            if extensions and fp.suffix.lower() not in extensions:
                continue
            try:
                all_findings.extend(self.scan_file(fp))
            except Exception as exc:
                logger.warning("Skipping %s: %s", fp, exc)

        logger.info(
            "scan_directory('%s'): %d total finding(s)",
            directory, len(all_findings),
        )
        return all_findings

    def summary(self, findings: list[Finding]) -> dict[str, Any]:
        """
        Produce a JSON-serialisable summary of a finding list.

        Returns
        -------
        dict with counts broken down by severity, category, and rule.
        """
        by_severity: dict[str, int] = {s.value: 0 for s in Severity}
        by_category: dict[str, int] = {c.value: 0 for c in Category}
        by_rule: dict[str, int] = {}

        for f in findings:
            by_severity[f.severity.value] += 1
            by_category[f.category.value] += 1
            by_rule[f.rule_name] = by_rule.get(f.rule_name, 0) + 1

        return {
            "total":       len(findings),
            "by_severity": by_severity,
            "by_category": by_category,
            "by_rule":     by_rule,
            "sources":     list({f.source for f in findings}),
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------
def _cli() -> None:
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="DetectionEngine – scan files or stdin for PII and secrets"
    )
    parser.add_argument(
        "targets", nargs="*",
        help="Files or directories to scan (omit to read from stdin)"
    )
    parser.add_argument(
        "--min-confidence", type=float, default=0.50,
        help="Minimum confidence threshold (0.0–1.0, default 0.50)"
    )
    parser.add_argument(
        "--no-dedup", action="store_true",
        help="Disable duplicate suppression"
    )
    parser.add_argument(
        "--summary-only", action="store_true",
        help="Print summary instead of full findings"
    )
    parser.add_argument(
        "--output-json", type=str, default=None,
        help="Write findings as JSON array to this file"
    )
    args = parser.parse_args()

    engine = DetectionEngine(
        min_confidence=args.min_confidence,
        deduplicate=not args.no_dedup,
    )
    all_findings: list[Finding] = []

    if args.targets:
        for target in args.targets:
            p = Path(target)
            if p.is_dir():
                all_findings.extend(engine.scan_directory(p))
            elif p.is_file():
                all_findings.extend(engine.scan_file(p))
            else:
                logger.error("Target not found: %s", target)
    else:
        # read from stdin
        text = sys.stdin.read()
        all_findings.extend(engine.scan_text(text, source="<stdin>"))

    if args.summary_only:
        print(json.dumps(engine.summary(all_findings), indent=2))
    else:
        print(json.dumps([f.to_dict() for f in all_findings], indent=2))

    if args.output_json:
        out_path = Path(args.output_json)
        out_path.write_text(
            json.dumps([f.to_dict() for f in all_findings], indent=2),
            encoding="utf-8",
        )
        logger.info("Findings written to %s", out_path)

    # non-zero exit if any CRITICAL / HIGH findings
    if any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in all_findings):
        sys.exit(1)


# ---------------------------------------------------------------------------
# Self-test / demo
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    _cli()
    
    
class FindingGenerator:

    def __init__(self):
        pass

    def generate(self, matches, file_path, content, layer_index):
        from black_sentinel.discovery.finding_generator import _redact
        
        mapping = {
            "AWS_ACCESS_KEY": "aws",
            "GITHUB_TOKEN": "github",
            "OPENAI_API_KEY": "openai",
            "STRIPE_KEY": "stripe",
            "JWT_TOKEN": "jwt",
        }
        
        findings = []
        for m in matches:
            f = m.copy()
            raw_value = f.get("raw_value", "")
            entity_type = f.get("entity_type", "")
            
            # Calculate line number based on the first occurrence of the raw value in the content
            idx = content.find(raw_value)
            line_no = content[:idx].count("\n") + 1 if idx != -1 else 1
            
            f.update({
                "type": mapping.get(entity_type),
                "value": raw_value,
                "source": file_path,
                "file_path": file_path,
                "line_number": line_no,
                "layer_index": layer_index,
                "masked_value": _redact(raw_value) if raw_value else "",
            })
            findings.append(f)
        return findings