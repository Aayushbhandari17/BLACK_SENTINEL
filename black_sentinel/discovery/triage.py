"""
triage_engine.py
=================
Production-ready Triage Engine for security findings.

Responsibilities : Risk scoring, severity scoring, confidence scoring,
                   finding prioritization, evidence collection,
                   finding deduplication, finding aggregation
Author           : Principal Cybersecurity Architect
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import uuid
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


class RiskLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    MINIMAL  = "MINIMAL"


class ValidationStatus(str, Enum):
    VALID          = "VALID"
    LIKELY_VALID   = "LIKELY_VALID"
    UNCERTAIN      = "UNCERTAIN"
    LIKELY_INVALID = "LIKELY_INVALID"
    INVALID        = "INVALID"
    PLACEHOLDER    = "PLACEHOLDER"
    UNVALIDATED    = "UNVALIDATED"


class ExposureLevel(str, Enum):
    PUBLIC     = "PUBLIC"      # internet-facing, public repo, CDN
    INTERNAL   = "INTERNAL"    # internal network, private repo
    RESTRICTED = "RESTRICTED"  # access-controlled, encrypted store
    UNKNOWN    = "UNKNOWN"


class DataSensitivity(str, Enum):
    CRITICAL    = "CRITICAL"    # private keys, live credentials, PAN, Aadhaar
    HIGH        = "HIGH"        # email + PII combo, financial data
    MEDIUM      = "MEDIUM"      # email-only, phone, test credentials
    LOW         = "LOW"         # public tokens, metadata
    INFORMATIONAL = "INFORMATIONAL"


# ---------------------------------------------------------------------------
# Weight tables (all values are additive risk points on a 0–100 scale)
# ---------------------------------------------------------------------------

SEVERITY_BASE_SCORE: dict[str, float] = {
    Severity.CRITICAL: 40.0,
    Severity.HIGH:     28.0,
    Severity.MEDIUM:   16.0,
    Severity.LOW:       8.0,
    Severity.INFO:      2.0,
}

VALIDATION_MODIFIER: dict[str, float] = {
    ValidationStatus.VALID:          +20.0,
    ValidationStatus.LIKELY_VALID:   +12.0,
    ValidationStatus.UNCERTAIN:       +4.0,
    ValidationStatus.LIKELY_INVALID:  -8.0,
    ValidationStatus.INVALID:        -16.0,
    ValidationStatus.PLACEHOLDER:    -20.0,
    ValidationStatus.UNVALIDATED:      0.0,
}

SENSITIVITY_MODIFIER: dict[str, float] = {
    DataSensitivity.CRITICAL:       +20.0,
    DataSensitivity.HIGH:           +12.0,
    DataSensitivity.MEDIUM:          +5.0,
    DataSensitivity.LOW:              0.0,
    DataSensitivity.INFORMATIONAL:   -5.0,
}

EXPOSURE_MODIFIER: dict[str, float] = {
    ExposureLevel.PUBLIC:      +18.0,
    ExposureLevel.INTERNAL:    +6.0,
    ExposureLevel.RESTRICTED:  -4.0,
    ExposureLevel.UNKNOWN:     +3.0,
}

# Entropy bonus/penalty: 0 = no entropy data, else scaled
ENTROPY_MAX_BONUS  = 8.0   # full bonus at entropy ≥ 5.5 bits
ENTROPY_MIN_CUTOFF = 2.5   # below this → penalty

# Context signal bonuses
CONTEXT_KEYWORD_BONUS   = 3.0   # per matching context keyword (capped at 9.0)
CONTEXT_KEYWORD_MAX     = 9.0

# File-type risk table (extension → additive modifier)
FILE_TYPE_MODIFIER: dict[str, float] = {
    # high risk: config / env / secret stores
    ".env":     +10.0, ".secret": +10.0, ".pem": +12.0, ".key": +12.0,
    ".pfx":     +10.0, ".p12":    +10.0, ".jks": +10.0, ".keystore": +10.0,
    # moderate risk: code / config
    ".py":      +5.0,  ".js":     +5.0,  ".ts":  +5.0,  ".go":  +5.0,
    ".java":    +5.0,  ".rb":     +5.0,  ".php": +5.0,  ".sh":  +6.0,
    ".bash":    +6.0,  ".zsh":    +6.0,  ".ps1": +6.0,
    ".yml":     +6.0,  ".yaml":   +6.0,  ".toml": +5.0, ".ini": +4.0,
    ".cfg":     +4.0,  ".conf":   +4.0,  ".config": +4.0,
    ".json":    +4.0,  ".xml":    +3.0,  ".tf":  +6.0,
    # lower risk: docs / logs
    ".log":     +2.0,  ".txt":    +1.0,  ".md":  +1.0,  ".csv": +2.0,
    ".sql":     +3.0,
    # binary / compiled → de-prioritise
    ".pyc":     -5.0,  ".class":  -5.0,  ".so":  -6.0,  ".dll": -6.0,
    ".exe":     -6.0,  ".bin":    -4.0,  ".img": -4.0,
}

# Recency decay: findings older than DECAY_DAYS lose points
RECENCY_DECAY_DAYS   = 30
RECENCY_MAX_PENALTY  = 5.0

# ---------------------------------------------------------------------------
# Rule-to-sensitivity mapping (rule_id prefix → DataSensitivity)
# ---------------------------------------------------------------------------
RULE_SENSITIVITY_MAP: dict[str, DataSensitivity] = {
    "CRYPTO":       DataSensitivity.CRITICAL,
    "SEC-AWS":      DataSensitivity.CRITICAL,
    "SEC-GITHUB":   DataSensitivity.CRITICAL,
    "SEC-OPENAI":   DataSensitivity.CRITICAL,
    "SEC-STRIPE":   DataSensitivity.CRITICAL,
    "SEC-SLACK":    DataSensitivity.CRITICAL,
    "SEC-GCP":      DataSensitivity.CRITICAL,
    "SEC-AZURE":    DataSensitivity.CRITICAL,
    "AUTH-JWT":     DataSensitivity.HIGH,
    "FIN-CC":       DataSensitivity.CRITICAL,
    "FIN-IBAN":     DataSensitivity.HIGH,
    "FIN-BANK":     DataSensitivity.HIGH,
    "IND-AADHAAR":  DataSensitivity.CRITICAL,
    "IND-PAN":      DataSensitivity.CRITICAL,
    "IND-PASSPORT": DataSensitivity.HIGH,
    "IND-DL":       DataSensitivity.HIGH,
    "PII-EMAIL":    DataSensitivity.MEDIUM,
    "PII-PHONE":    DataSensitivity.MEDIUM,
}

# ---------------------------------------------------------------------------
# Evidence item
# ---------------------------------------------------------------------------
@dataclass
class Evidence:
    """A single piece of supporting evidence for a triage case."""
    evidence_id:     str  = field(default_factory=lambda: str(uuid.uuid4())[:8])
    source:          str  = ""
    line_number:     int  = 0
    column_number:   int  = 0
    context_snippet: str  = ""
    redacted_value:  str  = ""
    rule_id:         str  = ""
    rule_name:       str  = ""
    raw_confidence:  float = 0.0
    detected_at:     str  = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# TriageFinding – the normalised input to the engine
# ---------------------------------------------------------------------------
@dataclass
class TriageFinding:
    """
    Normalised representation of a raw detection finding fed into TriageEngine.
    Compatible with Finding objects from detection_engine.py and
    ValidationResult from validation_engine.py.
    """
    # identity
    finding_id:       str   = field(default_factory=lambda: str(uuid.uuid4()))
    rule_id:          str   = ""
    rule_name:        str   = ""

    # classification
    category:         str   = ""
    severity:         Severity          = Severity.MEDIUM
    validation_status: ValidationStatus = ValidationStatus.UNVALIDATED

    # value / location
    matched_value:    str   = ""
    redacted_value:   str   = ""
    source:           str   = ""
    start_offset:     int   = 0
    end_offset:       int   = 0
    line_number:      int   = 0
    column_number:    int   = 0
    context_snippet:  str   = ""

    # enrichment
    entropy:          float | None = None
    exposure_level:   ExposureLevel    = ExposureLevel.UNKNOWN
    data_sensitivity: DataSensitivity | None = None
    tags:             list[str]         = field(default_factory=list)
    metadata:         dict[str, Any]    = field(default_factory=dict)

    # timestamps
    detected_at:      str  = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "TriageFinding":
        """Deserialise from a plain dict (e.g. from detection_engine JSON output)."""
        f = cls()
        for k, v in d.items():
            if k == "severity":
                try:
                    f.severity = Severity(v)
                except ValueError:
                    pass
            elif k == "validation_status":
                try:
                    f.validation_status = ValidationStatus(v)
                except ValueError:
                    pass
            elif k == "exposure_level":
                try:
                    f.exposure_level = ExposureLevel(v)
                except ValueError:
                    pass
            elif k == "data_sensitivity" and v:
                try:
                    f.data_sensitivity = DataSensitivity(v)
                except ValueError:
                    pass
            elif k in ("raw_value", "value", "matched_value"):
                f.matched_value = v
            elif k in ("masked_value", "redacted_value"):
                f.redacted_value = v
            elif k in ("id", "finding_id"):
                f.finding_id = v
            elif hasattr(f, k):
                setattr(f, k, v)
        return f


# ---------------------------------------------------------------------------
# TriageCase – the aggregated output
# ---------------------------------------------------------------------------
@dataclass
class TriageCase:
    """Aggregated triage case for one logical group of findings."""

    case_id:          str  = field(default_factory=lambda: str(uuid.uuid4()))
    title:            str  = ""
    description:      str  = ""

    # scoring
    risk_score:       float    = 0.0      # 0–100
    risk_level:       RiskLevel = RiskLevel.MINIMAL
    triage_severity:  Severity  = Severity.INFO
    confidence:       float    = 0.0      # 0–1

    # constituent findings
    finding_ids:      list[str]         = field(default_factory=list)
    evidence:         list[Evidence]    = field(default_factory=list)

    # risk factor breakdown (for explainability)
    risk_breakdown:   dict[str, float]  = field(default_factory=dict)
    risk_factors:     list[str]         = field(default_factory=list)   # human-readable

    # metadata
    rule_ids:         list[str]         = field(default_factory=list)
    sources:          list[str]         = field(default_factory=list)
    tags:             list[str]         = field(default_factory=list)
    data_sensitivity: DataSensitivity   = DataSensitivity.INFORMATIONAL
    exposure_level:   ExposureLevel     = ExposureLevel.UNKNOWN
    validation_status: ValidationStatus = ValidationStatus.UNVALIDATED
    occurrence_count: int  = 1

    created_at:       str  = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    metadata:         dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["risk_level"]       = self.risk_level.value
        d["triage_severity"]  = self.triage_severity.value
        d["data_sensitivity"] = self.data_sensitivity.value
        d["exposure_level"]   = self.exposure_level.value
        d["validation_status"] = self.validation_status.value
        return d

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)


# ---------------------------------------------------------------------------
# Internal scoring result (intermediate; not returned to caller)
# ---------------------------------------------------------------------------
@dataclass
class _ScoredFinding:
    finding:      TriageFinding
    risk_score:   float
    confidence:   float
    severity:     Severity
    sensitivity:  DataSensitivity
    breakdown:    dict[str, float]
    factors:      list[str]


# ---------------------------------------------------------------------------
# TriageEngine
# ---------------------------------------------------------------------------
class TriageEngine:
    """
    Triage Engine: scores, prioritises, deduplicates, and aggregates findings
    from detection and validation engines into actionable triage cases.

    Usage
    -----
    engine = TriageEngine()
    findings = [TriageFinding.from_dict(d) for d in raw_findings]
    cases    = engine.build_case(findings)
    for case in cases:
        print(case.to_json())
    """

    def __init__(
        self,
        exposure_default: ExposureLevel = ExposureLevel.UNKNOWN,
        dedup_window_chars: int = 0,          # 0 = exact value match only
        min_risk_score: float = 0.0,           # filter cases below this score
        max_cases: int | None = None,
    ) -> None:
        self.exposure_default   = exposure_default
        self.dedup_window_chars = dedup_window_chars
        self.min_risk_score     = min_risk_score
        self.max_cases          = max_cases

    # ── helpers ──────────────────────────────────────────────────────────────

    @staticmethod
    def _shannon_entropy(s: str) -> float:
        if not s:
            return 0.0
        freq: dict[str, int] = {}
        for c in s:
            freq[c] = freq.get(c, 0) + 1
        n = len(s)
        return -sum((v / n) * math.log2(v / n) for v in freq.values())

    @staticmethod
    def _file_extension(source: str) -> str:
        return Path(source).suffix.lower() if source else ""

    @staticmethod
    def _recency_penalty(detected_at: str) -> float:
        """Return a penalty (0–RECENCY_MAX_PENALTY) for old findings."""
        try:
            dt = datetime.fromisoformat(detected_at)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            age_days = (datetime.now(timezone.utc) - dt).days
            if age_days <= 0:
                return 0.0
            ratio = min(1.0, age_days / RECENCY_DECAY_DAYS)
            return round(RECENCY_MAX_PENALTY * ratio, 2)
        except Exception:
            return 0.0

    @staticmethod
    def _infer_sensitivity(finding: TriageFinding) -> DataSensitivity:
        """Infer DataSensitivity from rule_id prefix if not already set."""
        if finding.data_sensitivity is not None:
            return finding.data_sensitivity
        for prefix, sensitivity in RULE_SENSITIVITY_MAP.items():
            if finding.rule_id.startswith(prefix):
                return sensitivity
        # fall back to severity-based inference
        return {
            Severity.CRITICAL: DataSensitivity.CRITICAL,
            Severity.HIGH:     DataSensitivity.HIGH,
            Severity.MEDIUM:   DataSensitivity.MEDIUM,
            Severity.LOW:      DataSensitivity.LOW,
            Severity.INFO:     DataSensitivity.INFORMATIONAL,
        }.get(finding.severity, DataSensitivity.MEDIUM)

    @staticmethod
    def _context_bonus(finding: TriageFinding) -> tuple[float, list[str]]:
        """Score context signals from snippet and tags."""
        HIGH_VALUE_KEYWORDS = {
            "production", "prod", "live", "master", "main", "deploy",
            "release", "api_key", "secret", "password", "private",
            "credential", "token", "auth", "access_key",
        }
        bonuses: list[str] = []
        score = 0.0
        combined = " ".join([
            finding.context_snippet.lower(),
            " ".join(finding.tags).lower(),
            finding.source.lower(),
        ])
        for kw in HIGH_VALUE_KEYWORDS:
            if kw in combined:
                score += CONTEXT_KEYWORD_BONUS
                bonuses.append(f"context keyword: '{kw}'")
        score = min(score, CONTEXT_KEYWORD_MAX)
        return round(score, 2), bonuses

    # ── public: calculate_severity ────────────────────────────────────────────

    def calculate_severity(self, finding: TriageFinding) -> Severity:
        """
        Derive a triage severity that may upgrade/downgrade the raw finding
        severity based on validation status, exposure, and data sensitivity.

        Returns a Severity enum.
        """
        sensitivity = self._infer_sensitivity(finding)
        base        = finding.severity

        # upgrade path: validated critical-sensitivity → at least HIGH
        if sensitivity == DataSensitivity.CRITICAL:
            if finding.validation_status in (
                ValidationStatus.VALID, ValidationStatus.LIKELY_VALID
            ) and base == Severity.MEDIUM:
                return Severity.HIGH

        # public exposure on any CRITICAL rule → upgrade to CRITICAL
        if (
            finding.exposure_level == ExposureLevel.PUBLIC
            and sensitivity in (DataSensitivity.CRITICAL, DataSensitivity.HIGH)
            and base in (Severity.HIGH, Severity.MEDIUM)
        ):
            return Severity.CRITICAL

        # placeholder / invalid → downgrade
        if finding.validation_status in (
            ValidationStatus.PLACEHOLDER, ValidationStatus.INVALID
        ):
            severity_order = [
                Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO
            ]
            idx = severity_order.index(base)
            return severity_order[min(idx + 1, len(severity_order) - 1)]

        return base

    # ── public: calculate_confidence ──────────────────────────────────────────

    def calculate_confidence(self, finding: TriageFinding) -> float:
        """
        Compute a 0.0–1.0 confidence score for the finding being a true positive.

        Factors
        -------
        - Raw detection confidence (from finding.metadata)
        - Validation status
        - Entropy of matched value
        - Context signal keywords
        - File type risk
        """
        # base: use raw confidence from metadata if available, else 0.5
        raw_conf = float(finding.metadata.get("raw_confidence", 0.50))

        # validation adjustment
        val_adj: dict[str, float] = {
            ValidationStatus.VALID:          +0.25,
            ValidationStatus.LIKELY_VALID:   +0.15,
            ValidationStatus.UNCERTAIN:       +0.00,
            ValidationStatus.LIKELY_INVALID:  -0.15,
            ValidationStatus.INVALID:        -0.25,
            ValidationStatus.PLACEHOLDER:    -0.35,
            ValidationStatus.UNVALIDATED:     +0.00,
        }
        conf = raw_conf + val_adj.get(finding.validation_status.value, 0.0)

        # entropy adjustment
        entropy = finding.entropy
        if entropy is None and finding.matched_value:
            entropy = self._shannon_entropy(finding.matched_value)
        if entropy is not None:
            if entropy >= 5.5:
                conf += 0.08
            elif entropy >= 4.0:
                conf += 0.04
            elif entropy < ENTROPY_MIN_CUTOFF:
                conf -= 0.10

        # context keyword bonus (max +0.06)
        ctx_score, _ = self._context_bonus(finding)
        conf += (ctx_score / CONTEXT_KEYWORD_MAX) * 0.06

        # file type signal
        ext = self._file_extension(finding.source)
        ft_mod = FILE_TYPE_MODIFIER.get(ext, 0.0)
        conf += ft_mod / 200.0   # scale to ±0.06 range

        return round(max(0.0, min(1.0, conf)), 4)

    # ── public: prioritize_findings ───────────────────────────────────────────

    def prioritize_findings(
        self, findings: list[TriageFinding]
    ) -> list[_ScoredFinding]:
        """
        Score and rank all findings by composite risk score (descending).

        Returns a list of _ScoredFinding (internal objects) sorted by risk_score.
        """
        scored: list[_ScoredFinding] = []

        for f in findings:
            sensitivity = self._infer_sensitivity(f)
            severity    = self.calculate_severity(f)
            confidence  = self.calculate_confidence(f)
            breakdown: dict[str, float] = {}
            factors:   list[str]        = []

            # ── base severity score ────────────────────────────────────────
            base = SEVERITY_BASE_SCORE[severity.value]
            breakdown["severity_base"] = base
            factors.append(f"base severity ({severity.value}): +{base:.1f}")

            # ── validation modifier ────────────────────────────────────────
            vm = VALIDATION_MODIFIER.get(f.validation_status.value, 0.0)
            breakdown["validation"] = vm
            if vm != 0.0:
                sign = "+" if vm > 0 else ""
                factors.append(f"validation ({f.validation_status.value}): {sign}{vm:.1f}")

            # ── sensitivity modifier ───────────────────────────────────────
            sm = SENSITIVITY_MODIFIER[sensitivity.value]
            breakdown["data_sensitivity"] = sm
            if sm != 0.0:
                sign = "+" if sm > 0 else ""
                factors.append(f"sensitivity ({sensitivity.value}): {sign}{sm:.1f}")

            # ── exposure modifier ──────────────────────────────────────────
            exposure = f.exposure_level if f.exposure_level != ExposureLevel.UNKNOWN \
                       else self.exposure_default
            em = EXPOSURE_MODIFIER[exposure.value]
            breakdown["exposure"] = em
            if em != 0.0:
                sign = "+" if em > 0 else ""
                factors.append(f"exposure ({exposure.value}): {sign}{em:.1f}")

            # ── entropy bonus ──────────────────────────────────────────────
            entropy = f.entropy
            if entropy is None and f.matched_value:
                entropy = self._shannon_entropy(f.matched_value)

            entropy_score = 0.0
            if entropy is not None:
                if entropy >= 5.5:
                    entropy_score = ENTROPY_MAX_BONUS
                elif entropy >= ENTROPY_MIN_CUTOFF:
                    entropy_score = ENTROPY_MAX_BONUS * (
                        (entropy - ENTROPY_MIN_CUTOFF) / (5.5 - ENTROPY_MIN_CUTOFF)
                    )
                else:
                    entropy_score = -4.0   # suspiciously low entropy
            breakdown["entropy"] = round(entropy_score, 2)
            if entropy_score != 0.0:
                sign = "+" if entropy_score > 0 else ""
                factors.append(f"entropy ({entropy:.2f} bits): {sign}{entropy_score:.1f}")

            # ── file-type modifier ─────────────────────────────────────────
            ext = self._file_extension(f.source)
            ft = FILE_TYPE_MODIFIER.get(ext, 0.0)
            breakdown["file_type"] = ft
            if ft != 0.0:
                sign = "+" if ft > 0 else ""
                factors.append(f"file type ({ext or 'unknown'}): {sign}{ft:.1f}")

            # ── context keyword bonus ──────────────────────────────────────
            ctx_score, ctx_labels = self._context_bonus(f)
            breakdown["context"] = ctx_score
            for lbl in ctx_labels:
                factors.append(f"{lbl}: +{CONTEXT_KEYWORD_BONUS:.1f}")

            # ── confidence weight ──────────────────────────────────────────
            # high-confidence findings get a 0–10 boost; low-confidence a penalty
            conf_adj = (confidence - 0.5) * 20.0    # ±10 range
            breakdown["confidence_weight"] = round(conf_adj, 2)
            if abs(conf_adj) > 0.5:
                sign = "+" if conf_adj > 0 else ""
                factors.append(f"confidence ({confidence:.0%}): {sign}{conf_adj:.1f}")

            # ── recency penalty ────────────────────────────────────────────
            recency_pen = -self._recency_penalty(f.detected_at)
            breakdown["recency"] = recency_pen
            if recency_pen < 0:
                factors.append(f"recency penalty: {recency_pen:.1f}")

            # ── final score (clamped 0–100) ────────────────────────────────
            total = sum(breakdown.values())
            risk_score = round(max(0.0, min(100.0, total)), 2)

            scored.append(_ScoredFinding(
                finding     = f,
                risk_score  = risk_score,
                confidence  = confidence,
                severity    = severity,
                sensitivity = sensitivity,
                breakdown   = breakdown,
                factors     = factors,
            ))

        scored.sort(key=lambda x: (-x.risk_score, -x.confidence))
        return scored

    # ── public: merge_duplicates ───────────────────────────────────────────────

    def merge_duplicates(
        self, findings: list[TriageFinding]
    ) -> list[TriageFinding]:
        """
        Deduplicate findings using a compound fingerprint:
          SHA-256( rule_id + normalised_value + source )

        When duplicates are found the representative with the highest raw
        confidence is retained and occurrence_count is recorded in metadata.

        Returns a deduplicated list of TriageFinding objects.
        """
        groups: dict[str, list[TriageFinding]] = defaultdict(list)

        for f in findings:
            normalised = re.sub(r"\s+", "", f.matched_value.strip().lower())
            fingerprint = hashlib.sha256(
                f"{f.rule_id}:{normalised}:{f.source}".encode()
            ).hexdigest()
            groups[fingerprint].append(f)

        deduped: list[TriageFinding] = []
        for members in groups.values():
            if len(members) == 1:
                deduped.append(members[0])
                continue

            # pick representative: highest raw confidence, else latest detected_at
            best = max(
                members,
                key=lambda x: (
                    float(x.metadata.get("raw_confidence", 0)),
                    x.detected_at,
                ),
            )
            best.metadata["occurrence_count"]   = len(members)
            best.metadata["duplicate_sources"]  = list({m.source for m in members})
            best.metadata["duplicate_offsets"]  = [m.start_offset for m in members]
            deduped.append(best)

        return deduped

    # ── public: build_case ────────────────────────────────────────────────────

    def build_case(
        self, findings: list[TriageFinding]
    ) -> list[TriageCase]:
        """
        Full triage pipeline:
          1. Deduplicate findings
          2. Score and prioritise
          3. Aggregate by rule_id group into TriageCase objects
          4. Collect evidence
          5. Apply min_risk_score filter and max_cases cap

        Returns a list of TriageCase objects sorted by risk_score (desc).
        """
        if not findings:
            return []

        # step 1 – deduplication
        deduped = self.merge_duplicates(findings)

        # step 2 – scoring
        scored = self.prioritize_findings(deduped)

        # step 3 – aggregation: group by rule_id → case
        case_groups: dict[str, list[_ScoredFinding]] = defaultdict(list)
        for sf in scored:
            # group key: coalesce rule_id family (e.g. "SEC-AWS" groups all SEC-AWS-* rules)
            key = "-".join(sf.finding.rule_id.split("-")[:2]) or sf.finding.rule_id or "UNKNOWN"
            case_groups[key].append(sf)

        cases: list[TriageCase] = []
        for group_key, group in case_groups.items():
            case = self._assemble_case(group_key, group)
            if case.risk_score >= self.min_risk_score:
                cases.append(case)

        # sort by risk_score desc, then triage_severity
        severity_order = {
            Severity.CRITICAL: 0, Severity.HIGH: 1,
            Severity.MEDIUM: 2,   Severity.LOW: 3, Severity.INFO: 4,
        }
        cases.sort(key=lambda c: (
            -c.risk_score,
            severity_order.get(c.triage_severity, 9),
        ))

        if self.max_cases is not None:
            cases = cases[:self.max_cases]

        return cases

    # ── private: assemble a single case from a scored group ──────────────────

    def _assemble_case(
        self, group_key: str, group: list[_ScoredFinding]
    ) -> TriageCase:
        # aggregate risk score: max score + small bonus per additional finding
        max_score     = max(sf.risk_score for sf in group)
        bonus         = min(5.0, len(group) * 0.5) if len(group) > 1 else 0.0
        agg_risk      = round(min(100.0, max_score + bonus), 2)

        # aggregate confidence: weighted average
        total_conf    = sum(sf.confidence * sf.risk_score for sf in group)
        total_weight  = sum(sf.risk_score for sf in group) or 1.0
        agg_confidence = round(total_conf / total_weight, 4)

        # highest triage severity in group
        sev_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        triage_severity = min(
            (sf.severity for sf in group),
            key=lambda s: sev_order.index(s),
        )

        # dominant sensitivity (most severe)
        sens_order = [
            DataSensitivity.CRITICAL, DataSensitivity.HIGH,
            DataSensitivity.MEDIUM,   DataSensitivity.LOW,
            DataSensitivity.INFORMATIONAL,
        ]
        dominant_sensitivity = min(
            (sf.sensitivity for sf in group),
            key=lambda s: sens_order.index(s),
        )

        # dominant exposure
        exp_order = [
            ExposureLevel.PUBLIC, ExposureLevel.UNKNOWN,
            ExposureLevel.INTERNAL, ExposureLevel.RESTRICTED,
        ]
        dominant_exposure = min(
            (sf.finding.exposure_level for sf in group),
            key=lambda e: exp_order.index(e) if e in exp_order else 99,
        )

        # validation: show the 'worst' (most positive) status
        val_order = [
            ValidationStatus.VALID, ValidationStatus.LIKELY_VALID,
            ValidationStatus.UNCERTAIN, ValidationStatus.UNVALIDATED,
            ValidationStatus.LIKELY_INVALID, ValidationStatus.INVALID,
            ValidationStatus.PLACEHOLDER,
        ]
        dominant_validation = min(
            (sf.finding.validation_status for sf in group),
            key=lambda v: val_order.index(v) if v in val_order else 99,
        )

        # risk level from agg_risk score
        risk_level = _risk_level_from_score(agg_risk)

        # collect unique sources, rule_ids, tags
        sources  = sorted({sf.finding.source   for sf in group if sf.finding.source})
        rule_ids = sorted({sf.finding.rule_id  for sf in group if sf.finding.rule_id})
        tags     = sorted({t for sf in group for t in sf.finding.tags})

        # occurrence count
        occ_count = sum(
            int(sf.finding.metadata.get("occurrence_count", 1)) for sf in group
        )

        # representative (highest-scored member) for title / description
        rep = group[0]

        title = (
            f"{triage_severity.value}: {rep.finding.rule_name or group_key}"
            + (f" ({occ_count} occurrences)" if occ_count > 1 else "")
        )
        description = _build_description(
            rep, dominant_sensitivity, dominant_exposure, dominant_validation, occ_count
        )

        # aggregate breakdown (sum contributions)
        agg_breakdown: dict[str, float] = defaultdict(float)
        for sf in group:
            for k, v in sf.breakdown.items():
                agg_breakdown[k] += v
        agg_breakdown = {k: round(v, 2) for k, v in agg_breakdown.items()}

        # collect all unique factors across group (deduped)
        seen_factors: set[str] = set()
        all_factors: list[str] = []
        for sf in group:
            for factor in sf.factors:
                if factor not in seen_factors:
                    seen_factors.add(factor)
                    all_factors.append(factor)

        # evidence collection
        evidence_list: list[Evidence] = []
        for sf in group:
            f = sf.finding
            ev = Evidence(
                source          = f.source,
                line_number     = f.line_number,
                column_number   = f.column_number,
                context_snippet = f.context_snippet,
                redacted_value  = f.redacted_value,
                rule_id         = f.rule_id,
                rule_name       = f.rule_name,
                raw_confidence  = float(f.metadata.get("raw_confidence", sf.confidence)),
                detected_at     = f.detected_at,
            )
            evidence_list.append(ev)

        return TriageCase(
            title             = title,
            description       = description,
            risk_score        = agg_risk,
            risk_level        = risk_level,
            triage_severity   = triage_severity,
            confidence        = agg_confidence,
            finding_ids       = [sf.finding.finding_id for sf in group],
            evidence          = evidence_list,
            risk_breakdown    = dict(agg_breakdown),
            risk_factors      = all_factors,
            rule_ids          = rule_ids,
            sources           = sources,
            tags              = tags,
            data_sensitivity  = dominant_sensitivity,
            exposure_level    = dominant_exposure,
            validation_status = dominant_validation,
            occurrence_count  = occ_count,
            metadata          = {
                "group_key":       group_key,
                "finding_count":   len(group),
                "max_risk_score":  max_score,
                "aggregation_bonus": bonus,
            },
        )

    # ── convenience ───────────────────────────────────────────────────────────

    def summary(self, cases: list[TriageCase]) -> dict[str, Any]:
        """Aggregate statistics over a list of TriageCase objects."""
        by_severity:  dict[str, int] = {s.value: 0 for s in Severity}
        by_risk:      dict[str, int] = {r.value: 0 for r in RiskLevel}
        by_sensitivity: dict[str, int] = {s.value: 0 for s in DataSensitivity}

        for c in cases:
            by_severity[c.triage_severity.value] += 1
            by_risk[c.risk_level.value]           += 1
            by_sensitivity[c.data_sensitivity.value] += 1

        total_findings = sum(len(c.finding_ids) for c in cases)
        avg_confidence = (
            sum(c.confidence for c in cases) / len(cases) if cases else 0.0
        )

        return {
            "total_cases":        len(cases),
            "total_findings":     total_findings,
            "average_confidence": round(avg_confidence, 4),
            "average_risk_score": round(sum(c.risk_score for c in cases) / len(cases), 2) if cases else 0.0,
            "max_risk_score":     max((c.risk_score for c in cases), default=0.0),
            "by_severity":        by_severity,
            "by_risk_level":      by_risk,
            "by_sensitivity":     by_sensitivity,
            "sources_affected":   sorted({s for c in cases for s in c.sources}),
            "generated_at":       datetime.now(timezone.utc).isoformat(),
        }

    def triage(self, findings, file_path=None, metadata=None):
        # Convert incoming findings to TriageFinding objects
        triage_findings = []
        for f in findings:
            if isinstance(f, dict):
                f_copy = f.copy()
                val_status = f_copy.get("validation_status", "UNVALIDATED")
                if not val_status:
                    val_status = "UNVALIDATED"
                f_copy["validation_status"] = str(val_status).upper()
                
                sev = f_copy.get("severity", "MEDIUM")
                if not sev:
                    sev = "MEDIUM"
                f_copy["severity"] = str(sev).upper()
                
                tf = TriageFinding.from_dict(f_copy)
            else:
                tf = f
            triage_findings.append(tf)
        
        # Deduplicate and score them
        deduped = self.merge_duplicates(triage_findings)
        scored = self.prioritize_findings(deduped)
        
        # Convert scored findings back to dictionary format
        findings_dicts = []
        max_risk = 0.0
        max_severity = "info"
        max_confidence = 0.0
        
        severity_order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        
        for sf in scored:
            f_dict = sf.finding.metadata.copy() if sf.finding.metadata else {}
            f_dict.update({
                "rule_id": sf.finding.rule_id,
                "rule_name": sf.finding.rule_name,
                "category": sf.finding.category,
                "severity": sf.severity.value if hasattr(sf.severity, "value") else sf.severity,
                "confidence": sf.confidence,
                "confidence_score": sf.risk_score,
                "matched_value": sf.finding.matched_value,
                "raw_value": sf.finding.matched_value,
                "redacted_value": sf.finding.redacted_value,
                "masked_value": sf.finding.redacted_value,
                "source": sf.finding.source,
                "file_path": sf.finding.source,
                "line_number": sf.finding.line_number,
                "column_number": sf.finding.column_number,
                "context_snippet": sf.finding.context_snippet,
                "context": sf.finding.context_snippet,
                "validation_status": sf.finding.validation_status.value if hasattr(sf.finding.validation_status, "value") else sf.finding.validation_status,
                "risk_score": sf.risk_score,
            })
            findings_dicts.append(f_dict)
            
            if sf.risk_score > max_risk:
                max_risk = sf.risk_score
            
            sev_str = sf.severity.value if hasattr(sf.severity, "value") else str(sf.severity)
            if sev_str.upper() in severity_order:
                if severity_order.index(sev_str.upper()) > severity_order.index(max_severity.upper()):
                    max_severity = sev_str.lower()
                    
            if sf.confidence > max_confidence:
                max_confidence = sf.confidence
                
        return {
            "findings": findings_dicts,
            "risk_score": max_risk,
            "severity": max_severity,
            "confidence": max_confidence,
        }


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------

def _risk_level_from_score(score: float) -> RiskLevel:
    if score >= 80:
        return RiskLevel.CRITICAL
    if score >= 60:
        return RiskLevel.HIGH
    if score >= 40:
        return RiskLevel.MEDIUM
    if score >= 20:
        return RiskLevel.LOW
    return RiskLevel.MINIMAL


def _build_description(
    rep:         _ScoredFinding,
    sensitivity: DataSensitivity,
    exposure:    ExposureLevel,
    validation:  ValidationStatus,
    occ_count:   int,
) -> str:
    f     = rep.finding
    parts = [
        f"Rule: {f.rule_name or f.rule_id}.",
        f"Sensitivity: {sensitivity.value}.",
        f"Exposure: {exposure.value}.",
        f"Validation: {validation.value}.",
        f"Risk score: {rep.risk_score:.1f}/100.",
    ]
    if occ_count > 1:
        parts.append(f"Detected {occ_count} time(s) across source(s).")
    if f.source:
        parts.append(f"Primary source: {f.source}.")
    if f.line_number:
        parts.append(f"First occurrence at line {f.line_number}.")
    return " ".join(parts)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _cli() -> None:
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="TriageEngine – score, prioritise, and aggregate security findings"
    )
    parser.add_argument(
        "input", nargs="?", default=None,
        help="JSON file of findings (detection_engine output); omit to read from stdin",
    )
    parser.add_argument(
        "--exposure", default="UNKNOWN",
        choices=[e.value for e in ExposureLevel],
        help="Default exposure level for all findings",
    )
    parser.add_argument(
        "--min-risk", type=float, default=0.0,
        help="Minimum risk score threshold for emitted cases (0–100)",
    )
    parser.add_argument(
        "--max-cases", type=int, default=None,
        help="Maximum number of cases to return",
    )
    parser.add_argument(
        "--summary-only", action="store_true",
        help="Print summary statistics instead of full cases",
    )
    parser.add_argument(
        "--output", default=None,
        help="Write JSON output to this file path",
    )
    args = parser.parse_args()

    src = open(args.input) if args.input else sys.stdin
    try:
        raw = json.load(src)
    finally:
        if args.input:
            src.close()

    if not isinstance(raw, list):
        raw = [raw]

    findings = [TriageFinding.from_dict(d) for d in raw]

    engine = TriageEngine(
        exposure_default=ExposureLevel(args.exposure),
        min_risk_score=args.min_risk,
        max_cases=args.max_cases,
    )
    cases = engine.build_case(findings)

    if args.summary_only:
        out = json.dumps(engine.summary(cases), indent=2)
    else:
        out = json.dumps([c.to_dict() for c in cases], indent=2, default=str)

    print(out)

    if args.output:
        Path(args.output).write_text(out, encoding="utf-8")

    # non-zero exit if any CRITICAL / HIGH cases
    if any(c.triage_severity in (Severity.CRITICAL, Severity.HIGH) for c in cases):
        sys.exit(1)


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    _cli()