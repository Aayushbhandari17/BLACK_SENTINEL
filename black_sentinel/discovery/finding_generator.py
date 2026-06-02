from typing import Dict, Any
from black_sentinel.schemas.models import Finding

def mask_value(raw: str) -> str:
    """
    Masks a sensitive string.
    Keeps only the first 4 and last 2 characters if the string is long enough.
    Otherwise masks entirely.
    """
    if not raw:
        return ""
    if len(raw) <= 6:
        return '*' * len(raw)
    return f"{raw[:4]}{'*' * (len(raw) - 6)}{raw[-2:]}"

def get_severity(category: str) -> str:
    """
    Maps detection categories to standard severity levels.
    """
    mapping = {
        "HIGH_SENSITIVE": "CRITICAL",
        "MEDIUM_SENSITIVE": "HIGH",
        "CREDENTIAL_STORE": "CRITICAL",
        "HIGH_ENTROPY_SECRET": "HIGH"
    }
    return mapping.get(category, "MEDIUM")

def create_finding(raw_finding: Dict[str, Any], file_path: str) -> Finding:
    """
    Converts a raw dictionary finding from detection engines into a structured Finding dataclass.
    Enforces masking and severity rules.
    """
    category = raw_finding.get("category", "")
    severity = get_severity(category)
    raw_val = raw_finding.get("raw_value", "")
    
    # Path-based detections might pass file_path inside raw_value, so handle context properly
    actual_file_path = file_path if file_path else raw_finding.get("raw_value", "")
    
    return Finding(
        event_type="finding_discovered",
        source="tracking_engine",
        severity=severity,
        file_path=actual_file_path,
        detector=raw_finding.get("detector", "unknown"),
        entity_type=raw_finding.get("entity_type", "UNKNOWN"),
        raw_value=raw_val,
        masked_value=mask_value(raw_val),
        context=raw_finding.get("context", ""),
        confidence=raw_finding.get("confidence", 0.0),
        validated=raw_finding.get("requires_validation", False)
    )
