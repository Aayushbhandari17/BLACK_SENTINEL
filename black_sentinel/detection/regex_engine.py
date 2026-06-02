import base64
import json
import re
from typing import List, Dict, Any

from black_sentinel.detection import confidence_engine, metrics

# Global stats for final summary
STATS = {}

def print_summary():
    print("\n--- Regex Validation Summary ---")
    for entity, counts in STATS.items():
        if counts["checked"] > 0:
            print(f"{entity}:")
            print(f"checked={counts['checked']}")
            print(f"validated={counts['validated']}\n")
    metrics.print_summary()

# Validators
def validate_luhn(card_number: str) -> bool:
    digits = [int(c) for c in card_number if c.isdigit()]
    if not digits:
        return False
    checksum = 0
    reverse_digits = digits[::-1]
    for i, d in enumerate(reverse_digits):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0

# Verhoeff algorithm structures
d = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 2, 3, 4, 0, 6, 7, 8, 9, 5),
    (2, 3, 4, 0, 1, 7, 8, 9, 5, 6),
    (3, 4, 0, 1, 2, 8, 9, 5, 6, 7),
    (4, 0, 1, 2, 3, 9, 5, 6, 7, 8),
    (5, 9, 8, 7, 6, 0, 4, 3, 2, 1),
    (6, 5, 9, 8, 7, 1, 0, 4, 3, 2),
    (7, 6, 5, 9, 8, 2, 1, 0, 4, 3),
    (8, 7, 6, 5, 9, 3, 2, 1, 0, 4),
    (9, 8, 7, 6, 5, 4, 3, 2, 1, 0)
)
p = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 5, 7, 6, 2, 8, 3, 0, 9, 4),
    (5, 8, 0, 3, 7, 9, 6, 1, 4, 2),
    (8, 9, 1, 6, 0, 4, 3, 5, 2, 7),
    (9, 4, 5, 3, 1, 2, 6, 8, 7, 0),
    (4, 2, 8, 6, 5, 7, 3, 9, 0, 1),
    (2, 7, 9, 3, 8, 0, 6, 4, 1, 5),
    (7, 0, 4, 6, 9, 1, 3, 2, 5, 8)
)

def validate_verhoeff(num: str) -> bool:
    c = 0
    num_array = [int(n) for n in reversed(num) if n.isdigit()]
    if len(num_array) != 12:
        return False
    for i, n in enumerate(num_array):
        c = d[c][p[i % 8][n]]
    return c == 0

def validate_pan(pan: str) -> bool:
    if len(pan) != 10:
        return False
    entity_char = pan[3].upper()
    valid_entities = {'P', 'C', 'H', 'A', 'B', 'G', 'J', 'L', 'E', 'F', 'T'}
    return entity_char in valid_entities

UPI_PROVIDERS = {
    "oksbi", "okhdfcbank", "okicici", "okaxis", "ybl", "ibl", "paytm", "axl"
}

NPM_SCOPE_PREFIXES = {
    "@swc", "@babel", "@types", "@next", "@eslint", "@react", "@angular", "@vue", "@vite"
}

NPM_SCOPE_PATTERN = re.compile(r'@[a-z0-9][a-z0-9._-]*/[a-z0-9][a-z0-9._-]*', re.IGNORECASE)

def validate_upi(upi: str) -> bool:
    lower = upi.lower()
    if any(lower.startswith(scope) for scope in NPM_SCOPE_PREFIXES):
        return False
    if NPM_SCOPE_PATTERN.search(lower):
        return False
    if lower.count("@") != 1:
        return False
    handle, provider = lower.rsplit("@", 1)
    return bool(handle) and provider in UPI_PROVIDERS

def validate_aws_access_key(key: str) -> bool:
    return bool(re.fullmatch(r'AKIA[0-9A-Z]{16}', key))

def _decode_base64url_json(part: str) -> bool:
    try:
        padded = part + "=" * (-len(part) % 4)
        decoded = base64.urlsafe_b64decode(padded.encode("ascii"))
        json.loads(decoded.decode("utf-8"))
        return True
    except Exception:
        return False

def validate_jwt(token: str) -> bool:
    parts = token.split(".")
    if len(parts) != 3 or not all(parts):
        return False
    return _decode_base64url_json(parts[0]) and _decode_base64url_json(parts[1])

def validate_google_api_key(key: str) -> bool:
    return bool(re.fullmatch(r'AIza[0-9A-Za-z_-]{35}', key))

def validate_github_token(token: str) -> bool:
    return bool(
        re.fullmatch(r'ghp_[A-Za-z0-9]{36}', token)
        or re.fullmatch(r'github_pat_[A-Za-z0-9_]{20,}', token)
    )

def validate_openai_key(key: str) -> bool:
    return bool(re.fullmatch(r'sk-[A-Za-z0-9_-]{20,}', key))

def validate_stripe_key(key: str) -> bool:
    return bool(re.fullmatch(r'(?:sk_live|pk_live)_[A-Za-z0-9]{16,}', key))

def validate_ssh_private_key_header(header: str) -> bool:
    return bool(re.fullmatch(r'-----BEGIN .{0,10}PRIVATE KEY-----', header))

VALIDATORS = {
    "CREDIT_CARD": validate_luhn,
    "AADHAAR": validate_verhoeff,
    "PAN_CARD": validate_pan,
    "UPI_ID": validate_upi,
    "AWS_ACCESS_KEY": validate_aws_access_key,
    "JWT_TOKEN": validate_jwt,
    "GOOGLE_API_KEY": validate_google_api_key,
    "GITHUB_TOKEN": validate_github_token,
    "OPENAI_API_KEY": validate_openai_key,
    "STRIPE_KEY": validate_stripe_key,
    "SSH_PRIVATE_KEY": validate_ssh_private_key_header
}

PATTERNS = [
    # HIGH_SENSITIVE
    {
        "name": "password_in_config",
        "entity_type": "PASSWORD",
        "category": "HIGH_SENSITIVE",
        "pattern": re.compile(r'(password|passwd|pwd|secret)\s*[:=]\s*\S+', re.IGNORECASE),
        "confidence": 0.85,
        "severity": "CRITICAL",
        "requires_validation": False,
        "requires_context": False,
        "keywords": ["password", "secret", "pwd"]
    },
    {
        "name": "bank_account",
        "entity_type": "BANK_ACCOUNT",
        "category": "HIGH_SENSITIVE",
        "pattern": re.compile(r'\b\d{9,18}\b'),
        "confidence": 0.90,
        "severity": "CRITICAL",
        "requires_validation": False,
        "requires_context": True,
        "keywords": ["account", "bank", "beneficiary", "ifsc", "branch"]
    },
    {
        "name": "credit_card",
        "entity_type": "CREDIT_CARD",
        "category": "HIGH_SENSITIVE",
        "pattern": re.compile(r'\b(?:\d[ \-]?){13,16}\b'),
        "confidence": 0.95,
        "severity": "CRITICAL",
        "requires_validation": True,
        "requires_context": True,
        "keywords": ["card", "visa", "mastercard", "amex", "cvv", "payment", "debit", "credit"]
    },
    {
        "name": "upi_id",
        "entity_type": "UPI_ID",
        "category": "HIGH_SENSITIVE",
        "pattern": re.compile(r'\b[a-zA-Z0-9.\-_]{2,256}@(oksbi|okhdfcbank|okicici|okaxis|ybl|ibl|paytm|axl)\b', re.IGNORECASE),
        "confidence": 0.85,
        "severity": "CRITICAL",
        "requires_validation": True,
        "requires_context": False,
        "keywords": ["upi", "vpa", "pay", "bhim", "gpay", "phonepe"]
    },
    {
        "name": "aadhaar_number",
        "entity_type": "AADHAAR",
        "category": "HIGH_SENSITIVE",
        "pattern": re.compile(r'[2-9]\d{3}\s?\d{4}\s?\d{4}'),
        "confidence": 0.95,
        "severity": "CRITICAL",
        "requires_validation": True,
        "requires_context": True,
        "keywords": ["aadhaar", "uidai", "aadhar"]
    },
    {
        "name": "passport_india",
        "entity_type": "PASSPORT",
        "category": "HIGH_SENSITIVE",
        "pattern": re.compile(r'[A-PR-WY][1-9]\d{7}'),
        "confidence": 0.85,
        "severity": "CRITICAL",
        "requires_validation": False,
        "requires_context": False,
        "keywords": ["passport", "travel", "visa"]
    },
    {
        "name": "aws_access_key",
        "entity_type": "AWS_ACCESS_KEY",
        "category": "HIGH_SENSITIVE",
        "pattern": re.compile(r'\bAKIA[0-9A-Z]{16}\b'),
        "confidence": 0.95,
        "severity": "CRITICAL",
        "requires_validation": True,
        "requires_context": False,
        "keywords": ["aws", "amazon", "access", "key"],
        "strong_validator": True
    },
    {
        "name": "google_api_key",
        "entity_type": "GOOGLE_API_KEY",
        "category": "HIGH_SENSITIVE",
        "pattern": re.compile(r'\bAIza[0-9A-Za-z_-]{35}\b'),
        "confidence": 0.95,
        "severity": "CRITICAL",
        "requires_validation": True,
        "requires_context": False,
        "keywords": ["google", "api", "key"],
        "strong_validator": True
    },
    {
        "name": "github_token",
        "entity_type": "GITHUB_TOKEN",
        "category": "HIGH_SENSITIVE",
        "pattern": re.compile(r'\b(?:ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{20,})\b'),
        "confidence": 0.95,
        "severity": "CRITICAL",
        "requires_validation": True,
        "requires_context": False,
        "keywords": ["github", "gh", "token", "pat"],
        "strong_validator": True
    },
    {
        "name": "openai_api_key",
        "entity_type": "OPENAI_API_KEY",
        "category": "HIGH_SENSITIVE",
        "pattern": re.compile(r'\bsk-[A-Za-z0-9_-]{20,}\b'),
        "confidence": 0.95,
        "severity": "CRITICAL",
        "requires_validation": True,
        "requires_context": False,
        "keywords": ["openai", "api", "key"],
        "strong_validator": True
    },
    {
        "name": "stripe_key",
        "entity_type": "STRIPE_KEY",
        "category": "HIGH_SENSITIVE",
        "pattern": re.compile(r'\b(?:sk_live|pk_live)_[A-Za-z0-9]{16,}\b'),
        "confidence": 0.95,
        "severity": "CRITICAL",
        "requires_validation": True,
        "requires_context": False,
        "keywords": ["stripe", "payment", "key"],
        "strong_validator": True
    },
    {
        "name": "jwt_token",
        "entity_type": "JWT_TOKEN",
        "category": "HIGH_SENSITIVE",
        "pattern": re.compile(r'\beyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b'),
        "confidence": 0.98,
        "severity": "CRITICAL",
        "requires_validation": True,
        "requires_context": False,
        "keywords": ["jwt", "token", "auth", "bearer"],
        "strong_validator": True
    },
    {
        "name": "ssh_private_key",
        "entity_type": "SSH_PRIVATE_KEY",
        "category": "HIGH_SENSITIVE",
        "pattern": re.compile(r'-----BEGIN .{0,10}PRIVATE KEY-----'),
        "confidence": 1.0,
        "severity": "CRITICAL",
        "requires_validation": True,
        "requires_context": False,
        "keywords": [],
        "strong_validator": True
    },
    {
        "name": "recovery_code",
        "entity_type": "RECOVERY_CODE",
        "category": "HIGH_SENSITIVE",
        "pattern": re.compile(r'\b[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}\b'),
        "confidence": 0.90,
        "severity": "CRITICAL",
        "requires_validation": False,
        "requires_context": True,
        "keywords": ["recovery", "backup", "mfa", "2fa"]
    },

    # MEDIUM_SENSITIVE
    {
        "name": "email_address",
        "entity_type": "EMAIL",
        "category": "MEDIUM_SENSITIVE",
        "pattern": re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}'),
        "confidence": 0.95,
        "severity": "HIGH",
        "requires_validation": False,
        "requires_context": False,
        "keywords": ["email", "mail", "contact"]
    },
    {
        "name": "indian_phone",
        "entity_type": "PHONE_NUMBER",
        "category": "MEDIUM_SENSITIVE",
        "pattern": re.compile(r'(\+91|0)?[6-9]\d{9}'),
        "confidence": 0.90,
        "severity": "HIGH",
        "requires_validation": False,
        "requires_context": True,
        "keywords": ["phone", "mobile", "contact", "call"]
    },
    {
        "name": "pan_card",
        "entity_type": "PAN_CARD",
        "category": "MEDIUM_SENSITIVE",
        "pattern": re.compile(r'[A-Z]{5}[0-9]{4}[A-Z]'),
        "confidence": 0.95,
        "severity": "HIGH",
        "requires_validation": True,
        "requires_context": True,
        "keywords": ["pan", "income tax"]
    },
    {
        "name": "ifsc_code",
        "entity_type": "IFSC_CODE",
        "category": "MEDIUM_SENSITIVE",
        "pattern": re.compile(r'[A-Z]{4}0[A-Z0-9]{6}'),
        "confidence": 0.85,
        "severity": "HIGH",
        "requires_validation": False,
        "requires_context": False,
        "keywords": ["ifsc", "bank", "branch"]
    },
    {
        "name": "driving_licence",
        "entity_type": "DRIVING_LICENCE",
        "category": "MEDIUM_SENSITIVE",
        "pattern": re.compile(r'[A-Z]{2}[0-9]{2}[A-Z]{2}[0-9]{11}'),
        "confidence": 0.85,
        "severity": "HIGH",
        "requires_validation": False,
        "requires_context": False,
        "keywords": ["driving", "licence", "dl", "rto"]
    },
    {
        "name": "voter_id",
        "entity_type": "VOTER_ID",
        "category": "MEDIUM_SENSITIVE",
        "pattern": re.compile(r'[A-Z]{3}[0-9]{7}'),
        "confidence": 0.80,
        "severity": "HIGH",
        "requires_validation": False,
        "requires_context": False,
        "keywords": ["voter", "epic", "election"]
    },
    {
        "name": "vehicle_registration",
        "entity_type": "VEHICLE_REGISTRATION",
        "category": "MEDIUM_SENSITIVE",
        "pattern": re.compile(r'[A-Z]{2}[0-9]{2}[A-Z]{1,2}[0-9]{4}'),
        "confidence": 0.75,
        "severity": "HIGH",
        "requires_validation": False,
        "requires_context": False,
        "keywords": ["vehicle", "rc", "registration", "car", "bike"]
    }
]

CREDENTIAL_STORES = [
    (re.compile(r'\.env$'), "ENV_FILE"),
    (re.compile(r'\.ssh/(id_rsa|id_ed25519)'), "SSH_PRIVATE_KEY_FILE"),
    (re.compile(r'\.git-credentials'), "GIT_CREDENTIALS"),
    (re.compile(r'\.aws/credentials'), "AWS_CREDENTIALS"),
    (re.compile(r'\.docker/config\.json'), "DOCKER_CONFIG"),
    (re.compile(r'\.kube/config'), "KUBERNETES_CONFIG"),
    (re.compile(r'Login Data$'), "BROWSER_CREDENTIALS"),
    (re.compile(r'Cookies$'), "BROWSER_COOKIES")
]

def scan(text: str, file_path: str = "") -> List[Dict[str, Any]]:
    findings = []
    
    # Path-based suppression
    if file_path:
        skip_paths = ['library/', 'applications/', 'caches/', 'logs/', 'node_modules/', 'package-lock', 'npm', 'browser']
        fp_lower = file_path.lower().replace('\\', '/')
        if any(sp in fp_lower for sp in skip_paths):
            return findings
            
    # 1. Path-based detection (CREDENTIAL_STORE)
    if file_path:
        norm_path = file_path.replace('\\', '/')
        for pattern, entity_type in CREDENTIAL_STORES:
            if pattern.search(norm_path):
                final_score = confidence_engine.score(file_path=file_path, regex_match=True)
                if not confidence_engine.should_publish(final_score):
                    break
                findings.append({
                    "detector": "path",
                    "rule_name": "credential_store_path",
                    "entity_type": entity_type,
                    "category": "CREDENTIAL_STORE",
                    "raw_value": file_path,
                    "context": file_path,
                    "confidence": confidence_engine.confidence_from_score(final_score),
                    "confidence_score": final_score,
                    "severity": "CRITICAL",
                    "requires_validation": False
                })
                break
                
    # 2. Content-based detection (Regex)
    for rule in PATTERNS:
        for match in rule["pattern"].finditer(text):
            metrics.increment("regex_candidates_checked")
            start = match.start()
            end = match.end()
            raw_value = match.group(0)
            validator_passed = False
            
            # Enforce validation if required
            if rule["requires_validation"]:
                validator = VALIDATORS.get(rule["entity_type"])
                if validator:
                    entity = rule["entity_type"]
                    if entity not in STATS:
                        STATS[entity] = {"checked": 0, "validated": 0}
                    STATS[entity]["checked"] += 1
                    
                    if validator(raw_value):
                        STATS[entity]["validated"] += 1
                        metrics.increment("regex_validated")
                        validator_passed = True
                    else:
                        continue
                else:
                    continue
            
            # Context window (60 chars)
            context_start = max(0, start - 60)
            context_end = min(len(text), end + 60)
            context = text[context_start:context_end]
            context_lower = context.lower()
            
            # Context evaluation
            has_context = False
            for kw in rule["keywords"]:
                if kw in context_lower:
                    has_context = True
                    break

            assignment_match = confidence_engine.has_assignment_pattern(context)
            final_score = confidence_engine.score(
                file_path=file_path,
                regex_match=True,
                format_validator_passed=validator_passed,
                context_keyword_match=has_context,
                assignment_pattern_match=assignment_match,
                strong_validator_passed=bool(rule.get("strong_validator") and validator_passed)
            )

            if not confidence_engine.should_publish(final_score):
                continue
                    
            findings.append({
                "detector": "regex",
                "rule_name": rule["name"],
                "entity_type": rule["entity_type"],
                "category": rule["category"],
                "raw_value": raw_value,
                "context": context.replace('\n', ' ').strip(),
                "confidence": confidence_engine.confidence_from_score(final_score),
                "confidence_score": final_score,
                "severity": rule["severity"],
                "requires_validation": rule["requires_validation"],
                "start": start,
                "end": end
            })
            
    # Post-processing: Resolve overlapping pattern false positives
    content_findings = [f for f in findings if "start" in f and "end" in f]
    path_findings = [f for f in findings if "start" not in f or "end" not in f]
    
    if content_findings:
        def get_priority(f):
            is_high = 1 if f.get("category") == "HIGH_SENSITIVE" else 0
            length = f["end"] - f["start"]
            return (f["confidence"], length, is_high)
            
        content_findings.sort(key=get_priority, reverse=True)
        
        kept_findings = []
        for f in content_findings:
            overlap = False
            for k in kept_findings:
                if max(f["start"], k["start"]) < min(f["end"], k["end"]):
                    overlap = True
                    break
            if not overlap:
                kept_findings.append(f)
                
        for f in kept_findings:
            f.pop("start", None)
            f.pop("end", None)
            
        findings = path_findings + kept_findings

    return findings
