import math
import os
import re
from typing import List, Dict, Any
from collections import Counter

from black_sentinel.detection import confidence_engine, metrics

# Entropy thresholds based on character set (Increased to reduce FPs)
THRESHOLDS = {
    'hex': 4.0,
    'base64': 4.8,
    'alphanumeric': 4.2
}

CONTEXT_KEYWORDS = ['key', 'secret', 'token', 'password']
CONTEXT_BOOST = 0.3

GENERATED_DIRECTORIES = {
    ".next", "dist", "build", "out", "coverage", ".turbo", ".cache"
}

GENERATED_FILES = {
    "build-manifest.json",
    "next-font-manifest.json",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "telemetry-core.json",
    "thirdpartynotices.txt",
    "nls.keys.json",
    "nls.messages.json",
}

GENERATED_NAME_HINTS = ("manifest", "font", "chunk", "asset", "bundle", "telemetry")
ASSET_EXTENSIONS = (".js", ".css", ".woff", ".woff2", ".png", ".jpg", ".jpeg", ".svg", ".map")
BUILD_CONTEXT_HINTS = (
    "build", "asset", "font", "manifest", "chunk", "webpack", "turbopack",
    "buildid", "moduleid", "chunkid", "contenthash", "webpack_require"
)

# Regular expressions for token filtering
HEX_REGEX = re.compile(r'^[0-9a-fA-F]+$')
BASE64_REGEX = re.compile(r'^[a-zA-Z0-9+/]+={0,2}$')
UUID_REGEX = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.IGNORECASE)
FILE_PATH_REGEX = re.compile(r'^([a-zA-Z]:\\|\/|\\)(?:[\w.\-]+[\\\/])+[\w.\-]+$')
URL_REGEX = re.compile(r'^(https?://|git://|ssh://|github\.com|www\.)', re.IGNORECASE)
EXTENSION_REGEX = re.compile(r'\.(js|ts|json|md|html|css|txt|yml|yaml|xml|csv|png|jpg|jpeg|gif|svg|exe|dll|so|dylib|zip|tar|gz)$', re.IGNORECASE)
PACKAGE_NAME_REGEX = re.compile(r'^@?[a-z0-9\-_]+/[a-z0-9\-_.]+$', re.IGNORECASE)
BUILD_HASH_REGEX = re.compile(r'^[A-Fa-f0-9]{16,}$')
GENERATED_ID_REGEX = re.compile(r'^[A-Za-z0-9_-]{16,}$')

def shannon_entropy(data: str) -> float:
    """Calculates the Shannon entropy of a given string."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    counts = Counter(data)
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy

def tokenize(text: str) -> List[tuple]:
    """
    Splits text on whitespace, quotes, equals, and colons.
    Returns a list of tuples (token_str, start_index, end_index).
    """
    tokens = []
    for match in re.finditer(r'[^\s"\'=:]+', text):
        token = match.group(0)
        tokens.append((token, match.start(), match.end()))
    return tokens

def determine_charset(token: str) -> str:
    """Identifies the primary character set of the token to select the correct threshold."""
    if HEX_REGEX.match(token):
        return 'hex'
    if BASE64_REGEX.match(token):
        return 'base64'
    return 'alphanumeric'

def _path_components(file_path: str) -> List[str]:
    normalized = os.path.normcase(file_path or "").replace('\\', '/').lower()
    return [part for part in normalized.split('/') if part]

def is_generated_entropy_source(file_path: str) -> bool:
    components = _path_components(file_path)
    if not components:
        return False
    basename = components[-1]
    if basename in GENERATED_FILES:
        return True
    if any(part in GENERATED_DIRECTORIES for part in components):
        return True
    return any(hint in basename for hint in GENERATED_NAME_HINTS)

def character_class_count(token: str) -> int:
    has_upper = any(c.isupper() for c in token)
    has_lower = any(c.islower() for c in token)
    has_digit = any(c.isdigit() for c in token)
    has_special = any(not c.isalnum() for c in token)
    return sum([has_upper, has_lower, has_digit, has_special])

def has_asset_extension_adjacency(token: str, context: str) -> bool:
    escaped = re.escape(token)
    extensions = "|".join(re.escape(ext) for ext in ASSET_EXTENSIONS)
    return bool(re.search(rf'(?i)(?:{escaped}\s*(?:{extensions})|(?:{extensions})\s*{escaped})', context))

def is_build_artifact_token(token: str, context: str) -> bool:
    context_lower = context.lower()
    token_lower = token.lower()
    if any(ext in token_lower for ext in ASSET_EXTENSIONS):
        return True
    if has_asset_extension_adjacency(token, context):
        return True
    if any(hint in context_lower for hint in BUILD_CONTEXT_HINTS):
        return bool(BUILD_HASH_REGEX.fullmatch(token) or GENERATED_ID_REGEX.fullmatch(token))
    return False

def is_false_positive(token: str, charset: str) -> bool:
    """Filters out common non-secret strings (URLs, packages, extensions, UUIDs)."""
    if len(token) < 16 or len(token) > 80:
        return True
    
    # Entropy alone is not enough; require at least two character classes.
    if character_class_count(token) < 2:
        return True
            
    # Exclude URLs, repository references
    if URL_REGEX.match(token) or "github.com/" in token.lower():
        return True
        
    # Exclude standard slash-separated file paths
    if FILE_PATH_REGEX.match(token):
        return True
        
    # Exclude strings containing common file extensions (like configuration.js)
    if EXTENSION_REGEX.search(token):
        return True
        
    # Exclude npm package identifiers (e.g. @msgpackr-extract)
    if PACKAGE_NAME_REGEX.match(token):
        return True
        
    # Exclude pure lower-case/digit/hyphen/underscore (catches dependency/package names like node-gyp-build)
    if re.match(r'^[a-z0-9\-_]+$', token):
        return True
        
    # Exclude UUIDs
    if UUID_REGEX.match(token):
        return True
        
    return False

def calculate_confidence(entropy: float, threshold: float) -> float:
    """Assigns a confidence score based on stricter entropy margins."""
    diff = entropy - threshold
    if diff >= 1.5:
        return 0.90
    elif diff >= 0.8:
        return 0.75
    elif diff >= 0.2:
        return 0.60
    return 0.0

def scan(text: str, file_path: str = "") -> List[Dict[str, Any]]:
    """
    Scans the provided text for high-entropy tokens indicating potential secrets.
    """
    findings = []
    if is_generated_entropy_source(file_path):
        return findings

    tokens = tokenize(text)
    seen_tokens = set()
    
    for token, start, end in tokens:
        # Strip trailing/leading punctuation that might get attached
        clean_token = token.strip('.,;()[]{}!<>?\'"')
        if not clean_token:
            continue
        
        # Suppress duplicate entropy findings from the same file
        if clean_token in seen_tokens:
            continue
        metrics.increment("entropy_candidates_checked")
            
        charset = determine_charset(clean_token)
        
        if is_false_positive(clean_token, charset):
            continue
            
        entropy = shannon_entropy(clean_token)
        base_threshold = THRESHOLDS[charset]
        
        # Context window (60 chars either side)
        context_start = max(0, start - 60)
        context_end = min(len(text), end + 60)
        context = text[context_start:context_end].replace('\n', ' ').strip()
        if is_build_artifact_token(clean_token, context):
            continue
        
        # Lower threshold if contextual keywords indicate a secret
        active_threshold = base_threshold
        context_lower = context.lower()
        has_context = any(kw in context_lower for kw in CONTEXT_KEYWORDS)
        if has_context:
            active_threshold -= CONTEXT_BOOST
            
        if entropy >= active_threshold:
            legacy_confidence = calculate_confidence(entropy, active_threshold)
            assignment_match = confidence_engine.has_assignment_pattern(context)
            final_score = confidence_engine.score(
                file_path=file_path,
                entropy_threshold_exceeded=True,
                context_keyword_match=has_context,
                assignment_pattern_match=assignment_match
            )
            if legacy_confidence > 0 and confidence_engine.should_publish(final_score):
                seen_tokens.add(clean_token)
                metrics.increment("entropy_accepted")
                findings.append({
                    "detector": "entropy",
                    "entity_type": "HIGH_ENTROPY_SECRET",
                    "category": "HIGH_SENSITIVE",
                    "raw_value": clean_token,
                    "context": context,
                    "confidence": confidence_engine.confidence_from_score(final_score),
                    "confidence_score": final_score,
                    "severity": "HIGH",
                    "requires_validation": False,
                    "start": start,  # Included for potential overlap resolution downstream
                    "end": end
                })
                
    return findings

class EntropyEngine:
    def score(self, findings, content):
        entropy_findings = scan(content)

        if not entropy_findings:
            return findings

        return findings + entropy_findings