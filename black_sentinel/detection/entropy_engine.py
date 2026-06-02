import math
import re
from typing import List, Dict, Any
from collections import Counter

# Entropy thresholds based on character set (Increased to reduce FPs)
THRESHOLDS = {
    'hex': 4.0,
    'base64': 4.8,
    'alphanumeric': 4.2
}

CONTEXT_KEYWORDS = ['key', 'secret', 'token', 'password']
CONTEXT_BOOST = 0.3

# Regular expressions for token filtering
HEX_REGEX = re.compile(r'^[0-9a-fA-F]+$')
BASE64_REGEX = re.compile(r'^[a-zA-Z0-9+/]+={0,2}$')
UUID_REGEX = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.IGNORECASE)
FILE_PATH_REGEX = re.compile(r'^([a-zA-Z]:\\|\/|\\)(?:[\w.\-]+[\\\/])+[\w.\-]+$')
URL_REGEX = re.compile(r'^(https?://|git://|ssh://|github\.com|www\.)', re.IGNORECASE)
EXTENSION_REGEX = re.compile(r'\.(js|ts|json|md|html|css|txt|yml|yaml|xml|csv|png|jpg|jpeg|gif|svg|exe|dll|so|dylib|zip|tar|gz)$', re.IGNORECASE)
PACKAGE_NAME_REGEX = re.compile(r'^@?[a-z0-9\-_]+/[a-z0-9\-_.]+$', re.IGNORECASE)

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

def is_false_positive(token: str, charset: str) -> bool:
    """Filters out common non-secret strings (URLs, packages, extensions, UUIDs)."""
    if len(token) < 16 or len(token) > 80:
        return True
    
    # Require a stronger mixture of uppercase, lowercase, and numbers
    has_upper = any(c.isupper() for c in token)
    has_lower = any(c.islower() for c in token)
    has_digit = any(c.isdigit() for c in token)
    
    if charset == 'hex':
        # Hex strings must have both digits and letters to be considered mixed enough
        if not (has_digit and (has_upper or has_lower)):
            return True
    else:
        # Base64 and Alphanumeric must have at least 2 out of 3 character classes
        classes_present = sum([has_upper, has_lower, has_digit])
        if classes_present < 2:
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

def scan(text: str) -> List[Dict[str, Any]]:
    """
    Scans the provided text for high-entropy tokens indicating potential secrets.
    """
    findings = []
    tokens = tokenize(text)
    seen_tokens = set()
    
    for token, start, end in tokens:
        # Strip trailing/leading punctuation that might get attached
        clean_token = token.strip('.,;()[]{}!<>?\'"')
        
        # Suppress duplicate entropy findings from the same file
        if clean_token in seen_tokens:
            continue
            
        charset = determine_charset(clean_token)
        
        if is_false_positive(clean_token, charset):
            continue
            
        entropy = shannon_entropy(clean_token)
        base_threshold = THRESHOLDS[charset]
        
        # Context window (60 chars either side)
        context_start = max(0, start - 60)
        context_end = min(len(text), end + 60)
        context = text[context_start:context_end].replace('\n', ' ').strip()
        
        # Lower threshold if contextual keywords indicate a secret
        active_threshold = base_threshold
        context_lower = context.lower()
        if any(kw in context_lower for kw in CONTEXT_KEYWORDS):
            active_threshold -= CONTEXT_BOOST
            
        if entropy >= active_threshold:
            confidence = calculate_confidence(entropy, active_threshold)
            if confidence > 0:
                seen_tokens.add(clean_token)
                findings.append({
                    "detector": "entropy",
                    "entity_type": "HIGH_ENTROPY_SECRET",
                    "category": "HIGH_SENSITIVE",
                    "raw_value": clean_token,
                    "context": context,
                    "confidence": confidence,
                    "severity": "HIGH",
                    "requires_validation": False,
                    "start": start,  # Included for potential overlap resolution downstream
                    "end": end
                })
                
    return findings
