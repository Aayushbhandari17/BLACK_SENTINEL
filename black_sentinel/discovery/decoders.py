import re
import base64
import urllib.parse
import codecs
import gzip
from typing import List

BASE64_PATTERN = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')
HEX_PATTERN = re.compile(r'(?:[0-9a-fA-F]{2}){10,}')
GZIP_MAGIC = b'\x1f\x8b'

def is_printable(text: str) -> bool:
    if not text: return False
    # Check if mostly printable
    printable = sum(1 for c in text if c.isprintable() or c in '\n\r\t')
    return (printable / len(text)) > 0.9

def base64_decode(text: str) -> List[str]:
    results = []
    for match in BASE64_PATTERN.findall(text):
        try:
            # Pad if needed
            padded = match + '=' * (-len(match) % 4)
            decoded = base64.b64decode(padded).decode('utf-8')
            if is_printable(decoded):
                results.append(decoded)
        except Exception:
            pass
    return results

def hex_decode(text: str) -> List[str]:
    results = []
    for match in HEX_PATTERN.findall(text):
        try:
            decoded = bytes.fromhex(match).decode('utf-8')
            if is_printable(decoded):
                results.append(decoded)
        except Exception:
            pass
    return results

def url_decode(text: str) -> List[str]:
    decoded = urllib.parse.unquote(text)
    if decoded != text:
        return [decoded]
    return []

def rot13_decode(text: str) -> List[str]:
    return [codecs.decode(text, 'rot_13')]

def gzip_decode(text: str) -> List[str]:
    results = []
    # Convert text to bytes to search for gzip magic
    try:
        raw_bytes = text.encode('utf-8')
    except Exception:
        raw_bytes = text.encode('latin-1', errors='ignore')
        
    idx = 0
    while True:
        idx = raw_bytes.find(GZIP_MAGIC, idx)
        if idx == -1:
            break
        try:
            decompressed = gzip.decompress(raw_bytes[idx:])
            decoded = decompressed.decode('utf-8')
            if is_printable(decoded):
                results.append(decoded)
        except Exception:
            pass
        idx += 1
    return results

def apply_all(text: str) -> List[str]:
    """Runs all decoders and returns a list of unique decoded text blobs."""
    variants = []
    variants.extend(base64_decode(text))
    variants.extend(hex_decode(text))
    variants.extend(url_decode(text))
    variants.extend(rot13_decode(text))
    variants.extend(gzip_decode(text))
    return list(set(variants))
