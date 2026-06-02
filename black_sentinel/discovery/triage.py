import os

MAGIC_BYTES = {
    b'\x4D\x5A': 'SKIP',
    b'\x25\x50\x44\x46': 'pdf_parser',
    b'\x50\x4B\x03\x04': 'zip_family',
    b'\x53\x51\x4C\x69': 'sqlite_parser',
    b'\xFF\xD8\xFF': 'exif_parser',
    b'\x89\x50\x4E\x47': 'exif_parser',
    b'\x52\x61\x72\x21': 'archive_parser',
    b'\x37\x7A\xBC\xAF': 'archive_parser',
    b'\x1F\x8B': 'archive_parser',
    b'-----BEG': 'text_parser', # '-----BEGIN' truncated to 8 bytes is '-----BEG'
}

def is_text_like(content: bytes) -> bool:
    # Check if bytes are mostly printable ASCII
    if not content:
        return True
    
    # Allow whitespace and typical printable chars
    # If more than 30% of the bytes are outside this range, consider it binary
    non_text = sum(1 for b in content if b < 32 and b not in (9, 10, 13))
    return (non_text / len(content)) < 0.3

def classify_file(file_path: str) -> str:
    try:
        with open(file_path, 'rb') as f:
            header = f.read(8)
            
            # Check magic bytes
            for magic, parser in MAGIC_BYTES.items():
                if header.startswith(magic):
                    if parser == 'zip_family':
                        # Distinguish between zip and docx/xlsx based on extension for simplicity
                        ext = os.path.splitext(file_path)[1].lower()
                        if ext in ['.docx', '.xlsx', '.pptx']:
                            return 'office_parser'
                        return 'archive_parser'
                    return parser
            
            # Fallback
            f.seek(0)
            fallback_header = f.read(512)
            if is_text_like(fallback_header):
                return 'text_parser'
            return 'SKIP'
    except Exception:
        return 'SKIP'
