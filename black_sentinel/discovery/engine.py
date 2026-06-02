import os
import queue
from pathlib import Path
from typing import List

from black_sentinel.discovery import walker, triage, decoders
from black_sentinel.discovery.parsers import text_parser, sqlite_parser
from black_sentinel.detection import regex_engine, entropy_engine
from black_sentinel.discovery.finding_generator import create_finding
from black_sentinel.core.event_system import bus
from black_sentinel.honeycomb import deployer

MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB
SUPPORTED_EXTENSIONS = {
    ".txt", ".env", ".json", ".yaml", ".yml", 
    ".log", ".config", ".sqlite", ".db", ".sqlite3"
}

def resolve_all_overlaps(findings: list) -> list:
    """
    Applies overlap suppression across both Regex and Entropy engines.
    """
    content_findings = [f for f in findings if "start" in f and "end" in f]
    path_findings = [f for f in findings if "start" not in f or "end" not in f]
    
    if not content_findings:
        return path_findings
        
    def get_priority(f):
        is_high = 1 if f.get("category") == "HIGH_SENSITIVE" else 0
        length = f.get("end", 0) - f.get("start", 0)
        return (f.get("confidence", 0), length, is_high)
        
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
            
    # Cleanup temporary start/end coordinates
    for f in kept_findings:
        f.pop("start", None)
        f.pop("end", None)
        
    return path_findings + kept_findings

def get_target_directories() -> List[str]:
    """Dynamically generates target paths across OS platforms."""
    home = str(Path.home())
    dirs = [
        home,
        os.path.join(home, "Desktop"),
        os.path.join(home, "Documents"),
        os.path.join(home, "Downloads"),
        os.path.join(home, "Projects")
    ]
    return [d for d in dirs if os.path.exists(d)]

def is_supported(file_path: str) -> bool:
    """Validates if file type is in scope for Phase 1 scanning."""
    ext = os.path.splitext(file_path)[1].lower()
    if not ext and os.path.basename(file_path).startswith('.'):
        ext = os.path.basename(file_path).lower()
    return ext in SUPPORTED_EXTENSIONS or os.path.basename(file_path).lower() == "config"

def start_tracking_engine():
    """
    Main orchestration loop for the discovery and detection pipeline.
    """
    print("[*] Tracking Engine: Initializing...")
    
    # 1. Load exclusion list (Honeytokens) to maintain coexistence boundaries
    try:
        manifest = deployer.get_manifest()
        excluded_paths = {os.path.normcase(os.path.abspath(t["path"])) for t in manifest.get("deployed_tokens", [])}
    except Exception:
        print("[!] Tracking Engine: Could not load Honeycomb manifest. Ensure deployer ran first.")
        excluded_paths = set()
    
    file_queue = queue.Queue()
    target_dirs = get_target_directories()
    
    print(f"[*] Tracking Engine: Walking {len(target_dirs)} root directories...")
    # 2. Walk directories
    for d in target_dirs:
        walker.walk(d, file_queue)
        
    print(f"[*] Tracking Engine: Enqueued {file_queue.qsize()} files for processing.")
    
    # 3. Process files
    processed = 0
    while not file_queue.empty():
        file_path = file_queue.get()
        norm_path = os.path.normcase(os.path.abspath(file_path))
        
        # Coexistence Rule: Exclude Honeytokens completely
        if norm_path in excluded_paths:
            continue
            
        # File Size Limit Rule
        try:
            if os.path.getsize(file_path) > MAX_FILE_SIZE:
                continue
        except OSError:
            continue
            
        # Extension Support Rule
        if not is_supported(file_path):
            continue
            
        # Classify Content Type
        parser_type = triage.classify_file(file_path)
        
        # Parse
        text_chunks = []
        if parser_type == 'text_parser':
            text_chunks.append(text_parser.parse(file_path))
        elif parser_type == 'sqlite_parser':
            text_chunks.append(sqlite_parser.parse(file_path))
        else:
            continue
            
        # Detect
        for chunk in text_chunks:
            if not chunk or not chunk.content:
                continue
                
            raw_findings = []
            
            # Step A: Scan raw plaintext content
            raw_findings.extend(regex_engine.scan(chunk.content, chunk.file_path))
            raw_findings.extend(entropy_engine.scan(chunk.content))
            
            # Step B: Decode content (Base64, Hex, URL, Gzip, ROT13) and scan variants
            decoded_variants = decoders.apply_all(chunk.content)
            for variant in decoded_variants:
                # pass empty file_path to avoid duplicate path-based credential store findings
                raw_findings.extend(regex_engine.scan(variant, "")) 
                raw_findings.extend(entropy_engine.scan(variant))
                
            # Step C: Overlap suppression across all engines for this specific chunk
            final_raw = resolve_all_overlaps(raw_findings)
            
            # Step D: Generate structured Finding objects and Publish
            for r in final_raw:
                finding_obj = create_finding(r, chunk.file_path)
                bus.publish("FINDING_DISCOVERED", finding_obj)
        
        processed += 1
        if processed % 100 == 0:
            print(f"[*] Tracking Engine: Processed {processed} files...")
            
    print("[*] Tracking Engine: Scan completed.")
