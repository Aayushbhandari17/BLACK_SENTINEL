import os
import queue
from pathlib import Path
from typing import List

from black_sentinel.discovery import walker, triage, decoders
from black_sentinel.discovery.scan_policy import (
    EXCLUDED,
    SCAN,
    get_file_scan_decision,
    should_scan_file,
)
from black_sentinel.discovery.parsers import text_parser, sqlite_parser
from black_sentinel.detection import regex_engine, entropy_engine
from black_sentinel.discovery.finding_generator import create_finding
from black_sentinel.core.event_system import bus
from black_sentinel.honeycomb import deployer

MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB

def _increment(stats: dict, key: str, amount: int = 1):
    stats[key] = stats.get(key, 0) + amount

def _record_file_skip(stats: dict, decision: str):
    if decision == EXCLUDED:
        _increment(stats, "files_skipped_by_exclusion_policy")
    else:
        _increment(stats, "files_skipped_by_extension")

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

def dedupe_roots(paths: List[str]) -> List[str]:
    """Drops nested roots when a parent root is already present."""
    existing = [os.path.abspath(p) for p in paths if os.path.exists(p)]
    deduped = []

    for path in sorted(existing, key=len):
        nested = False
        for kept in deduped:
            try:
                nested = os.path.commonpath([path, kept]) == kept
            except ValueError:
                nested = False
            if nested:
                break
        if not nested:
            deduped.append(path)

    return deduped

def get_target_directories() -> List[str]:
    """Dynamically generates target paths across OS platforms."""
    home = str(Path.home())
    dirs = [
        os.path.join(home, "Desktop"),
        os.path.join(home, "Documents"),
        os.path.join(home, "Downloads")
    ]
    return dedupe_roots(dirs)

def scan_regex(text: str, file_path: str):
    if not should_scan_file(file_path):
        return []
    return regex_engine.scan(text, file_path)

def scan_entropy(text: str, file_path: str):
    if not should_scan_file(file_path):
        return []
    return entropy_engine.scan(text)

def decode_content(text: str, file_path: str):
    if not should_scan_file(file_path):
        return []
    return decoders.apply_all(text)

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
    stats = {
        "files_discovered": 0,
        "files_skipped_by_extension": 0,
        "files_skipped_by_exclusion_policy": 0,
        "directories_skipped_by_exclusion_policy": 0,
        "files_scanned": 0,
        "findings_generated": 0,
    }
    target_dirs = get_target_directories()
    
    print(f"[*] Tracking Engine: Walking {len(target_dirs)} root directories...")
    # 2. Walk directories
    for d in target_dirs:
        walker.walk(d, file_queue, stats)
        
    print(f"[*] Tracking Engine: Enqueued {file_queue.qsize()} files for processing.")
    
    # 3. Process files
    while not file_queue.empty():
        file_path = file_queue.get()
        norm_path = os.path.normcase(os.path.abspath(file_path))
        
        # Coexistence Rule: Exclude Honeytokens completely
        if norm_path in excluded_paths:
            _increment(stats, "files_skipped_by_exclusion_policy")
            continue

        # Shared file scan policy must pass before parsing or detection.
        decision = get_file_scan_decision(file_path)
        if decision != SCAN:
            _record_file_skip(stats, decision)
            continue
            
        # File Size Limit Rule
        try:
            if os.path.getsize(file_path) > MAX_FILE_SIZE:
                _increment(stats, "files_skipped_by_exclusion_policy")
                continue
        except OSError:
            _increment(stats, "files_skipped_by_exclusion_policy")
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
            _increment(stats, "files_skipped_by_exclusion_policy")
            continue

        _increment(stats, "files_scanned")
            
        # Detect
        for chunk in text_chunks:
            if not chunk or not chunk.content:
                continue
            if not should_scan_file(chunk.file_path):
                continue
                
            raw_findings = []
            
            # Step A: Scan raw plaintext content
            raw_findings.extend(scan_regex(chunk.content, chunk.file_path))
            raw_findings.extend(scan_entropy(chunk.content, chunk.file_path))
            
            # Step B: Decode content (Base64, Hex, URL, Gzip, ROT13) and scan variants
            decoded_variants = decode_content(chunk.content, chunk.file_path)
            for variant in decoded_variants:
                raw_findings.extend(scan_regex(variant, chunk.file_path))
                raw_findings.extend(scan_entropy(variant, chunk.file_path))
                
            # Step C: Overlap suppression across all engines for this specific chunk
            final_raw = resolve_all_overlaps(raw_findings)
            
            # Step D: Generate structured Finding objects and Publish
            for r in final_raw:
                finding_obj = create_finding(r, chunk.file_path)
                bus.publish("FINDING_DISCOVERED", finding_obj)
                _increment(stats, "findings_generated")
        
        if stats["files_scanned"] % 100 == 0:
            print(f"[*] Tracking Engine: Processed {stats['files_scanned']} files...")
            
    print("[*] Tracking Engine: Scan completed.")
    print(
        "[*] Tracking Engine: Startup statistics: "
        f"files discovered={stats['files_discovered']}, "
        f"files skipped by extension={stats['files_skipped_by_extension']}, "
        f"files skipped by exclusion policy={stats['files_skipped_by_exclusion_policy']}, "
        f"files scanned={stats['files_scanned']}, "
        f"findings generated={stats['findings_generated']}"
    )
