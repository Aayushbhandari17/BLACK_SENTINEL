COUNTERS = {
    "files_scanned": 0,
    "files_skipped": 0,
    "files_excluded": 0,
    "regex_candidates_checked": 0,
    "regex_validated": 0,
    "entropy_candidates_checked": 0,
    "entropy_accepted": 0,
    "final_findings_published": 0,
}


def increment(name: str, amount: int = 1):
    COUNTERS[name] = COUNTERS.get(name, 0) + amount


def print_summary():
    print("\n--- Black Sentinel Measurement Summary ---")
    print(f"Files scanned={COUNTERS.get('files_scanned', 0)}")
    print(f"Files skipped={COUNTERS.get('files_skipped', 0)}")
    print(f"Files excluded={COUNTERS.get('files_excluded', 0)}")
    print(f"Regex candidates checked={COUNTERS.get('regex_candidates_checked', 0)}")
    print(f"Regex validated={COUNTERS.get('regex_validated', 0)}")
    print(f"Entropy candidates checked={COUNTERS.get('entropy_candidates_checked', 0)}")
    print(f"Entropy accepted={COUNTERS.get('entropy_accepted', 0)}")
    print(f"Final findings published={COUNTERS.get('final_findings_published', 0)}")
