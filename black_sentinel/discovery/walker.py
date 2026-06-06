import os
import queue
from typing import Optional

from black_sentinel.discovery.scan_policy import (
    EXCLUDED,
    SCAN,
    get_file_scan_decision,
    should_scan_directory,
)
from black_sentinel.detection import metrics


def _increment(stats: Optional[dict], key: str):
    if stats is not None:
        stats[key] = stats.get(key, 0) + 1


def _record_file_decision(stats: Optional[dict], decision: str):
    if decision == EXCLUDED:
        _increment(stats, "files_skipped_by_exclusion_policy")
        metrics.increment("files_excluded")
    else:
        _increment(stats, "files_skipped_by_extension")
        metrics.increment("files_skipped")


def walk(root_dir: str, file_queue: queue.Queue, stats: Optional[dict] = None):
    for root, dirs, files in os.walk(root_dir):
        kept_dirs = []
        for directory in dirs:
            full_dir = os.path.join(root, directory)
            if should_scan_directory(full_dir):
                kept_dirs.append(directory)
            else:
                _increment(stats, "directories_skipped_by_exclusion_policy")
        dirs[:] = kept_dirs
        
        for file in files:
            _increment(stats, "files_discovered")
            full_path = os.path.abspath(os.path.join(root, file))
            decision = get_file_scan_decision(full_path)
            if decision == SCAN:
                file_queue.put(full_path)
            else:
                _record_file_decision(stats, decision)
                
                
from queue import Queue

class Walker:

    def __init__(self, policy=None):
        self.policy = policy

    def walk(self, root):
        q = Queue()

        walk(root, q)

        while not q.empty():
            from pathlib import Path
            yield Path(q.get())