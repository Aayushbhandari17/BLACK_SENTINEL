import os
import queue

BLACKLISTED_BASENAMES = {
    "node_modules", ".git", ".cache", ".venv", "venv", "pycache", "__pycache__"
}

BLACKLISTED_PATHS = [
    r"C:\Windows",
    r"C:\Program Files",
    r"C:\Program Files (x86)",
    r"C:\ProgramData\Microsoft",
    r"C:\$Recycle.Bin",
    ".local/share/opencode",
    ".config/opencode",
    "Library/Caches"
]

def is_blacklisted(dir_path: str) -> bool:
    norm = os.path.normcase(os.path.abspath(dir_path))
    basename = os.path.basename(norm).lower()
    
    if basename.startswith("$") or basename == "system volume information":
        return True
        
    if basename in BLACKLISTED_BASENAMES:
        return True
        
    norm_lower = norm.replace('\\', '/').lower()
    for b in BLACKLISTED_PATHS:
        b_lower = b.replace('\\', '/').lower()
        if b_lower in norm_lower:
            return True
            
    return False

def walk(root_dir: str, file_queue: queue.Queue):
    for root, dirs, files in os.walk(root_dir):
        # Filter directories in place to avoid descending into blacklisted ones
        dirs[:] = [d for d in dirs if not is_blacklisted(os.path.join(root, d))]
        
        for file in files:
            # Re-check file just in case
            full_path = os.path.abspath(os.path.join(root, file))
            if not is_blacklisted(full_path):
                file_queue.put(full_path)
