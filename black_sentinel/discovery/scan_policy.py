import os
import sqlite3
from pathlib import Path


SCAN = "scan"
EXCLUDED = "excluded"
UNSUPPORTED_EXTENSION = "unsupported_extension"


SUPPORTED_EXTENSIONS = {
    # Text-based
    ".txt", ".env", ".json", ".yaml", ".yml", ".config", ".csv", ".tsv", ".xml", ".html", ".htm", ".reg", ".ini", ".cfg", ".log",
    # Scripts/Code
    ".py", ".js", ".ts", ".java", ".go", ".rb", ".php", ".cs", ".cpp", ".c", ".h", ".sh", ".bash", ".zsh", ".ps1", ".bat",
    # Rich documents
    ".pdf", ".docx", ".doc", ".xlsx", ".xls", ".xlsm", ".xlsb", ".pptx", ".ppt", ".rtf",
    # Database
    ".sqlite", ".db", ".sqlite3", ".db3",
    # Archives
    ".zip", ".tar", ".gz", ".7z", ".rar",
}

BLACKLISTED_BASENAMES = {
    "node_modules", ".git", ".cache", ".next", ".turbo", ".venv", "venv",
    "pycache", "__pycache__", "dist", "build", "out", "coverage", "vendor",
    ".black_sentinel"
}

EXCLUDED_FILE_BASENAMES = {
    "build-manifest.json",
    "desktop.ini",
    "events.db",
    "events.db-journal",
    "events.db-shm",
    "events.db-wal",
    "findings.db",
    "findings.db-journal",
    "findings.db-shm",
    "findings.db-wal",
    "honeycomb_manifest.enc",
    "honeycomb_manifest.json",
    "manifest.enc",
    "next-font-manifest.json",
    "nls.keys.json",
    "nls.messages.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "scanner.db",
    "scanner.db-journal",
    "scanner.db-shm",
    "scanner.db-wal",
    "telemetry-core.json",
    "thirdpartynotices.txt",
    "thumbs.db",
    "yarn.lock",
    "package.json",
}

EXCLUDED_APP_BASENAMES = {
    "android studio.app",
    "chrome.app",
    "cursor.app",
    "firefox.app",
    "google chrome.app",
    "safari.app",
    "visual studio code.app",
    "xcode.app",
}

DOWNLOADS_DISTRIBUTION_EXTENSIONS = {
    ".app",
    ".dmg",
    ".pkg",
}

EXCLUDED_PATH_FRAGMENTS = (
    r"C:\Windows",
    r"C:\Program Files",
    r"C:\Program Files (x86)",
    r"C:\ProgramData",
    r"C:\ProgramData\Microsoft",
    r"C:\$Recycle.Bin",
    r"AppData\Local\Temp",
    r"AppData\Roaming\Code",
    r"AppData\Local\Google",
    ".local/share/opencode",
    ".config/opencode",
    "Library/Caches",
    "Library/Application Support",
    "Google/Chrome",
    "Chromium",
    "Microsoft/Edge",
    "LevelDB",
    "Extension Storage",
    "Code Cache",
    "Cache_Data",
)


def _normalize(path: str) -> str:
    return os.path.normcase(os.path.abspath(path)).replace("\\", "/").lower()


def _basename(path: str) -> str:
    return os.path.basename(path).lower()


def _path_components(path: str) -> list:
    return [part for part in _normalize(path).split("/") if part]


def _is_app_bundle_path(path: str) -> bool:
    components = _path_components(path)
    return any(part.endswith(".app") for part in components)


def _is_downloads_distribution_path(path: str) -> bool:
    components = _path_components(path)
    if "downloads" not in components:
        return False
    return any(
        os.path.splitext(part)[1] in DOWNLOADS_DISTRIBUTION_EXTENSIONS
        for part in components
    )


def _is_black_sentinel_sqlite(path: str) -> bool:
    ext = os.path.splitext(path)[1].lower()
    if ext not in {".db", ".sqlite", ".sqlite3"}:
        return False

    conn = None
    try:
        uri = Path(path).resolve().as_uri() + "?mode=ro"
        conn = sqlite3.connect(uri, uri=True)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {row[0] for row in cursor.fetchall()}
    except Exception:
        return False
    finally:
        if conn is not None:
            conn.close()

    return {"findings", "honeycomb_alerts"}.issubset(tables)


def _is_excluded_path(path: str) -> bool:
    norm = _normalize(path)
    basename = _basename(norm)
    components = _path_components(path)

    if basename.startswith("$") or basename == "system volume information":
        return True

    if any(component in BLACKLISTED_BASENAMES for component in components):
        return True

    if basename in EXCLUDED_FILE_BASENAMES:
        return True

    if basename in EXCLUDED_APP_BASENAMES:
        return True

    if _is_app_bundle_path(path):
        return True

    if _is_downloads_distribution_path(path):
        return True

    for fragment in EXCLUDED_PATH_FRAGMENTS:
        if fragment.replace("\\", "/").lower() in norm:
            return True

    return False


def should_scan_directory(path: str) -> bool:
    return not _is_excluded_path(path)


def get_file_scan_decision(path: str) -> str:
    if _is_excluded_path(path):
        return EXCLUDED

    basename = _basename(path)
    if _is_black_sentinel_sqlite(path):
        return EXCLUDED

    ext = os.path.splitext(path)[1].lower()
    if not ext and basename.startswith("."):
        ext = basename

    if ext in SUPPORTED_EXTENSIONS or basename == "config" or not ext:
        return SCAN

    return UNSUPPORTED_EXTENSION


def should_scan_file(path: str) -> bool:
    return get_file_scan_decision(path) == SCAN

class ScanPolicy:

    def should_scan_file(self, path):
        return should_scan_file(str(path))

    def should_scan_directory(self, path):
        return should_scan_directory(str(path))

    def should_scan(self, path):
        return should_scan_file(str(path))