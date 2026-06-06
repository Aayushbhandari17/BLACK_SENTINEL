"""
archive_engine.py
=================
Production-ready Archive Engine for ZIP, RAR, 7Z, TAR, and GZ formats.

Security features:
  - Path traversal prevention
  - Archive bomb protection (ratio + file count + depth)
  - File size limits
  - Extraction depth limits
  - Secure temp directory management
  - SHA-256 hashing of extracted files
  - Thread-safe design

Author : Senior Cybersecurity Engineer
License: MIT
"""

from __future__ import annotations

import gzip
import hashlib
import logging
import os
import shutil
import stat
import tarfile
import tempfile
import threading
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set

# ---------------------------------------------------------------------------
# Optional third-party dependencies (graceful degradation)
# ---------------------------------------------------------------------------
try:
    import rarfile  # pip install rarfile
    _RAR_AVAILABLE = True
except ImportError:
    _RAR_AVAILABLE = False

try:
    import py7zr  # pip install py7zr
    _7Z_AVAILABLE = True
except ImportError:
    _7Z_AVAILABLE = False

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logger = logging.getLogger("archive_engine")
if not logger.handlers:
    _handler = logging.StreamHandler()
    _handler.setFormatter(
        logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s (%(threadName)s): %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S",
        )
    )
    logger.addHandler(_handler)
logger.setLevel(logging.INFO)

# ---------------------------------------------------------------------------
# Configuration / limits
# ---------------------------------------------------------------------------
@dataclass
class EngineConfig:
    """Tunable safety limits and behavioural flags."""

    # Maximum on-disk size (bytes) of a single extracted file  [1 GB]
    max_file_size: int = 1 * 1024 ** 3

    # Maximum *total* on-disk size of all extracted files      [5 GB]
    max_total_size: int = 5 * 1024 ** 3

    # Largest ratio (compressed → uncompressed) before abort   [100x]
    max_compression_ratio: float = 100.0

    # Maximum number of files extracted across all recursion   [10 000]
    max_file_count: int = 10_000

    # Maximum nested archive depth                             [5]
    max_depth: int = 5

    # Follow symbolic links inside archives?                   [False]
    allow_symlinks: bool = False

    # Delete temp directories automatically on cleanup         [True]
    auto_cleanup: bool = True


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------
@dataclass
class ExtractedFile:
    """Metadata for a single successfully extracted file."""

    path: Path                          # Absolute path on disk
    sha256: str                         # Hex digest
    size: int                           # Bytes
    depth: int                          # Nesting depth where it was found
    source_archive: Path                # Archive it came from


@dataclass
class ExtractionResult:
    """Aggregated result returned by extract() / extract_recursive()."""

    files: List[ExtractedFile] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    skipped: List[str] = field(default_factory=list)
    temp_dirs: List[Path] = field(default_factory=list)   # managed by engine


# ---------------------------------------------------------------------------
# Custom exceptions
# ---------------------------------------------------------------------------
class ArchiveEngineError(Exception):
    """Base class for all engine errors."""


class ArchiveBombError(ArchiveEngineError):
    """Raised when archive-bomb heuristics trigger."""


class PathTraversalError(ArchiveEngineError):
    """Raised when a member path escapes the extraction root."""


class UnsupportedFormatError(ArchiveEngineError):
    """Raised for formats without an available backend."""


class ExtractionDepthError(ArchiveEngineError):
    """Raised when max_depth is exceeded."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
_ARCHIVE_EXTENSIONS: Set[str] = {
    ".zip", ".rar", ".7z",
    ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2",
    ".tar.xz", ".txz", ".tar.zst", ".gz",
}


def _sha256(path: Path) -> str:
    """Return the SHA-256 hex digest of *path*."""
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _safe_join(base: Path, member: str) -> Path:
    """
    Resolve *member* relative to *base*.

    Raises PathTraversalError if the resolved path escapes *base*.
    """
    # Normalise: strip leading slashes, resolve ".." components
    member_clean = os.path.normpath(member).lstrip("/\\")
    if member_clean.startswith(".."):
        raise PathTraversalError(f"Traversal attempt: {member!r}")
    target = (base / member_clean).resolve()
    try:
        target.relative_to(base.resolve())
    except ValueError:
        raise PathTraversalError(
            f"Member {member!r} resolves outside extraction root {base}"
        )
    return target


def _remove_readonly(func, path, _exc_info):
    """Error handler for shutil.rmtree on Windows read-only files."""
    os.chmod(path, stat.S_IWRITE)
    func(path)


# ---------------------------------------------------------------------------
# ArchiveEngine
# ---------------------------------------------------------------------------
class ArchiveEngine:
    """
    Thread-safe archive extraction engine.

    Usage
    -----
    engine = ArchiveEngine()
    result = engine.extract("/path/to/archive.zip")
    for ef in result.files:
        print(ef.path, ef.sha256)
    engine.cleanup()
    """

    def __init__(self, config: Optional[EngineConfig] = None) -> None:
        self.config = config or EngineConfig()
        self._lock = threading.Lock()
        # Shared mutable counters — always access under self._lock
        self._total_bytes: int = 0
        self._total_files: int = 0
        # All temp dirs created by this engine instance
        self._temp_dirs: List[Path] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def extract(
        self,
        archive_path: str | Path,
        dest_dir: Optional[str | Path] = None,
    ) -> ExtractionResult:
        """
        Extract *archive_path* (non-recursively) into *dest_dir*.

        If *dest_dir* is None a secure temp directory is created and
        registered for later cleanup.

        Returns an ExtractionResult with metadata for every extracted file.
        """
        archive_path = Path(archive_path).resolve()
        if not archive_path.is_file():
            raise FileNotFoundError(f"Archive not found: {archive_path}")

        if dest_dir is None:
            dest_dir = self._make_temp_dir()
        else:
            dest_dir = Path(dest_dir).resolve()
            dest_dir.mkdir(parents=True, exist_ok=True)

        result = ExtractionResult(temp_dirs=list(self._temp_dirs))
        logger.info("Extracting %s → %s", archive_path, dest_dir)

        try:
            extracted_paths = self._dispatch_extract(archive_path, dest_dir, result)
        except ArchiveEngineError:
            raise
        except Exception as exc:
            msg = f"Unexpected error extracting {archive_path}: {exc}"
            logger.exception(msg)
            result.errors.append(msg)
            return result

        for p in extracted_paths:
            self._register_file(p, archive_path, depth=0, result=result)

        return result

    def extract_recursive(
        self,
        archive_path: str | Path,
        dest_dir: Optional[str | Path] = None,
        *,
        _depth: int = 0,
        _result: Optional[ExtractionResult] = None,
    ) -> ExtractionResult:
        """
        Extract *archive_path* and recursively extract any nested archives.

        Depth, file count, and size limits are enforced across the entire
        recursion tree.
        """
        archive_path = Path(archive_path).resolve()

        if _depth == 0:
            # Reset shared counters for a fresh top-level call
            with self._lock:
                self._total_bytes = 0
                self._total_files = 0

        if _depth > self.config.max_depth:
            raise ExtractionDepthError(
                f"Max extraction depth {self.config.max_depth} exceeded "
                f"at {archive_path}"
            )

        if dest_dir is None:
            dest_dir = self._make_temp_dir()
        else:
            dest_dir = Path(dest_dir).resolve()
            dest_dir.mkdir(parents=True, exist_ok=True)

        if _result is None:
            _result = ExtractionResult(temp_dirs=list(self._temp_dirs))

        logger.info("[depth=%d] Recursive extract: %s", _depth, archive_path)

        try:
            extracted_paths = self._dispatch_extract(archive_path, dest_dir, _result)
        except ArchiveEngineError:
            raise
        except Exception as exc:
            msg = f"[depth={_depth}] Error extracting {archive_path}: {exc}"
            logger.exception(msg)
            _result.errors.append(msg)
            return _result

        for p in extracted_paths:
            if self.is_archive(p):
                nested_dest = self._make_temp_dir()
                self.extract_recursive(
                    p,
                    nested_dest,
                    _depth=_depth + 1,
                    _result=_result,
                )
            else:
                self._register_file(p, archive_path, depth=_depth, result=_result)

        return _result

    def is_archive(self, path: str | Path) -> bool:
        """Return True if *path* looks like a supported archive."""
        path = Path(path)
        name_lower = path.name.lower()

        # Check compound extensions first
        for ext in (".tar.gz", ".tar.bz2", ".tar.xz", ".tar.zst"):
            if name_lower.endswith(ext):
                return True

        suffix = path.suffix.lower()
        if suffix in _ARCHIVE_EXTENSIONS:
            # For .rar / .7z, only say True if backend is available
            if suffix == ".rar" and not _RAR_AVAILABLE:
                return False
            if suffix == ".7z" and not _7Z_AVAILABLE:
                return False
            return True
        return False

    def enumerate_contents(
        self, archive_path: str | Path
    ) -> List[Dict[str, object]]:
        """
        List the members of *archive_path* without extracting.

        Returns a list of dicts with keys: name, size, is_dir, is_symlink.
        """
        archive_path = Path(archive_path).resolve()
        suffix = archive_path.suffix.lower()
        name_lower = archive_path.name.lower()
        entries: List[Dict[str, object]] = []

        try:
            if name_lower.endswith((".tar.gz", ".tgz", ".tar.bz2", ".tbz2",
                                    ".tar.xz", ".txz", ".tar.zst")) or suffix == ".tar":
                with tarfile.open(archive_path) as tf:
                    for m in tf.getmembers():
                        entries.append({
                            "name": m.name,
                            "size": m.size,
                            "is_dir": m.isdir(),
                            "is_symlink": m.issym() or m.islnk(),
                        })

            elif suffix == ".zip":
                with zipfile.ZipFile(archive_path) as zf:
                    for info in zf.infolist():
                        entries.append({
                            "name": info.filename,
                            "size": info.file_size,
                            "is_dir": info.filename.endswith("/"),
                            "is_symlink": False,
                        })

            elif suffix == ".gz":
                entries.append({
                    "name": archive_path.stem,
                    "size": -1,
                    "is_dir": False,
                    "is_symlink": False,
                })

            elif suffix == ".rar":
                if not _RAR_AVAILABLE:
                    raise UnsupportedFormatError("rarfile not installed")
                with rarfile.RarFile(archive_path) as rf:
                    for info in rf.infolist():
                        entries.append({
                            "name": info.filename,
                            "size": info.file_size,
                            "is_dir": info.is_dir(),
                            "is_symlink": False,
                        })

            elif suffix == ".7z":
                if not _7Z_AVAILABLE:
                    raise UnsupportedFormatError("py7zr not installed")
                with py7zr.SevenZipFile(archive_path, mode="r") as sz:
                    for fname, info in sz.list():
                        entries.append({
                            "name": fname,
                            "size": info.uncompressed if info.uncompressed else 0,
                            "is_dir": info.is_directory,
                            "is_symlink": False,
                        })

            else:
                raise UnsupportedFormatError(f"Unsupported format: {suffix}")

        except (ArchiveEngineError, UnsupportedFormatError):
            raise
        except Exception as exc:
            raise ArchiveEngineError(
                f"Cannot enumerate {archive_path}: {exc}"
            ) from exc

        return entries

    def cleanup(self) -> None:
        """
        Remove all temporary directories created by this engine instance.

        Safe to call multiple times.
        """
        with self._lock:
            dirs = list(self._temp_dirs)
            self._temp_dirs.clear()

        for d in dirs:
            if d.exists():
                try:
                    shutil.rmtree(d, onerror=_remove_readonly)
                    logger.debug("Removed temp dir: %s", d)
                except Exception as exc:
                    logger.warning("Could not remove %s: %s", d, exc)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _make_temp_dir(self) -> Path:
        td = Path(tempfile.mkdtemp(prefix="archive_engine_"))
        with self._lock:
            self._temp_dirs.append(td)
        logger.debug("Created temp dir: %s", td)
        return td

    def _dispatch_extract(
        self,
        archive_path: Path,
        dest_dir: Path,
        result: ExtractionResult,
    ) -> List[Path]:
        """
        Route to the correct backend and return a flat list of extracted Paths.
        """
        name_lower = archive_path.name.lower()
        suffix = archive_path.suffix.lower()

        if name_lower.endswith((".tar.gz", ".tgz", ".tar.bz2", ".tbz2",
                                 ".tar.xz", ".txz", ".tar.zst")) or suffix == ".tar":
            return self._extract_tar(archive_path, dest_dir, result)
        if suffix == ".zip":
            return self._extract_zip(archive_path, dest_dir, result)
        if suffix == ".gz":
            return self._extract_gz(archive_path, dest_dir, result)
        if suffix == ".rar":
            if not _RAR_AVAILABLE:
                raise UnsupportedFormatError(
                    "RAR support requires 'rarfile': pip install rarfile"
                )
            return self._extract_rar(archive_path, dest_dir, result)
        if suffix == ".7z":
            if not _7Z_AVAILABLE:
                raise UnsupportedFormatError(
                    "7Z support requires 'py7zr': pip install py7zr"
                )
            return self._extract_7z(archive_path, dest_dir, result)

        raise UnsupportedFormatError(f"No backend for: {archive_path.name}")

    # --- ZIP ---

    def _extract_zip(
        self,
        archive_path: Path,
        dest_dir: Path,
        result: ExtractionResult,
    ) -> List[Path]:
        extracted: List[Path] = []
        archive_size = archive_path.stat().st_size

        with zipfile.ZipFile(archive_path) as zf:
            members = zf.infolist()
            self._check_bomb_zip(members, archive_size)

            for info in members:
                if info.filename.endswith("/"):
                    continue  # directory entry

                target = _safe_join(dest_dir, info.filename)

                # Symlink check
                is_symlink = (info.external_attr >> 16) & 0xFFFF == 0xA1ED
                if is_symlink and not self.config.allow_symlinks:
                    msg = f"ZIP symlink skipped: {info.filename}"
                    logger.warning(msg)
                    result.skipped.append(msg)
                    continue

                self._check_file_size(info.file_size, info.filename)
                target.parent.mkdir(parents=True, exist_ok=True)

                with zf.open(info) as src, target.open("wb") as dst:
                    written = self._stream_copy(src, dst, info.filename)

                self._update_counters(written)
                extracted.append(target)
                logger.debug("ZIP extracted: %s (%d bytes)", target.name, written)

        return extracted

    # --- TAR (all sub-formats) ---

    def _extract_tar(
        self,
        archive_path: Path,
        dest_dir: Path,
        result: ExtractionResult,
    ) -> List[Path]:
        extracted: List[Path] = []

        with tarfile.open(archive_path) as tf:
            members = tf.getmembers()
            self._check_bomb_tar(members, archive_path)

            for m in members:
                if m.isdir():
                    continue

                if (m.issym() or m.islnk()) and not self.config.allow_symlinks:
                    msg = f"TAR symlink skipped: {m.name}"
                    logger.warning(msg)
                    result.skipped.append(msg)
                    continue

                # Block dangerous member names
                target = _safe_join(dest_dir, m.name)
                self._check_file_size(m.size, m.name)
                target.parent.mkdir(parents=True, exist_ok=True)

                fobj = tf.extractfile(m)
                if fobj is None:
                    continue

                with target.open("wb") as dst:
                    written = self._stream_copy(fobj, dst, m.name)

                self._update_counters(written)
                extracted.append(target)
                logger.debug("TAR extracted: %s (%d bytes)", target.name, written)

        return extracted

    # --- GZ (single file, not tar) ---

    def _extract_gz(
        self,
        archive_path: Path,
        dest_dir: Path,
        result: ExtractionResult,
    ) -> List[Path]:
        out_name = archive_path.stem  # strip .gz
        target = _safe_join(dest_dir, out_name)
        target.parent.mkdir(parents=True, exist_ok=True)

        with gzip.open(archive_path, "rb") as src, target.open("wb") as dst:
            written = self._stream_copy(src, dst, out_name)

        self._update_counters(written)
        logger.debug("GZ extracted: %s (%d bytes)", target.name, written)
        return [target]

    # --- RAR ---

    def _extract_rar(
        self,
        archive_path: Path,
        dest_dir: Path,
        result: ExtractionResult,
    ) -> List[Path]:
        extracted: List[Path] = []

        with rarfile.RarFile(archive_path) as rf:
            members = rf.infolist()
            self._check_bomb_generic(
                sum(m.file_size for m in members if not m.is_dir()),
                archive_path.stat().st_size,
                len(members),
                "RAR",
            )

            for info in members:
                if info.is_dir():
                    continue
                target = _safe_join(dest_dir, info.filename)
                self._check_file_size(info.file_size, info.filename)
                target.parent.mkdir(parents=True, exist_ok=True)

                with rf.open(info) as src, target.open("wb") as dst:
                    written = self._stream_copy(src, dst, info.filename)

                self._update_counters(written)
                extracted.append(target)
                logger.debug("RAR extracted: %s (%d bytes)", target.name, written)

        return extracted

    # --- 7Z ---

    def _extract_7z(
        self,
        archive_path: Path,
        dest_dir: Path,
        result: ExtractionResult,
    ) -> List[Path]:
        extracted: List[Path] = []

        with py7zr.SevenZipFile(archive_path, mode="r") as sz:
            entries = sz.list()
            total_uncompressed = sum(
                (e.uncompressed or 0) for e in entries if not e.is_directory
            )
            self._check_bomb_generic(
                total_uncompressed,
                archive_path.stat().st_size,
                len(entries),
                "7Z",
            )

            # py7zr extracts everything at once; we filter afterwards
            sz.extractall(path=dest_dir)

        for e in entries:
            if e.is_directory:
                continue
            target = _safe_join(dest_dir, e.filename)
            if not target.exists():
                continue
            size = target.stat().st_size
            self._check_file_size(size, e.filename)
            self._update_counters(size)
            extracted.append(target)
            logger.debug("7Z extracted: %s (%d bytes)", target.name, size)

        return extracted

    # ------------------------------------------------------------------
    # Streaming copy with live size guard
    # ------------------------------------------------------------------

    def _stream_copy(self, src, dst, name: str) -> int:
        """Copy *src* → *dst* in chunks, enforcing per-file size limit."""
        written = 0
        chunk_size = 1 << 20  # 1 MiB
        limit = self.config.max_file_size

        while True:
            chunk = src.read(chunk_size)
            if not chunk:
                break
            written += len(chunk)
            if written > limit:
                raise ArchiveBombError(
                    f"File {name!r} exceeds max_file_size "
                    f"({limit / 1024**2:.0f} MiB)"
                )
            dst.write(chunk)

        return written

    # ------------------------------------------------------------------
    # Bomb detection helpers
    # ------------------------------------------------------------------

    def _check_bomb_zip(
        self,
        members: List[zipfile.ZipInfo],
        compressed_size: int,
    ) -> None:
        uncompressed = sum(m.file_size for m in members if not m.filename.endswith("/"))
        self._check_bomb_generic(
            uncompressed, compressed_size, len(members), "ZIP"
        )

    def _check_bomb_tar(
        self,
        members: List[tarfile.TarInfo],
        archive_path: Path,
    ) -> None:
        uncompressed = sum(m.size for m in members if m.isfile())
        compressed_size = archive_path.stat().st_size
        self._check_bomb_generic(
            uncompressed, compressed_size, len(members), "TAR"
        )

    def _check_bomb_generic(
        self,
        uncompressed: int,
        compressed_size: int,
        member_count: int,
        fmt: str,
    ) -> None:
        cfg = self.config

        if member_count > cfg.max_file_count:
            raise ArchiveBombError(
                f"{fmt}: member count {member_count} exceeds limit "
                f"{cfg.max_file_count}"
            )

        if uncompressed > cfg.max_total_size:
            raise ArchiveBombError(
                f"{fmt}: uncompressed size {uncompressed / 1024**3:.2f} GiB "
                f"exceeds max_total_size {cfg.max_total_size / 1024**3:.2f} GiB"
            )

        if compressed_size > 0:
            ratio = uncompressed / compressed_size
            if ratio > cfg.max_compression_ratio:
                raise ArchiveBombError(
                    f"{fmt}: compression ratio {ratio:.1f}x exceeds "
                    f"limit {cfg.max_compression_ratio}x (possible zip-bomb)"
                )

    # ------------------------------------------------------------------
    # Counter updates (thread-safe)
    # ------------------------------------------------------------------

    def _update_counters(self, size: int) -> None:
        with self._lock:
            self._total_bytes += size
            self._total_files += 1

            if self._total_bytes > self.config.max_total_size:
                raise ArchiveBombError(
                    f"Cumulative extraction size "
                    f"{self._total_bytes / 1024**3:.2f} GiB "
                    f"exceeds max_total_size"
                )
            if self._total_files > self.config.max_file_count:
                raise ArchiveBombError(
                    f"Cumulative file count {self._total_files} "
                    f"exceeds max_file_count"
                )

    def _check_file_size(self, declared_size: int, name: str) -> None:
        if declared_size > self.config.max_file_size:
            raise ArchiveBombError(
                f"Member {name!r} declared size "
                f"{declared_size / 1024**2:.1f} MiB exceeds "
                f"max_file_size {self.config.max_file_size / 1024**2:.0f} MiB"
            )

    # ------------------------------------------------------------------
    # File registration
    # ------------------------------------------------------------------

    def _register_file(
        self,
        path: Path,
        source_archive: Path,
        depth: int,
        result: ExtractionResult,
    ) -> None:
        try:
            size = path.stat().st_size
            digest = _sha256(path)
            result.files.append(
                ExtractedFile(
                    path=path,
                    sha256=digest,
                    size=size,
                    depth=depth,
                    source_archive=source_archive,
                )
            )
            logger.debug(
                "Registered: %s  sha256=%s  size=%d",
                path.name, digest[:12] + "…", size,
            )
        except Exception as exc:
            msg = f"Could not register {path}: {exc}"
            logger.warning(msg)
            result.errors.append(msg)

    # ------------------------------------------------------------------
    # Context manager support
    # ------------------------------------------------------------------

    def __enter__(self) -> "ArchiveEngine":
        return self

    def __exit__(self, *_) -> None:
        if self.config.auto_cleanup:
            self.cleanup()

    # ------------------------------------------------------------------
    # Repr
    # ------------------------------------------------------------------

    def __repr__(self) -> str:
        return (
            f"ArchiveEngine("
            f"max_depth={self.config.max_depth}, "
            f"max_file_size={self.config.max_file_size // 1024**2}MiB, "
            f"max_total_size={self.config.max_total_size // 1024**3}GiB)"
        )


# ---------------------------------------------------------------------------
# CLI smoke-test (python archive_engine.py <archive> [dest])
# ---------------------------------------------------------------------------
def _main() -> None:
    import sys

    logging.basicConfig(level=logging.DEBUG)

    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <archive> [dest_dir]")
        sys.exit(1)

    archive = sys.argv[1]
    dest = sys.argv[2] if len(sys.argv) > 2 else None

    with ArchiveEngine() as engine:
        print(f"\nEnumerating contents of: {archive}")
        try:
            contents = engine.enumerate_contents(archive)
            for entry in contents[:20]:
                print(f"  {entry['name']}  ({entry['size']} bytes)")
            if len(contents) > 20:
                print(f"  … and {len(contents) - 20} more entries")
        except ArchiveEngineError as exc:
            print(f"  [WARN] enumerate failed: {exc}")

        print(f"\nRecursive extraction → {dest or '<temp>'}")
        result = engine.extract_recursive(archive, dest)

        print(f"\n{'='*60}")
        print(f"Files extracted : {len(result.files)}")
        print(f"Errors          : {len(result.errors)}")
        print(f"Skipped         : {len(result.skipped)}")
        print()
        for ef in result.files:
            print(f"  [{ef.depth}] {ef.path}  sha256={ef.sha256[:16]}…")

        for err in result.errors:
            print(f"  ERROR: {err}")


if __name__ == "__main__":
    _main()
    
class ArchiveParser:
    def extract_members(self, path):
        import zipfile
        import tarfile
        from pathlib import Path
        import os
        
        path = Path(path)
        suffix = path.suffix.lower()
        
        if suffix == ".zip" or zipfile.is_zipfile(path):
            with zipfile.ZipFile(path) as zf:
                for info in zf.infolist():
                    if not info.filename.endswith("/"):
                        try:
                            yield info.filename, zf.read(info)
                        except Exception:
                            pass
            return
            
        if suffix in (".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz"):
            try:
                with tarfile.open(path) as tf:
                    for member in tf.getmembers():
                        if member.isfile():
                            f = tf.extractfile(member)
                            if f:
                                yield member.name, f.read()
            except Exception:
                pass
            return
            
        engine = ArchiveEngine()
        try:
            res = engine.extract_recursive(path)
            for ef in res.files:
                try:
                    rel_path_str = str(ef.path)
                    for td in res.temp_dirs:
                        td_str = str(td)
                        if rel_path_str.startswith(td_str):
                            rel_path_str = os.path.relpath(rel_path_str, td_str)
                            break
                    yield rel_path_str, ef.path.read_bytes()
                except Exception:
                    pass
        finally:
            engine.cleanup()