"""
black_sentinel/discovery/engine.py
===================================
Master Orchestrator — Black Sentinel Secret-Detection Platform
Principal Cybersecurity Architect Edition

Scan pipeline:
    Walker → ArchiveParser → ParserRegistry → DecoderEngine
          → RegexEngine → FindingGenerator → ValidationEngine
          → EntropyEngine → ConfidenceEngine → TriageEngine
          → EventSystem → Final Results

Public surface
--------------
    ScanEngine          – primary entry point
    ScanResult          – per-file result dataclass
    ScanSummary         – aggregate run summary dataclass
    ParserRegistry      – auto-built extension → parser map
"""

from __future__ import annotations

import hashlib
import logging
import os
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# Core infrastructure
# ---------------------------------------------------------------------------
from black_sentinel.core.event_store import (
    init_db,
    save_finding,
    save_honeycomb_alert,
    handle_finding_event,
    handle_honeycomb_event,
    EventStore
)
from black_sentinel.core.event_system import EventBus, bus

# ---------------------------------------------------------------------------
# Detection engines
# ---------------------------------------------------------------------------
from black_sentinel.detection.confidence_engine import ConfidenceEngine
from black_sentinel.detection.entropy_engine import EntropyEngine
from black_sentinel.detection.metrics import DetectionMetrics
from black_sentinel.detection.regex_engine import RegexEngine

# ---------------------------------------------------------------------------
# Discovery: parsers
# ---------------------------------------------------------------------------
from black_sentinel.discovery.parsers.archive_parser import ArchiveParser
from black_sentinel.discovery.parsers.config_parser import ConfigParser
from black_sentinel.discovery.parsers.docx_parser import DOCXParser
from black_sentinel.discovery.parsers.ocr_parser import OCRParser
from black_sentinel.discovery.parsers.office_parser import OfficeParser
from black_sentinel.discovery.parsers.pdf_parser import PDFParser
from black_sentinel.discovery.parsers.sqlite_parser import SQLiteParser
from black_sentinel.discovery.parsers.text_parser import TextParser
from black_sentinel.discovery.parsers.xlsx_parsers import XLSXParser
from black_sentinel.discovery.parsers.rtf_parser import RTFParser

# ---------------------------------------------------------------------------
# Discovery: pipeline components
# ---------------------------------------------------------------------------
from black_sentinel.discovery.decoders import DecoderEngine
from black_sentinel.discovery.finding_generator import FindingGenerator
from black_sentinel.discovery.scan_policy import ScanPolicy
from black_sentinel.discovery.triage import TriageEngine
from black_sentinel.discovery.validators import ValidationEngine
from black_sentinel.discovery.walker import Walker

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logger = logging.getLogger("black_sentinel.discovery.engine")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
MAX_ARCHIVE_DEPTH: int = 10
MAX_FILE_SIZE_BYTES: int = 512 * 1024 * 1024  # 512 MiB
MAX_WORKER_THREADS: int = min(32, (os.cpu_count() or 4) * 2)

# ---------------------------------------------------------------------------
# Event topic constants
# ---------------------------------------------------------------------------
EVT_SCAN_STARTED: str = "scan_started"
EVT_FILE_PROCESSED: str = "file_processed"
EVT_FINDING_DETECTED: str = "finding_detected"
EVT_SCAN_COMPLETED: str = "scan_completed"


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class ScanResult:
    """Per-file result produced by the orchestrator pipeline."""

    file_path: str
    file_type: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    risk_score: float = 0.0
    severity: str = "info"
    confidence: float = 0.0

    # Internal bookkeeping — excluded from public serialisation helpers
    _scan_duration_ms: float = field(default=0.0, repr=False)
    _archive_depth: int = field(default=0, repr=False)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file_path": self.file_path,
            "file_type": self.file_type,
            "metadata": self.metadata,
            "findings": self.findings,
            "risk_score": self.risk_score,
            "severity": self.severity,
            "confidence": self.confidence,
        }


@dataclass
class ScanSummary:
    """Aggregate summary returned at the end of a full scan run."""

    scan_id: str
    root_path: str
    total_files: int = 0
    total_findings: int = 0
    total_duration_ms: float = 0.0
    results: List[ScanResult] = field(default_factory=list)
    errors: List[Dict[str, str]] = field(default_factory=list)
    metrics: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Parser Registry
# ---------------------------------------------------------------------------

class ParserRegistry:
    """
    Auto-built extension → parser instance map.

    Design
    ------
    * Single instance per ScanEngine (injected).
    * Parsers are instantiated once and reused (thread-safe read-only after init).
    * Falls back to TextParser for unknown plain-text extensions.
    * Falls back to None (skip) for truly binary/unknown content.
    """

    # Canonical extension sets — all lowercase, no leading dot.
    _PDF_EXTS: frozenset = frozenset({"pdf"})
    _DOCX_EXTS: frozenset = frozenset({"docx", "doc"})
    _XLSX_EXTS: frozenset = frozenset({"xlsx", "xls", "xlsm", "xlsb"})
    _RTF_EXTS: frozenset = frozenset({"rtf"})
    _OFFICE_EXTS: frozenset = frozenset({"pptx", "ppt", "odt", "ods", "odp"})
    _SQLITE_EXTS: frozenset = frozenset({"db", "sqlite", "sqlite3", "db3"})
    _ARCHIVE_EXTS: frozenset = frozenset(
        {"zip", "tar", "gz", "bz2", "xz", "7z", "rar", "tgz", "tar.gz", "tar.bz2"}
    )
    _OCR_EXTS: frozenset = frozenset({"png", "jpg", "jpeg", "tiff", "tif", "bmp", "gif", "webp"})
    _CONFIG_EXTS: frozenset = frozenset(
        {
            "yaml", "yml", "toml", "ini", "cfg", "conf", "env",
            "json", "properties", "hcl", "tf", "config",
        }
    )
    _TEXT_EXTS: frozenset = frozenset(
        {
            "txt", "md", "rst", "log", "csv", "tsv", "xml", "html", "htm",
            "py", "js", "ts", "java", "go", "rb", "php", "cs", "cpp", "c",
            "h", "sh", "bash", "zsh", "fish", "ps1", "psm1", "psd1",
            "sql", "graphql", "proto", "rs", "kt", "swift", "dart",
            "reg", "bat",
        }
    )

    def __init__(self) -> None:
        self._pdf = PDFParser()
        self._docx = DOCXParser()
        self._xlsx = XLSXParser()
        self._office = OfficeParser()
        self._sqlite = SQLiteParser()
        self._archive = ArchiveParser()
        self._ocr = OCRParser()
        self._config = ConfigParser()
        self._text = TextParser()
        self._rtf = RTFParser()

        # Build fast lookup: ext → parser
        self._map: Dict[str, Any] = {}
        self._register(self._PDF_EXTS, self._pdf)
        self._register(self._DOCX_EXTS, self._docx)
        self._register(self._XLSX_EXTS, self._xlsx)
        self._register(self._RTF_EXTS, self._rtf)
        self._register(self._OFFICE_EXTS, self._office)
        self._register(self._SQLITE_EXTS, self._sqlite)
        self._register(self._ARCHIVE_EXTS, self._archive)
        self._register(self._OCR_EXTS, self._ocr)
        self._register(self._CONFIG_EXTS, self._config)
        self._register(self._TEXT_EXTS, self._text)

        logger.debug(
            "ParserRegistry initialised with %d extension mappings.", len(self._map)
        )

    def _register(self, extensions: frozenset, parser: Any) -> None:
        for ext in extensions:
            self._map[ext] = parser

    def resolve(self, file_path: Path) -> Optional[Any]:
        """Return the appropriate parser for *file_path*, or ``None``."""
        suffix = file_path.suffix.lstrip(".").lower()
        if not suffix and file_path.name.startswith("."):
            suffix = file_path.name.lstrip(".").lower()
        return self._map.get(suffix)

    def is_archive(self, file_path: Path) -> bool:
        suffix = file_path.suffix.lstrip(".").lower()
        return suffix in self._ARCHIVE_EXTS

    @property
    def archive_parser(self) -> ArchiveParser:
        return self._archive


# ---------------------------------------------------------------------------
# ScanEngine — master orchestrator
# ---------------------------------------------------------------------------

class ScanEngine:
    """
    Master orchestrator for Black Sentinel.

    Responsibilities
    ----------------
    1. Accept a root path and a ScanPolicy.
    2. Walk the filesystem via Walker.
    3. Dispatch each file through the full detection pipeline.
    4. Publish lifecycle events via EventSystem.
    5. Return a ScanSummary.

    Thread Safety
    -------------
    * ScanEngine itself is not reentrant — create one instance per scan run.
    * Internal pipeline components are shared across worker threads; all
      stateful mutations are protected by _result_lock.
    """

    def __init__(
        self,
        *,
        policy: Optional[ScanPolicy] = None,
        event_system: Optional[EventBus] = None,
        registry: Optional[ParserRegistry] = None,
        max_workers: int = MAX_WORKER_THREADS,
        max_archive_depth: int = MAX_ARCHIVE_DEPTH,
        max_file_size: int = MAX_FILE_SIZE_BYTES,
    ) -> None:
        # --- dependency injection with sensible defaults ---
        self._policy = policy or ScanPolicy()
        self._event_system = event_system or bus
        self._event_store = EventStore()
        self._registry = registry or ParserRegistry()

        # --- detection pipeline ---
        self._decoder = DecoderEngine()
        self._regex = RegexEngine()
        self._finding_gen = FindingGenerator()
        self._validator = ValidationEngine()
        self._entropy = EntropyEngine()
        self._confidence = ConfidenceEngine()
        self._triage = TriageEngine()
        self._metrics = DetectionMetrics()
        self._walker = Walker(policy=self._policy)

        # --- operational limits ---
        self._max_workers = max(1, max_workers)
        self._max_archive_depth = max_archive_depth
        self._max_file_size = max_file_size

        # --- run-time state ---
        self._result_lock = threading.Lock()
        self._seen_hashes: Set[str] = set()          # duplicate-content guard
        self._seen_paths: Set[str] = set()           # duplicate-path guard

        logger.info(
            "ScanEngine ready — workers=%d, max_depth=%d, max_file=%dMiB",
            self._max_workers,
            self._max_archive_depth,
            self._max_file_size // (1024 * 1024),
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan(self, root_path: str | Path) -> ScanSummary:
        """
        Execute a full scan of *root_path* and return a :class:`ScanSummary`.

        Parameters
        ----------
        root_path:
            Directory or single file to scan.

        Returns
        -------
        ScanSummary
            Aggregate result containing all per-file findings.
        """
        root = Path(root_path).resolve()
        scan_id = str(uuid.uuid4())
        start_ts = time.monotonic()

        summary = ScanSummary(scan_id=scan_id, root_path=str(root))

        logger.info("Scan [%s] started — root: %s", scan_id, root)
        self._publish(EVT_SCAN_STARTED, {"scan_id": scan_id, "root_path": str(root)})

        try:
            file_paths: List[Path] = list(self._walker.walk(root))
            summary.total_files = len(file_paths)
            logger.info("Walker discovered %d files.", summary.total_files)

            results, errors = self._process_files_parallel(file_paths, scan_id)

            with self._result_lock:
                summary.results = results
                summary.errors = errors
                summary.total_findings = sum(len(r.findings) for r in results)

        except Exception as exc:  # pylint: disable=broad-except
            logger.exception("Fatal error during scan [%s]: %s", scan_id, exc)
            summary.errors.append({"type": "fatal", "message": str(exc)})

        finally:
            summary.total_duration_ms = (time.monotonic() - start_ts) * 1_000
            summary.metrics = self._metrics.snapshot()

            self._publish(
                EVT_SCAN_COMPLETED,
                {
                    "scan_id": scan_id,
                    "total_files": summary.total_files,
                    "total_findings": summary.total_findings,
                    "duration_ms": summary.total_duration_ms,
                },
            )
            logger.info(
                "Scan [%s] completed — %d files, %d findings, %.1f ms",
                scan_id,
                summary.total_files,
                summary.total_findings,
                summary.total_duration_ms,
            )

        return summary

    # ------------------------------------------------------------------
    # Parallel file processing
    # ------------------------------------------------------------------

    def _process_files_parallel(
        self, file_paths: List[Path], scan_id: str
    ) -> Tuple[List[ScanResult], List[Dict[str, str]]]:
        results: List[ScanResult] = []
        errors: List[Dict[str, str]] = []

        with ThreadPoolExecutor(max_workers=self._max_workers) as executor:
            future_map = {
                executor.submit(self._process_single_file, fp, scan_id, 0): fp
                for fp in file_paths
            }
            for future in as_completed(future_map):
                fp = future_map[future]
                try:
                    result = future.result()
                    if result is not None:
                        results.append(result)
                except Exception as exc:  # pylint: disable=broad-except
                    logger.warning("Error processing %s: %s", fp, exc)
                    errors.append({"file": str(fp), "error": str(exc)})

        return results, errors

    # ------------------------------------------------------------------
    # Single-file pipeline
    # ------------------------------------------------------------------

    def _process_single_file(
        self,
        file_path: Path,
        scan_id: str,
        archive_depth: int,
    ) -> Optional[ScanResult]:
        """
        Full detection pipeline for one file.  Returns ``None`` when the
        file is skipped (size, duplicate, policy exclusion, etc.).
        """
        path_str = str(file_path)

        # ---- guard: path deduplication ----
        with self._result_lock:
            if path_str in self._seen_paths:
                logger.debug("Skipping duplicate path: %s", path_str)
                return None
            self._seen_paths.add(path_str)

        # ---- guard: file size ----
        try:
            file_size = file_path.stat().st_size
        except OSError as exc:
            logger.warning("Cannot stat %s: %s", path_str, exc)
            return None

        if file_size > self._max_file_size:
            logger.warning(
                "Skipping oversized file (%d bytes): %s", file_size, path_str
            )
            return None

        # ---- guard: policy exclusion ----
        if not self._policy.should_scan(file_path):
            logger.debug("Policy excluded: %s", path_str)
            return None

        t0 = time.monotonic()
        file_type = self._detect_file_type(file_path)

        result = ScanResult(
            file_path=path_str,
            file_type=file_type,
            metadata={"size_bytes": file_size, "archive_depth": archive_depth},
            _archive_depth=archive_depth,
        )

        try:
            # ---- STEP 1: archive expansion ----
            if self._registry.is_archive(file_path):
                self._handle_archive(file_path, scan_id, archive_depth, result)
                # Archives produce child results; the archive itself gets a
                # summary result with aggregated findings.
            else:
                self._run_detection_pipeline(file_path, result)

        except Exception as exc:  # pylint: disable=broad-except
            logger.exception("Pipeline error for %s: %s", path_str, exc)
            result.metadata["pipeline_error"] = str(exc)

        result._scan_duration_ms = (time.monotonic() - t0) * 1_000
        result.metadata["scan_duration_ms"] = round(result._scan_duration_ms, 2)

        # ---- publish file_processed ----
        self._publish(
            EVT_FILE_PROCESSED,
            {
                "scan_id": scan_id,
                "file_path": path_str,
                "file_type": file_type,
                "findings_count": len(result.findings),
                "risk_score": result.risk_score,
            },
        )

        self._metrics.record_file(result)
        return result

    # ------------------------------------------------------------------
    # Detection pipeline (non-archive files)
    # ------------------------------------------------------------------

    def _run_detection_pipeline(self, file_path: Path, result: ScanResult) -> None:
        """
        Execute the ordered detection stages for a single content file.

        Walker output → ParserRegistry → DecoderEngine → RegexEngine
        → FindingGenerator → ValidationEngine → EntropyEngine
        → ConfidenceEngine → TriageEngine → EventSystem
        """
        # ---- STEP 2: parse content via registry ----
        raw_content = self._parse_file(file_path, result)
        if not raw_content:
            return

        # ---- guard: content-hash deduplication ----
        content_hash = self._hash_content(raw_content)
        with self._result_lock:
            if content_hash in self._seen_hashes:
                logger.debug("Skipping duplicate content: %s", file_path)
                result.metadata["duplicate_of_hash"] = content_hash
                return
            self._seen_hashes.add(content_hash)
        result.metadata["content_hash"] = content_hash

        # ---- STEP 3: decode all layers ----
        decoded_layers: List[str] = self._decoder.decode_all(raw_content)
        all_content: List[str] = [raw_content] + decoded_layers
        result.metadata["decoded_layers"] = len(decoded_layers)

        # ---- STEP 4+5: regex detection + finding generation ----
        raw_findings: List[Dict[str, Any]] = []
        for layer_idx, content_layer in enumerate(all_content):
            regex_matches = self._regex.scan(content_layer, file_path=str(file_path))
            if regex_matches:
                layer_findings = self._finding_gen.generate(
                    matches=regex_matches,
                    file_path=str(file_path),
                    content=content_layer,
                    layer_index=layer_idx,
                )
                raw_findings.extend(layer_findings)

        if not raw_findings:
            return

        # ---- STEP 6: validation ----
        validated_findings = self._validator.validate(raw_findings)
        if not validated_findings:
            return

        # ---- STEP 7: entropy scoring ----
        entropy_findings = self._entropy.score(validated_findings, raw_content)

        # ---- STEP 8: confidence scoring ----
        confidence_findings = self._confidence.score(
            entropy_findings,
            file_path=str(file_path),
            content=raw_content,
        )

        # ---- STEP 9: triage ----
        triaged: Dict[str, Any] = self._triage.triage(
            confidence_findings,
            file_path=str(file_path),
            metadata=result.metadata,
        )

        result.findings = triaged.get("findings", confidence_findings)
        result.risk_score = triaged.get("risk_score", 0.0)
        result.severity = triaged.get("severity", "info")
        result.confidence = triaged.get("confidence", 0.0)

        # ---- STEP 10: emit per-finding events ----
        for finding in result.findings:
            self._publish(
                EVT_FINDING_DETECTED,
                {
                    "file_path": str(file_path),
                    "finding_type": finding.get("type", "unknown"),
                    "severity": finding.get("severity", result.severity),
                    "confidence": finding.get("confidence", result.confidence),
                    "finding_data": finding,
                },
            )

    # ------------------------------------------------------------------
    # Archive handling
    # ------------------------------------------------------------------

    def _handle_archive(
        self,
        archive_path: Path,
        scan_id: str,
        current_depth: int,
        parent_result: ScanResult,
    ) -> None:
        """
        Recursively expand an archive and scan its members.

        Depth protection: stops at MAX_ARCHIVE_DEPTH.
        Duplicate protection: content-hash deduplication per archive member.
        """
        if current_depth >= self._max_archive_depth:
            logger.warning(
                "Max archive depth (%d) reached at: %s",
                self._max_archive_depth,
                archive_path,
            )
            parent_result.metadata["archive_depth_exceeded"] = True
            return

        logger.debug(
            "Expanding archive (depth=%d): %s", current_depth, archive_path
        )

        try:
            members: Iterator[Tuple[str, bytes]] = (
                self._registry.archive_parser.extract_members(archive_path)
            )
        except Exception as exc:  # pylint: disable=broad-except
            logger.warning("Cannot expand archive %s: %s", archive_path, exc)
            parent_result.metadata["archive_error"] = str(exc)
            return

        child_findings: List[Dict[str, Any]] = []

        for member_name, member_bytes in members:
            member_path = Path(member_name)
            member_hash = self._hash_bytes(member_bytes)

            with self._result_lock:
                if member_hash in self._seen_hashes:
                    logger.debug(
                        "Skipping duplicate archive member: %s", member_name
                    )
                    continue
                self._seen_hashes.add(member_hash)

            # Write member to a temp-like in-memory path for type detection
            virtual_path = archive_path / member_name  # logical path only

            # Is the member itself an archive? → recurse
            if self._registry.is_archive(member_path):
                import tempfile
                import io

                # Materialise member to a real temp file for recursive parsing
                with tempfile.NamedTemporaryFile(
                    suffix=member_path.suffix, delete=False
                ) as tmp:
                    tmp.write(member_bytes)
                    tmp_path = Path(tmp.name)

                try:
                    child_result = ScanResult(
                        file_path=str(virtual_path),
                        file_type=self._detect_file_type(member_path),
                        metadata={"archive_member": member_name, "parent": str(archive_path)},
                        _archive_depth=current_depth + 1,
                    )
                    self._handle_archive(
                        tmp_path, scan_id, current_depth + 1, child_result
                    )
                    child_findings.extend(child_result.findings)
                finally:
                    try:
                        tmp_path.unlink(missing_ok=True)
                    except OSError:
                        pass
            else:
                # Parse member bytes directly
                member_content = self._parse_bytes(member_bytes, member_path)
                if member_content:
                    synthetic = ScanResult(
                        file_path=str(virtual_path),
                        file_type=self._detect_file_type(member_path),
                        metadata={
                            "archive_member": member_name,
                            "parent": str(archive_path),
                            "content_hash": member_hash,
                        },
                        _archive_depth=current_depth + 1,
                    )
                    # Feed into detection pipeline via a lightweight inline call
                    self._run_detection_pipeline_on_content(
                        member_content, member_path, synthetic
                    )
                    child_findings.extend(synthetic.findings)

                    self._publish(
                        EVT_FILE_PROCESSED,
                        {
                            "scan_id": scan_id,
                            "file_path": str(virtual_path),
                            "file_type": synthetic.file_type,
                            "findings_count": len(synthetic.findings),
                            "archive_depth": current_depth + 1,
                        },
                    )

        # Roll up child findings into the parent archive result
        parent_result.findings.extend(child_findings)
        parent_result.metadata["archive_members_scanned"] = True
        logger.debug(
            "Archive %s: %d child findings surfaced.", archive_path, len(child_findings)
        )

    # ------------------------------------------------------------------
    # Detection pipeline variant — operates on pre-parsed string content
    # ------------------------------------------------------------------

    def _run_detection_pipeline_on_content(
        self,
        content: str,
        logical_path: Path,
        result: ScanResult,
    ) -> None:
        """Same pipeline as _run_detection_pipeline but accepts pre-parsed content."""
        decoded_layers: List[str] = self._decoder.decode_all(content)
        all_layers: List[str] = [content] + decoded_layers

        raw_findings: List[Dict[str, Any]] = []
        for layer_idx, layer in enumerate(all_layers):
            matches = self._regex.scan(layer, file_path=str(logical_path))
            if matches:
                findings = self._finding_gen.generate(
                    matches=matches,
                    file_path=str(logical_path),
                    content=layer,
                    layer_index=layer_idx,
                )
                raw_findings.extend(findings)

        if not raw_findings:
            return

        validated = self._validator.validate(raw_findings)
        if not validated:
            return

        entropy_scored = self._entropy.score(validated, content)
        confidence_scored = self._confidence.score(
            entropy_scored, file_path=str(logical_path), content=content
        )
        triaged = self._triage.triage(
            confidence_scored,
            file_path=str(logical_path),
            metadata=result.metadata,
        )

        result.findings = triaged.get("findings", confidence_scored)
        result.risk_score = triaged.get("risk_score", 0.0)
        result.severity = triaged.get("severity", "info")
        result.confidence = triaged.get("confidence", 0.0)

        for finding in result.findings:
            self._publish(
                EVT_FINDING_DETECTED,
                {
                    "file_path": str(logical_path),
                    "finding_type": finding.get("type", "unknown"),
                    "severity": finding.get("severity", result.severity),
                    "confidence": finding.get("confidence", result.confidence),
                    "finding_data": finding,
                },
            )

    # ------------------------------------------------------------------
    # Parsing helpers
    # ------------------------------------------------------------------

    def _parse_file(self, file_path: Path, result: ScanResult) -> Optional[str]:
        """Resolve parser from registry and extract text content."""
        parser = self._registry.resolve(file_path)
        if parser is None:
            logger.debug("No parser for: %s — skipping.", file_path)
            return None

        try:
            content: str = parser.parse(file_path)
            if not content or not content.strip():
                return None
            result.metadata["parser"] = type(parser).__name__
            return content
        except Exception as exc:  # pylint: disable=broad-except
            logger.warning("Parser %s failed on %s: %s", type(parser).__name__, file_path, exc)
            result.metadata["parse_error"] = str(exc)
            return None

    def _parse_bytes(self, data: bytes, logical_path: Path) -> Optional[str]:
        """Parse raw bytes using the appropriate parser for *logical_path*."""
        parser = self._registry.resolve(logical_path)
        if parser is None:
            # Fallback: attempt UTF-8 decode
            try:
                return data.decode("utf-8", errors="replace")
            except Exception:
                return None

        try:
            if hasattr(parser, "parse_bytes"):
                return parser.parse_bytes(data)
            # Fallback: decode as UTF-8
            return data.decode("utf-8", errors="replace")
        except Exception as exc:  # pylint: disable=broad-except
            logger.debug("parse_bytes failed for %s: %s", logical_path, exc)
            return None

    # ------------------------------------------------------------------
    # Utility helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _detect_file_type(file_path: Path) -> str:
        return file_path.suffix.lstrip(".").lower() or "unknown"

    @staticmethod
    def _hash_content(content: str) -> str:
        return hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest()

    @staticmethod
    def _hash_bytes(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    def _publish(self, topic: str, payload: Dict[str, Any]) -> None:
        """Fire-and-forget event publication; errors are logged, not raised."""
        try:
            self._event_system.publish(topic, payload)
            self._event_store.store(topic, payload)
        except Exception as exc:  # pylint: disable=broad-except
            logger.debug("Event publish failed [%s]: %s", topic, exc)
            
# ------------------------------------------------------------------
# Legacy compatibility wrapper
# ------------------------------------------------------------------

def start_tracking_engine():
    """
    Backwards compatibility for old main.py
    """
    engine = ScanEngine()
    import os
    target = r"C:\ThisPCTest" if os.path.exists(r"C:\ThisPCTest") else "."
    return engine.scan(target)