from __future__ import annotations

import hashlib
import os
import threading
from pathlib import Path
from typing import Callable, Iterable

from .definitions import Definitions
from .models import ScanFinding, ScanSummary, utc_now_iso


ProgressCallback = Callable[[str, int, int], None]


class LocalScanner:
    def __init__(
        self,
        definitions: Definitions,
        max_file_size_mb: int = 64,
        enable_heuristics: bool = True,
    ) -> None:
        self.definitions = definitions
        self.max_file_size = max(1, int(max_file_size_mb)) * 1024 * 1024
        self.enable_heuristics = enable_heuristics
        self._hash_lookup: dict[str, dict[str, object]] = {}
        for signature in definitions.hash_signatures:
            self._hash_lookup.setdefault(signature.kind, {})[signature.value] = signature
        self._patterns = [signature for signature in definitions.content_signatures if signature.value]
        self._max_pattern_length = max((len(sig.value.encode("utf-8")) for sig in self._patterns), default=0)

    def scan_path(
        self,
        root: Path,
        cancel_event: threading.Event | None = None,
        progress: ProgressCallback | None = None,
    ) -> ScanSummary:
        started_at = utc_now_iso()
        summary = ScanSummary(started_at=started_at, completed_at=started_at, root=str(root))
        root = root.expanduser()
        files = list(self._iter_files(root, summary))
        total = len(files)

        for index, path in enumerate(files, start=1):
            if cancel_event and cancel_event.is_set():
                summary.cancelled = True
                break
            if progress:
                progress(str(path), index, total)
            try:
                findings = self.scan_file(path)
                summary.findings.extend(findings)
                summary.files_scanned += 1
                summary.bytes_scanned += path.stat().st_size
            except PermissionError:
                summary.files_skipped += 1
                summary.errors.append(f"Permission denied: {path}")
            except OSError as exc:
                summary.files_skipped += 1
                summary.errors.append(f"{path}: {exc}")

        summary.completed_at = utc_now_iso()
        return summary

    def scan_file(self, path: Path) -> list[ScanFinding]:
        stat = path.stat()
        if stat.st_size > self.max_file_size:
            return []

        hashers = {
            "md5": hashlib.md5(usedforsecurity=False),
            "sha1": hashlib.sha1(usedforsecurity=False),
            "sha256": hashlib.sha256(),
        }
        pattern_matches: dict[str, ScanFinding] = {}
        tail = b""
        encoded_patterns = [(sig, sig.value.encode("utf-8", errors="ignore")) for sig in self._patterns]

        with path.open("rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                for hasher in hashers.values():
                    hasher.update(chunk)
                if encoded_patterns:
                    searchable = tail + chunk
                    for signature, pattern in encoded_patterns:
                        if pattern and pattern in searchable and signature.id not in pattern_matches:
                            pattern_matches[signature.id] = ScanFinding(
                                path=str(path),
                                threat_name=signature.name,
                                severity=signature.severity,
                                reason=f"Content signature match: {signature.id}",
                                sha256="",
                                size=stat.st_size,
                            )
                    if self._max_pattern_length > 1:
                        tail = searchable[-(self._max_pattern_length - 1) :]

        file_hashes = {algorithm: hasher.hexdigest() for algorithm, hasher in hashers.items()}
        sha256 = file_hashes["sha256"]
        findings = list(pattern_matches.values())
        for finding in findings:
            finding.sha256 = sha256

        for algorithm, digest in file_hashes.items():
            signature = self._hash_lookup.get(algorithm, {}).get(digest)
            if signature:
                findings.append(
                    ScanFinding(
                        path=str(path),
                        threat_name=signature.name,
                        severity=signature.severity,
                        reason=f"Known {algorithm.upper()} signature match: {signature.id}",
                        sha256=sha256,
                        size=stat.st_size,
                    )
                )

        if self.enable_heuristics:
            heuristic = self._heuristic_finding(path, sha256, stat.st_size)
            if heuristic:
                findings.append(heuristic)

        return findings

    def _iter_files(self, root: Path, summary: ScanSummary) -> Iterable[Path]:
        if root.is_file():
            yield root
            return
        if not root.exists():
            summary.errors.append(f"Path does not exist: {root}")
            return

        for current_root, dirs, files in os.walk(root):
            dirs[:] = [name for name in dirs if name not in {"$RECYCLE.BIN", "System Volume Information"}]
            for name in files:
                yield Path(current_root) / name

    def _heuristic_finding(self, path: Path, sha256: str, size: int) -> ScanFinding | None:
        suffixes = [suffix.lower() for suffix in path.suffixes]
        if len(suffixes) >= 2:
            final = suffixes[-1]
            previous = suffixes[-2]
            document_exts = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".jpeg", ".png", ".txt"}
            executable_exts = {".exe", ".scr", ".cmd", ".bat", ".ps1", ".vbs", ".js", ".msi"}
            if previous in document_exts and final in executable_exts:
                return ScanFinding(
                    path=str(path),
                    threat_name="Suspicious Double Extension",
                    severity="medium",
                    reason=f"File name ends with '{previous}{final}', a common disguise pattern.",
                    sha256=sha256,
                    size=size,
                )

        if path.suffix.lower() in self.definitions.risky_extensions:
            return ScanFinding(
                path=str(path),
                threat_name="Risky Script or Executable Type",
                severity="low",
                reason=f"File extension '{path.suffix.lower()}' is configured for review.",
                sha256=sha256,
                size=size,
            )

        return None
