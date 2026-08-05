"""Read-only on-demand scans through a separately installed ClamAV engine."""

from __future__ import annotations

import os
import stat
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from .engine import resolve_local_path, run_command
from .models import ScanFinding, ScanSummary, utc_now_iso
from .storage import app_data_dir


SUMMARY_INTEGER_KEYS = {
    "Scanned files": "files_scanned",
    "Infected files": "infected_files",
}

MAX_FILE_SIZE_BYTES = 100 * 1024 * 1024
MAX_SCAN_SIZE_MIB = 400
MAX_BATCH_FILES = 64
MAX_BATCH_ARGUMENT_CHARS = 20_000


@dataclass(frozen=True)
class ScanItem:
    outcome: str
    path: Path
    size: int = 0
    detail: str = ""


class ClamAvScanner:
    def __init__(self, clamscan_path: Path, database_dir: Path, engine_version: str) -> None:
        self.clamscan_path = Path(clamscan_path)
        self.database_dir = Path(database_dir)
        self.engine_version = engine_version

    def scan_path(
        self,
        root: Path,
        *,
        cancel_event: threading.Event | None = None,
    ) -> ScanSummary:
        target = validate_scan_target(root)
        if not database_is_ready(self.database_dir):
            raise RuntimeError("ClamAV definitions are not ready. Run Update Definitions first.")

        base_argv = [
            str(self.clamscan_path),
            f"--database={self.database_dir}",
            "--official-db-only=yes",
            "--infected",
            "--scan-archive=no",
            "--max-filesize=100M",
            f"--max-scansize={MAX_SCAN_SIZE_MIB}M",
            "--follow-dir-symlinks=0",
            "--follow-file-symlinks=0",
            "--cross-fs=no",
            "--stdout",
        ]
        started_at = utc_now_iso()
        summary = ScanSummary(
            started_at=started_at,
            completed_at=started_at,
            root=str(target),
            exit_code=0,
            engine_version=self.engine_version,
        )
        pending: list[ScanItem] = []
        pending_chars = 0

        for item in stream_scan_items(target):
            if cancel_event and cancel_event.is_set():
                break
            summary.files_enumerated += 1
            if item.outcome == "skipped":
                summary.files_skipped += 1
                continue
            if item.outcome == "oversized":
                summary.files_oversized += 1
                continue
            if item.outcome == "failed":
                summary.files_failed += 1
                summary.errors.append(f"{item.path}: {item.detail}"[:500])
                continue

            path_chars = len(str(item.path)) + 1
            if pending and (
                len(pending) >= MAX_BATCH_FILES
                or pending_chars + path_chars > MAX_BATCH_ARGUMENT_CHARS
            ):
                self._scan_batch(base_argv, pending, summary, cancel_event)
                pending = []
                pending_chars = 0
                if summary.cancelled:
                    break
            pending.append(item)
            pending_chars += path_chars

        if pending:
            if cancel_event and cancel_event.is_set():
                summary.files_cancelled += len(pending)
                summary.cancelled = True
            elif not summary.cancelled:
                self._scan_batch(base_argv, pending, summary, cancel_event)

        if cancel_event and cancel_event.is_set():
            summary.cancelled = True
        summary.completed_at = utc_now_iso()
        if summary.files_reconciled != summary.files_enumerated:
            summary.errors.append(
                "Internal scan accounting did not reconcile every enumerated item."
            )
        return summary

    def _scan_batch(
        self,
        base_argv: list[str],
        batch: list[ScanItem],
        summary: ScanSummary,
        cancel_event: threading.Event | None,
    ) -> None:
        result = run_command(
            [*base_argv, *(str(item.path) for item in batch)],
            cancel_event=cancel_event,
        )
        partial = parse_clamscan_output(
            result.output,
            root=Path(summary.root),
            started_at=summary.started_at,
            exit_code=result.returncode,
            cancelled=result.cancelled,
            timed_out=result.timed_out,
            engine_version=self.engine_version,
        )
        scanned = min(partial.files_scanned, len(batch))
        summary.files_scanned += scanned
        summary.bytes_scanned += sum(item.size for item in batch[:scanned])
        summary.findings.extend(partial.findings)
        summary.errors.extend(partial.errors)
        unaccounted = len(batch) - scanned
        if result.cancelled:
            summary.cancelled = True
            summary.files_cancelled += unaccounted
        elif unaccounted:
            summary.files_failed += unaccounted
            if not partial.errors:
                summary.errors.append(
                    f"ClamAV did not report a terminal result for {unaccounted} file(s)."
                )
        if result.returncode not in (0, 1):
            summary.exit_code = result.returncode
        elif summary.exit_code in (0, 1):
            summary.exit_code = max(summary.exit_code or 0, result.returncode)


def stream_scan_items(root: Path) -> Iterator[ScanItem]:
    """Yield terminal pre-scan outcomes and regular files using bounded traversal."""

    if root.is_file():
        yield _classify_path(root)
        return

    iterators: list[os.ScandirIterator[str]] = []
    try:
        try:
            iterators.append(os.scandir(root))
        except OSError as exc:
            yield ScanItem("failed", root, detail=f"Cannot enumerate directory: {exc}")
            return

        while iterators:
            try:
                entry = next(iterators[-1])
            except StopIteration:
                iterators.pop().close()
                continue
            except OSError as exc:
                yield ScanItem("failed", root, detail=f"Directory enumeration failed: {exc}")
                iterators.pop().close()
                continue

            path = Path(entry.path)
            try:
                if entry.is_symlink():
                    yield ScanItem("skipped", path, detail="Symbolic links are not followed.")
                    continue
                metadata = entry.stat(follow_symlinks=False)
                if stat.S_ISDIR(metadata.st_mode):
                    try:
                        iterators.append(os.scandir(path))
                    except OSError as exc:
                        yield ScanItem(
                            "failed", path, detail=f"Cannot enumerate directory: {exc}"
                        )
                    continue
                if not stat.S_ISREG(metadata.st_mode):
                    yield ScanItem("skipped", path, detail="Not a regular file.")
                    continue
                yield _classify_path(path, size=metadata.st_size)
            except OSError as exc:
                yield ScanItem("failed", path, detail=f"Cannot inspect path: {exc}")
    finally:
        for iterator in iterators:
            iterator.close()


def _classify_path(path: Path, *, size: int | None = None) -> ScanItem:
    if "\n" in str(path) or "\r" in str(path):
        return ScanItem("failed", path, detail="Newline-containing paths are unsupported.")
    try:
        file_size = path.stat().st_size if size is None else size
    except OSError as exc:
        return ScanItem("failed", path, detail=f"Cannot read file metadata: {exc}")
    if file_size > MAX_FILE_SIZE_BYTES:
        return ScanItem("oversized", path, size=file_size, detail="Exceeds the 100 MiB limit.")
    if not os.access(path, os.R_OK):
        return ScanItem("failed", path, size=file_size, detail="File is not readable.")
    return ScanItem("candidate", path, size=file_size)


def validate_scan_target(value: Path | str) -> Path:
    raw = str(value)
    if not raw.strip():
        raise ValueError("Choose a local file or directory to scan.")
    if raw.startswith("\\\\") or raw.startswith("//"):
        raise ValueError("UNC and network scan targets are not supported in this beta.")
    path = Path(value).expanduser()
    resolved = resolve_local_path(path, "the scan target")
    if not (resolved.is_file() or resolved.is_dir()):
        raise ValueError("The scan target must be a local file or directory.")
    try:
        resolved.relative_to(app_data_dir().resolve())
    except ValueError:
        pass
    else:
        raise ValueError("The application-data directory cannot be selected as a scan target.")
    return resolved


def database_is_ready(path: Path) -> bool:
    if not path.is_dir():
        return False
    names = {item.name.casefold() for item in path.iterdir() if item.is_file()}
    return any(name in names for name in ("main.cvd", "main.cld")) and any(
        name in names for name in ("daily.cvd", "daily.cld")
    )


def parse_clamscan_output(
    output: str,
    *,
    root: Path,
    started_at: str,
    exit_code: int,
    cancelled: bool = False,
    timed_out: bool = False,
    engine_version: str = "",
) -> ScanSummary:
    summary = ScanSummary(
        started_at=started_at,
        completed_at=utc_now_iso(),
        root=str(root),
        cancelled=cancelled,
        engine_version=engine_version,
        exit_code=exit_code,
    )
    parsed_values: dict[str, int] = {}

    for raw_line in output.splitlines():
        line = raw_line.strip()
        finding_path, separator, finding_result = line.partition(": ")
        if separator and finding_result.endswith(" FOUND"):
            signature = finding_result[: -len(" FOUND")]
            size = 0
            try:
                size = Path(finding_path).stat().st_size
            except OSError:
                pass
            summary.findings.append(
                ScanFinding(
                    path=finding_path,
                    threat_name=signature,
                    severity="not provided",
                    reason="Detected by the external ClamAV engine.",
                    sha256="",
                    size=size,
                )
            )
            continue

        if separator and finding_result.endswith(" ERROR"):
            summary.errors.append(f"{finding_path}: {finding_result[: -len(' ERROR')]}")
            continue

        if line.startswith(("ERROR:", "WARNING:", "LibClamAV Error:", "LibClamAV Warning:")):
            summary.errors.append(line[:500])
            continue

        if ":" in line:
            key, raw_value = (item.strip() for item in line.split(":", 1))
            if key in SUMMARY_INTEGER_KEYS:
                try:
                    parsed_values[key] = int(raw_value.replace(",", ""))
                except ValueError:
                    summary.errors.append(f"Unrecognized ClamAV summary value: {line}")

    summary.files_scanned = parsed_values.get("Scanned files", 0)
    if timed_out:
        summary.errors.append("The ClamAV scan timed out.")
    if not cancelled:
        if "Scanned files" not in parsed_values or "Infected files" not in parsed_values:
            summary.errors.append("ClamAV did not return a complete parseable scan summary.")
        infected_files = parsed_values.get("Infected files")
        if infected_files is not None and infected_files != len(summary.findings):
            summary.errors.append(
                "ClamAV's infected-file count does not match its parseable findings."
            )
        if exit_code not in (0, 1):
            summary.errors.append(f"ClamAV ended with error exit code {exit_code}.")
        if exit_code == 0 and (infected_files or summary.findings):
            summary.errors.append("ClamAV returned a clean exit code with infection output.")
        if exit_code == 1 and not summary.findings:
            summary.errors.append("ClamAV reported an infection but returned no parseable finding.")
    return summary
