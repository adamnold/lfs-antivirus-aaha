"""Read-only on-demand scans through a separately installed ClamAV engine."""

from __future__ import annotations

import threading
from pathlib import Path

from .engine import resolve_local_path, run_command
from .models import ScanFinding, ScanSummary, utc_now_iso
from .storage import app_data_dir


SUMMARY_INTEGER_KEYS = {
    "Scanned files": "files_scanned",
    "Infected files": "infected_files",
}


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

        argv = [
            str(self.clamscan_path),
            f"--database={self.database_dir}",
            "--official-db-only=yes",
            "--infected",
            "--scan-archive=no",
            "--follow-dir-symlinks=0",
            "--follow-file-symlinks=0",
            "--cross-fs=no",
            "--stdout",
        ]
        if target.is_dir():
            argv.append("--recursive=yes")
        argv.append(str(target))

        started_at = utc_now_iso()
        result = run_command(argv, cancel_event=cancel_event)
        return parse_clamscan_output(
            result.output,
            root=target,
            started_at=started_at,
            exit_code=result.returncode,
            cancelled=result.cancelled,
            timed_out=result.timed_out,
            engine_version=self.engine_version,
        )


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
