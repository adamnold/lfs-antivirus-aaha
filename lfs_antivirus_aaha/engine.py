"""Validated external-process boundary for a separately installed ClamAV."""

from __future__ import annotations

import os
import signal
import stat
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from .models import utc_now_iso


@dataclass(frozen=True)
class ProcessResult:
    returncode: int
    output: str
    cancelled: bool = False
    timed_out: bool = False


@dataclass(frozen=True)
class ClamAvInstallation:
    clamscan_path: Path
    freshclam_path: Path
    clamscan_version: str
    freshclam_version: str
    validated_at: str


def run_command(
    argv: Sequence[str],
    *,
    cancel_event: threading.Event | None = None,
    timeout: float | None = None,
) -> ProcessResult:
    """Run a fixed argv without a shell and support bounded cancellation."""

    if not argv or any(not isinstance(item, str) or not item for item in argv):
        raise ValueError("A non-empty argument list is required.")
    if cancel_event and cancel_event.is_set():
        return ProcessResult(returncode=-1, output="", cancelled=True)

    creationflags = 0
    if os.name == "nt":
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) | getattr(
            subprocess, "CREATE_NEW_PROCESS_GROUP", 0
        )

    process = subprocess.Popen(
        list(argv),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        shell=False,
        creationflags=creationflags,
        start_new_session=os.name != "nt",
    )
    deadline = time.monotonic() + timeout if timeout is not None else None

    while True:
        try:
            output, _ = process.communicate(timeout=0.2)
            return ProcessResult(
                returncode=process.returncode,
                output=output or "",
                cancelled=bool(cancel_event and cancel_event.is_set()),
            )
        except subprocess.TimeoutExpired:
            cancelled = bool(cancel_event and cancel_event.is_set())
            timed_out = bool(deadline is not None and time.monotonic() >= deadline)
            if not (cancelled or timed_out):
                continue

            _terminate_process_tree(process)
            try:
                output, _ = process.communicate(timeout=2)
            except subprocess.TimeoutExpired as terminate_timeout:
                partial_output = _timeout_output(terminate_timeout)
                _force_kill_process_tree(process)
                try:
                    output, _ = process.communicate(timeout=2)
                except subprocess.TimeoutExpired as kill_timeout:
                    output = _timeout_output(kill_timeout) or partial_output
                    if process.stdout is not None:
                        process.stdout.close()
                    try:
                        process.wait(timeout=1)
                    except subprocess.TimeoutExpired:
                        pass
            return ProcessResult(
                returncode=process.poll() if process.poll() is not None else -9,
                output=output or "",
                cancelled=cancelled,
                timed_out=timed_out,
            )


def validate_installation(
    clamscan_path: Path | str,
    freshclam_path: Path | str,
    *,
    cancel_event: threading.Event | None = None,
) -> ClamAvInstallation:
    """Validate exact executable paths from one ClamAV installation directory."""

    clamscan = _validate_executable(clamscan_path, "clamscan.exe")
    freshclam = _validate_executable(freshclam_path, "freshclam.exe")
    if os.path.normcase(str(clamscan.parent)) != os.path.normcase(str(freshclam.parent)):
        raise ValueError("clamscan.exe and freshclam.exe must be in the same directory.")

    scan_version = run_command(
        [str(clamscan), "--version"], cancel_event=cancel_event, timeout=15
    )
    if scan_version.cancelled or (cancel_event and cancel_event.is_set()):
        raise RuntimeError("ClamAV validation was cancelled.")
    if scan_version.returncode != 0 or scan_version.timed_out:
        raise RuntimeError("clamscan.exe did not return a valid version response.")
    scan_text = _version_line(scan_version.output, "clamscan.exe")

    # FreshClam parses freshclam.conf before handling --version, but handles
    # --help first. A clean official Windows installation has no active config
    # yet, so validate its versioned identity banner through --help.
    fresh_version = run_command(
        [str(freshclam), "--help"], cancel_event=cancel_event, timeout=15
    )
    if fresh_version.cancelled or (cancel_event and cancel_event.is_set()):
        raise RuntimeError("ClamAV validation was cancelled.")
    if fresh_version.returncode != 0 or fresh_version.timed_out:
        raise RuntimeError("freshclam.exe did not return a valid identity response.")

    fresh_text = _freshclam_identity_line(fresh_version.output)
    return ClamAvInstallation(
        clamscan_path=clamscan,
        freshclam_path=freshclam,
        clamscan_version=scan_text,
        freshclam_version=fresh_text,
        validated_at=utc_now_iso(),
    )


def suggested_installation() -> tuple[Path, Path] | None:
    """Return a standard Windows installation pair without consulting PATH."""

    roots: list[Path] = []
    for variable in ("ProgramFiles", "ProgramFiles(x86)"):
        value = os.environ.get(variable)
        if value:
            roots.append(Path(value))
    for root in roots:
        parent = root / "ClamAV"
        clamscan = parent / "clamscan.exe"
        freshclam = parent / "freshclam.exe"
        try:
            clamscan = _validate_executable(clamscan, "clamscan.exe")
            freshclam = _validate_executable(freshclam, "freshclam.exe")
        except ValueError:
            continue
        if os.path.normcase(str(clamscan.parent)) == os.path.normcase(
            str(freshclam.parent)
        ):
            return clamscan, freshclam
    return None


def _validate_executable(value: Path | str, expected_name: str) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        raise ValueError(f"Choose an absolute path to {expected_name}.")
    if path.name.casefold() != expected_name.casefold():
        raise ValueError(f"The selected file must be named {expected_name}.")
    resolved = resolve_local_path(path, expected_name)
    if not resolved.is_file():
        raise ValueError(f"The selected {expected_name} path is not a file.")
    return resolved


def _version_line(output: str, executable_name: str) -> str:
    line = next((item.strip() for item in output.splitlines() if item.strip()), "")
    if "clamav" not in line.casefold():
        raise RuntimeError(f"{executable_name} returned an unexpected version response.")
    return line[:240]


def _freshclam_identity_line(output: str) -> str:
    line = next(
        (
            item.strip()
            for item in output.splitlines()
            if "clam antivirus: database updater" in item.casefold()
        ),
        "",
    )
    if not line:
        raise RuntimeError("freshclam.exe returned an unexpected identity response.")
    return line[:240]


def resolve_local_path(value: Path | str, label: str) -> Path:
    """Resolve an existing path while rejecting network and link indirection."""

    path = Path(value).expanduser()
    if not path.is_absolute():
        raise ValueError(f"Choose an absolute path for {label}.")
    if _is_unc_path(path):
        raise ValueError(f"UNC-style network paths are not accepted for {label}.")
    if path_is_remote(path):
        raise ValueError(f"Mapped and UNC network paths are not accepted for {label}.")
    try:
        for candidate in reversed((path, *path.parents)):
            if _is_link_or_reparse_point(candidate):
                raise ValueError(
                    f"Symbolic-link, junction, and reparse-point paths are not accepted for {label}."
                )
        resolved = path.resolve(strict=True)
    except ValueError:
        raise
    except OSError as exc:
        raise ValueError(f"Cannot resolve {label}: {exc}") from exc
    if _is_unc_path(resolved) or path_is_remote(resolved):
        raise ValueError(f"Mapped and UNC network paths are not accepted for {label}.")
    return resolved


def path_is_remote(path: Path) -> bool:
    """Return whether Windows reports the path's drive as remote."""

    if os.name != "nt":
        return False
    anchor = path.anchor
    if not anchor:
        raise ValueError(f"Cannot determine the drive for local path: {path}")
    try:
        import ctypes

        drive_type = int(ctypes.windll.kernel32.GetDriveTypeW(str(anchor)))
    except (AttributeError, OSError) as exc:
        raise ValueError(f"Cannot verify that the path is on a local drive: {path}") from exc
    if drive_type in (0, 1):
        raise ValueError(f"Windows could not verify the path's drive type: {path}")
    return drive_type == 4


def _is_unc_path(path: Path) -> bool:
    raw = str(path)
    return raw.startswith("\\\\") or raw.startswith("//")


def _is_link_or_reparse_point(path: Path) -> bool:
    metadata = path.lstat()
    attributes = getattr(metadata, "st_file_attributes", 0)
    return stat.S_ISLNK(metadata.st_mode) or bool(
        attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    )


def _timeout_output(exc: subprocess.TimeoutExpired) -> str:
    output = exc.output or ""
    if isinstance(output, bytes):
        return output.decode("utf-8", errors="replace")
    return output


def _terminate_process_tree(process: subprocess.Popen[str]) -> None:
    """Terminate descendants while the parent still identifies the process tree."""

    if os.name == "nt":
        # Console children can retain the inherited stdout pipe after their
        # parent exits. Kill the complete tree before terminating the parent so
        # communicate() cannot remain blocked on a surviving descendant.
        _run_taskkill(process.pid, force=True)
    else:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except OSError:
            pass
    try:
        process.terminate()
    except OSError:
        pass


def _force_kill_process_tree(process: subprocess.Popen[str]) -> None:
    """Best-effort tree termination without allowing shutdown to wait forever."""

    if os.name == "nt":
        _run_taskkill(process.pid, force=True)
    else:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except OSError:
            pass
    try:
        process.kill()
    except OSError:
        pass


def _run_taskkill(pid: int, *, force: bool) -> None:
    system_root = os.environ.get("SystemRoot")
    taskkill = Path(system_root) / "System32" / "taskkill.exe" if system_root else None
    if not taskkill or not taskkill.is_file():
        return
    argv = [str(taskkill), "/PID", str(pid), "/T"]
    if force:
        argv.append("/F")
    try:
        subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=False,
            timeout=5,
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.SubprocessError):
        pass
