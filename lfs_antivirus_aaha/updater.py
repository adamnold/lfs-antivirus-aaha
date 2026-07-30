"""FreshClam-backed official definition updates with last-known-good rollback."""

from __future__ import annotations

import os
import shutil
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from .engine import ProcessResult, run_command
from .scanner import database_is_ready
from .storage import (
    clamav_database_backup_dir,
    clamav_database_dir,
    freshclam_config_path,
    read_json,
    write_json,
)


@dataclass(frozen=True)
class DatabaseStatus:
    ready: bool
    file_count: int
    newest_at: str | None


@dataclass(frozen=True)
class UpdateResult:
    database_status: DatabaseStatus
    output: str
    recovery_note: str | None = None


class UpdateControl:
    """Atomically separate cancellable work from the database commit phase."""

    def __init__(self) -> None:
        self.cancel_event = threading.Event()
        self.commit_started = threading.Event()
        self._lock = threading.Lock()

    def request_cancel(self) -> bool:
        with self._lock:
            if self.commit_started.is_set():
                return False
            self.cancel_event.set()
            return True

    def begin_commit(self) -> bool:
        with self._lock:
            if self.cancel_event.is_set():
                return False
            self.commit_started.set()
            return True


class FreshClamUpdater:
    def __init__(self, freshclam_path: Path, clamscan_path: Path) -> None:
        self.freshclam_path = Path(freshclam_path)
        self.clamscan_path = Path(clamscan_path)
        self.database_dir = clamav_database_dir()
        self.backup_dir = clamav_database_backup_dir()
        self.staging_dir = self.database_dir.with_name(self.database_dir.name + ".staging")
        self.previous_dir = self.database_dir.with_name(self.database_dir.name + ".previous")
        self.activation_marker = self.database_dir.parent / "clamav-database-activation.json"

    def update(
        self,
        *,
        control: UpdateControl | None = None,
        cancel_event: threading.Event | None = None,
    ) -> UpdateResult:
        if control is not None and cancel_event is not None:
            raise ValueError("Use either UpdateControl or cancel_event, not both.")
        effective_cancel = control.cancel_event if control is not None else cancel_event
        with database_operation_lock():
            return self._update_locked(control=control, cancel_event=effective_cancel)

    def _update_locked(
        self,
        *,
        control: UpdateControl | None,
        cancel_event: threading.Event | None,
    ) -> UpdateResult:
        config = freshclam_config_path()
        try:
            self._prepare_staging()
            if cancel_event and cancel_event.is_set():
                raise RuntimeError("FreshClam update was cancelled; the active database was not changed.")
            write_freshclam_config(config, self.staging_dir)
            update_result = run_command(
                [
                    str(self.freshclam_path),
                    f"--config-file={config}",
                    f"--datadir={self.staging_dir}",
                    "--stdout",
                ],
                cancel_event=cancel_event,
                timeout=15 * 60,
            )
            _require_success(update_result, "FreshClam update")
            _require_not_cancelled(cancel_event, "FreshClam update")
            if not database_is_ready(self.staging_dir):
                raise RuntimeError("FreshClam did not produce both Main and Daily databases.")

            probe = config.with_name("clamav-database-probe.txt")
            probe.write_text("AAHA ClamAV database validation probe\n", encoding="utf-8")
            try:
                validation = run_command(
                    [
                        str(self.clamscan_path),
                        f"--database={self.staging_dir}",
                        "--official-db-only=yes",
                        "--scan-archive=no",
                        "--stdout",
                        str(probe),
                    ],
                    cancel_event=cancel_event,
                    timeout=120,
                )
            finally:
                probe.unlink(missing_ok=True)
            _require_success(validation, "ClamAV database validation")
            if control is not None:
                if not control.begin_commit():
                    raise RuntimeError(
                        "ClamAV database validation was cancelled; the active database was not changed."
                    )
            else:
                _require_not_cancelled(cancel_event, "ClamAV database validation")
            recovery_note = self._activate_staging()
            return UpdateResult(
                database_status=database_status(),
                output=update_result.output,
                recovery_note=recovery_note,
            )
        except Exception:
            if self.staging_dir.exists():
                shutil.rmtree(self.staging_dir)
            raise
        finally:
            config.unlink(missing_ok=True)

    def _prepare_staging(self) -> None:
        _recover_database_activation_unlocked()
        if self.staging_dir.exists():
            shutil.rmtree(self.staging_dir)
        if self.database_dir.exists():
            shutil.copytree(self.database_dir, self.staging_dir)
        else:
            self.staging_dir.mkdir(parents=True)

    def _activate_staging(self) -> str | None:
        if self.previous_dir.exists():
            raise RuntimeError("A previous database activation still requires recovery.")
        had_current = self.database_dir.exists()
        write_json(
            self.activation_marker,
            {"phase": "prepared", "had_current": had_current},
        )
        try:
            if had_current:
                self.database_dir.replace(self.previous_dir)
                write_json(
                    self.activation_marker,
                    {"phase": "active_moved", "had_current": True},
                )
            self.staging_dir.replace(self.database_dir)
        except Exception as exc:
            rollback_error: Exception | None = None
            if had_current and self.previous_dir.exists() and not self.database_dir.exists():
                try:
                    self.previous_dir.replace(self.database_dir)
                except Exception as rollback_exc:
                    rollback_error = rollback_exc
            if self.database_dir.exists() or not had_current:
                self.activation_marker.unlink(missing_ok=True)
            if rollback_error:
                raise RuntimeError(
                    "Database activation was interrupted and automatic rollback failed; "
                    "restart the app to retry recovery."
                ) from rollback_error
            if not had_current:
                raise RuntimeError(
                    "Database activation failed; no active database was replaced."
                ) from exc
            raise RuntimeError(
                "Database activation failed; the previous active database was restored."
            ) from exc

        try:
            _rotate_previous_to_backup(self.previous_dir, self.backup_dir)
            self.activation_marker.unlink(missing_ok=True)
            return None
        except Exception as exc:
            return (
                "The new database is active, but previous-database backup cleanup is pending "
                f"startup recovery: {exc}"
            )


def recover_database_activation() -> str | None:
    """Recover an interrupted same-volume database directory activation."""

    with database_operation_lock():
        return _recover_database_activation_unlocked()


def _recover_database_activation_unlocked() -> str | None:
    """Recover activation while the caller holds the database operation lock."""

    database = clamav_database_dir()
    backup = clamav_database_backup_dir()
    staging = database.with_name(database.name + ".staging")
    previous = database.with_name(database.name + ".previous")
    marker = database.parent / "clamav-database-activation.json"
    marker_exists = marker.exists()
    marker_state = read_json(marker, {}) if marker_exists else {}
    marker_phase = marker_state.get("phase") if isinstance(marker_state, dict) else None
    marker_had_current = marker_state.get("had_current") if isinstance(marker_state, dict) else None
    note: str | None = None

    if not database_is_ready(database):
        if database.exists():
            shutil.rmtree(database)
        if database_is_ready(previous):
            previous.replace(database)
            note = "Recovered the previous active ClamAV database after an interrupted activation."
        elif database_is_ready(backup):
            recovery = database.with_name(database.name + ".recovery")
            if recovery.exists():
                shutil.rmtree(recovery)
            shutil.copytree(backup, recovery)
            recovery.replace(database)
            note = "Restored the last-known-good ClamAV database backup."
        elif (
            marker_exists
            and marker_phase in {"prepared", "active_moved"}
            and database_is_ready(staging)
        ):
            staging.replace(database)
            note = "Completed an interrupted first ClamAV database activation."
        elif marker_exists and marker_had_current is False:
            if staging.exists():
                shutil.rmtree(staging)
            marker.unlink(missing_ok=True)
            return "Cleared an incomplete first database activation; update definitions again."
        elif marker_exists:
            raise RuntimeError(
                "ClamAV database activation is incomplete and no recoverable database was found."
            )

    if database_is_ready(database) and previous.exists():
        if database_is_ready(previous):
            _rotate_previous_to_backup(previous, backup)
            note = note or "Completed pending ClamAV database backup recovery."
        else:
            shutil.rmtree(previous)

    if database_is_ready(database):
        if staging.exists() and marker_exists:
            shutil.rmtree(staging)
        marker.unlink(missing_ok=True)
    return note


@contextmanager
def database_operation_lock() -> Iterator[None]:
    """Hold a process-scoped non-blocking lock for recovery and definition updates."""

    path = clamav_database_dir().parent / "clamav-database.lock"
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = path.open("a+b")
    acquired = False
    try:
        try:
            if os.name == "nt":
                import msvcrt

                handle.seek(0, os.SEEK_END)
                if handle.tell() == 0:
                    handle.write(b"\0")
                    handle.flush()
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            acquired = True
        except OSError as exc:
            raise RuntimeError(
                "Another Local-First Antivirus process is updating or recovering definitions."
            ) from exc
        yield
    finally:
        if acquired:
            try:
                handle.seek(0)
                if os.name == "nt":
                    import msvcrt

                    msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            except OSError:
                pass
        handle.close()


def _rotate_previous_to_backup(previous: Path, backup: Path) -> None:
    if not previous.exists():
        return
    if backup.exists():
        shutil.rmtree(backup)
    previous.replace(backup)


def write_freshclam_config(path: Path, database_dir: Path) -> None:
    value = str(database_dir)
    if "\n" in value or "\r" in value or '"' in value:
        raise ValueError("The database path cannot be represented safely in freshclam.conf.")
    content = "\n".join(
        (
            f'DatabaseDirectory "{value}"',
            "DatabaseMirror database.clamav.net",
            "MaxAttempts 3",
            "ConnectTimeout 20",
            "ReceiveTimeout 60",
            "TestDatabases yes",
            "Bytecode yes",
            "",
        )
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(content, encoding="utf-8", newline="\n")
    temp.replace(path)


def database_status() -> DatabaseStatus:
    path = clamav_database_dir()
    if not path.is_dir():
        return DatabaseStatus(ready=False, file_count=0, newest_at=None)
    files = [
        item
        for item in path.iterdir()
        if item.is_file() and item.suffix.casefold() in {".cvd", ".cld"}
    ]
    newest = max((item.stat().st_mtime for item in files), default=None)
    newest_at = (
        datetime.fromtimestamp(newest, timezone.utc).replace(microsecond=0).isoformat()
        if newest is not None
        else None
    )
    return DatabaseStatus(
        ready=database_is_ready(path),
        file_count=len(files),
        newest_at=newest_at,
    )


def _require_success(result: ProcessResult, label: str) -> None:
    if result.cancelled:
        raise RuntimeError(f"{label} was cancelled; the active database was not changed.")
    if result.timed_out:
        raise RuntimeError(f"{label} timed out; the active database was not changed.")
    if result.returncode != 0:
        tail = next((line.strip() for line in reversed(result.output.splitlines()) if line.strip()), "")
        detail = f" {tail[:300]}" if tail else ""
        raise RuntimeError(f"{label} failed with exit code {result.returncode}.{detail}")


def _require_not_cancelled(cancel_event: threading.Event | None, label: str) -> None:
    if cancel_event and cancel_event.is_set():
        raise RuntimeError(f"{label} was cancelled; the active database was not changed.")
