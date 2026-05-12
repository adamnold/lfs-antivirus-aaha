from __future__ import annotations

from pathlib import Path

from .models import utc_now_iso
from .storage import ensure_app_dirs, logs_dir


def log_path() -> Path:
    ensure_app_dirs()
    return logs_dir() / "localshield.log"


def append_log(message: str) -> None:
    ensure_app_dirs()
    with log_path().open("a", encoding="utf-8") as handle:
        handle.write(f"{utc_now_iso()} {message}\n")


def read_log_tail(limit: int = 500) -> str:
    path = log_path()
    if not path.exists():
        return ""
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    return "\n".join(lines[-limit:])
