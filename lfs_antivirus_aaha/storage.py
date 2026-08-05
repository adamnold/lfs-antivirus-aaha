"""Application-state paths and JSON persistence for Local-First Antivirus."""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path
from typing import Any

from .platform_support import config_home, data_home, state_home


APP_DIRECTORY_NAME = "lfs-antivirus-aaha"
APP_ORGANIZATION_DIRECTORY = "AAHA"
LEGACY_APP_DIRECTORY_NAME = "LocalShieldAV"


def canonical_app_data_dir() -> Path:
    """Return the canonical AAHA data directory for new installations."""

    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        return Path(local_app_data) / APP_ORGANIZATION_DIRECTORY / APP_DIRECTORY_NAME
    return data_home() / APP_ORGANIZATION_DIRECTORY.lower() / APP_DIRECTORY_NAME


def legacy_app_data_dir() -> Path:
    """Return the pre-0.2 LocalShieldAV data directory."""

    root = os.environ.get("LOCALAPPDATA")
    if root:
        return Path(root) / LEGACY_APP_DIRECTORY_NAME
    return Path.home() / f".{LEGACY_APP_DIRECTORY_NAME.lower()}"


def app_data_dir() -> Path:
    """Use legacy state in place until the user intentionally migrates it.

    Automatically moving antivirus quarantine data is risky: interruption or a
    partial copy could strand quarantined files. A new installation uses the
    canonical AAHA path, while an existing legacy-only installation continues
    using its original directory without modification.
    """

    canonical = canonical_app_data_dir()
    legacy = legacy_app_data_dir()
    if not canonical.exists() and legacy.exists():
        return legacy
    return canonical


def clamav_database_dir() -> Path:
    return app_data_dir() / "clamav-database"


def clamav_database_backup_dir() -> Path:
    return app_data_dir() / "clamav-database.backup"


def freshclam_config_path() -> Path:
    return app_data_dir() / "freshclam.conf"


def quarantine_dir() -> Path:
    return app_data_dir() / "quarantine"


def logs_dir() -> Path:
    if os.environ.get("LOCALAPPDATA") or os.name == "nt":
        return app_data_dir() / "logs"
    return state_home() / APP_ORGANIZATION_DIRECTORY.lower() / APP_DIRECTORY_NAME / "logs"


def settings_path() -> Path:
    if os.environ.get("LOCALAPPDATA") or os.name == "nt":
        return app_data_dir() / "settings.json"
    return config_home() / APP_ORGANIZATION_DIRECTORY.lower() / APP_DIRECTORY_NAME / "settings.json"


def ensure_app_dirs() -> None:
    for path in (
        app_data_dir(),
        clamav_database_dir(),
        quarantine_dir(),
        logs_dir(),
    ):
        path.mkdir(parents=True, exist_ok=True)


def read_json(path: Path, default: Any) -> Any:
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, UnicodeError, json.JSONDecodeError):
        return default


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    with temp.open("w", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
    temp.replace(path)


DEFAULT_SETTINGS: dict[str, Any] = {
    "clamscan_path": "",
    "freshclam_path": "",
    "theme": "Default",
    "last_successful_scan": None,
    "last_attempt": None,
}


def load_settings() -> dict[str, Any]:
    ensure_app_dirs()
    canonical_settings = settings_path()
    legacy_settings = app_data_dir() / "settings.json"
    if (
        os.name != "nt"
        and not canonical_settings.exists()
        and legacy_settings.exists()
        and legacy_settings != canonical_settings
    ):
        canonical_settings.parent.mkdir(parents=True, exist_ok=True)
        try:
            shutil.copy2(legacy_settings, canonical_settings)
        except OSError:
            pass
    loaded = read_json(canonical_settings, {})
    settings = dict(DEFAULT_SETTINGS)
    if isinstance(loaded, dict):
        settings.update(loaded)
        if not settings.get("last_successful_scan") and loaded.get("last_scan"):
            settings["last_successful_scan"] = loaded.get("last_scan")
    return settings


def save_settings(settings: dict[str, Any]) -> None:
    ensure_app_dirs()
    write_json(settings_path(), settings)
