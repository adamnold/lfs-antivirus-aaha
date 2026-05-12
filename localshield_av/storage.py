from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any


APP_NAME = "LocalShieldAV"


def app_data_dir() -> Path:
    root = os.environ.get("LOCALAPPDATA")
    if root:
        return Path(root) / APP_NAME
    return Path.home() / f".{APP_NAME.lower()}"


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def bundled_definitions_path() -> Path:
    return repo_root() / "definitions" / "signatures.json"


def user_definitions_path() -> Path:
    return app_data_dir() / "definitions" / "signatures.json"


def quarantine_dir() -> Path:
    return app_data_dir() / "quarantine"


def logs_dir() -> Path:
    return app_data_dir() / "logs"


def settings_path() -> Path:
    return app_data_dir() / "settings.json"


def ensure_app_dirs() -> None:
    for path in (
        app_data_dir(),
        user_definitions_path().parent,
        quarantine_dir(),
        logs_dir(),
    ):
        path.mkdir(parents=True, exist_ok=True)


def read_json(path: Path, default: Any) -> Any:
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    with temp.open("w", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
    temp.replace(path)


DEFAULT_SETTINGS: dict[str, Any] = {
    "max_file_size_mb": 64,
    "enable_heuristics": True,
    "definition_update_url": "",
    "app_update_url": "",
    "last_scan": None,
}


def load_settings() -> dict[str, Any]:
    ensure_app_dirs()
    loaded = read_json(settings_path(), {})
    settings = dict(DEFAULT_SETTINGS)
    if isinstance(loaded, dict):
        settings.update(loaded)
    return settings


def save_settings(settings: dict[str, Any]) -> None:
    ensure_app_dirs()
    write_json(settings_path(), settings)
