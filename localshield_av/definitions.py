from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .models import Signature, utc_now_iso
from .storage import bundled_definitions_path, ensure_app_dirs, read_json, user_definitions_path, write_json


@dataclass
class Definitions:
    version: str
    updated_at: str
    hash_signatures: list[Signature]
    content_signatures: list[Signature]
    risky_extensions: set[str]
    scan_archives: bool

    @property
    def signature_count(self) -> int:
        return len(self.hash_signatures) + len(self.content_signatures)


def active_definitions_path() -> Path:
    ensure_app_dirs()
    if user_definitions_path().exists():
        return user_definitions_path()
    return bundled_definitions_path()


def validate_definitions(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("Definitions file must contain a JSON object.")
    if not isinstance(value.get("version"), str) or not value["version"].strip():
        raise ValueError("Definitions file is missing a version string.")
    for key in ("hashes", "content"):
        if key in value and not isinstance(value[key], list):
            raise ValueError(f"Definitions field '{key}' must be a list.")
    heuristics = value.get("heuristics", {})
    if heuristics and not isinstance(heuristics, dict):
        raise ValueError("Definitions field 'heuristics' must be an object.")
    return value


def load_definitions() -> Definitions:
    raw = validate_definitions(read_json(active_definitions_path(), {}))

    hash_signatures: list[Signature] = []
    for item in raw.get("hashes", []):
        if not isinstance(item, dict):
            continue
        algorithm = ""
        digest = ""
        for candidate in ("sha256", "sha1", "md5"):
            if item.get(candidate):
                algorithm = candidate
                digest = str(item[candidate]).lower()
                break
        if not digest and item.get("hash") and item.get("algorithm"):
            algorithm = str(item["algorithm"]).lower()
            digest = str(item["hash"]).lower()
        if algorithm in {"sha256", "sha1", "md5"} and digest:
            hash_signatures.append(
                Signature(
                    id=str(item.get("id", digest[:12])),
                    name=str(item.get("name", "Known Malware Hash")),
                    severity=str(item.get("severity", "high")),
                    kind=algorithm,
                    value=digest,
                    description=str(item.get("description", "")),
                )
            )

    content_signatures: list[Signature] = []
    for item in raw.get("content", []):
        if isinstance(item, dict) and item.get("pattern"):
            content_signatures.append(
                Signature(
                    id=str(item.get("id", item["pattern"][:12])),
                    name=str(item.get("name", "Content Signature")),
                    severity=str(item.get("severity", "medium")),
                    kind="content",
                    value=str(item["pattern"]),
                    description=str(item.get("description", "")),
                )
            )

    heuristics = raw.get("heuristics", {})
    risky_extensions = {
        str(ext).lower() if str(ext).startswith(".") else f".{str(ext).lower()}"
        for ext in heuristics.get("risky_extensions", [])
    }

    return Definitions(
        version=str(raw["version"]),
        updated_at=str(raw.get("updated_at", utc_now_iso())),
        hash_signatures=hash_signatures,
        content_signatures=content_signatures,
        risky_extensions=risky_extensions,
        scan_archives=bool(heuristics.get("scan_archives", False)),
    )


def install_definitions(source: Path) -> Definitions:
    raw = validate_definitions(read_json(source, {}))
    ensure_app_dirs()
    write_json(user_definitions_path(), raw)
    return load_definitions()


def reset_to_bundled_definitions() -> Definitions:
    ensure_app_dirs()
    path = user_definitions_path()
    if path.exists():
        path.unlink()
    return load_definitions()


def export_active_definitions(destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(active_definitions_path(), destination)
