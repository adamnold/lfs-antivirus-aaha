"""Definition-source adapters for Local-First Antivirus."""

from __future__ import annotations

import io
import json
import tarfile
import tempfile
import uuid
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen

from .definitions import install_definitions, reset_to_bundled_definitions, validate_definitions
from .models import utc_now_iso
from .storage import write_json

MAX_DOWNLOAD_BYTES = 260 * 1024 * 1024
MAX_IMPORTED_HASH_SIGNATURES = 250_000
HTTP_USER_AGENT = "AAHA-Local-First-Antivirus/0.2.0"

DEFINITION_SOURCES: dict[str, dict[str, str]] = {
    "Bundled Local-First Antivirus demo definitions": {
        "kind": "bundled",
        "note": "Offline demo set included with the app.",
    },
    "ClamAV Daily CVD (official)": {
        "kind": "clamav_cvd",
        "url": "https://database.clamav.net/daily.cvd",
        "note": "Official ClamAV daily database; Local-First Antivirus imports file-hash signatures it can use.",
    },
    "ClamAV Main CVD (official)": {
        "kind": "clamav_cvd",
        "url": "https://database.clamav.net/main.cvd",
        "note": "Official ClamAV main database; Local-First Antivirus imports file-hash signatures it can use.",
    },
    "ClamAV Bytecode CVD (not compatible yet)": {
        "kind": "unsupported",
        "note": "ClamAV bytecode signatures require the ClamAV engine, not this hash scanner.",
    },
    "MalwareBazaar recent hashes (API key needed)": {
        "kind": "unsupported",
        "note": "MalwareBazaar is useful for hashes, but the community API requires an Auth-Key.",
    },
    "ThreatFox recent file-hash IOCs (API key needed)": {
        "kind": "unsupported",
        "note": "ThreatFox can provide file-hash IOCs, but the community API requires an Auth-Key.",
    },
}

DEFINITION_SOURCE_NAMES = tuple(DEFINITION_SOURCES)


def download_definitions(url: str, timeout: int = 20) -> Path:
    request = Request(url, headers={"User-Agent": HTTP_USER_AGENT})
    with urlopen(request, timeout=timeout) as response:
        if response.status >= 400:
            raise RuntimeError(f"Definitions server returned HTTP {response.status}.")
        body = response.read(5 * 1024 * 1024)
    raw = json.loads(body.decode("utf-8"))
    validate_definitions(raw)
    temp = Path(tempfile.gettempdir()) / f"lfs-antivirus-aaha-definitions-{uuid.uuid4().hex}.json"
    write_json(temp, raw)
    return temp


def update_definitions_from_url(url: str):
    temp = download_definitions(url)
    try:
        return install_definitions(temp)
    finally:
        temp.unlink(missing_ok=True)


def update_definitions_from_source(source_name: str):
    source = DEFINITION_SOURCES.get(source_name)
    if not source:
        raise ValueError("Choose a known definitions source.")
    if source["kind"] == "bundled":
        return reset_to_bundled_definitions()
    if source["kind"] == "clamav_cvd":
        temp = download_clamav_cvd(source["url"], source_name)
        try:
            converted = convert_clamav_cvd_file(temp, source_name)
            converted_path = Path(tempfile.gettempdir()) / f"lfs-antivirus-aaha-clamav-{uuid.uuid4().hex}.json"
            write_json(converted_path, converted)
            try:
                return install_definitions(converted_path)
            finally:
                converted_path.unlink(missing_ok=True)
        finally:
            temp.unlink(missing_ok=True)
    raise ValueError(source["note"])


def download_clamav_cvd(url: str, source_name: str, timeout: int = 60) -> Path:
    request = Request(url, headers={"User-Agent": HTTP_USER_AGENT})
    temp = Path(tempfile.gettempdir()) / f"lfs-antivirus-aaha-{uuid.uuid4().hex}.cvd"
    total = 0
    with urlopen(request, timeout=timeout) as response:
        if response.status >= 400:
            raise RuntimeError(f"{source_name} returned HTTP {response.status}.")
        with temp.open("wb") as output:
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_DOWNLOAD_BYTES:
                    raise RuntimeError("Downloaded definitions exceeded the local safety limit.")
                output.write(chunk)
    return temp


def convert_clamav_cvd_file(path: Path, source_name: str) -> dict[str, Any]:
    with path.open("rb") as handle:
        header = handle.read(512)
        if not header.startswith(b"ClamAV-VDB:"):
            raise ValueError("This does not look like a ClamAV CVD file.")
        header_text = header.decode("utf-8", errors="ignore").strip("\x00 ")
        payload = handle.read()

    hashes: list[dict[str, str]] = []
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as archive:
        for member in archive.getmembers():
            if not member.isfile() or not member.name.lower().endswith((".hdb", ".hsb", ".hdu", ".hsu")):
                continue
            extracted = archive.extractfile(member)
            if extracted is None:
                continue
            for raw_line in extracted:
                if len(hashes) >= MAX_IMPORTED_HASH_SIGNATURES:
                    break
                parsed = parse_clamav_hash_line(raw_line.decode("utf-8", errors="ignore"))
                if parsed:
                    hashes.append(parsed)
            if len(hashes) >= MAX_IMPORTED_HASH_SIGNATURES:
                break

    if not hashes:
        raise ValueError("No compatible file-hash signatures were found in that source.")

    version = _clamav_version_from_header(header_text)
    return {
        "version": f"{source_name} {version}".strip(),
        "updated_at": utc_now_iso(),
        "source": source_name,
        "source_header": header_text,
        "hashes": hashes,
        "content": [],
        "heuristics": {
            "risky_extensions": [".bat", ".cmd", ".js", ".ps1", ".scr", ".vbs"],
            "scan_archives": False,
        },
    }


def parse_clamav_hash_line(line: str) -> dict[str, str] | None:
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None
    parts = stripped.split(":")
    if len(parts) < 3:
        return None
    digest = parts[0].lower()
    name = ":".join(parts[2:]).strip() or "ClamAV Hash Signature"
    algorithm = _hash_algorithm(digest)
    if not algorithm:
        return None
    return {
        "id": f"CLAMAV-{algorithm.upper()}-{digest[:12]}",
        "name": name,
        "severity": "high",
        algorithm: digest,
        "description": "Imported from a ClamAV hash-signature database.",
    }


def _hash_algorithm(digest: str) -> str | None:
    if not all(character in "0123456789abcdef" for character in digest):
        return None
    if len(digest) == 32:
        return "md5"
    if len(digest) == 40:
        return "sha1"
    if len(digest) == 64:
        return "sha256"
    return None


def _clamav_version_from_header(header: str) -> str:
    parts = header.split(":")
    if len(parts) > 2 and parts[2]:
        return f"v{parts[2]}"
    return "import"
