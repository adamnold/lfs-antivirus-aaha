"""Fail a release when the bundled ClamAV provenance/license set is incomplete."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
BUNDLE = ROOT / "dist" / "linux-payload" / "Local-First Antivirus"
RELEASE = ROOT / "dist" / "release"
EXPECTED_VERSION = "1.5.3"
EXPECTED_PACKAGE_SHA256 = "0c69e033a976855cfecfa1b6c36563822f2cc618f0c7e40ce5bcc2703d0dc436"
EXPECTED_SOURCE_SHA256 = "89af57a45bbf13de4dc91ed7f20b435388c88428eb7dc30639a02b2f0fc2dad1"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def require_text(path: Path, fragments: tuple[str, ...]) -> None:
    text = path.read_text(encoding="utf-8")
    for fragment in fragments:
        if fragment not in text:
            raise RuntimeError(f"{path.name} is missing required notice text: {fragment}")


def main() -> None:
    manifest_path = BUNDLE / "clamav" / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    expected = {
        "version": EXPECTED_VERSION,
        "package_sha256": EXPECTED_PACKAGE_SHA256,
        "source_sha256": EXPECTED_SOURCE_SHA256,
    }
    for key, value in expected.items():
        if manifest.get(key) != value:
            raise RuntimeError(f"Unexpected ClamAV manifest {key}: {manifest.get(key)!r}")

    for executable in ("clamscan", "freshclam"):
        path = BUNDLE / "clamav" / "bin" / executable
        if sha256(path) != manifest[f"{executable}_sha256"]:
            raise RuntimeError(f"Bundled {executable} does not match the provenance manifest.")

    corresponding_source = RELEASE / f"ClamAV-{EXPECTED_VERSION}-Corresponding-Source.tar.gz"
    if sha256(corresponding_source) != EXPECTED_SOURCE_SHA256:
        raise RuntimeError("The ClamAV corresponding-source archive hash is incorrect.")

    require_text(
        BUNDLE / "licenses" / "ClamAV-GPL-2.0-only.txt",
        ("GNU GENERAL PUBLIC LICENSE", "Version 2, June 1991"),
    )
    require_text(
        BUNDLE / "THIRD_PARTY_NOTICES.md",
        ("ClamAV", "GPLv2", "corresponding source"),
    )
    require_text(
        BUNDLE / "licenses" / "Python-LICENSE.txt",
        ("Python", "License"),
    )
    require_text(
        BUNDLE / "licenses" / "Python-build-requirements.txt",
        ("pyinstaller==",),
    )
    build_info = json.loads((BUNDLE / "BUILD_INFO.json").read_text(encoding="utf-8"))
    if build_info.get("clamav_bundled") is not True or build_info.get("clamav_version") != EXPECTED_VERSION:
        raise RuntimeError("BUILD_INFO.json does not identify the bundled ClamAV release.")
    print("Bundled ClamAV provenance, license, and corresponding-source gate passed.")


if __name__ == "__main__":
    main()
