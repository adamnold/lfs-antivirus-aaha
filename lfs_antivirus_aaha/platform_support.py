"""Platform and package-runtime boundaries for Local-First Antivirus."""

from __future__ import annotations

import os
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path


APP_ID = "com.aaha.lfs-antivirus-aaha"
APP_SLUG = "lfs-antivirus-aaha"


@dataclass(frozen=True)
class RuntimeContext:
    platform: str
    package_kind: str
    managed_engine: bool

    @property
    def uses_portal_picker(self) -> bool:
        return self.package_kind == "flatpak"


def runtime_context() -> RuntimeContext:
    if os.environ.get("FLATPAK_ID"):
        return RuntimeContext(sys.platform, "flatpak", True)
    if os.environ.get("APPIMAGE") or os.environ.get("APPDIR"):
        return RuntimeContext(sys.platform, "appimage", True)
    provider = os.environ.get("AAHA_CLAMAV_PROVIDER", "").strip().casefold()
    if provider == "bundled":
        return RuntimeContext(sys.platform, "bundled", True)
    if provider == "system":
        return RuntimeContext(sys.platform, "rpm", True)
    if os.name == "nt":
        return RuntimeContext(sys.platform, "windows", False)
    return RuntimeContext(sys.platform, "development", False)


def data_home() -> Path:
    compatibility_root = os.environ.get("LOCALAPPDATA")
    if compatibility_root:
        return Path(compatibility_root)
    if os.name == "nt":
        return Path.home() / "AppData" / "Local"
    root = os.environ.get("XDG_DATA_HOME")
    return Path(root).expanduser() if root else Path.home() / ".local" / "share"


def config_home() -> Path:
    if os.environ.get("LOCALAPPDATA") or os.name == "nt":
        return data_home()
    root = os.environ.get("XDG_CONFIG_HOME")
    return Path(root).expanduser() if root else Path.home() / ".config"


def state_home() -> Path:
    if os.environ.get("LOCALAPPDATA") or os.name == "nt":
        return data_home()
    root = os.environ.get("XDG_STATE_HOME")
    return Path(root).expanduser() if root else Path.home() / ".local" / "state"


def packaged_engine_paths() -> tuple[Path, Path, str] | None:
    """Return exact package-owned or RPM-owned ClamAV paths when configured."""

    context = runtime_context()
    explicit_root = os.environ.get("AAHA_CLAMAV_ROOT")
    candidates: list[tuple[Path, str]] = []
    if explicit_root:
        root = Path(explicit_root).expanduser()
        candidates.append((root / "bin" if (root / "bin").is_dir() else root, "bundled"))
    if context.package_kind == "flatpak":
        candidates.append((Path("/app/libexec/lfs-antivirus-aaha/app/clamav/bin"), "bundled"))
    if context.package_kind in {"appimage", "bundled"}:
        appdir = os.environ.get("APPDIR")
        if appdir:
            candidates.append((Path(appdir) / "usr" / "libexec" / APP_SLUG / "app" / "clamav" / "bin", "bundled"))
        executable_root = Path(sys.executable).resolve().parent
        candidates.append((executable_root / "clamav" / "bin", "bundled"))

    for root, provider in candidates:
        clamscan = root / executable_name("clamscan")
        freshclam = root / executable_name("freshclam")
        if clamscan.is_file() and freshclam.is_file():
            return clamscan, freshclam, provider

    if context.package_kind == "rpm" or os.environ.get("AAHA_CLAMAV_PROVIDER", "").casefold() == "system":
        clamscan_value = shutil.which("clamscan")
        freshclam_value = shutil.which("freshclam")
        if clamscan_value and freshclam_value:
            return Path(clamscan_value), Path(freshclam_value), "system"
    return None


def executable_name(base: str) -> str:
    return f"{base}.exe" if os.name == "nt" else base


def reveal_path(path: Path) -> bool:
    """Open a local directory without passing user content through a shell."""

    if os.name == "nt" and hasattr(os, "startfile"):
        os.startfile(str(path))  # type: ignore[attr-defined]
        return True
    launcher = shutil.which("xdg-open")
    if not launcher:
        return False
    import subprocess

    subprocess.Popen(
        [launcher, str(path)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        shell=False,
        start_new_session=True,
    )
    return True
