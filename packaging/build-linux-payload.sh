#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_root"
python_command=${PYTHON:-python3}
expected_version=0.4.0-beta.1
payload_root="$repo_root/dist/linux-payload"
build_root="$repo_root/build/linux-pyinstaller"
clamav_root="$repo_root/build/clamav-linux"
cache_root=${AAHA_DOWNLOAD_CACHE:-"$repo_root/build/download-cache"}
case "$cache_root" in
    /*) ;;
    *) cache_root="$repo_root/$cache_root" ;;
esac

actual_version=$($python_command -c 'from lfs_antivirus_aaha import __version__; print(__version__)')
if [ "$actual_version" != "$expected_version" ]; then
    echo "Expected version $expected_version; received $actual_version." >&2
    exit 1
fi

rm -rf "$payload_root" "$build_root" "$clamav_root"
mkdir -p "$payload_root" "$build_root"
"$repo_root/packaging/fetch-clamav-linux.sh" "$clamav_root" "$cache_root"

$python_command -m PyInstaller \
    --noconfirm \
    --clean \
    --onedir \
    --windowed \
    --name "Local-First Antivirus" \
    --icon "$repo_root/assets/lfs-antivirus-aaha.svg" \
    --distpath "$payload_root" \
    --workpath "$build_root/work" \
    --specpath "$build_root/spec" \
    "$repo_root/lfs_antivirus_aaha/app.py"

bundle="$payload_root/Local-First Antivirus"
cp -a "$clamav_root" "$bundle/clamav"
mkdir -p "$bundle/licenses"
cp "$repo_root/LICENSE" "$bundle/licenses/AAHA-MIT.txt"
cp "$repo_root/packaging/licenses/GPL-2.0-only.txt" "$bundle/licenses/ClamAV-GPL-2.0-only.txt"
cp "$repo_root/packaging/requirements-build-linux.txt" "$bundle/licenses/Python-build-requirements.txt"

python_license=$($python_command - <<'PY'
import pathlib
import sys

candidates = (
    pathlib.Path(sys.base_prefix) / "LICENSE.txt",
    pathlib.Path(sys.base_prefix) / "LICENSE",
    pathlib.Path("/usr/share/doc/python3/copyright"),
    pathlib.Path(f"/usr/share/doc/python{sys.version_info.major}.{sys.version_info.minor}/copyright"),
)
for candidate in candidates:
    if candidate.is_file():
        print(candidate)
        break
else:
    raise SystemExit("Unable to locate the packaged Python runtime license.")
PY
)
cp "$python_license" "$bundle/licenses/Python-LICENSE.txt"

for runtime_license in /usr/share/doc/tcl*/copyright /usr/share/doc/tk*/copyright; do
    if [ -f "$runtime_license" ]; then
        runtime_name=$(basename "$(dirname "$runtime_license")")
        cp "$runtime_license" "$bundle/licenses/${runtime_name}-copyright.txt"
    fi
done
cp "$repo_root/NOTICE.md" "$repo_root/PRIVACY.md" "$repo_root/SECURITY.md" "$bundle/"
cp "$repo_root/packaging/THIRD_PARTY_NOTICES.md" "$bundle/"
mkdir -p "$repo_root/dist/release"
cp "$clamav_root/clamav-1.5.3.tar.gz" "$repo_root/dist/release/ClamAV-1.5.3-Corresponding-Source.tar.gz"
rm "$bundle/clamav/clamav-1.5.3.tar.gz"

source_commit=$(git rev-parse HEAD)
python3 - "$bundle/BUILD_INFO.json" "$source_commit" <<'PY'
import json
import pathlib
import platform
import sys

path, commit = sys.argv[1:]
value = {
    "app_name": "Local-First Antivirus",
    "app_version": "0.4.0-beta.1",
    "architecture": "linux-x86_64",
    "source_commit": commit,
    "python_version": platform.python_version(),
    "clamav_bundled": True,
    "clamav_version": "1.5.3",
}
pathlib.Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

$python_command -c 'import lfs_antivirus_aaha.app'
echo "Built Linux payload at $bundle"
