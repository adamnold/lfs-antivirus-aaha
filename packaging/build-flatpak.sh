#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_root"
builder=${FLATPAK_BUILDER:-flatpak-builder}
manifest="$repo_root/packaging/flatpak/com.aaha.lfs-antivirus-aaha.yml"
build_directory="$repo_root/build/flatpak/build"
repository="$repo_root/build/flatpak/repository"
release="$repo_root/dist/release/Local-First-Antivirus-v0.4.0-beta.1-x86_64.flatpak"

if [ ! -x "$repo_root/dist/linux-payload/Local-First Antivirus/Local-First Antivirus" ]; then
    echo "Build the Linux payload before the Flatpak." >&2
    exit 1
fi
rm -rf "$build_directory" "$repository"
rm -f "$release" "$release.sha256"
mkdir -p "$repo_root/dist/release"
if flatpak info --user org.flatpak.Builder >/dev/null 2>&1; then
    # Older Flatpak hosts do not always expand the Builder app's
    # xdg-data/flatpak grant to the user installation. Mount the exact user
    # installation so the pinned SDK remains visible inside the Builder.
    flatpak run --filesystem="$HOME/.local/share/flatpak" org.flatpak.Builder --user --force-clean --repo="$repository" --default-branch=beta "$build_directory" "$manifest"
elif command -v "$builder" >/dev/null 2>&1; then
    "$builder" --user --force-clean --repo="$repository" --default-branch=beta "$build_directory" "$manifest"
else
    echo "Install flatpak-builder or org.flatpak.Builder before building." >&2
    exit 1
fi
flatpak build-bundle "$repository" "$release" com.aaha.lfs-antivirus-aaha beta
(cd "$(dirname "$release")" && sha256sum "$(basename "$release")" > "$(basename "$release").sha256")
echo "Built $release"
