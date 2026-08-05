#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_root"
appimagetool=${APPIMAGETOOL:-appimagetool}
runtime=${APPIMAGE_RUNTIME:-}
payload="$repo_root/dist/linux-payload/Local-First Antivirus"
appdir="$repo_root/build/appimage/Local-First-Antivirus.AppDir"
release="$repo_root/dist/release/Local-First-Antivirus-v0.4.0-beta.1-x86_64.AppImage"

if [ ! -x "$payload/Local-First Antivirus" ]; then
    echo "Build the Linux payload before the AppImage." >&2
    exit 1
fi
if [ ! -f "$runtime" ]; then
    echo "APPIMAGE_RUNTIME must point to the pinned type-2 x86-64 runtime." >&2
    exit 1
fi
rm -rf "$appdir"
rm -f "$release" "$release.sha256"
mkdir -p "$appdir/usr/bin" "$appdir/usr/libexec/lfs-antivirus-aaha" "$appdir/usr/share/applications" "$appdir/usr/share/icons/hicolor/scalable/apps" "$appdir/usr/share/metainfo" "$repo_root/dist/release"
cp -a "$payload" "$appdir/usr/libexec/lfs-antivirus-aaha/app"
cp "$repo_root/packaging/linux/local-first-antivirus" "$appdir/usr/bin/local-first-antivirus"
cp "$repo_root/packaging/linux/com.aaha.lfs-antivirus-aaha.desktop" "$appdir/usr/share/applications/"
cp "$repo_root/packaging/linux/com.aaha.lfs-antivirus-aaha.metainfo.xml" "$appdir/usr/share/metainfo/"
cp "$repo_root/packaging/linux/com.aaha.lfs-antivirus-aaha.metainfo.xml" "$appdir/usr/share/metainfo/com.aaha.lfs-antivirus-aaha.appdata.xml"
cp "$repo_root/assets/lfs-antivirus-aaha.svg" "$appdir/usr/share/icons/hicolor/scalable/apps/com.aaha.lfs-antivirus-aaha.svg"
cp "$repo_root/packaging/linux/com.aaha.lfs-antivirus-aaha.desktop" "$appdir/com.aaha.lfs-antivirus-aaha.desktop"
cp "$repo_root/assets/lfs-antivirus-aaha.svg" "$appdir/com.aaha.lfs-antivirus-aaha.svg"
ln -s com.aaha.lfs-antivirus-aaha.svg "$appdir/.DirIcon"
cp "$repo_root/packaging/linux/local-first-antivirus" "$appdir/AppRun"
chmod 0755 "$appdir/AppRun" "$appdir/usr/bin/local-first-antivirus"

ARCH=x86_64 "$appimagetool" --runtime-file "$runtime" "$appdir" "$release"
(cd "$(dirname "$release")" && sha256sum "$(basename "$release")" > "$(basename "$release").sha256")
echo "Built $release"
