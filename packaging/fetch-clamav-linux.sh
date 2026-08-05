#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
    echo "usage: $0 OUTPUT_DIRECTORY CACHE_DIRECTORY" >&2
    exit 2
fi

output_directory=$1
cache_directory=$2
version=1.5.3
deb_name="clamav-${version}.linux.x86_64.deb"
source_name="clamav-${version}.tar.gz"
deb_sha256=0c69e033a976855cfecfa1b6c36563822f2cc618f0c7e40ce5bcc2703d0dc436
source_sha256=89af57a45bbf13de4dc91ed7f20b435388c88428eb7dc30639a02b2f0fc2dad1
release_root="https://github.com/Cisco-Talos/clamav/releases/download/clamav-${version}"

mkdir -p "$cache_directory"
deb_path="$cache_directory/$deb_name"
source_path="$cache_directory/$source_name"

if [ ! -f "$deb_path" ]; then
    curl --fail --location --proto '=https' --tlsv1.2 "$release_root/$deb_name" --output "$deb_path"
fi
printf '%s  %s\n' "$deb_sha256" "$deb_path" | sha256sum --check --status

if [ ! -f "$source_path" ]; then
    curl --fail --location --proto '=https' --tlsv1.2 "$release_root/$source_name" --output "$source_path"
fi
printf '%s  %s\n' "$source_sha256" "$source_path" | sha256sum --check --status

extract_directory="$output_directory.extract"
rm -rf "$extract_directory" "$output_directory"
mkdir -p "$extract_directory" "$output_directory"
if command -v dpkg-deb >/dev/null 2>&1; then
    dpkg-deb --extract "$deb_path" "$extract_directory"
else
    archive_directory="$extract_directory/archive"
    mkdir -p "$archive_directory"
    (
        cd "$archive_directory"
        ar x "$deb_path"
        data_archive=$(find . -maxdepth 1 -type f -name 'data.tar.*' -print -quit)
        if [ -z "$data_archive" ]; then
            echo "The verified Debian package has no data archive." >&2
            exit 1
        fi
        tar -xf "$data_archive" -C "$extract_directory"
    )
    rm -rf "$archive_directory"
fi

clamscan_path=$(find "$extract_directory" -type f -path '*/bin/clamscan' -print -quit)
freshclam_path=$(find "$extract_directory" -type f -path '*/bin/freshclam' -print -quit)
if [ -z "$clamscan_path" ] || [ -z "$freshclam_path" ]; then
    echo "The verified ClamAV package did not contain clamscan and freshclam." >&2
    exit 1
fi
clamav_root=$(dirname "$(dirname "$clamscan_path")")
cp -a "$clamav_root/." "$output_directory/"

clamscan_hash=$(sha256sum "$output_directory/bin/clamscan" | awk '{print $1}')
freshclam_hash=$(sha256sum "$output_directory/bin/freshclam" | awk '{print $1}')
python3 - "$output_directory/manifest.json" "$version" "$deb_name" "$deb_sha256" "$source_name" "$source_sha256" "$clamscan_hash" "$freshclam_hash" <<'PY'
import json
import pathlib
import sys

path, version, package, package_hash, source, source_hash, scan_hash, fresh_hash = sys.argv[1:]
payload = {
    "schema_version": 1,
    "provider": "Cisco Talos ClamAV official release",
    "version": version,
    "package": package,
    "package_sha256": package_hash,
    "source": source,
    "source_sha256": source_hash,
    "source_url": f"https://github.com/Cisco-Talos/clamav/releases/download/clamav-{version}/{source}",
    "clamscan_sha256": scan_hash,
    "freshclam_sha256": fresh_hash,
}
pathlib.Path(path).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

cp "$source_path" "$output_directory/$source_name"
rm -rf "$extract_directory"
