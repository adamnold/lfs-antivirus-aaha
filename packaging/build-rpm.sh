#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_root"
topdir="$repo_root/build/rpmbuild"
source_name="lfs-antivirus-aaha-0.4.0-beta.1"
source_archive="$topdir/SOURCES/$source_name.tar.gz"
spec="$repo_root/packaging/rpm/lfs-antivirus-aaha.spec"

rm -rf "$topdir"
mkdir -p "$topdir/BUILD" "$topdir/BUILDROOT" "$topdir/RPMS" "$topdir/SOURCES" "$topdir/SPECS" "$topdir/SRPMS" "$topdir/TMP" "$repo_root/dist/release"
git archive --format=tar.gz --prefix="$source_name/" HEAD > "$source_archive"
cp "$spec" "$topdir/SPECS/"
rpmbuild --define "_topdir $topdir" --define "_tmppath $topdir/TMP" -ba "$topdir/SPECS/lfs-antivirus-aaha.spec"

find "$topdir/RPMS" -type f -name '*.rpm' -exec cp {} "$repo_root/dist/release/" \;
find "$topdir/SRPMS" -type f -name '*.src.rpm' -exec cp {} "$repo_root/dist/release/" \;
(cd "$repo_root/dist/release" && sha256sum lfs-antivirus-aaha-*.rpm > RPM-SOURCE-and-x86_64.sha256)
echo "Built RPM and SRPM under $repo_root/dist/release"
