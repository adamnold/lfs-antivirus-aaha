"""Exercise the real external ClamAV boundary in disposable Windows state."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from lfs_antivirus_aaha.engine import validate_installation
from lfs_antivirus_aaha.scanner import ClamAvScanner
from lfs_antivirus_aaha.updater import FreshClamUpdater


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--clamscan", required=True, type=Path)
    parser.add_argument("--freshclam", required=True, type=Path)
    parser.add_argument("--scan-root", required=True, type=Path)
    parser.add_argument("--evidence", required=True, type=Path)
    args = parser.parse_args()

    if os.name != "nt":
        raise RuntimeError("The live ClamAV gate is a Windows-only release check.")

    installation = validate_installation(args.clamscan, args.freshclam)
    update = FreshClamUpdater(
        freshclam_path=installation.freshclam_path,
        clamscan_path=installation.clamscan_path,
    ).update()
    if not update.database_status.ready:
        raise RuntimeError("FreshClam did not activate a ready official database.")

    args.scan_root.mkdir(parents=True, exist_ok=True)
    probe = args.scan_root / "aaha-clean-probe.txt"
    probe.write_text(
        "AAHA Local-First Antivirus clean integration probe.\n",
        encoding="utf-8",
    )
    summary = ClamAvScanner(
        clamscan_path=installation.clamscan_path,
        database_dir=FreshClamUpdater(
            freshclam_path=installation.freshclam_path,
            clamscan_path=installation.clamscan_path,
        ).database_dir,
        engine_version=installation.clamscan_version,
    ).scan_path(probe)

    if summary.exit_code != 0:
        raise RuntimeError(f"The clean probe returned ClamAV exit code {summary.exit_code}.")
    if summary.cancelled or summary.errors or summary.findings:
        raise RuntimeError("The clean probe did not produce a clean, complete scan result.")
    if summary.files_scanned < 1:
        raise RuntimeError("ClamAV did not report scanning the clean probe.")

    evidence = {
        "schema_version": 1,
        "clamav_version": installation.clamscan_version,
        "freshclam_version": installation.freshclam_version,
        "official_database_ready": update.database_status.ready,
        "official_database_file_count": update.database_status.file_count,
        "clean_probe_files_scanned": summary.files_scanned,
        "clean_probe_findings": len(summary.findings),
        "clean_probe_errors": len(summary.errors),
        "clean_probe_exit_code": summary.exit_code,
    }
    args.evidence.parent.mkdir(parents=True, exist_ok=True)
    args.evidence.write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
