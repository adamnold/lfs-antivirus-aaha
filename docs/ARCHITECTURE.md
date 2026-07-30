# Architecture

## Summary

Local-First Antivirus is a single-process Python/Tkinter Windows desktop
prototype. The UI starts worker threads for scans and definition downloads while
Tkinter remains on the main thread. It has no service, browser UI, account, or
remote application backend.

## Components

| Path | Responsibility |
| --- | --- |
| `lfs_antivirus_aaha/app.py` | Tkinter window, tabs, user actions, worker events |
| `lfs_antivirus_aaha/scanner.py` | Recursive file enumeration, hashing, content matching, heuristics |
| `lfs_antivirus_aaha/definitions.py` | Definition validation, loading, import, export, reset |
| `lfs_antivirus_aaha/updater.py` | Definition-source catalog, download, compatible CVD hash conversion |
| `lfs_antivirus_aaha/quarantine.py` | Move, restore, and delete operations plus record files |
| `lfs_antivirus_aaha/storage.py` | Application-data selection, directories, settings JSON |
| `lfs_antivirus_aaha/logger.py` | Local append-only activity log |
| `lfs_antivirus_aaha/models.py` | Signatures, findings, summaries, quarantine records |
| `definitions/signatures.json` | Bundled demonstration definitions |

## Scan flow

1. The UI saves scanner settings and validates the selected path.
2. A worker creates `LocalScanner` with the active in-memory definitions.
3. The scanner enumerates files, reads eligible files, computes hashes, and
   evaluates content and heuristic rules.
4. Progress and the final `ScanSummary` return through an in-process queue.
5. Findings remain in memory until cleared or the application closes.
6. The user may explicitly request quarantine for a selected finding.

## State layout

New state is rooted at `%LOCALAPPDATA%\AAHA\lfs-antivirus-aaha`. Settings,
definitions, quarantine payloads and records, and logs live below that root.

For legacy preservation, `storage.app_data_dir()` uses
`%LOCALAPPDATA%\LocalShieldAV` only when the canonical AAHA directory does not
exist and the legacy directory does. It does not copy, merge, or delete state.

## Definition-update flow

The UI selects a source and starts a worker. Bundled definitions reset locally.
The two ClamAV presets attempt a direct CVD download, parse compatible hash
files, serialize them to local JSON, and replace the active user definition
file.

This flow is currently incomplete: the remote service rejects the direct
download method; container signatures are not verified; Main and Daily replace
rather than merge one another; and imports stop at a fixed hash count. These
limitations are documented but intentionally unchanged in the 0.2.0 branding
work.

## Known technical debt

- Directory enumeration is materialized before scanning and cannot be cancelled
  during enumeration.
- Inaccessible directories may be omitted without appearing in scan errors.
- Oversized files are counted as scanned rather than skipped.
- Archive scanning and the `scan_archives` definition flag are not implemented.
- Quarantine is not transactional and does not re-hash a file immediately before
  moving it.
- The application-data directory is not excluded automatically from broad scans.
- The App Update URL setting has no consumer.
- There is no packaged executable, code signing, installer upgrade path, or
  completed Windows UI acceptance suite.

## Security posture

The process runs with the privileges of the current user. It should not be run
as Administrator for routine scanning. It is a review-oriented local scanner,
not an isolation boundary or a full endpoint-protection engine.
