# Architecture

Last Updated: 2026-07-29

## Summary

Local-First Antivirus `0.3.0-beta.1` is an unsigned Windows x64 prerelease. Its
single-process Python/Tkinter UI starts worker threads that supervise a
separately installed ClamAV command-line engine. The installer embeds the
Python/Tk runtime but not ClamAV. The application has no service, browser UI,
account, remote backend, telemetry, or automatic updater.

## Components

| Path | Responsibility |
| --- | --- |
| `lfs_antivirus_aaha/app.py` | Tkinter tabs, truthful state, worker events, cancellation |
| `lfs_antivirus_aaha/engine.py` | Exact executable validation and shell-free process supervision |
| `lfs_antivirus_aaha/scanner.py` | Safe scan argv, target validation, ClamAV output/exit parsing |
| `lfs_antivirus_aaha/updater.py` | FreshClam staging, validation, transactional activation/recovery |
| `lfs_antivirus_aaha/quarantine.py` | Read-only listing of preserved legacy records |
| `lfs_antivirus_aaha/storage.py` | Canonical/legacy data selection and atomic settings JSON |
| `lfs_antivirus_aaha/logger.py` | Local append-only activity summaries |
| `lfs_antivirus_aaha/models.py` | Findings, scan summaries, and legacy record models |

The earlier `definitions.py` module and bundled `definitions/signatures.json`
are removed. Production scanning no longer uses AAHA demo/hash/heuristic rules.

## External engine boundary

1. The user selects absolute `clamscan.exe` and `freshclam.exe` paths.
2. `engine.validate_installation()` requires exact filenames, normal files from
   one resolved local directory without mapped/UNC or link/reparse ancestry, and
   a ClamScan version response plus FreshClam's versioned help identity. The help
   route is required because FreshClam parses its configuration before handling
   `--version`, while `--help` exits before configuration parsing.
3. Every invocation passes a Python argument list to `subprocess.Popen` with
   `shell=False`, a disabled stdin, merged output, a hidden Windows console, and
   no `PATH` lookup.
4. Cancellation is polled while the process runs. POSIX gets a graceful process-
   group request followed by a forced stop; Windows stops the full process tree
   while the parent still identifies its descendants. Final waits are bounded.

Validation is session-local and does not verify Authenticode publisher at
runtime. Release automation pins and live-tests official ClamAV 1.5.3 x64; the
user still controls and must trust the exact installation selected at runtime.

## Scan flow

1. The UI requires a session-validated engine and ready Main/Daily database.
2. The selected target must exist, be a local file/directory, not use a mapped
   or UNC network location, not be the active application-data tree, and have no
   symbolic-link, junction, or reparse-point ancestry.
3. A worker invokes `clamscan` with the app-owned database, official-database-
   only mode, no archive expansion, no symlink following, no cross-filesystem
   traversal, infected-only output, and recursion only for a directory.
4. The adapter does not pass ClamAV quarantine/delete/copy options.
5. `FOUND` and `ERROR` lines are parsed at the first `: ` separator so a Windows
   drive-letter colon is preserved. `Scanned files` comes from ClamAV's summary.
6. Exit `0` means no infection reported; exit `1` requires a parsed finding;
   other or inconsistent results become visible errors.

ClamAV retains its own access and resource limits. This beta does not enumerate
the target independently, so it cannot yet reconcile every inaccessible or
internally skipped file. The UI says what ClamAV reported and warns on errors
rather than asserting complete system cleanliness.

## Definition-update flow

1. An update starts only after the user selects **Update Definitions** and takes
   a non-blocking OS lock shared by definition recovery/update operations in all
   app processes.
2. The current database is copied to a sibling staging directory so FreshClam
   can attempt an incremental update without touching the active database.
3. The app writes a minimal local `freshclam.conf` naming the staging directory
   and official `database.clamav.net` mirror.
4. A fixed-argv `freshclam` process runs with a 15-minute supervisor timeout.
5. Main and Daily database files must exist. A fixed-argv `clamscan` probe must
   load the staged official database and return clean.
6. An atomic control barrier ends the cancellable phase. Only then is a
   transaction marker written, the active directory renamed to
   a temporary `previous` location, and staging renamed active on the same
   volume. A caught activation failure restores the prior active directory.
7. After the new database is active, `previous` rotates to the backup location
   and the marker is removed. Startup recovery uses the marker plus the active,
   previous, and backup directories to finish or roll back an interrupted move.
8. Failure or cancellation before activation removes staging and does not
   replace active data.

FreshClam performs its own official database retrieval and database tests. The
application no longer downloads or parses CVD containers itself.

## State layout and legacy preservation

New state is rooted at `%LOCALAPPDATA%\AAHA\lfs-antivirus-aaha`:

- `settings.json`
- `logs/lfs-antivirus-aaha.log`
- `clamav-database/`
- `clamav-database.backup/` after a successful replacement
- transaction-only `.staging`/`.previous` directories and activation marker,
  removed after activation or recovery
- `clamav-database.lock`, a persistent coordination file whose OS lock is held
  only during recovery or a requested definition update
- a temporary `freshclam.conf` only while a requested update is active
- preserved `quarantine/` state, if any

`storage.app_data_dir()` uses `%LOCALAPPDATA%\LocalShieldAV` only when the
canonical directory does not exist and that legacy directory does. It does not
copy, merge, restore, or delete legacy state.

## Windows package and release gates

The package uses an exact Python 3.13.14 Windows x64 runner, pinned PyInstaller
inputs, a multi-resolution AAHA icon, and an Inno Setup 7.0.2 per-user installer.
The onedir bundle includes the AAHA, Python, and Tcl/Tk notices and deliberately
contains no Python source files, ClamAV executables, or definitions.

The release-candidate workflow verifies source tests and dependency audit,
executable metadata, the expected unsigned state, install and same-version
upgrade, visible UI launch and clean exit, uninstall, shortcut cleanup, and
preservation of canonical and legacy application state. A separate live gate
verifies the official ClamAV GitHub asset URL, published digest, and downloaded
installer hash, runs FreshClam against disposable state, and scans a benign
local probe. Release and evidence artifacts are produced by CI; the workflow
itself has read-only repository permissions and cannot publish a GitHub release.

## Deferred work

- Repeat UI and external-engine acceptance on clean physical Windows 10 and 11
  systems; current automated acceptance runs on GitHub's Windows runner.
- Expand redirected-output, cancellation/commit UI, access-denied, scan-limit,
  and large-target coverage beyond the current clean-probe release gate.
- Add executable publisher/provenance verification.
- Decide whether to build a new transactional, recoverable quarantine workflow.
- Provision an AAHA code-signing certificate and add signed-publisher gates.
- Real-time/on-access protection, privileged scans, services, scheduling,
  Security Center integration, telemetry, and automatic remediation remain out
  of scope.
