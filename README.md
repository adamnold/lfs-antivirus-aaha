# Local-First Antivirus

Last Updated: 2026-07-29

Local-First Antivirus is an open-source Windows desktop scanner from
**Adam And His Agents (AAHA)** and the **AAHA Local-First Series**. Its canonical
repository slug is `lfs-antivirus-aaha`.

> [!IMPORTANT]
> `0.3.0-beta.1` is an unsigned public prerelease. It is an on-demand interface
> for a separately installed ClamAV engine, not a replacement for Microsoft
> Defender or another supported security product. Verify the release checksum
> before running the installer and expect Windows to identify its publisher as
> unknown until AAHA provisions a code-signing certificate.

## What changed in this checkpoint

The earlier demonstration hash scanner and broken direct-CVD importer are no
longer active. The UI now:

- validates user-selected absolute paths to `clamscan.exe` and `freshclam.exe`;
- requires both executables to be real local files in the same installation
  folder and rejects mapped drives plus link/reparse-point ancestry;
- invokes them with fixed argument lists, `shell=False`, and no `PATH` lookup;
- runs read-only, user-selected local file or folder scans through ClamAV;
- reports ClamAV findings, ClamAV-reported scanned-file counts, exit errors, and
  cancellation without claiming a failed scan was clean;
- uses FreshClam for user-triggered official definition updates;
- serializes definition updates across app processes, stages and validates a
  candidate database before transactional activation, recovers interrupted
  activation on startup, and retains the previous working database as a local
  backup; and
- preserves existing quarantine files and records while showing them only in a
  read-only recovery view.

## Deliberately disabled or unavailable

- Quarantine, restore, and deletion controls are disabled. The earlier workflow
  was not transactional enough for safe use.
- The bundled AAHA demo definitions, heuristic findings, manual definition
  import/export, direct CVD downloads, and inert App Update URL are removed.
- Mapped/UNC targets and paths with symbolic-link, junction, or reparse-point
  ancestry are rejected. Recursive scans instruct ClamAV not to follow file or
  directory symlinks and not to cross filesystems.
- Archive/container expansion is disabled for this beta source checkpoint.
- There is no real-time or on-access protection, service, elevation, scheduled
  scan, automatic remediation, Security Center integration, tamper protection,
  telemetry, or application self-update.
- ClamAV applies its own engine limits. The UI does not yet enumerate and
  reconcile every file ClamAV may internally skip.
- Release automation validates the external adapter with official ClamAV 1.5.3
  x64. Other ClamAV versions have not completed release acceptance.

## Local-first and network behavior

Selected files are read locally by the external `clamscan.exe` process. AAHA
does not upload files, paths, hashes, findings, logs, settings, or quarantine
data, and the application contains no telemetry or account system.

Network access occurs only when the user presses **Update Definitions**.
`freshclam.exe` then contacts ClamAV's configured official database mirror. The
application does not implement automatic definition or application updates.

See [Privacy](PRIVACY.md), [Architecture](docs/ARCHITECTURE.md), and
[Local-First Series](docs/LOCAL_FIRST_SERIES.md) for the complete boundaries.

## Install the packaged beta

Download these two files from the GitHub `v0.3.0-beta.1` prerelease:

- `Local-First-Antivirus-v0.3.0-beta.1-Windows-x64-Setup.exe`
- `SHA256SUMS`

In PowerShell, verify the installer before opening it:

```powershell
(Get-FileHash .\Local-First-Antivirus-v0.3.0-beta.1-Windows-x64-Setup.exe -Algorithm SHA256).Hash.ToLowerInvariant()
Get-Content .\SHA256SUMS
```

The values must match. The per-user installer places the application below
`%LOCALAPPDATA%\Programs\AAHA\lfs-antivirus-aaha`, does not require elevation,
and preserves application state during upgrade and uninstall. It contains the
Python/Tk runtime needed by the UI, but does not contain ClamAV or definitions.

## Source requirements

- Windows 10 or Windows 11
- Python 3.10 or later available as `python`
- Tkinter included with the selected Python installation
- A separately installed ClamAV distribution containing `clamscan.exe` and
  `freshclam.exe` in the same directory

Neither source nor the packaged beta bundles ClamAV. Obtain ClamAV through the
[official ClamAV installation guidance](https://docs.clamav.net/manual/Installing.html)
and review its own license and security guidance.

## Run from source

From the repository root in PowerShell:

```powershell
.\run-lfs-antivirus-aaha.ps1
```

Or run the Python module directly:

```powershell
python -m lfs_antivirus_aaha.app
```

Then:

1. Open **ClamAV Engine**.
2. Select `clamscan.exe` and `freshclam.exe` from the same installation.
3. Select **Validate Exact Paths**.
4. Select **Update Definitions**. This is the only update action that uses the
   network.
5. Choose a local file or folder on **Scan** and start the on-demand scan.

Executable paths must be revalidated after each application start. Saved paths
are local convenience values, not a durable trust decision.

## Development source-copy installer

`install-lfs-antivirus-aaha.ps1` remains a development source-copy helper. It
copies this repository to:

```text
%LOCALAPPDATA%\Programs\AAHA\lfs-antivirus-aaha
```

It is not the packaged beta installer and remains outside the release artifact
set. Do not present it as a release download.

## Local data and legacy preservation

New installations use:

```text
%LOCALAPPDATA%\AAHA\lfs-antivirus-aaha
```

The active ClamAV database is stored below `clamav-database`; the previous
working database is retained below `clamav-database.backup` after a successful
replacement. Short-lived sibling staging/previous directories and an activation
marker make interrupted directory swaps recoverable on the next start. A
persistent lock file serializes recovery and definition updates across app
processes. Download and validation can be cancelled; once the atomic commit
phase begins, the app finishes or recovers it instead of interrupting the swap.

If the canonical AAHA directory does not exist and the legacy
`%LOCALAPPDATA%\LocalShieldAV` directory does, the application continues using
the legacy directory in place. It does not automatically move, restore, delete,
or reconcile old quarantine payloads. If both locations exist, the canonical
AAHA directory wins. Preserve both until legacy state has been reviewed safely.

## Run tests

The local tests use synthetic process output and temporary files; they do not
require ClamAV or live malware. Windows CI additionally exercises real
cross-process locking, process-tree cancellation, and mapped-drive rejection.
The release-candidate workflow builds the installer, tests install/upgrade/UI
launch/removal/state preservation, and runs a real clean-file scan after an
official FreshClam definition update.

```powershell
$env:LOCALAPPDATA = Join-Path $env:TEMP "lfs-antivirus-aaha-tests"
python -m unittest discover -s tests -v
python -m compileall -q lfs_antivirus_aaha tests
```

## Repository layout

```text
lfs_antivirus_aaha/   Tkinter UI, fixed-argv engine adapter, scanner, updater, state
tests/                Synthetic tests plus Windows release integration gates
assets/               Source vector and generated multi-resolution Windows icon
packaging/            Exact build inputs, installer, verification, notices, notes
docs/                 Architecture and Local-First Series documentation
.github/workflows/    Source validation and non-publishing release-candidate build
```

## Security and contributions

- Review [SECURITY.md](SECURITY.md) before reporting a vulnerability.
- Review [CONTRIBUTING.md](CONTRIBUTING.md) before proposing changes.
- Changes are recorded in [CHANGELOG.md](CHANGELOG.md).

## License

Copyright 2026 Adam And His Agents (AAHA). Released under the
[MIT License](LICENSE). The optional external ClamAV project is separate and is
licensed under its own terms; attribution is in [NOTICE.md](NOTICE.md).
