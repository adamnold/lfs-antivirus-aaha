# Local-First Antivirus

Local-First Antivirus is an open-source Windows desktop scanner from
**Adam And His Agents (AAHA)** and the **AAHA Local-First Series**. Its canonical
repository slug is `lfs-antivirus-aaha`.

The application uses Python and Tkinter to provide a native desktop UI. Scans
run on the local computer. Files and scan contents are not uploaded by the
scanner.

> [!IMPORTANT]
> Version 0.2.0 remains an early defensive-scanner prototype. It is not a
> replacement for Microsoft Defender or a supported commercial antivirus
> engine.

## Current capabilities

- Scan a selected local file or folder.
- Match SHA-256 hashes from the bundled JSON definitions.
- Match imported MD5, SHA-1, and SHA-256 file hashes.
- Match harmless local content signatures.
- Flag review-oriented heuristics such as risky script extensions and disguised
  double extensions.
- Quarantine, restore, or permanently delete files only through user-selected
  actions.
- Import, export, and reset JSON definitions.
- Display local status, scan findings, quarantine records, settings, and logs.

## Known limitations

- The configured direct ClamAV `daily.cvd` and `main.cvd` downloads are
  currently rejected by ClamAV's distribution service. The UI retains those
  source choices for the existing prototype, but network definition updates
  should be treated as unavailable until a supported update integration is
  implemented.
- The **App Update URL** setting is stored locally but is not consumed by an
  application-update mechanism.
- Only compatible file-hash entries are imported from ClamAV containers; this
  is not the ClamAV scanning engine and does not provide ClamAV-equivalent
  coverage.
- Archive scanning, real-time protection, Windows Security Center integration,
  scheduled scanning, and tamper protection are not implemented.
- No signed executable, MSI, or other release artifact is published yet.

See [Architecture](docs/ARCHITECTURE.md) for additional boundaries and known
technical debt.

## Local-first behavior

- Scans are read-only until the user explicitly chooses a quarantine action.
- Findings, settings, definitions, quarantine records, and logs remain on the
  local computer.
- There is no telemetry, analytics SDK, account system, or cloud scan service.
- Network access occurs only when the user explicitly starts a configured
  definitions update.

The complete commitments are documented in
[Local-First Series](docs/LOCAL_FIRST_SERIES.md) and [Privacy](PRIVACY.md).

## Requirements

- Windows 10 or Windows 11
- Python 3.10 or later available as `python`
- Tkinter included with the selected Python installation

The current source has not yet completed a Windows release acceptance pass.

## Run from source

From the repository root in PowerShell:

```powershell
.\run-lfs-antivirus-aaha.ps1
```

Or run the Python module directly:

```powershell
python -m lfs_antivirus_aaha.app
```

## Install for the current Windows user

```powershell
.\install-lfs-antivirus-aaha.ps1
```

The development installer copies the source tree to:

```text
%LOCALAPPDATA%\Programs\AAHA\lfs-antivirus-aaha
```

It then creates a **Local-First Antivirus** Start Menu shortcut. This is a
source-copy installer, not a signed Windows package.

## Local application data and legacy fallback

New installations use:

```text
%LOCALAPPDATA%\AAHA\lfs-antivirus-aaha
```

Version 0.2.0 deliberately does not move quarantine data automatically. If the
new AAHA directory does not exist and the legacy `%LOCALAPPDATA%\LocalShieldAV`
directory does exist, the application continues using the legacy directory in
place. This avoids stranding quarantine payloads or records during an automatic
copy. If both locations exist, the canonical AAHA directory is used; reconcile
legacy quarantine state manually before removing either directory.

## Safe detection test

Create a text file containing this harmless marker:

```text
LFS_ANTIVIRUS_AAHA_TEST_THREAT
```

Scan the folder containing that file. The expected finding is
`Local-First Antivirus Demo Test Signature`.

## Run tests

Tests write application state, so direct them to an isolated temporary
`LOCALAPPDATA` location when running outside CI.

```powershell
$env:LOCALAPPDATA = Join-Path $env:TEMP "lfs-antivirus-aaha-tests"
python -m unittest discover -s tests -v
```

## Repository layout

```text
lfs_antivirus_aaha/   Python package and Tkinter UI
definitions/          Bundled harmless demonstration definitions
tests/                Scanner, quarantine, and definition-conversion tests
docs/                 Architecture and Local-First Series documentation
.github/workflows/    Automated test workflow
```

## Security and contributions

- Review [SECURITY.md](SECURITY.md) before reporting a vulnerability.
- Review [CONTRIBUTING.md](CONTRIBUTING.md) before proposing changes.
- Changes are recorded in [CHANGELOG.md](CHANGELOG.md).

## License

Copyright 2026 Adam And His Agents (AAHA). Released under the
[MIT License](LICENSE). Third-party notices and attribution are in
[NOTICE.md](NOTICE.md).
