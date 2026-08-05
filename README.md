# Local-First Antivirus

Last Updated: 2026-08-05

Local-First Antivirus is an open-source, on-demand desktop scanner from
**Adam And His Agents (AAHA)** and the **AAHA Local-First Series**. Its canonical
repository slug is `lfs-antivirus-aaha`.

> [!IMPORTANT]
> `0.4.0-beta.1` is an unsigned prerelease, not real-time protection and not a
> replacement for Microsoft Defender or another supported endpoint-security
> product. Keep established protection enabled and review every skipped,
> oversized, failed, or cancelled item before interpreting a scan.

## Platforms and engine providers

All releases invoke ClamAV as separate command-line executables; the application
does not link `libclamav`.

- **Windows 10/11 x64:** verified separately installed ClamAV. Release tooling
  verifies the supported upstream installer/signature, captures exact executable
  SHA-256 values, and embeds that allow-manifest into the unsigned installer.
- **AppImage x86-64:** bundled, pinned ClamAV 1.5.3 executable payload.
- **Flatpak x86-64:** the same pinned ClamAV payload with portal-only selected
  file/folder access and no broad host filesystem permission.
- **Fedora RPM/COPR x86-64:** Fedora's system `clamav` and `clamav-freshclam`
  packages, with their package provenance retained as the trust boundary.

The AppImage/Flatpak payload verifies `clamscan` and `freshclam` against its
generated SHA-256 manifest at every application start. The corresponding
ClamAV 1.5.3 source archive, GPLv2 text, exact package/source hashes, build
metadata, and notices are release requirements.

## Scan behavior

- Scans are local, read-only, on-demand, and limited to a selected file/folder.
- Directory traversal streams entries with bounded open iterators and batches;
  it does not construct an unbounded inventory.
- Every enumerated item is reconciled as scanned, skipped, oversized, failed,
  or cancelled. Unreadable files are failures; files above 100 MiB are reported
  separately. A failed or incomplete scan is never presented as clean.
- Symbolic links are not followed. Network/UNC targets, link/reparse-point target
  ancestry, cross-filesystem traversal, and archive expansion are disabled.
- Cancellation terminates the external process tree and accounts for remaining
  batch items.
- Quarantine, restore, deletion, real-time protection, scheduling, elevation,
  Defender replacement, Security Center integration, and automatic remediation
  are absent. Existing legacy quarantine data is visible read-only.

## Definition updates

The user-visible **Update Definitions** action starts FreshClam. The candidate
database is staged separately, checked for Main/Daily files, loaded by ClamAV,
and atomically activated. The previous working set is retained. A transaction
marker and startup recovery finish or roll back an interrupted activation;
updates are serialized across app processes. The commit phase is deliberately
non-cancellable once its atomic barrier begins.

This is the application's only network action. It contacts ClamAV's configured
official database mirror. The application has no AAHA telemetry, analytics,
cloud account, remote scan, or automatic application updater.

## Install the beta

Download the appropriate x86-64 artifact and checksum from the
`v0.4.0-beta.1` GitHub prerelease.

AppImage (Ubuntu 22.04 or newer, Debian 12 or newer, current Fedora):

```sh
sha256sum -c Local-First-Antivirus-v0.4.0-beta.1-x86_64.AppImage.sha256
chmod 0755 Local-First-Antivirus-v0.4.0-beta.1-x86_64.AppImage
./Local-First-Antivirus-v0.4.0-beta.1-x86_64.AppImage
```

Flatpak bundle:

```sh
sha256sum -c Local-First-Antivirus-v0.4.0-beta.1-x86_64.flatpak.sha256
flatpak install --user ./Local-First-Antivirus-v0.4.0-beta.1-x86_64.flatpak
flatpak run com.aaha.lfs-antivirus-aaha
```

Fedora RPM or shared COPR:

```sh
sudo dnf install ./lfs-antivirus-aaha-0.4.0-0.1.beta1*.x86_64.rpm
local-first-antivirus
```

Windows PowerShell:

```powershell
(Get-FileHash .\Local-First-Antivirus-v0.4.0-beta.1-Windows-x64-Setup.exe -Algorithm SHA256).Hash.ToLowerInvariant()
Get-Content .\SHA256SUMS
```

The Windows installer is per-user and unsigned until **Technology Biased LLC**
completes Microsoft Artifact Signing. Expect an unknown-publisher warning. It
does not bundle ClamAV. Application state is outside the installed program
directory and is preserved by upgrade and uninstall.

Flatpak is distributed directly, not submitted to Flathub. It can scan only
paths explicitly granted through the desktop file chooser portal. AppImage and
RPM can scan any selected path readable by the invoking user.

## Local data

Windows uses `%LOCALAPPDATA%\AAHA\lfs-antivirus-aaha`. Linux follows XDG data,
config, and state directories. Definitions, prior-definition backup, settings,
bounded activity logs, and preserved legacy quarantine state remain local.

If the Windows canonical directory is absent but `%LOCALAPPDATA%\LocalShieldAV`
exists, the legacy directory continues in place. The application does not
automatically move, merge, restore, or delete legacy state.

## Run and verify from source

Python 3.10+ with Tkinter is required. Windows source use requires a supported
ClamAV installation; Fedora source/RPM use system ClamAV.

```sh
python -m lfs_antivirus_aaha.app
python -m unittest discover -s tests -v
python -m compileall -q lfs_antivirus_aaha packaging tests
```

Linux release builders use pinned PyInstaller inputs, a pinned AppImage tool and
runtime, Freedesktop 25.08 Flatpak runtime, and ClamAV package/source hashes.
`packaging/verify-linux-compliance.py` is the bundled-GPL release gate.

## Release boundaries

The next-minor beta remains “implementation complete; external gates pending”
until physical ordinary-user Windows 10/11 acceptance, Technology Biased LLC
Artifact Signing verification, and the independent security-review gate pass.
Source/package tests do not replace those external gates.

See [Privacy](PRIVACY.md), [Security](SECURITY.md),
[Architecture](docs/ARCHITECTURE.md), and [Notices](NOTICE.md).

## License

AAHA source is released under the [MIT License](LICENSE). Bundled AppImage and
Flatpak distributions aggregate separately licensed ClamAV GPLv2 executables;
see [packaged runtime notices](packaging/THIRD_PARTY_NOTICES.md). The RPM uses
Fedora's separately packaged ClamAV.
