# Notices

Last Updated: 2026-08-05

**Local-First Antivirus** is part of the **AAHA Local-First Series** from
**Adam And His Agents (AAHA)**. AAHA source is Copyright 2026 Adam And His
Agents (AAHA) and licensed under the repository MIT License.

## ClamAV

Local-First Antivirus interoperates with Cisco Talos ClamAV through separate
`clamscan` and `freshclam` executables. It does not link `libclamav` and is not
affiliated with or endorsed by Cisco Talos, Cisco Systems, or the ClamAV project.

The AppImage and Flatpak aggregate the pinned official ClamAV 1.5.3 Linux x86-64
executable distribution under GPLv2. Each release includes the GPLv2 license,
exact package/source/executable hashes, provenance manifest, and corresponding
source archive. The RPM depends on Fedora's separately distributed ClamAV
packages. Windows requires a separately installed ClamAV whose supported hashes
are derived from a verified upstream installer.

Python, Tcl/Tk, PyInstaller, Inno Setup, AppImage, Flatpak, and other dependencies
remain subject to their own licenses. See `packaging/THIRD_PARTY_NOTICES.md` and
packaged license files.

Unsigned Windows artifacts are prepared for future signing only under the exact
legal identity **Technology Biased LLC**. No signing credentials or secrets are
included.
