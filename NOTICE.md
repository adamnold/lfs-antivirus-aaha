# Notices

Last Updated: 2026-07-29

## Project identity

**Local-First Antivirus** is part of the **AAHA Local-First Series** from
**Adam And His Agents (AAHA)**.

Copyright 2026 Adam And His Agents (AAHA). The project source is licensed under
the MIT License in `LICENSE`.

## External ClamAV interoperability

Local-First Antivirus can invoke a separately installed ClamAV `clamscan` and
`freshclam` command-line installation selected by the user. ClamAV is a separate
project, is not bundled or linked into this repository, and retains its own
license, copyright, security guidance, distribution terms, and trademarks.

Local-First Antivirus is not ClamAV and is not affiliated with or endorsed by
Cisco Talos, Cisco Systems, or the ClamAV project. ClamAV's name is used only to
describe optional command-line interoperability.

The packaged Windows beta contains the Python runtime and Tcl/Tk UI components.
Their exact license texts are installed with the application under `licenses/`.
PyInstaller and Inno Setup are build tools and are not runtime endorsements.
See `packaging/THIRD_PARTY_NOTICES.md` for the packaged-runtime boundary.
