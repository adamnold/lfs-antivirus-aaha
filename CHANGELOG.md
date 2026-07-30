# Changelog

This file records user-visible and project-level changes to Local-First
Antivirus. The AAHA application program advances source versions by minor
version rather than patch version.

## [0.2.0] - Unreleased

### Changed

- Renamed LocalShield AV to **Local-First Antivirus**.
- Adopted the canonical repository slug `lfs-antivirus-aaha` and Python package
  name `lfs_antivirus_aaha`.
- Added Adam And His Agents (AAHA) and Local-First Series attribution to the UI,
  installer, source identifiers, documentation, and test definitions.
- Renamed run and install scripts for the new repository identity.
- Changed new-install application data, log, temporary-file, and HTTP user-agent
  identifiers to the AAHA naming scheme.
- Added public-project documentation and continuous-integration configuration.

### Preserved

- Existing legacy-only `%LOCALAPPDATA%\LocalShieldAV` state is used in place
  rather than moved automatically, protecting quarantine records from a partial
  migration.

### Known limitations

- Direct ClamAV definition downloads remain unavailable because the configured
  download method is rejected by ClamAV's distribution service.
- The App Update URL setting remains storage-only and does not update the app.
- Scanner, updater, quarantine, packaging, and Windows acceptance gaps documented
  in `README.md` and `docs/ARCHITECTURE.md` remain intentionally unfixed in this
  branding release.

## [0.1.0] - 2026-05-12

- Added the initial Windows Tkinter scanner prototype.
- Added local JSON definitions, scan findings, manual quarantine, settings, and
  logs.
- Added compatible ClamAV hash-signature conversion and background definition
  updates.
