# Changelog

Last Updated: 2026-08-05

This file records user-visible and project-level changes to Local-First
Antivirus. The AAHA application program advances public source versions by
minor version rather than patch-only releases.

## [0.4.0-beta.1] - 2026-08-05

### Added

- AppImage and direct Flatpak x86-64 packages with pinned ClamAV 1.5.3.
- Native Fedora RPM/SRPM and shared COPR configuration using system ClamAV.
- Platform/runtime provider isolation, XDG state paths, and Flatpak portal selection.
- SHA-256 engine provenance manifests, pinned package/source hashes, GPLv2 text,
  corresponding source, and an automated Linux licensing-compliance gate.
- Bounded streaming traversal and terminal accounting for scanned, skipped,
  oversized, failed, and cancelled items.
- Isolated future Technology Biased LLC Artifact Signing integration.

### Changed

- Windows release packaging now embeds supported ClamAV executable hashes derived
  from the verified upstream installer and fails closed without its manifest.
- Managed AppImage/Flatpak engines are automatic; RPM resolves Fedora system ClamAV.
- FreshClam keeps staged validation, atomic activation, recovery, and rollback on
  every supported package type.
- User-visible limitations replace inert or unavailable controls.

### Release gates

- Added AppImage/Flatpak/RPM build, checksum, startup, update/removal, and state
  preservation workflows.
- Physical ordinary-user Windows 10/11, signed-artifact, and independent review
  gates remain external.

## [0.3.0-beta.1] - 2026-07-29

### Changed

- Replaced the demonstration Python hash/heuristic scanner with a read-only
  adapter for user-selected `clamscan.exe` and `freshclam.exe` paths.
- Added exact-path, same-directory, executable-name, and engine-identity
  validation without `PATH` lookup or shell invocation, including FreshClam's
  config-independent versioned help banner.
- Replaced direct CVD downloading/parsing with user-triggered FreshClam updates
  into an AAHA-owned staged database directory.
- Added candidate database validation, transaction-marked activation,
  interruption recovery/rollback, and preservation of the previous working
  database.
- Added a cross-process definition-operation lock and an atomic cancellation
  barrier before the non-cancellable database commit phase.
- Rejected mapped/UNC paths and symbolic-link, junction, or reparse-point
  ancestry for both scan targets and selected engine executables.
- Added bounded process-tree termination and cancellation sampling even when an
  external process exits at the same time as the cancellation request.
- Added ClamAV output and exit-code classification plus responsive process
  cancellation.
- Reworked the UI around truthful engine-required, definitions-required,
  scanning, cancellation, and failure states.

### Removed or disabled

- Removed bundled demo definitions, AAHA heuristic findings, manual definition
  import/export, broken direct CVD presets, and the inert App Update URL.
- Removed quarantine, restore, and delete operations from the active code path.
  Existing quarantine state remains preserved and visible read-only.
- Disabled archive expansion and rejected network, symbolic-link, and reparse-
  point scan targets for this minimal beta scope.

### Verification boundary

- Synthetic unit coverage now exercises engine validation, fixed argument
  construction, output/exit parsing, cancellation, FreshClam failure,
  database-validation failure, activation failure/recovery, rollback, retained
  accepted-scan state, process serialization, mapped/link path rejection,
  bounded forced shutdown, malformed legacy records, and legacy data-path
  preservation.
- Added Windows-only integration coverage for real cross-process locking,
  process-tree cancellation, and mapped-drive rejection.
- Added an exact Python 3.13.14/PyInstaller build, Inno Setup per-user installer,
  runtime notices, SHA-256 manifest, and release provenance metadata.
- Added automated install, same-version upgrade, visible UI launch/exit,
  uninstall, shortcut cleanup, unsigned-state, and application-state
  preservation gates.
- Added a live official ClamAV 1.5.3 x64 installer-provenance, FreshClam update,
  and benign clean-file scan gate. Physical Windows 10/11 and broader engine
  acceptance remain outside this release.

## [0.2.0] - 2026-07-29

- Renamed LocalShield AV to **Local-First Antivirus**.
- Adopted repository slug `lfs-antivirus-aaha`, package name
  `lfs_antivirus_aaha`, AAHA attribution, documentation, and Windows CI.
- Preserved existing legacy-only `%LOCALAPPDATA%\LocalShieldAV` state in place.
- Retained the earlier prototype scanner/update/quarantine limitations pending a
  later engineering pass.

## [0.1.0] - 2026-05-12

- Added the initial Windows Tkinter scanner prototype.
- Added local JSON definitions, findings, manual quarantine, settings, logs,
  compatible CVD hash conversion, and background definition updates.
