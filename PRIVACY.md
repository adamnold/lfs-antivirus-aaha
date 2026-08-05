# Privacy

Last Updated: 2026-08-05

Local-First Antivirus `0.4.0-beta.1` processes selected scan targets on the
device. It has no AAHA telemetry, analytics, advertising, cloud account, remote
scan service, or automatic application update.

## Local processing and state

The selected ClamAV provider reads only the file/folder paths included in a
user-requested scan. The application parses local output containing paths,
signature names, counts, and errors, and stores bounded local activity summaries.
It does not upload scan content, paths, hashes, findings, settings, or logs.

Definitions, the prior working definition backup, settings, logs, and preserved
legacy quarantine records remain in OS-managed application-data locations.
Windows uses `%LOCALAPPDATA%\AAHA\lfs-antivirus-aaha` (or a pre-existing
legacy-only `%LOCALAPPDATA%\LocalShieldAV`). Linux follows XDG data, config, and
state paths. Package upgrade/removal does not intentionally delete user state.

Scanning does not modify targets. Quarantine, restore, and deletion actions are
absent. Definition updates write only within application state, stage and verify
a candidate, then atomically activate or recover/roll back it.

## Network and package boundaries

Network access occurs only when the user selects **Update Definitions**.
FreshClam then contacts its configured official ClamAV database mirror, which
receives ordinary request metadata. AAHA does not receive that traffic.

AppImage and RPM can access selected paths readable by the user. Flatpak has no
broad host filesystem permission; the desktop file chooser portal grants only
explicitly selected files/folders. Bundled ClamAV is a separate GPLv2 component
with its own behavior and update service.
