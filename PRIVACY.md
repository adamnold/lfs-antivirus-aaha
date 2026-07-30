# Privacy

Last Updated: 2026-07-29

Local-First Antivirus keeps application state and scanning activity on the
computer where it runs. This statement describes the public `0.3.0-beta.1`
source and packaged Windows x64 prerelease.

## Local processing

When the user starts a scan, the separately installed `clamscan.exe` process may
read the selected local file or folder and produce local output containing file
paths, ClamAV signature names, counts, and errors. Local-First Antivirus parses
that output in memory and records bounded activity summaries in its local log.
It does not upload scan targets or results.

The application stores exact validated ClamAV executable paths, display
preferences, the last accepted-scan timestamp, a bounded last-attempt outcome
(counts or a truncated local error that can include a path), official ClamAV
database files, local logs, and any preserved legacy quarantine records/payloads
in the active application-data directory. A minimal FreshClam configuration is
created only for an active user-requested update and removed when that attempt
ends.

New installations use:

```text
%LOCALAPPDATA%\AAHA\lfs-antivirus-aaha
```

An existing legacy-only installation continues to use:

```text
%LOCALAPPDATA%\LocalShieldAV
```

The application does not automatically migrate or delete either location.
The installer writes program files under
`%LOCALAPPDATA%\Programs\AAHA\lfs-antivirus-aaha`. Upgrade and uninstall do not
remove the application-data locations above.

## Network behavior

The application has no telemetry, analytics, advertising, cloud account,
remote scan service, or automatic application update.

Network access occurs only after the user selects **Update Definitions**. The
external `freshclam.exe` process may then contact ClamAV's configured official
database mirror and expose ordinary network metadata such as the source IP,
request time, requested database versions, and FreshClam user agent. AAHA does
not receive that traffic or add a second update request.

## File changes

Scanning is read-only. Definition updates write only within the active AAHA
application-data directory. A candidate database is staged and validated before
activation. Cancellation before the commit barrier does not replace the active
database. Once the short directory-commit phase begins it is deliberately not
interruptible; it completes or is recovered at the next start.

The earlier quarantine, restore, and delete implementations are not available
through this prerelease. Existing payloads and record files remain untouched
and are displayed read-only for later recovery work.

## External software boundary

ClamAV is separately installed software with its own behavior, security model,
configuration, update infrastructure, and privacy documentation. Local-First
Antivirus validates and invokes the exact paths the user selected; it does not
bundle, modify, or monitor ClamAV outside a user-requested scan or definition
update.
