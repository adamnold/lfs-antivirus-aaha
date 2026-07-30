# Privacy

Local-First Antivirus is designed to keep scanning and security data on the
computer where the application runs.

## Data processed locally

The application may process local file paths, file sizes, file contents, and
MD5, SHA-1, or SHA-256 hashes while scanning. It stores settings, active
definitions, quarantine payloads and records, scan timestamps, and local logs in
the active application-data directory.

New installations use:

```text
%LOCALAPPDATA%\AAHA\lfs-antivirus-aaha
```

An existing legacy-only installation continues to use:

```text
%LOCALAPPDATA%\LocalShieldAV
```

See `README.md` before changing or deleting either location because it may hold
quarantined files.

## Network behavior

The scanner does not upload files, paths, hashes, findings, logs, settings, or
quarantine data. It has no telemetry, analytics, advertising, cloud account, or
remote scan service.

A network request is made only when a user explicitly selects a definitions
source and starts an update. The remote service can then observe ordinary
network metadata such as the source IP address, request time, and application
user agent. The currently configured direct ClamAV download method is known to
be rejected and should be treated as unavailable.

The App Update URL setting is stored locally but is not currently used to make a
request.

## User-directed file changes

Scanning is read-only. Quarantine, restore, and permanent deletion occur only
after the user invokes the corresponding UI action. Quarantine and permanent
deletion require confirmation; restore is user-triggered but does not currently
display a second confirmation dialog.

## Scope

This statement describes version 0.2.0 source behavior. Review future release
notes and source changes before assuming later versions behave identically.
