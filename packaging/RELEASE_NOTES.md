# Local-First Antivirus v0.3 Beta 1

Last Updated: 2026-07-29

This is the first packaged AAHA Local-First Antivirus beta and remains an
on-demand scanner interface, not complete endpoint protection.

## What is included

- A Python-free Windows x64 per-user installer for the AAHA application.
- Exact-path integration with a separately installed ClamAV command-line engine.
- Read-only local scans, user-triggered official FreshClam definition updates,
  failure-safe database activation/recovery, and read-only display of preserved
  legacy quarantine records.

## Required external software

Install ClamAV separately from its official distribution. Release verification
uses ClamAV 1.5.3 x64. ClamAV and its definitions are not bundled in this
release.

## Important limitations

- The installer and application executable are not code-signed. Windows may
  show Unknown Publisher or SmartScreen warnings; verify `SHA256SUMS` before use.
- Keep Microsoft Defender or another supported security product enabled.
- There is no real-time protection, service, scheduling, automatic remediation,
  Security Center integration, app self-update, or active quarantine workflow.
- Archive expansion and network/link-indirected scan targets remain disabled.
- Scan completeness and resource limits ultimately depend on ClamAV; review any
  displayed scan errors before treating a result as complete.

Uninstall removes the program and shortcuts but deliberately preserves local
settings, logs, definitions, backups, and legacy quarantine state.
