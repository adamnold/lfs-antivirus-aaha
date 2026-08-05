# Architecture

Last Updated: 2026-08-05

## Boundaries

```text
Tkinter UI and platform context
  -> engine-provider resolution and provenance
  -> bounded traversal and scan accounting
  -> fixed-argv clamscan / freshclam child processes
  -> local definition and state directories
```

The application is a Python/Tk desktop process. It has no service, browser UI,
account, remote backend, telemetry, automatic updater, or linked `libclamav`.
ClamAV always runs as separate executables under the invoking user's authority.

## Platform and engine providers

`platform_support.py` isolates package detection, XDG/Windows paths, file
selection mode, process launching, and engine location.

- Windows uses exact user-selected `clamscan.exe`/`freshclam.exe` paths and an
  embedded release-generated executable-hash manifest in packaged builds.
- AppImage and Flatpak use package-owned ClamAV 1.5.3 executables and require
  their adjacent provenance manifest.
- RPM resolves Fedora's system `clamscan`/`freshclam` and records
  `system-package-and-version` provenance.

Validation requires the two executables in one directory, fixed expected names,
SHA-256 values, ClamScan version identity, and FreshClam help identity. Bundled
or packaged Windows engines fail closed if their manifest is missing or hashes
differ. Release automation verifies the upstream Windows installer and, when
provided upstream, its Authenticode publisher before producing the manifest.

All invocations use argument arrays, `shell=False`, closed stdin, bounded waits,
and process-tree cancellation. POSIX uses a new process group; Windows uses
bounded tree termination while the parent still identifies descendants.

## Bounded scan flow

1. Validate a selected local regular file/directory outside application state.
2. Stream directory entries through a bounded stack of `scandir` iterators.
3. Classify links/non-regular files as skipped, files over 100 MiB as oversized,
   and metadata/access errors as failed.
4. Send at most 64 files and 20,000 argument characters per ClamAV batch.
5. Invoke ClamAV with official-database-only mode, archive scanning disabled,
   no link following, a 400 MiB per-file scan expansion limit, and no
   cross-filesystem traversal.
6. Parse findings/errors and reconcile every enumerated item into one terminal
   accounting state. Missing terminal ClamAV results become failures.

Cancellation accounts for unscanned batch items. Clean exit with infection
output, infected exit without a parseable finding, incomplete summary output,
timeout, or non-0/1 exit becomes a visible error. No destructive ClamAV option
is passed.

## Definition transaction

FreshClam writes only into a sibling staging directory. The app verifies Main
and Daily database presence and loads the candidate through ClamAV before an
atomic same-filesystem activation. A lock serializes recovery/updates across
processes. The prior active set rotates to a backup; a transaction marker plus
active/previous/backup directories allows startup to finish or roll back an
interrupted activation.

## Packaging

The stable app ID is `com.aaha.lfs-antivirus-aaha`.

- AppImage/Flatpak payloads are built on Ubuntu 22.04 with pinned Python and
  ClamAV 1.5.3 binaries. The AppImage tool and type-2 runtime are pinned by hash.
- Flatpak pins Freedesktop 25.08 and grants network/display/portal access but no
  broad host filesystem path.
- RPM installs Python source/UI with Fedora `python3-tkinter`, `clamav`, and
  `clamav-freshclam` dependencies; user state is never package-owned.
- Windows uses PyInstaller and a stable per-user Inno Setup AppId. Signing is an
  isolated optional layer whose accepted legal identity is Technology Biased LLC.

The ClamAV official package hash, corresponding-source hash, executable hashes,
GPLv2 text, notices, and source archive are enforced by
`verify-linux-compliance.py`. ClamAV is aggregated, not linked into AAHA code.

Platform paths, process control, engine selection, icons, and packaging remain
outside scan/update logic. Future macOS work adds an Apple packaging/signing and
file-selection layer rather than another application redesign.

## Deliberately absent and external gates

Quarantine/restore/delete, real-time/on-access protection, privileged scans,
services, scheduling, automatic remediation, Security Center integration, and
Defender-replacement claims are absent. Physical ordinary-user Windows 10/11,
future signed-artifact verification, and independent security review remain
external acceptance gates.
