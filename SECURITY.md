# Security Policy

Last Updated: 2026-08-05

Local-First Antivirus `0.4.0-beta.1` is an on-demand prerelease. Do not use it as
the only protection on a production system or disable Microsoft Defender or
another supported security product to test it.

## Reporting

Use GitHub's private **Report a vulnerability** feature if available. Otherwise
request private contact through the repository owner’s profile without posting
exploit details. Include the affected commit/package, OS, ClamAV version/provider,
safe synthetic reproduction, and impact. Do not send malware, private paths,
credentials, or personal data.

## Safeguards and trust boundaries

- ClamAV always runs as separate executables; AAHA does not link `libclamav`.
- Windows packaged builds validate exact executable hashes derived from the
  release-verified upstream installer. AppImage/Flatpak validate bundled
  ClamAV 1.5.3 hashes against a package manifest. RPM uses Fedora's system
  ClamAV package provenance.
- Fixed argument arrays and `shell=False` are mandatory. The app never invokes
  ClamAV destructive move/copy/remove options.
- Streaming traversal is bounded. Links are not followed; unreadable, skipped,
  oversized, failed, scanned, and cancelled items are reconciled explicitly.
- Clean, infected, incomplete, inconsistent, timed-out, and cancelled results
  remain distinct. Errors are not styled or recorded as clean scans.
- FreshClam candidates are staged, loaded by ClamAV, and atomically activated.
  The previous working database, transaction marker, cross-process lock, and
  startup recovery provide rollback.
- Flatpak has no broad host filesystem permission. Selected paths arrive through
  the desktop portal. AppImage/RPM remain limited by invoking-user access.
- Quarantine, restore, delete, real-time protection, services, elevation,
  scheduling, and automatic remediation are absent.

## Release and remaining limits

Bundled release artifacts must pass source tests, dependency audit, executable
hash/provenance checks, GPLv2/corresponding-source compliance, package startup,
and lifecycle tests. Windows artifacts remain unsigned pending Technology
Biased LLC Microsoft Artifact Signing.

ClamAV signatures and engines can have false positives, false negatives, parsing
bugs, and resource limits. The app does not guarantee system cleanliness. A
formal independent security review and physical ordinary-user Windows 10/11
acceptance remain external gates.
