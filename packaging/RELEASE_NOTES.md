# Local-First Antivirus v0.4 Beta 1

Last Updated: 2026-08-05

This prerelease expands the read-only ClamAV interface to Linux and adds bounded,
per-item scan accounting. It is not endpoint protection.

## Included

- Windows x64 per-user installer using verified external ClamAV hashes
- AppImage/Flatpak x86-64 with pinned, hash-verified ClamAV 1.5.3
- Fedora x86-64 RPM/SRPM and shared-COPR-ready package using system ClamAV
- Bounded streaming traversal and explicit scanned/skipped/oversized/failed/
  cancelled accounting
- Staged, validated, atomic FreshClam update activation with rollback
- Package startup/lifecycle, dependency, checksum, and GPL compliance gates

## Limits and external gates

- No quarantine, restore, delete, real-time protection, service, scheduling,
  automatic remediation, Defender replacement, or application auto-update
- Flatpak scans only user-selected portal paths; no Flathub submission
- Windows artifacts are unsigned pending Technology Biased LLC Artifact Signing
- Physical Windows 10/11 acceptance and independent security review remain pending

Keep another supported endpoint-security product enabled. Review incomplete scan
categories and verify artifact checksums before use.
