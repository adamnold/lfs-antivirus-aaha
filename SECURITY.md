# Security Policy

Last Updated: 2026-07-29

Local-First Antivirus is an early on-demand scanner UI. Do not use it as the
only protection on a production Windows system, and do not disable Microsoft
Defender or another supported security product to test it.

## Supported prerelease

Security fixes are accepted against the public `0.3.0-beta.1` source and Windows
x64 prerelease. It is an unsigned beta without a long-term support commitment.
Verify its published SHA-256 checksum, keep an established endpoint-protection
product enabled, and do not bypass organizational software-execution policy.

## Report a vulnerability

Use GitHub's private **Report a vulnerability** feature if it is available for
this repository. Otherwise contact the repository owner privately through their
GitHub profile. Do not publish exploit details, malware samples, private paths,
credentials, or personal data in an issue.

Include only the minimum needed to reproduce the problem:

- affected source version or commit;
- Windows, Python, and external ClamAV versions;
- affected component and expected behavior;
- safe reproduction steps using synthetic files/output; and
- likely impact.

Do not send live malware.

## Trust boundaries and safeguards

- ClamAV is separately installed and retains its own license and trust boundary.
- The application accepts only absolute files named `clamscan.exe` and
  `freshclam.exe` from the same directory, validates version responses, and
  invokes fixed argument lists with `shell=False`. It never searches `PATH` and
  rejects mapped/UNC drives plus link, junction, or reparse-point ancestry.
- Engine validation confirms identity signals, not publisher signature or
  provenance. Users must obtain ClamAV from a trusted official distribution.
  The release workflow separately verifies the official ClamAV 1.5.3 GitHub
  release asset URL, published digest, and downloaded MSI hash for acceptance;
  that build-time check does not replace runtime provenance validation.
- Scans do not pass ClamAV's destructive `--remove`, `--move`, or `--copy`
  options. Archive expansion and symlink following are disabled.
- Scan exit `0` is clean, `1` is infected only with a parseable `FOUND` line,
  and other or inconsistent results are errors. A failed scan is not presented
  as clean.
- FreshClam updates occur in a staging directory. The candidate is checked for
  Main and Daily databases and loaded by ClamAV before activation. The previous
  active database is retained as a backup. A local transaction marker and
  startup recovery finish or roll back an interrupted directory activation.
- An OS-level file lock serializes recovery and definition updates across app
  processes. Cancellation terminates external work and removes staging before
  the commit barrier. The directory commit itself is non-cancellable and is
  completed or recovered rather than interrupted.
- Legacy quarantine state is visible read-only. This checkpoint exposes no
  quarantine, restore, or delete action.

## Remaining security limits

- ClamAV 1.5.3 x64 has live release-workflow acceptance; compatibility with
  other releases remains unverified.
- Executable publisher/signature validation is not implemented.
- Recursive scan completeness depends on ClamAV's own limits and access rights;
  the UI does not yet reconcile every internally skipped file.
- The application provides no service isolation, hardened quarantine vault,
  real-time protection, code signing, or signed installer trust chain. The beta
  publishes a checksum, but a checksum is not a publisher identity guarantee.
