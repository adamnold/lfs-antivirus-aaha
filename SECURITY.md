# Security Policy

Local-First Antivirus is an early defensive-scanner prototype. Do not use it as
the only protection on a production Windows system, and do not disable Microsoft
Defender or another supported security product to test it.

## Supported source version

Security fixes are accepted against the current `0.2.0` development line. No
signed binary release or long-term support commitment exists yet.

## Report a vulnerability

Use GitHub's private **Report a vulnerability** feature if it is available for
this repository. If it is unavailable, contact the repository owner privately
through their GitHub profile. Do not include exploit details, malware samples,
private file paths, credentials, or personal data in a public issue.

Include only the minimum information needed to reproduce the problem:

- affected source version or commit;
- Windows and Python versions;
- affected component and expected behavior;
- safe reproduction steps using synthetic files; and
- likely impact.

Do not send live malware. Use the harmless bundled test marker whenever
possible.

## Important trust boundaries

- Imported definition files are trusted local input and are not signed by this
  project.
- The prototype parser does not verify the digital signature of a downloaded
  ClamAV CVD container.
- Quarantine does not provide an encrypted vault or hardened containment
  boundary.
- A file can change between scanning and a later quarantine action.
- Broad scans can silently omit inaccessible directories.

These limitations are tracked openly so the UI is not mistaken for a complete
antivirus engine.
