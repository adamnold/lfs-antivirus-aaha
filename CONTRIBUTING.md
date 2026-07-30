# Contributing

Last Updated: 2026-07-29

Thank you for helping improve Local-First Antivirus and the AAHA Local-First
Series.

## Before starting

- Read `README.md`, `SECURITY.md`, `PRIVACY.md`, and
  `docs/LOCAL_FIRST_SERIES.md`.
- Use synthetic files and captured process-output fixtures. Never commit malware,
  private data, credentials, generated database/quarantine state, or user logs.
- Open a private vulnerability report instead of a public issue for security
  defects with exploit value.

## Development

The AAHA application uses only the Python standard library. Unit tests do not
require ClamAV to be installed.

```powershell
python -m unittest discover -s tests -v
python -m compileall -q lfs_antivirus_aaha packaging tests
```

Set `LOCALAPPDATA` to a disposable test directory so tests cannot interact with
normal state.

## Adapter test expectations

- Use exact absolute executable paths and fixed argument-list assertions.
- Verify `shell=False`; do not add `PATH` discovery or string-built commands.
- Cover clean, infected, error, malformed/inconsistent output, timeout, and
  cancellation outcomes with synthetic fixtures.
- Cover FreshClam success/failure, database-load failure, staging cleanup, and
  last-known-good rollback without live network access.
- Do not add `--remove`, `--move`, `--copy`, automatic quarantine, or another
  destructive ClamAV option.
- Preserve legacy application and quarantine state unless a separately reviewed
  migration/recovery design is implemented and tested.

## Change expectations

- Keep scanning local, user-triggered, and read-only.
- Make every network action visible and intentional.
- Add tests for changed behavior and document user-visible limitations.
- Do not describe the UI as full antivirus or endpoint protection.
- Keep product, repository, package, local-data, and AAHA identity aligned.
- Follow the AAHA minor-only public version rule; prerelease identifiers such as
  `0.3.0-beta.1` may identify a beta candidate without creating a patch release.

## Pull requests

Keep each pull request focused. Explain the problem, user impact, verification,
privacy/security implications, and remaining limitations. Building or uploading
a release artifact requires a separate explicit release workflow.
`packaging/build-windows.ps1` uses the exact dependencies in
`packaging/requirements-build.txt`; `packaging/verify-windows-package.ps1` must
pass before any artifact is considered. The GitHub release-candidate workflow
builds and verifies artifacts with read-only repository permission and never
publishes them automatically.
