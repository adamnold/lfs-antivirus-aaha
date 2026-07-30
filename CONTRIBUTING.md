# Contributing

Thank you for helping improve Local-First Antivirus and the AAHA Local-First
Series.

## Before starting

- Read `README.md`, `SECURITY.md`, `PRIVACY.md`, and
  `docs/LOCAL_FIRST_SERIES.md`.
- Use synthetic fixtures or the bundled harmless marker; never commit malware,
  private data, credentials, generated quarantine state, or user logs.
- Open a private vulnerability report instead of a public issue for security
  defects with exploit value.

## Development

The project currently uses only the Python standard library.

```powershell
python -m unittest discover -s tests -v
python -m compileall -q lfs_antivirus_aaha tests
```

Set `LOCALAPPDATA` to a disposable test directory before running tests so they
cannot interact with normal application state.

## Change expectations

- Keep scans local and read-only by default.
- Require explicit user action for quarantine, restore, or deletion.
- Preserve or explicitly migrate existing settings and quarantine data.
- Add tests for changed behavior and document user-visible limitations.
- Do not describe a prototype capability as complete antivirus protection.
- Keep UI, source identifiers, and docs aligned with `Local-First Antivirus`,
  `lfs-antivirus-aaha`, `lfs_antivirus_aaha`, and AAHA attribution.
- Follow the AAHA minor-only source version rule; do not introduce patch-version
  bumps.

## Pull requests

Keep each pull request focused. Explain the problem, user impact, verification
performed, privacy or security implications, and any remaining limitation.
