# Technology Biased LLC Windows Signing Gate

Last Updated: 2026-08-05

The `v0.4.0-beta.1` release candidate is intentionally unsigned. Do not place an
Azure credential, certificate, metadata secret, or downloaded key in this
repository.

After Technology Biased LLC completes Microsoft Artifact Signing public-trust
identity validation, provide the Windows SDK `signtool.exe`, Microsoft's
Artifact Signing Dlib, and a non-secret metadata JSON file to
`packaging/build-windows.ps1`. The build signs the packaged application before
constructing the installer, then signs and verifies the installer. Both
signatures must be valid, timestamped with SHA-256, and display the exact
validated `Technology Biased LLC` subject.

Signing is a future next-minor release gate. Never replace the published
unsigned assets in place.
