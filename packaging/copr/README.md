# COPR Packaging

Last Updated: 2026-08-05

The release workflow produces a source RPM through `packaging/build-rpm.sh`.
After the protected release commit and tag exist, upload that SRPM to the shared
AAHA COPR project. Use only current supported Fedora x86-64 chroots. Never store
the COPR login token in this repository or in a workflow artifact.

Example after interactive `copr-cli` authentication:

```sh
copr-cli build aaha-local-first dist/release/lfs-antivirus-aaha-0.4.0-0.1.beta1*.src.rpm
```

Verify `dnf install`, upgrade, launch, and removal from the resulting repository
before linking the COPR from public release notes.
