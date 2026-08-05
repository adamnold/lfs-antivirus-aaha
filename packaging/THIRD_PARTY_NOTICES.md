# Packaged Runtime Notices

Last Updated: 2026-08-05

AAHA application source is MIT-licensed. Runtime components keep their own
licenses and are not represented as AAHA or endorsers.

## ClamAV

AppImage and Flatpak artifacts aggregate the official ClamAV 1.5.3 Linux x86-64
command-line distribution as separate executables under GPLv2; AAHA does not
link `libclamav`. The payload contains `licenses/ClamAV-GPL-2.0-only.txt` and a
SHA-256 provenance manifest. The release includes
`ClamAV-1.5.3-Corresponding-Source.tar.gz` as the corresponding source, pinned to
the exact source hash in that manifest. RPM and Windows packages do not bundle
ClamAV: RPM uses Fedora packages and Windows uses a verified separate install.

## Other packaged runtimes

Windows embeds Python and Tcl/Tk; their license texts are copied into the
installed `licenses` directory. Linux AppImage/Flatpak embed a PyInstaller-built
Python/Tk runtime. The Linux payload includes the available Python and Tcl/Tk
runtime license evidence plus its pinned Python build requirements. PyInstaller's
bootloader exception permits distribution of the generated application under
its own license. Inno Setup, AppImage tooling, Flatpak Builder, and RPM tooling
are build/package tools and do not endorse the application.
