# Packaged Runtime Notices

Last Updated: 2026-07-29

Local-First Antivirus source is licensed under the repository's MIT License.
The Windows installer contains an embedded Python runtime and Tcl/Tk components
needed to run the AAHA application without a separate Python installation. Their
license texts are copied from the exact Python build into the installed
`licenses` directory during packaging.

PyInstaller is used only as the build tool. Its GPLv2 exception permits the
generated executable bundle to be distributed under the application's license;
PyInstaller is not represented as part of AAHA. Inno Setup is used to compile
the per-user Windows installer. Neither project endorses Local-First Antivirus.

ClamAV is not contained in the executable or installer. It is separately
installed, separately licensed GPLv2 software selected by the user. The ClamAV
name describes interoperability only; AAHA is not affiliated with or endorsed
by Cisco Talos, Cisco Systems, or the ClamAV project.
