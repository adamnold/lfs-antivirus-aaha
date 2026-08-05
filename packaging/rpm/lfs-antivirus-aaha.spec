%global debug_package %{nil}

Name:           lfs-antivirus-aaha
Version:        0.4.0
Release:        0.1.beta1%{?dist}
Summary:        Local, on-demand ClamAV scanning application
License:        MIT
URL:            https://github.com/adamnold/lfs-antivirus-aaha
Source0:        %{url}/archive/refs/tags/v%{version}-beta.1/%{name}-%{version}-beta.1.tar.gz

BuildArch:      x86_64
BuildRequires:  python3-devel
Requires:       python3
Requires:       python3-tkinter
Requires:       clamav >= 1.4
Requires:       clamav-freshclam >= 1.4

%description
Local-First Antivirus is a local, on-demand graphical scanner that invokes the
Fedora ClamAV packages through fixed argument lists. It is not real-time
protection and is not a replacement for an endpoint-security product.

%prep
%autosetup -n %{name}-%{version}-beta.1

%build
python3 -m compileall -q lfs_antivirus_aaha

%install
install -d %{buildroot}%{python3_sitelib}/lfs_antivirus_aaha
cp -a lfs_antivirus_aaha/. %{buildroot}%{python3_sitelib}/lfs_antivirus_aaha/
find %{buildroot}%{python3_sitelib}/lfs_antivirus_aaha -type d -name __pycache__ -prune -exec rm -rf {} +
install -Dm755 packaging/linux/local-first-antivirus %{buildroot}%{_bindir}/local-first-antivirus
install -Dm644 packaging/linux/com.aaha.lfs-antivirus-aaha.desktop %{buildroot}%{_datadir}/applications/com.aaha.lfs-antivirus-aaha.desktop
install -Dm644 packaging/linux/com.aaha.lfs-antivirus-aaha.metainfo.xml %{buildroot}%{_metainfodir}/com.aaha.lfs-antivirus-aaha.metainfo.xml
install -Dm644 assets/lfs-antivirus-aaha.svg %{buildroot}%{_datadir}/icons/hicolor/scalable/apps/com.aaha.lfs-antivirus-aaha.svg

%check
LOCALAPPDATA=%{_builddir}/%{name}-test-state python3 -m unittest discover -s tests -v

%files
%license LICENSE
%doc NOTICE.md PRIVACY.md README.md SECURITY.md
%{_bindir}/local-first-antivirus
%{python3_sitelib}/lfs_antivirus_aaha/
%{_datadir}/applications/com.aaha.lfs-antivirus-aaha.desktop
%{_metainfodir}/com.aaha.lfs-antivirus-aaha.metainfo.xml
%{_datadir}/icons/hicolor/scalable/apps/com.aaha.lfs-antivirus-aaha.svg

%changelog
* Wed Aug 05 2026 AAHA Release Automation <noreply@localhost> - 0.4.0-0.1.beta1
- Add AppImage, Flatpak, RPM, reconciled scan accounting, and cross-platform engine providers.
