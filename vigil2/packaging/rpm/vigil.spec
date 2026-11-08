# Fedora (COPR via Packit) and openSUSE (OBS). Builds from the release source tarball,
# which carries vendored crates (`cargo vendor`), so the build needs no network.
Name:           vigil
Version:        0.2.0
Release:        1%{?dist}
Summary:        Watch your PC for suspicious programs and connections
License:        MIT
URL:            https://github.com/EternalMangekyoSharingan/vigil
Source0:        %{url}/releases/download/v%{version}/vigil-%{version}-vendored.tar.zst

BuildRequires:  cargo >= 1.89
BuildRequires:  rust >= 1.89
BuildRequires:  gcc
BuildRequires:  systemd-rpm-macros
BuildRequires:  pkgconfig(dbus-1)
Requires:       dbus
Requires:       polkit
%{?systemd_requires}
%{?sysusers_requires_compat}

%description
Vigil watches this computer in the background: which program talks to which
address, what starts automatically, which files and packages look disguised or
risky. Every finding explains itself, with the evidence and commands to check,
fix and undo. Nothing leaves the computer unless the user switches it on.

%prep
%autosetup -n vigil-%{version}

%build
cd vigil2
cargo build --release --frozen --offline --workspace
cargo run --release --frozen --offline -p xtask -- dist --root %{_builddir}/stage --no-build

%install
cp -a %{_builddir}/stage/usr %{buildroot}/

%check
cd vigil2
cargo test --release --frozen --offline --workspace --exclude vigil-ui

%pre
%sysusers_create_compat %{buildroot}%{_sysusersdir}/vigil.conf

%post
%systemd_post vigild.service
%systemd_user_post vigil-notify.service

%preun
%systemd_preun vigild.service
%systemd_user_preun vigil-notify.service

%postun
%systemd_postun_with_restart vigild.service

%files
%license LICENSE
%{_bindir}/vigil
%{_bindir}/vigil-cli
%{_prefix}/lib/vigil/vigild
%{_unitdir}/vigild.service
%{_userunitdir}/vigil-notify.service
%{_sysusersdir}/vigil.conf
%{_datadir}/dbus-1/system.d/org.vigil.Daemon.conf
%{_datadir}/dbus-1/system-services/org.vigil.Daemon.service
%{_datadir}/polkit-1/actions/org.vigil.policy
%{_datadir}/applications/org.vigil.Vigil.desktop
%{_metainfodir}/org.vigil.Vigil.metainfo.xml
%{_datadir}/icons/hicolor/scalable/apps/org.vigil.Vigil.svg

%changelog
* Sun Nov 08 2026 Ula <ulakozdoj@gmail.com> - 0.1.0-1
- First Vigil 2 preview: daemon, command line and finding format
