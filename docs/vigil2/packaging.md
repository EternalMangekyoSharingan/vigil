# Packaging, installing and the policy checks

## Installing a release

```bash
tar -xzf vigil-0.2.0-x86_64-linux.tar.gz
cd vigil-0.2.0
sudo ./install.sh
```

`install.sh` lists at its top exactly what it changes. It asks whether to turn on automatic updates
(a daily check of GitHub releases, `vigil-update.timer`). Remove everything with
`sudo /usr/lib/vigil/uninstall.sh` (add `--purge` to delete history too). Build the same tarball
yourself with `cargo run --release -p xtask -- package` (it lands in `vigil2/target/package/`).

## One install tree for every package

`cargo run -p xtask -- dist` builds and stages:

```
usr/bin/vigil                                  the app
usr/bin/vigil-cli                              the terminal client
usr/lib/vigil/vigild                           the daemon (same path on every distro)
usr/lib/systemd/system/vigild.service          hardened system service
usr/lib/systemd/user/vigil-notify.service      notifications and tray (milestone 5)
usr/share/dbus-1/system.d/org.vigil.Daemon.conf
usr/share/dbus-1/system-services/org.vigil.Daemon.service
usr/share/polkit-1/actions/org.vigil.policy
usr/lib/sysusers.d/vigil.conf                  the vigil account
usr/share/applications/org.vigil.Vigil.desktop
usr/share/metainfo/org.vigil.Vigil.metainfo.xml
usr/share/icons/hicolor/scalable/apps/org.vigil.Vigil.svg
```

The AUR `PKGBUILD` (`packaging/arch/`), the RPM spec for Fedora COPR and openSUSE OBS
(`packaging/rpm/`) and the Debian files for OBS (`packaging/debian/`) all copy this tree.

## Checks that run in CI

- `xtask check-deps`: every direct dependency of every crate is on the allowlist in
  docs/RUST_REWRITE.md section 9. A new crate fails the build until the owner says yes.
- `xtask check-packaging`: the unit keeps its hardening (and never gains `ProtectProc=`, which
  would blind the sensor, or an internet address family); bus names agree across files; every
  polkit action the daemon uses is declared; desktop-file-validate, appstreamcli and xmllint pass.
- `cargo deny` (licences, advisories, sources) and `cargo audit`.

## Not done yet

- Installing from these packages on Arch, Fedora and Tumbleweed has not been tried: it needs
  those systems (or VMs), which the build container does not have.
- Release automation (Packit for COPR, OBS, the AUR push, signed tarballs with cargo-dist,
  SBOM, reproducible builds) arrives with the first release.
- Updates: system package managers bring new versions; the in-app "Update" button (PackageKit)
  and minisign-signed rule packs come later (section 7).
