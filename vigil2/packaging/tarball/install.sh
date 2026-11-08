#!/bin/sh
# Vigil installer. Run from the unpacked tarball:  sudo ./install.sh
#
# What it changes, and nothing else:
#   - copies Vigil's files into /usr (binaries, systemd units, D-Bus and polkit policy,
#     the desktop entry and icon); the list is kept in /usr/lib/vigil/MANIFEST;
#   - creates the "vigil" system account the daemon runs as (systemd-sysusers);
#   - starts the daemon (vigild.service) now and at boot;
#   - with automatic updates on, a daily timer (vigil-update.timer) checks GitHub for a
#     new release and installs it after checking its SHA-256 (and minisign signature,
#     once the project publishes a key). Settings: /etc/vigil/update.conf;
#   - if fapolicyd is running, trusts exactly Vigil's three programs; if SELinux is on,
#     restores the default labels on the copied files.
# Options: --auto-update / --no-auto-update (default: ask), --update (used by vigil-update).
set -eu
here=$(cd "$(dirname "$0")" && pwd)
[ "$(id -u)" = 0 ] || { echo "Run it as root: sudo $0" >&2; exit 1; }
auto=ask; updating=no
for a in "$@"; do
  case "$a" in
    --auto-update) auto=yes ;;
    --no-auto-update) auto=no ;;
    --update) updating=yes; auto=keep ;;
    *) echo "unknown option $a" >&2; exit 2 ;;
  esac
done
version=$(cat "$here/usr/lib/vigil/VERSION")
echo "Installing Vigil $version"

# Files, and the manifest the uninstaller reads.
( cd "$here" && find usr -type f -o -type l ) | sed 's#^#/#' > "$here/usr/lib/vigil/MANIFEST"
# A running program's file cannot be overwritten ("Text file busy"): stop the daemon, and
# unlink each old file before copying (an app window still open keeps its old copy in memory).
systemctl stop vigild.service 2>/dev/null || true
cp -r --remove-destination --no-preserve=ownership "$here/usr/." /usr/
systemd-sysusers /usr/lib/sysusers.d/vigil.conf

if command -v getenforce >/dev/null 2>&1 && [ "$(getenforce 2>/dev/null)" != Disabled ]; then
  xargs restorecon -F < /usr/lib/vigil/MANIFEST 2>/dev/null || true
fi
if systemctl is-active --quiet fapolicyd 2>/dev/null; then
  for f in /usr/bin/vigil /usr/bin/vigil-cli /usr/lib/vigil/vigild; do
    fapolicyd-cli --file delete "$f" >/dev/null 2>&1 || true
    fapolicyd-cli --file add "$f" >/dev/null
  done
  fapolicyd-cli --update >/dev/null
  echo "fapolicyd: trusted /usr/bin/vigil, /usr/bin/vigil-cli and /usr/lib/vigil/vigild"
fi

systemctl daemon-reload
systemctl reload dbus 2>/dev/null || systemctl reload dbus-broker 2>/dev/null || true
systemctl enable --now vigild.service >/dev/null
systemctl restart vigild.service

mkdir -p /etc/vigil
[ -f /etc/vigil/update.conf ] || cat > /etc/vigil/update.conf <<'CONF'
# Vigil's automatic updates (vigil-update.timer, once a day).
# REPO: where releases come from. GITHUB_TOKEN: only needed if that repository is private.
REPO=EternalMangekyoSharingan/vigil
GITHUB_TOKEN=
CONF
chmod 600 /etc/vigil/update.conf
if [ "$auto" = ask ]; then
  if [ -t 0 ]; then
    printf 'Turn on automatic updates? Vigil will check GitHub once a day. [Y/n] '
    read -r answer || answer=y
    case "$answer" in n*|N*) auto=no ;; *) auto=yes ;; esac
  else
    auto=no
  fi
fi
case "$auto" in
  yes) systemctl enable --now vigil-update.timer >/dev/null; echo "Automatic updates: on (daily)" ;;
  no) systemctl disable --now vigil-update.timer >/dev/null 2>&1 || true; echo "Automatic updates: off (sudo systemctl enable --now vigil-update.timer to turn on)" ;;
esac

[ "$updating" = yes ] || {
  echo
  echo "Done. Open Vigil from your app launcher, or run: vigil"
  echo "Check the setup with: vigil-cli doctor"
  echo "Remove it with: sudo /usr/lib/vigil/uninstall.sh"
}
