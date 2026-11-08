#!/bin/sh
# Remove Vigil: stops its services and deletes every file the installer copied (listed in
# /usr/lib/vigil/MANIFEST). History in /var/lib/vigil and /etc/vigil stay unless --purge.
set -eu
[ "$(id -u)" = 0 ] || { echo "Run it as root: sudo $0" >&2; exit 1; }
systemctl disable --now vigil-update.timer vigild.service >/dev/null 2>&1 || true
if systemctl is-active --quiet fapolicyd 2>/dev/null; then
  for f in /usr/bin/vigil /usr/bin/vigil-cli /usr/lib/vigil/vigild; do fapolicyd-cli --file delete "$f" >/dev/null 2>&1 || true; done
  fapolicyd-cli --update >/dev/null 2>&1 || true
fi
manifest=/usr/lib/vigil/MANIFEST
if [ -f "$manifest" ]; then
  tmp=$(mktemp); cp "$manifest" "$tmp"
  while read -r f; do case "$f" in /usr/*) rm -f "$f" ;; esac; done < "$tmp"
  rm -f "$tmp"
fi
rmdir /usr/lib/vigil 2>/dev/null || true
systemctl daemon-reload
systemctl reload dbus 2>/dev/null || true
if [ "${1:-}" = --purge ]; then
  rm -rf /var/lib/vigil /etc/vigil
  userdel vigil 2>/dev/null || true
  echo "Vigil removed, with its history and settings."
else
  echo "Vigil removed. Its history is still in /var/lib/vigil (sudo $0 --purge removes it)."
fi
