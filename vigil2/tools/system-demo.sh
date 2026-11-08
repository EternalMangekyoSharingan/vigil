#!/bin/sh
# Milestone 2 check in a throwaway container or VM (it changes system state: adds users,
# installs the D-Bus and polkit files, starts a system bus and polkitd). Never run it on
# a real PC: there, install the package instead.
#
# Starts vigild the way vigild.service does (user vigil, two capabilities), then lists
# processes and connections as the unprivileged user "ula" through the daemon.
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
id vigil >/dev/null 2>&1 || useradd --system --home-dir /var/lib/vigil --shell /usr/sbin/nologin vigil
id ula >/dev/null 2>&1 || useradd --create-home ula
install -Dm644 "$here/packaging/dbus/org.vigil.Daemon.conf" /usr/share/dbus-1/system.d/org.vigil.Daemon.conf
install -Dm644 "$here/packaging/polkit/org.vigil.policy" /usr/share/polkit-1/actions/org.vigil.policy
install -d -o vigil -g vigil -m 0750 /var/lib/vigil
mkdir -p /run/dbus
[ -S /run/dbus/system_bus_socket ] || dbus-daemon --system --fork
pgrep -x polkitd >/dev/null || (/usr/lib/polkit-1/polkitd --no-debug >/tmp/polkitd.log 2>&1 &)
sleep 1
setpriv --reuid=vigil --regid=vigil --init-groups \
  --inh-caps=+sys_ptrace,+dac_read_search --ambient-caps=+sys_ptrace,+dac_read_search \
  "$here/target/release/vigild" --bus system --state-dir /var/lib/vigil >/tmp/vigild.log 2>&1 &
sleep 2
echo "vigild runs as: $(ps -o user= -p "$(pgrep -x vigild)") with $(grep CapEff /proc/"$(pgrep -x vigild)"/status)"
