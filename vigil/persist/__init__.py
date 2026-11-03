"""Vigil Persist: what starts automatically, and what changed since last time?

A Linux "Autoruns": systemd units and timers, cron, XDG autostart, shell start-up
files, /etc/ld.so.preload, PAM, sudoers, SSH keys, kernel modules, udev rules and other
hooks. Baseline, then diff; each file is checked against its package where the distro's
database can be read. Read-only."""
