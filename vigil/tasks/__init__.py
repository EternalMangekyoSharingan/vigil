"""Vigil Tasks: what is running, where did it come from, and should it be?

An EDR-style process tree from /proc: binary, owning package, hash, parent, command
line, sockets, systemd unit and start time per process, with flags for deleted
binaries, programs in /tmp or ~/.cache, LD_PRELOAD and odd parents. Read-only: it never
signals a process; stopping one is a command for you to copy."""
