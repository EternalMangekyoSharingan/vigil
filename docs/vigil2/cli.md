# vigil-cli: the terminal client

`vigil2/crates/vigil-cli/`. Talks to the daemon over D-Bus, the same way the app does.

```bash
vigil-cli status                  # what the daemon sees and how
vigil-cli processes -f firefox    # every process, filtered
vigil-cli connections             # outbound and inbound connections with their programs
vigil-cli connections --all       # also listening sockets and loopback
vigil-cli at -2h                  # the time machine
vigil-cli events --since -1d      # Vigil's own log: first sightings, starts
vigil-cli doctor                  # every check, with the fix for each problem
vigil-cli --json processes        # the daemon's JSON, for scripts
vigil-cli --bus session status    # a development daemon (vigild --bus session)
```

- Every cell printed to the terminal passes through `wording::printable`: process names and
  command lines are chosen by whoever started the process, and could otherwise contain newlines
  or terminal escape sequences that rewrite the screen.
- Errors are sentences with the likely fix ("the Vigil daemon is not running ... Fix: sudo
  systemctl enable --now vigild").
- The terminal UI (`vigil tui`, ratatui) is planned with the Expert view (milestone 7).
