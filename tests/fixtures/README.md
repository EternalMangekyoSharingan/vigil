# Test fixtures (SYNTHETIC)

Everything under this directory is **synthetic test data**, written for Vigil's tests.
None of it was captured from a real machine, and the addresses use documentation
ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32) or private
ranges, so no real host is implicated.

## proc/

A miniature `/proc` in the real kernel formats:

- `net/tcp`, `net/tcp6`, `net/udp`, `net/udp6`: socket tables. Addresses were encoded
  with `socket.inet_pton` + little-endian `struct` words, independently of Vigil's
  decoder. `net/tcp` ends with one malformed line the parser must skip.
- `<pid>/status`, `comm`, `cmdline`, `stat`: thirteen processes, including a Firefox
  parent and child sharing one socket, two Python programs (a script and `-m module`),
  a process whose executable was deleted, and one whose `comm` (`upd) S 1 2`) is
  crafted to break naive `/proc/<pid>/stat` parsers.
- `links.txt`: the `fd/*` and `exe` symlinks. They are listed rather than committed
  as symlinks so the fixture survives any checkout; `tests/helpers.py` creates them
  in a temporary copy.
- `unreadable.txt`: pids a non-root viewer (uid 1000) cannot inspect. Tests simulate
  the kernel's permission check for these, because they run as root in CI containers.
- `stat`: only `btime` matters (boot time for process start times).
