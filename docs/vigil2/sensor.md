# vigil-sensor: where observations come from

`vigil2/crates/vigil-sensor/`.

## Today: /proc polling (`procfs.rs`)

A port of Vigil 1's `net/collector.py`:

1. Read the socket tables `/proc/net/tcp`, `tcp6`, `udp`, `udp6`. Each line is one socket:
   addresses in hex (in the CPU's byte order), the state, the owner's uid, and an **inode**
   number that names the socket.
2. List `/proc/<pid>/fd/*` for every process. A link like `socket:[2001]` means "this process
   holds socket 2001". That is how a socket gets its program.
3. For each holder, read `status`, `comm`, `cmdline`, `exe` and `stat` to know the program, its
   user, its parent chain and when it started.
4. A socket nobody visibly holds gets a **reason**, in plain words: closed already, another
   user's (the kernel hides other users' fd tables), a protected process of your own, or
   unknown (exited between reads, or in a container).

Details carried over from Vigil 1 and pinned by the golden test:
- interpreters are keyed by their script, so two Python scripts are two programs;
- a `)` inside a process name cannot break `/proc/<pid>/stat` parsing (fields are counted from
  the last `)`);
- a connection on a port we listen on is "in", everything else "out";
- TIME_WAIT's timer dates when a connection was closed.

`ProcRoot` can point at another directory (tests use the synthetic fixture in
`tests/fixtures/proc`) and can pretend some pids are unreadable, the way the kernel treats a
normal user, so the "hidden" explanations are tested without being root.

**What polling misses:** anything that starts and ends between two looks (the daemon looks every
2 s). That is milestone 3's job (netlink proc connector, sock_diag, then eBPF).

## "What Vigil can and cannot see" (`visibility.rs`)

Reads facts about the kernel (BTF present, `unprivileged_bpf_disabled`, lockdown mode, LSMs) and
reports, per signal, which source is live and why, in sentences. Sources that are not built yet
say so. The daemon includes this in `Status`, and `vigil-cli status` and `doctor` show it.
