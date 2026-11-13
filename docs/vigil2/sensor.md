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

## Process events (milestone 3)

`events.rs` subscribes to the kernel's proc connector (netlink, through `neli`): every exec,
fork and exit as it happens. It needs CAP_NET_ADMIN (the service has it) and the host's PID
namespace; without them the daemon says so in the visibility panel and polls /proc as before.

The daemon's fast path (`vigild/src/fast.rs`) reads each new program from /proc at once,
records it, runs the process checks on it, and watches it for its first 4 seconds: every 20 ms
it lists the program's socket inodes (`ProcRoot::socket_inodes`) and attributes new ones from
the program's own socket tables (`ProcRoot::sockets_of`, `/proc/<pid>/net/*`). When a watched
program that made connections exits, an event says what it did ("curl ran for 60 ms and
connected to ..."). With nothing to watch the thread sleeps until the next event.

Tested on the real kernel (`tests/events.rs`): a millisecond-long `/bin/true` is seen starting
and ending, and a program that connects to the test's own loopback listener and exits after
50 ms is caught with its connection attributed to it.

Still missed until the eBPF sensor: short connections made by long-running programs between two
looks, and programs that end within a millisecond or two (counted, not shown).
