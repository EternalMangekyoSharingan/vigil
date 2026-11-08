# vigild: the system service

`vigil2/crates/vigild/`. Small and boring on purpose (rule 7 in docs/RUST_REWRITE.md).

## What it does

```
start ─ open the store ─ first look at /proc ─ take the bus name ─ READY=1 to systemd
          │
          └ sensor thread: every 2 s look, record, note first sightings, send Changed
            bus handlers: answer queries from the latest look and the store
            watchdog: ping systemd only while the sensor thread keeps looking
```

## The D-Bus API

Object `/org/vigil/Daemon`, bus name `org.vigil.Daemon`. Methods return JSON text in the shapes
of `vigil_model::host` (D-011).

| interface | method | returns |
| --- | --- | --- |
| `org.vigil.Daemon` | `Status()` | version, sources (what it can and cannot see), store, own memory and CPU |
| | `Whoami()` | the caller's uid and pid as the bus reported them (no permission needed) |
| | property `ApiVersion` | 1 |
| `org.vigil.Processes` | `List()`, `Get(pid)` | every process at the last look |
| `org.vigil.Network` | `Snapshot()` | sockets, their programs, what is hidden and why |
| | `At(t)`, `Between(from, to)` | the time machine |
| `org.vigil.Events` | `Since(ts, limit)` | the event log |
| | signal `Changed(kind, taken_at)` | after each look; skipped, never queued, if a client is slow |
| `org.vigil.Findings` | `List()` | stored findings as JSON lines (empty until milestone 3) |

There is no method that changes the system. Run mode, firewall blocks and quarantine arrive in
milestones 5 and 6, each behind its own polkit action.

## Who may call (`src/auth.rs`, D-008)

1. The bus tells the daemon the caller's uid and pid (`GetConnectionCredentials`; the bus gets
   them from the kernel with `SO_PEERCRED`, so a caller cannot lie about them).
2. On the system bus the daemon asks polkit: may this caller do `org.vigil.read`? polkit decides
   from `org.vigil.policy` and the caller's session: yes for the people logged in at the
   machine, an admin password otherwise. If polkit cannot be reached, the answer is no.
3. On a development bus (`--bus session`) only the daemon's own uid may call.

polkit only answers questions about other users to root or to an action's declared **owner**.
vigild runs as the `vigil` account, so every action in `org.vigil.policy` names `unix-user:vigil`
as its owner (found by running against real polkit; D-012).

## How it runs (`packaging/systemd/vigild.service`)

User `vigil`, never root; capabilities limited to what the sensors need; no network address
families at all; read-only file system except its state directory; memory ceiling; watchdog.
`systemd-analyze security` rates it 2.0 "OK". Logs go to the journal with levels
(`journalctl -u vigild`).

## Flags

`--bus system|session|address=...`, `--state-dir`, `--proc-root` (tests),
`--interval-ms` (2000), `--retention-days` (30), `--auth polkit|same-uid`, `--once` (one look,
print the status, exit).
