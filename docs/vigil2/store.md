# vigil-store: the history

`vigil2/crates/vigil-store/`. One SQLite file the daemon owns: `/var/lib/vigil/vigil.db`.

## Tables (schema 1)

| table | one row per | used for |
| --- | --- | --- |
| `connections` | socket (protocol, both ends, inode) with first and last sighting | the time machine, "what was talking at 3 a.m.?" |
| `programs` | program that ever held a socket, first and last sighting | "first time this program used the network" |
| `destinations` | address beyond this machine ever contacted | first-seen destinations |
| `processes` | process, keyed by pid **and** start time (pids get reused) | lineage that survives exits (milestone 3) |
| `events` | something Vigil itself did or noticed | the event log (`vigil-cli events`) |
| `findings` | finding, by its stable id | Home, Cases (milestone 5) |

## Rules

- **Migrations are append-only.** `MIGRATIONS` in `src/lib.rs` is a list; schema N is the first
  N entries. To change the schema, add an entry; never edit an old one.
- **Backup before migrating.** Before upgrading an existing file, it is copied with
  `VACUUM INTO vigil.db.bak-vN`.
- **Never touch a newer file.** If the file's schema is newer than this version knows (after a
  downgrade), the store refuses to open it rather than damage it.
- **First seen outlives retention.** Connections, processes and events older than the
  retention window (30 days by default) are deleted. `programs` and `destinations` are kept, so a
  program you have used for months is not "new" again next week.
- **WAL mode**, so readers never block the writer.

## The time machine

`connections_at(t, slack)` returns connections whose first sighting is before `t` and last
sighting after it. `slack` (3 s on the bus) covers the polling interval. `connections_between`
answers for a range. Polling means a connection shorter than one interval may be missing; the
event sensors in milestone 3 close that gap.
