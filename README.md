# Vigil

A personal blue-team lab for one Linux PC: a live **Network Map** (who is this PC
talking to, and which program) and, later, a **File Inspector** (what would this file
do). The plan is in [docs/SPEC.md](docs/SPEC.md); what has been built so far, with test
results and known limits, is in [docs/PROGRESS.md](docs/PROGRESS.md).

Status: build step 1 (Network Map core) is done.

## Run it

Needs Python 3.11 or newer on Linux. Nothing to install; no root needed.

```bash
python3 -m vigil
```

Then open <http://127.0.0.1:8765/>. Options: `--port`, `--interval` (seconds between
polls, default 2) and `--data DIR` (evidence store, default `./data`, also settable with
`VIGIL_DATA`).

For a one-off look in the terminal, with no database and no web server:

```bash
python3 -m vigil snapshot          # current connections and their programs
python3 -m vigil snapshot --all    # include listening sockets
python3 -m vigil snapshot --json   # everything the collector sees, as JSON
```

## What you see

- **Programs → destinations.** Each program holding a socket is a node on the left;
  each remote address is a node on the right. Solid lines are open now, dashed lines
  closed within the selected window. Labels show the port and how long ago. Chips
  count live connections, destinations and programs. A blue `new` chip marks things
  first seen after Vigil's baseline (its first poll).
- **Direction.** A connection accepted on one of your listening ports is shown as
  inbound (`in 22`), keyed by the service port, not the client's random port.
- **Side panel.** Select a node to see the executable, command line, user, parent
  chain and start time, the destinations it used, and a timeline of events. Every
  event says where it came from (for example `/proc/net/tcp inode 4069, owner from
  /proc/90/fd`).
- **First-seen tracking.** Vigil remembers every destination, program-to-destination
  pair and each program's first outbound connection in SQLite. The first poll is
  recorded as the baseline, so "new" means new since Vigil started watching.
- **Listening sockets** and their exposure (all interfaces, one interface, this
  machine only).

## What Vigil can't see without root, and says so

Vigil runs as your user. The kernel shows every socket's addresses and owning uid to
everyone, but shows *which process* holds a socket only to that process's owner and
to root. Instead of dropping those sockets, Vigil lists them under clearly labelled
nodes with the reason:

- **Hidden: other user**: owned by another uid (system daemons, other accounts).
- **Hidden: protected process**: your own uid, but a setuid or non-dumpable process
  (ssh-agent, keyring daemons) that refuses inspection.
- **Closed before attribution**: already closed by its program and lingering in
  `TIME_WAIT`, so no process owns it.

The "not attributed" link in the top bar opens the full breakdown. Other limits: Vigil
polls, so a connection that opens and closes between polls can be missed. Unconnected
UDP has no remote address in `/proc`. Containers with their own network namespace are
not visible. Missing `/proc/net/tcp6` (IPv6 disabled) is reported, not an error.

## Safety

- The web server binds to `127.0.0.1` only (not configurable). It refuses requests
  whose `Host` header is not its own, which blocks DNS-rebinding pages. State-changing
  requests need a custom header and a matching `Origin`, so other sites can't forge
  them. Pages are served with a strict Content-Security-Policy.
- Monitoring is read-only: Vigil only reads `/proc`. It changes no firewall, route, DNS
  or kernel setting and never signals processes.
- No network calls. Nothing about your traffic leaves the machine.
- The evidence store (`data/vigil.db`) is created in a directory only you can read.

## Tests

The tests use only the standard library's `unittest`; pytest also runs them.

```bash
python3 -m unittest discover -s tests -t .
```

`tests/fixtures/` holds a **synthetic** miniature `/proc` (labelled as such; see its
README) covering IPv4, IPv6, IPv4-mapped addresses, shared sockets, interpreters,
deleted executables, a hostile process name and every "hidden" case. One live test
opens a socket pair and checks the collector attributes it to the test process.

## Layout

```
vigil/collector.py   read-only /proc parser: sockets, processes, what is hidden
vigil/store.py       SQLite evidence store; tracker turning polls into history
vigil/server.py      127.0.0.1 web server, JSON API, background poller
vigil/__main__.py    command line
static/              the UI: plain HTML, CSS and JavaScript, hand-written SVG graph
tests/               unittest suite and synthetic fixtures
```
