# Progress

Claude appends a section here after each build step: what was built, test results,
known limitations, and decisions made without asking.

## Step 1: Network Map core (2026-10-30)

### What was built
- `vigil/collector.py`: read-only parser for `/proc/net/{tcp,tcp6,udp,udp6}`, with
  addresses decoded in the CPU's byte order (IPv4-mapped IPv6 normalised to IPv4).
  Sockets are mapped to processes through `/proc/<pid>/fd`. Each process gets its
  exe, command line, user, parent chain (from world-readable `status`) and start time.
  Interpreters are keyed by their script (`python3 updater.py` and `python3 -m x` are
  separate programs). A deleted executable is flagged. Connections are marked inbound
  when their local port is a listening port.
- Sockets that can't be attributed are kept and labelled with the reason: other user,
  protected (setuid / non-dumpable) process, closed (TIME_WAIT, inode 0), or unknown
  (exited mid-scan / other PID namespace). `hidepid` on `/proc` and missing IPv6 tables
  are detected and reported.
- `vigil/store.py`: SQLite store (WAL) and a tracker that diffs polls into connection
  lifetimes. It records first-seen facts as events (new destination, first use of a
  program→destination:port pair, a program's first outbound connection, new listening
  socket). Each event carries its source (`/proc/net/tcp inode N`, `/proc/<pid>/fd`).
  The first poll is recorded as the baseline, and its events say so. A connection's
  TIME_WAIT tail is linked to the connection already tracked, not counted as a new
  one. After a restart, still-open connections continue and ones that vanished get
  "closed while Vigil was stopped".
- `vigil/server.py`: `ThreadingHTTPServer` on 127.0.0.1 (hard-coded), background
  poller, JSON API (`/api/status`, `graph`, `program`, `destination`, `listeners`).
- UI (`static/`): dark graphite theme, hand-written SVG graph with programs on the
  left and destinations on the right. The shorter column is placed at its neighbours'
  barycentre. Count chips, timed edge labels (`443 · 3 live`, `80 · 4m`), a side panel
  with details and an event timeline, a "what Vigil can and cannot see" section, and
  listening sockets with exposure. All DOM is built with `textContent`, never
  `innerHTML`, because process names are attacker-controlled.
- CLI: `python3 -m vigil` (serve) and `python3 -m vigil snapshot [--all|--json]`.

### Test results
- 33 tests, all passing on Python 3.13.17 and Python 3.11.17 (`python3 -m unittest
  discover -s tests -t .`).
- Synthetic fixture (`tests/fixtures/proc`, labelled synthetic): 17 sockets across all
  four tables, 13 processes. It includes a shared socket (Firefox parent and child), a
  hostile `comm` (`upd) S 1 2`) that must not break `/proc/<pid>/stat` parsing, a
  deleted executable, and every hidden case. Fixture hex was produced with
  `inet_pton` + `struct`, independently of the decoder. One real line captured from
  the container is also decoded in a test.
- Live: a test opens a loopback socket pair and checks the real collector attributes
  both ends and the listener to the test's own pid and executable.
- Manual live run in the cloud container: as root, the collector read 14–53 real
  sockets (Claude Code's HTTPS connections, the local proxy, the headless browser
  used for UI checks). Dropped to `nobody`, it listed the same sockets as "Hidden:
  root (uid 0)" with the explanation, and reported 78 unreadable root processes.
  The container has no `tcp6`/`udp6`, which is reported correctly.
- UI checked in headless Chromium against the live server: no console errors. I
  looked at screenshots of the overview, a selected program and a selected inbound
  service.

### Decisions made without asking
- **No GitHub push yet.** This session had no repository, and the proxy refused to
  create one ("sessions are bound to their configured repositories"). Work is
  committed locally on branch `claude/build-steps-1-5` (starter on `main`), and a git
  bundle is written after each step. See the end of this file for how to fetch it.
- **unittest instead of pytest**: pytest isn't installed, and `.claude/settings.json`
  denies `pip install`. Tests are standard `unittest` and also run under pytest.
- **Direction**: an inbound connection's edge is keyed by our service port (`in 22`).
  Keying it by the client's ephemeral port would be noise. An inbound connection does
  not count as the program's "first outbound".
- **HTTP/1.1 keep-alive**: without it, every UI poll left a TIME_WAIT socket, and
  Vigil's own traffic dominated the "not attributed" count. Loopback-only hidden
  sockets are also counted separately in the header.
- **"LAN" is an explicit list** (RFC 1918, CGNAT 100.64/10, ULA fc00::/7). Python's
  `is_private` also counts documentation ranges, which Vigil labels "reserved".
- **Data directory** defaults to `./data` (already gitignored), mode 0700.
- **Retention**: closed connection rows older than 14 days are pruned hourly. Events
  and first-seen tables are kept indefinitely (they are the evidence trail).
- **Request hygiene** for a localhost server: Host-header check (DNS rebinding),
  custom header and Origin check for writes, strict CSP, static files whitelisted by
  name.

### Known limitations
- Polling (default every 2 s) misses connections that open and close between polls.
  Some reappear as TIME_WAIT under "Closed before attribution". eBPF or audit would
  need root, so they are out of scope.
- Unconnected UDP sockets (most DNS lookups via `sendto`) have no remote address in
  `/proc`.
- Only the network namespace Vigil runs in is visible. Docker containers with their
  own namespace are not.
- An interpreter's "script" is a heuristic (first non-option argument). For example,
  `java -cp lib.jar Main` is keyed as `lib.jar`.
- Process start time and the parent chain come from `/proc` at poll time. A parent that
  exited is cut off.
- The UI redraws the whole SVG on each 3 s refresh. That is fine for hundreds of
  nodes, not for thousands.

### Unsure about
- The default window (15 min) and poll interval (2 s) are guesses. They are easy to
  change in the UI and with `--interval`.
