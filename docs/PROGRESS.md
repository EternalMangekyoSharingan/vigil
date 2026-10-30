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

## Step 2: Network scoring (2026-10-30)

### What was built
- `vigil/scoring.py`: per-pair scores (program → address → service port →
  direction) over the last 24 h. Each finding records points, a plain-language
  reason, the check, the data used and when it was computed. Checks:
  - beacon regularity (coefficient of variation of start intervals), persistence and
    data-size consistency;
  - long connection (≥ 1 h);
  - new destination and new program (after the baseline, within 24 h);
  - rare destination;
  - uncommon port;
  - process location (`/tmp`, `/var/tmp`, `/dev/shm`, hidden directories, deleted
    executable).
- Beacon details: starts within 1.5 poll intervals merge into one check-in. An
  interval that is a whole multiple of the median counts as missed check-ins, not
  jitter. A pair needs ≥ 6 check-ins and a median interval ≥ 3× the poll interval.
- Alerts at score ≥ 70 for pairs no allowlist rule covers. They are deduplicated by
  pair, keep their peak score, can be dismissed with a note (logged as an
  analyst event), and are raised as an `alert` event on the timeline with the top
  reason.
- Allowlist: 11 built-in rules (loopback, NTP, DNS to LAN, mDNS, NetworkManager,
  timesyncd, chrony, PackageKit, snapd, fwupd, APT), each with its reason. User
  rules live in `data/allowlist.json` and need a reason. Built-ins can be switched
  off and on. Program patterns match the real `/proc/<pid>/exe` path, so a renamed
  copy elsewhere does not match. Allowlisted pairs are still scored and shown.
- Collector: per-socket byte counts through `sock_diag` netlink (no root; the
  interface `ss -ti` uses), parsed with `struct`. Each TIME_WAIT socket's
  remaining timer gives how long ago the connection closed (Linux holds TIME_WAIT
  for a fixed 60 s).
- Tracker: connections seen only in TIME_WAIT are recorded once, already closed and
  dated by the kernel timer. A tracked connection's close time is refined from its
  TIME_WAIT tail. Byte counts are stored per connection. A small in-place
  migration adds the new columns to step-1 databases (checked against a real
  step-1 database).
- UI: score chips (only for scores ≥ 20, so the map isn't dotted with small
  numbers), red edges for alerting pairs, a "Scores" section in the side panel
  (verdict first, findings underneath, Allowlist… / Dismiss actions), and an Alerts
  tab with an open-alert count, filters and allowlist management.

### Test results
- 60 tests, all passing on Python 3.13.17 and 3.11.17. New: 20 scoring tests, 3
  netlink tests, 5 API tests.
- Synthetic histories (generated in the tests) for: a dropper in `/tmp` beaconing to
  a new destination on port 4444 (alerts at 100 with five checks explained); NTP
  from chronyd (scored > 40, allowlisted, no alert); a long-known program polling a
  known destination (beacon only, below threshold); a beacon seen only in
  TIME_WAIT (90 s period recovered exactly from the kernel timer); a 3 h SSH
  session (long connection, no alert); a one-off internet destination (rarity); a
  user rule suppressing an alert.
- Statistics: perfect, jittered (±8%), missed check-ins, bursts, too-few/too-fast,
  and random Poisson traffic (scores nothing).
- Live netlink: a loopback pair's byte counts read back exactly (250 / 1000).
- **Live end-to-end in the container**: a test beacon script in the scratchpad (under
  `/tmp`) connected every 8 s to a loopback listener on port 4444. It ran in a
  separate Vigil instance with the built-in loopback rule switched off, and nothing
  left the machine. Vigil raised one alert, score 100, with: periodic every 8 s
  (CV 0.00, 10 check-ins), runs from /tmp, first outbound connection, similar size
  ≈ 501 B (real `sock_diag` counts), persistence. UI checked in headless Chromium:
  the red edge, score chips, findings panel and Alerts tab, with no console errors.

### Decisions made without asking
- **A beacon alone cannot alert** (max 45+10+10 = 65 < 70). Updaters, sync clients
  and telemetry poll on timers too. This is the main lever behind "few alerts, high
  confidence".
- **Weights** are in one table (`POINTS` in `scoring.py`). They are my judgement,
  not tuned on real data.
- **Rarity** counts only internet addresses that one program contacted at most 5
  times. A beacon contacted 20 times is not rare, even from one program.
- Loopback is excluded from the uncommon-port check and allowlisted by a built-in
  rule (visible, and can be switched off).
- External DNS (e.g. 8.8.8.8:53) is *not* allowlisted: DNS to an outside resolver is
  scored like anything else.
- Dismissed alerts stay dismissed even if the score changes. The current and peak
  scores are kept.

### Two test mistakes found and fixed (not weakened)
- One scenario reused the baseline's long-lived connection for the "known
  destination" beacon, so the scorer correctly reported a long connection too. The
  scenario now uses a destination seen at baseline and then closed.
- The dropper test expected "rarity", but 20 contacts is not rare by design. The
  expectation was removed and a dedicated rarity test added.

### Known limitations
- Start times are measured to the poll interval (±2 s by default) unless a TIME_WAIT
  timer dates the close. At a period that is a multiple of the poll interval, the
  coefficient of variation is quantised (the live check showed "± 0%"). The data
  line states the precision.
- A beacon over one persistent connection (HTTP keep-alive, WebSocket) is one long
  connection, not a series of starts. It shows up only through the long-connection
  check. Watching periodic byte-count growth on one socket would catch it; that is
  not done.
- Connections seen only in TIME_WAIT can't be tied to a program ("Closed before
  attribution"). Their timing is still scored, but process-based findings can't
  apply.
- Byte counts are the last poll's values before a close, so slightly low. UDP has no
  byte counts.

## Step 3: Enrichment (2026-10-30)

### What was built
- `vigil/enrich.py`:
  - **Threat feeds**: abuse.ch Feodo Tracker (JSON, with a CSV fallback), SSLBL (CSV)
    and URLhaus `csv_online` (URL hosts, IPs and domains). Downloads happen only in
    `update_feeds()`, which is called only by the Intel tab's button (a POST that
    needs the custom header) or `python3 -m vigil update-feeds`. Each update keeps
    the raw file (`data/feeds/<name>.dat`), records its SHA-256 and entry count, and
    replaces that feed's rows in one transaction. If a download or parse fails, the
    previous data is kept and the error is shown. There is a 128 MB download cap,
    and the abuse.ch Auth-Key is optional and sent only to abuse.ch hosts.
  - **Country/ASN**: IPtoASN `ip2asn-combined.tsv.gz` (public domain). It is
    imported into a separate `data/geo.db`, built beside the old one and swapped in
    atomically. Lookups are one indexed query on 16-byte big-endian keys (IPv4
    mapped into `::ffff:0:0/96`). "Not routed" rows are dropped. `update-geo --file`
    loads a local copy. Country names come from `iso-codes` when installed, with
    codes as the fallback.
  - **Scoring hooks**: a feed hit is a `threat_intel` finding (Feodo/SSLBL 80,
    URLhaus 60) naming the feed, the listed malware, port agreement, the listing
    date, the feed's download time, entries and SHA-256, and staleness (> 7 days). A
    `rare_country` finding (10) marks the first connection to a country after the
    baseline. A country's first contact is the earliest first-seen of its
    destinations, so installing the database later doesn't make every country "new".
- Scorer: further checks now plug in as objects with `prepare(ctx)` and
  `findings(pair, ctx)`.
- **Alerts are now one per program × address × direction** (a step-2 behaviour,
  changed here). They list every port involved, and the highest-scoring port's
  findings are shown. Reason below.
- API: `/api/intel` (status), `/api/intel/update` (the only network path),
  `/api/lookup?ip=`. The map's destinations carry an owner label and a "listed"
  chip.
- UI: Intel tab (per-source status, errors, SHA-256, licence, "Update now" buttons,
  a plain statement of what a download reveals, and an offline lookup box) and a
  "Who is this" section in the destination panel.
- CLI: `update-feeds [feed…]`, `update-geo [--file]`, `lookup IP`.
- Friendlier start-up: if the port is taken, Vigil says so and exits before opening
  the database or starting the poller.

### Test results
- 80 tests, all passing on Python 3.13.17 and 3.11.17. New: 17 enrichment tests
  and 3 API tests.
- Parsers on synthetic files in each source's published format
  (`tests/fixtures/feeds`, labelled synthetic). Documentation addresses and RFC 5398
  ASNs are used throughout. The Feodo JSON and CSV variants parse to the same
  records, invalid rows are skipped, and an HTML login page parses to nothing.
- Download path against a local HTTP server on 127.0.0.1: User-Agent set, no
  Auth-Key sent to non-abuse.ch hosts (and sent to abuse.ch when configured), HTTP
  404 and unrecognised content keep the previous data, size cap enforced.
- Geo: gzip and plain import, inclusive range ends, gaps, dropped "Not routed",
  IPv6, a bad file that keeps the old database, the country-name fallback.
- Scoring: a Feodo-listed address alone scores 80 and alerts. A URLhaus host gets
  "2 URLs, e.g. …" and a stale-feed note. The first contact to a new country is
  flagged, and a country seen at baseline is not.
- **No-network guarantee**: a static test that `urlopen` appears in exactly one
  function (`enrich.fetch`), and a full App poll, score, graph, destination and
  lookup cycle with `urlopen` and `socket.create_connection` patched to fail.
- Cross-site protection: a POST to `/api/intel/update` without the custom header is
  refused, and the update function is never called.
- In the container: the Intel tab's buttons were pressed in headless Chromium, with
  the sources pointed at `file://` scratch files (no network). The feed imported
  and missing sources showed readable errors. The map's destination panel showed
  owner, country and range, and the CLI `lookup` worked. No console errors.

### Decisions made without asking
- **I did not download the real feeds or database** from this container. CLAUDE.md
  allows only network calls you trigger. The parsers follow the published formats
  as I know them, and are tolerant and loud when a format doesn't match ("no
  indicators recognised; the feed format may have changed (previous data kept)").
  **The first real "Update" on your PC is the first contact with the live formats.**
- **Alert grouping changed.** In a scratch check (loopback rule switched off and a
  synthetic feed listing 127.0.0.1), one listed address produced 124 alerts: one
  per port, mostly my own test suites' throwaway loopback servers. That was a
  scratch artefact, since loopback is allowlisted by default. But it showed that
  per-port alerts fan out. One alert per program × address × direction is closer to
  "few alerts", and scores are still kept per port.
- Feed points: Feodo/SSLBL 80 (alerts alone: "a hit turns a guess into a lead"),
  URLhaus 60 (it lists hosts that served malware, which includes compromised shared
  hosts, so it needs a second signal).
- IPtoASN over MaxMind (needs an account and licence key) and DB-IP (two files, CC-BY
  attribution). One public-domain file gives range, ASN, country and owner.
- No reverse DNS: it would send every address to your resolver.

### Unsure about
- abuse.ch has been moving its services to authenticated access. I don't know
  whether the bulk download URLs used here need an Auth-Key as of today. If they do,
  the error message says where to get one.
- SSLBL's IP blacklist may be deprecated by abuse.ch. If its URL stops working,
  that feed shows an error and the others carry on.

### Known limitations
- URLhaus domain hosts are stored but not yet matched against connections (Vigil
  sees IPs, not names, until the DNS view in v2). They will be used for File
  Inspector IOCs in step 4.
- The country/ASN database is about 0.5 M ranges and takes a few seconds to import.
  Lookups are cached only by SQLite's page cache.
