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

## Step 4: File Inspector static triage (2026-10-30)

### What was built
- `vigil/ole.py`: read-only OLE2 compound-file reader (MS-CFB: DIFAT, FAT,
  directory tree, mini stream; version 3 and 4 sectors). Every offset is
  bounds-checked and every chain checked for loops. Also the MS-OVBA
  decompressor, and VBA module extraction from the project's `dir` stream,
  including its irregular `PROJECTVERSION` record, module text offsets and the
  code page.
- `vigil/inspector.py`: static triage that reads bytes only.
  - Identification by magic bytes (PDF, OLE2, OOXML/ZIP/JAR/APK/ODF, RTF, PE, ELF,
    Mach-O, LNK, ISO, archives, images, HTML, scripts, text).
  - Disguise checks: double extension, bidi override, padded name, type/extension
    mismatch.
  - PDF triage in the style of PDFiD, over the body *and* inflated streams.
  - OOXML: macros, auto-exec, behaviour, XLM, remote templates, Follina-style remote
    objects, DDE, embeddings, ActiveX.
  - Legacy OLE2: VBA, BIFF8 macro sheets and Auto_Open, Ole10Native packages,
    encryption.
  - RTF exploit structures; archives (members inspected recursively, two levels).
  - Script, LNK and HTML command patterns.
  - IOC extraction (URLs, IPs, domains, e-mails, hashes in text) from raw bytes,
    UTF-16 strings, inflated streams, XML parts and macro source.
  - Verdict: "Likely malicious" ≥ 70, "Suspicious" ≥ 30, otherwise "No suspicious
    indicators found", never "safe". Each finding has points, a reason and where in
    the file it came from. "What this check cannot tell you" is always listed.
  - Context from local data only: IOCs matched against the downloaded feeds, and
    IPs this PC has really connected to (linking the file to the Network Map).
  - Reports (not files) are stored in an `inspections` table.
- Safety measures: in-memory only; 32 MB per archive member and 64 MB total
  decompression budget; zlib `max_length` on PDF streams; no XML parser (regex over
  relationship tags, so no entity-expansion risk); every parser failure becomes a
  stated limit. Oversized members are named in the limits.
- API: `POST /api/inspect` (raw body, custom header required, 100 MB cap checked
  before reading), `GET /api/inspections`, `GET /api/inspection`,
  `DELETE /api/inspection`. CLI: `python3 -m vigil inspect FILE [--json] [--no-save]`.
- UI: Files tab with drop zone, history with verdict dots, verdict banner,
  identity/hashes, findings, PDF keywords and JavaScript, macro source (collapsible),
  archive members and their nested verdicts, indicators as plain text with feed hits
  and "this PC connected to it" links to the map, and the limits.

### Test results
- 106 tests, all passing on Python 3.13.17 and 3.11.17. New: 26 inspector tests and
  2 API tests.
- **Decompressor checked against both worked examples in the MS-OVBA
  specification** (3.2.1 and 3.2.2), byte for byte. Round trips use an
  independently written greedy compressor with copy tokens.
- **Compound-file reader checked against real files written by LibreOffice 24.2**
  (`.doc`, `.xls`): every stream's length matches its directory entry, and the BIFF8
  workbook starts with a BOF record. My synthetic writer also covers regular
  (> 4 kB) sectors, and a self-referencing FAT chain fails cleanly.
- Benign real documents (LibreOffice `.doc`, `.docx`, `.xls`, `.xlsx`, `.pdf`, committed
  as fixtures) all come out "No suspicious indicators found" with score < 10. The
  words "safe" or "clean" appear nowhere in any report.
- 18 synthetic suspicious samples land in their expected verdicts with the expected
  checks: macro dropper `.docm` and `.doc`, benign macro in `.docx`, remote template,
  Follina pattern, DDEAUTO, XLM `.xlsm` and very-hidden `.xls`, four PDF variants
  (auto-run JS, hex-escaped names, JS only inside an object stream, Launch + embedded
  exe, exe appended after `%%EOF`), Equation Editor RTF, malformed-header RTF named
  `.doc`, delivery ZIP with a double-extension member and an encrypted member, LNK
  with a PowerShell cradle, HTML smuggling, shell and PowerShell droppers.
- **Safety test**: every sample is inspected with `subprocess.Popen`, `os.system` and
  `os.execv` patched to fail and `open()` refusing write modes, in an empty working
  directory that stays empty. A static test checks that `inspector.py` and `ole.py`
  use no subprocess, exec/eval, importlib, pickle, marshal, ctypes or webbrowser.
- Robustness: truncated `.docm`/`.doc`, random bytes behind an OLE magic, a broken PDF
  stream, a broken ZIP, bad RTF hex, an empty file and random bytes all produce a
  report, never an exception. A 32 MB+ member is skipped and named in the limits.
- In the container: uploads through the Files tab in headless Chromium (file input,
  real POST): a benign LibreOffice `.docx`, a delivery ZIP, an object-stream PDF and a
  macro `.docm`. Screenshots checked the verdict banner, findings, macro source,
  indicators and limits. No console errors. The CLI `inspect` was run on the `.docm`.

### Decisions made without asking
- **Suspicious samples are generated at test time and not committed.** Committed
  files with `AutoOpen` + `Shell` + download patterns could be quarantined by
  antivirus when you pull. Only benign LibreOffice documents are committed.
- **No XML parser on untrusted input.** Relationship tags and DDE fields are matched
  with regexes, which avoids entity-expansion attacks entirely.
- Calibration changed during this step, each change checked against the benign
  fixtures:
  - An executable disguised as a document, or a bidi-override name, scores 60 (on
    its own nearly "Likely malicious").
  - A remote template over http/https/UNC scores 50 (60 by bare IP); a local
    `file:///` template scores 5 (normal in companies).
  - A PDF auto-action without JavaScript or /Launch is a 0-point note.
  - A COM name like `WScript.Shell` no longer counts as the `wscript.exe` LOLBin.
- **IOC false positives found on real files and fixed**: LibreOffice's version
  string (`LibreOffice/24.2.7.2`) is no longer read as an IP, `schemas.libreoffice.org`
  is ignored as a namespace, and run-together URLs in font tables are split.
- Hashes are only extracted from text-like content and macro source; in binaries
  and PDFs (document IDs) they are mostly noise.
- The file itself is never stored, so a report can't be re-run against feeds updated
  later. The report keeps its hashes and IOCs for that.

### Unsure about
- Points and thresholds are judgement calls, calibrated on synthetic samples and a
  handful of benign documents, not on a real malware corpus. Nothing here was run
  against real malware, by design.
- VBA extraction is checked against my reading of MS-OVBA (verified with the spec's
  vectors) and my own project builder, not against Office-written `vbaProject.bin`
  files: none were available. Real projects with unusual references might trip the
  `dir` parser. That shows as a stated limit ("VBA project … could not be decoded"),
  not a crash.

### Known limitations
- No PE/ELF code analysis (imports, sections, packers): executables get identity,
  name, string and IOC checks.
- PDF: JavaScript is extracted from literal `/JS (…)` strings only (not hex strings or
  indirect references). Encrypted PDFs are reported, not decrypted.
- OOXML encryption, password-protected ZIPs, 7z/RAR/ISO/gzip contents and OneNote
  files are not unpacked.
- Excel 4.0 macro *formulas* in `.xls` are not decompiled. Macro sheets and
  Auto_Open are detected.
- Domain extraction uses a curated TLD set, so a rare TLD can be missed and an odd
  dotted identifier (`System.IO`) can show up. Domains are informational (0 points
  unless a feed lists them).

## Step 5: Cases and exports (2026-10-30)

### What was built
- `vigil/cases.py`:
  - **Cases**: title, status (open / investigating / closed, with closed time),
    tags, summary, notes, and an activity log that records every change, piece of
    evidence, indicator toggle and note with its time.
  - **Evidence**: alerts, programs, destinations and file reports, copied into the
    case as snapshots when added. The case survives connection pruning and alert
    deletion (tested).
    - An alert snapshot carries its findings and the destination's enrichment.
    - A program snapshot hashes the running executable through `/proc/<pid>/exe`
      (bytes only, works for deleted binaries). If that isn't possible it says why.
  - **Indicators**: derived from evidence and deduplicated with merged context, plus
    manual entries with validation. Each can be excluded from exports. Removing
    evidence removes the indicators that came only from it.
- Exports:
  - CSV with formula-injection guarding.
  - STIX 2.1 bundle with identity, indicators (patterns for IPv4/IPv6, domain, URL,
    e-mail and MD5/SHA-1/SHA-256, with quotes and backslashes escaped), notes and a
    grouping. Deterministic UUIDv5 IDs, `malicious-activity` or `anomalous-activity`
    indicator types, case tags as labels.
  - Markdown report: evidence chain with every finding's check and data, indicator
    table, merged timeline, notes, limits. **All** links in it are defanged.
- API: `/api/cases`, `/api/case`, `/api/case/update`, `/api/case/note`,
  `/api/case/item` (POST/DELETE), `/api/case/ioc`, `/api/case/ioc/exclude`, and
  `/api/case/export?format=csv|stix|md` (download with a file name). The
  dispatcher now turns unknown records into 404 and unexpected errors into a JSON
  500 instead of a dropped connection.
- UI: Cases tab (editable title, status, tags and summary, export buttons, evidence
  cards with "Show live", the indicator table with export checkboxes and manual
  entry, notes and activity). "Add to case…" sits on map panels, score cards, alert
  cards and file reports, and can open a new case on the spot.

### Test results
- **117 tests, all passing on Python 3.13.17 and 3.11.17.** New: 11 case tests.
- Lifecycle and audit log; validation (empty titles and notes, unknown status,
  malformed indicators); duplicate evidence refused.
- Evidence from the full pipeline (tracker → scorer → Feodo-listed alert; synthetic
  macro document; benign LibreOffice document; program; destination): indicators,
  malicious flags, merged context, removal.
- **Live executable hash**: the test process's own `/proc/<pid>/exe` hashes to the
  same SHA-256 as the Python binary on disk.
- STIX: a structural validator (ID format and type, timestamps, required properties,
  pattern shape, no dangling references, no empty labels) passes. Patterns are
  checked exactly, including an escaped quote. IDs are stable across exports and the
  bundle ID changes.
- CSV: rows, UTC times, formula neutralised. Markdown: headings, defanging, escaping,
  findings with provenance, notes, timeline.
- API round trip including the cross-site refusal, 400/404 cases and export headers.
- In the container, end to end in headless Chromium:
  1. Upload the synthetic macro `.docm`, then "Add to case…" with a new case.
  2. Add a real live destination (160.79.104.10) from the map's panel.
  3. Add a note.
  The three exports were then fetched over HTTP. The STIX bundle passed the
  validator; the CSV had 5 indicator rows; the Markdown indicators were defanged. No
  console errors.

### Decisions made without asking
- **Snapshots, not references.** Evidence is copied when added, so pruning (14 days)
  or deleting an alert can't hollow out a case. The cost is a few kB per item.
- **"Malicious" flag semantics.** At first I labelled it "listed", but file hashes
  were flagged because of Vigil's own verdict, not a feed listing. It is now
  "assessed malicious" (a feed listing, or a file judged Likely malicious), stated
  in the CSV comment, the report and the UI tooltip.
- **Defang everything in Markdown.** The first version defanged only the indicator
  table; a test showed live URLs in finding snippets and feed references. Every
  scheme URL and `www.` name in the report text is now defanged. CSV and STIX keep
  raw values, because tools need them.
- STIX `grouping` (context `suspicious-activity`) rather than `report`: a case is
  ongoing, not a published report. No `observed-data` objects (indicators are what
  downstream tools consume).
- Program indicators: the executable's hashes and the addresses it contacted. The
  executable *path* is kept in the snapshot and report but not exported as an
  indicator (paths are weak and noisy).

### Known limitations
- No PDF report export (v2 in the spec), no MISP JSON or Suricata rules (v2).
- Cases are single-user. Notes have no author field, since this is a personal lab.
- The evidence snapshot is not re-hashed or signed. The case database is as
  trustworthy as the `data/` directory's permissions (0700).

## Redesign and desktop app (2026-10-31, at the owner's request)

You asked for the UI to look almost exactly like your EDR process-analyzer screenshot,
with Darktrace-like visuals, lots of purposeful motion, the colours of your wallpaper
(dark purple, warm orange), Apple-like fonts, a desktop app, and to keep it light.

### What was built
- **Palette, measured from your wallpaper.** It is an 8-pixel repeating stripe of teal
  `#00665d`, aqua `#5dbdb9`, slate `#333a40`, mauve `#b290a1`, plum `#5e3a60`,
  periwinkle `#7780a9`, sky `#59bddf` and ice `#62f3ff`. Base: plum-graphite derived
  from the plum and slate. Main accent: warm orange `#ff9f43`. The teal → ice gradient
  is used for process cubes and live traffic; periwinkle and mauve for supporting
  shapes; coral `#ff5d73` for alerts.
- **Type.** `-apple-system`/SF Pro wherever the system has it, otherwise **Inter**,
  the open typeface closest to SF, bundled as a 48 KB variable woff2 covering every
  weight. Code is in JetBrains Mono (40 KB). Both are SIL OFL; their licences are in
  `static/fonts/`. SF Pro itself can't be bundled (Apple's licence).
- **Graph (`static/netmap.js`, rewritten).**
  - Map view: isometric cubes for processes (inner cube as in your screenshot); state
    labels above (`LIVE PROCESS`, `IDLE PROCESS`, `ALERT · …`, `ANALYZED · …`); names
    in orange pills; count chips; globes with cyan pills for destinations; hexagon
    rings for the selected node and pulsing ones for alerts.
  - Edges: thick bands with particles flowing in the traffic's direction, and labels
    rotated along the edge. Labels take the first free spot along their curve, tested
    with each label's rotated bounding box, in priority order (selected, alerting,
    live); one with no free spot steps aside to the tooltip.
  - **Analyzer view**: your screenshot's diagonal cascade. Parents (oldest first) →
    program → destinations, with edges labelled by the real time between process
    starts. The collector now records each ancestor's start time.
  - Nodes are keyed and tweened, so refreshes and view switches glide instead of
    redrawing.
  - The event panel is on the left, as in the screenshot: breadcrumb header, Events /
    Details / Scores tabs, and screenshot-style event items with clickable addresses.
- **Motion (`static/fx.js`).** A background constellation canvas (≤ 30 fps, stopped
  when hidden), a sliding tab indicator, button ripples, toasts for every action,
  animated score rings, count-up tiles, a scanning bar for uploads and feed
  downloads, a rotating gradient border on the drop zone, a radar sweep for the empty
  map, and a breathing brand mark. Everything is still under `prefers-reduced-motion`.
- **Desktop app (`vigil/desktop.py`)**: `python3 -m vigil app`, with no new
  dependency. The window comes from a native WebKitGTK window when PyGObject is
  installed, otherwise a Chromium-family browser in `--app` mode with a private
  profile and background networking off, otherwise the default browser. The server
  lives exactly as long as the window. `install-desktop` / `uninstall-desktop` add or
  remove a per-user menu entry and icon (XDG, no root).
- **One Vigil per data directory**: an `flock` plus a port file. `serve` refuses a
  second poller; `app` opens a window onto the running instance.

### Verification
- **127 tests, all passing on Python 3.13.17 and 3.11.17.** New: 8 desktop tests
  (browser discovery, app-mode flags, window/server lifetime, single-instance join,
  fallback, launcher file parsed back, Exec quoting, XDG), font serving, ancestor
  start times, and beacon pauses.
- **The real desktop window**: `python3 -m vigil app --window chromium`, run as the
  unprivileged `nobody` user on a virtual X display (Xvfb), opened an app-mode window
  with no tabs or address bar. I captured the X screen. It showed live data in the
  non-root view: root's connections as "Hidden: root" with the explanation. Closing
  the window stopped Vigil, closed its port and removed the port file.
- Headless Chromium screenshots of every tab against a live instance with a loopback
  test beacon: alert styling, Analyzer cascade (with "40.8 seconds" from real start
  times), files with score ring and toasts, cases, intel. No console errors.
- **Lightness, measured**: idle map with all animations, Chromium software
  rendering: 5.8% of one core on the renderer main thread, scripts 0.1%, JS heap
  2.4 MB. The Python backend uses about 30 MB and under 1% CPU. Polling the API pauses
  while the window is hidden.

### Bugs found and fixed in this round
- **Scoring: long silences counted as "missed check-ins".** The test beacon stopped
  for two hours (worker restart) and resumed. The scorer reported "1025 probably
  missed between polls" and "1083 check-ins". Missed-check-in recovery now applies
  only to gaps of up to 5 periods. Longer gaps are *pauses* (sleep, restart): left
  out of the statistics and named in the reason ("1 pause (longest 2h 4m) left
  out"). New test.
- The entrance animations replayed on every refresh (the panel rebuilt on each
  count change). The overview now updates numbers in place, and re-renders of the
  same panel are drawn without entrance motion.
- `hidden` badges still displayed (a CSS `display` rule beat the attribute); chip rows
  overflowed the node block; colliding edge labels; a CSS transform on the exit
  animation would have dropped a node's position; an inline `style` attribute would
  have been blocked by the page's CSP (now set through the CSSOM).

### Decisions made without asking
- **No Electron/Tauri/pywebview.** Each means npm, a Rust toolchain or a pip
  dependency, plus 100+ MB. The shell uses what Linux desktops already have. If you
  would rather have a single self-contained binary, that's a dependency decision for
  you.
- **Inter instead of SF Pro**: SF Pro may not be redistributed. Inter was drawn in the
  same spirit and is what Vigil falls back to everywhere except macOS.
- Fonts came from the `@fontsource-variable` packages' published files (fetched once
  at development time, Latin subset). Nothing is loaded from a CDN at runtime.
- `CLAUDE.md`'s UI-style section now carries a dated note recording your new
  direction, so later sessions don't revert it. Your original text is unchanged.

### Known limitations
- The native WebKitGTK path is untested here: this container's PyGObject is broken.
  It is tried first, and any failure falls through to Chromium. The Chromium path was
  verified end to end.
- The "Chrome for Testing" banner in the desktop screenshot belongs to Playwright's
  test build; normal Chromium/Chrome doesn't show it.
- On Wayland, Chromium's `--class` may not set the app id, so the taskbar may group
  the window with the browser.
- The bundled fonts cover Latin. Other scripts fall back to system fonts.
- A browser fallback (option 3) is a normal tab in your browser, with its extensions.

## Bomb detection, explanations, right-click and precision (2026-10-31, at the owner's request)

The owner's feedback: text misaligned; explanations say what something *is* rather
than what it *does*; a real zip bomb (`location.zip`) got through the File Inspector;
the analyzer needs more precision and a right-click to look things up.

### What was built
- **Archive-bomb detection** (`vigil/archives.py`, wired into `inspector.py`). Each
  compressed stream is decompressed into a counter that keeps a 4 KB head and a 1 MB
  tail; nothing is extracted or written. The zip directory is found by its record
  signatures, not by trusting the end record, so a forged end record is reported
  instead of hiding entries. Entries that share compressed data are grouped and
  each group is measured once, then multiplied out. Nested zips are parsed from the
  kept tail and sampled ranges. Caps: 1 GB counted per stream, 12 s overall; past
  them the size is reported as "at least". Findings: `decompression_bomb` (90/50/20 at
  10 GB/1 GB/100 MB), `overlapping_entries` 60, `size_lie` 40, `forged_directory` 30,
  `impossible_ratio` 40, `path_traversal` 50, `symlink_member` 25, `entry_flood` 25.
  A bomb stops further unpacking. `.gz`, `.bz2` and `.xz` are measured the same way.
- **Every finding says what it means** (`means` on findings, with a fallback table
  in the UI): "Opening this archive would try to write about 275 GB…".
- **Offline knowledge** (`vigil/knowledge.py`): notes on about 50 common programs
  (what it does, why it uses the network, what is normal, what to watch for), a port
  catalog, and package ownership read straight from dpkg/pacman databases (falling
  back to `rpm -qf`; Snap/Flatpak/AppImage/Nix from the path). The panel's "What is
  this?" card combines those with what Vigil observed. Node tooltips carry the title.
- **Inspect executable**: `POST /api/program/inspect` reads `/proc/<pid>/exe` as
  bytes (capped at 512 MB) and runs static triage; the report opens in the Files tab
  with its source recorded as "executable of X (pid N), read via /proc/N/exe".
- **Right-click menus** (`static/menu.js`) on programs, parents, destinations and
  every address in event lists and the connection table. Keyboard friendly.
- **Precision**: a Connections tab (open time to the millisecond, duration, both
  ends, service, state, inode, bytes each way); analyzer gaps as `3 min 12.4 s`;
  parents' exact start times. Map edge labels stay rounded for space.
- **Alignment and layout**: text in name pills and chips is centred on the shapes'
  real centres (`dominant-baseline: central`); the window can no longer drift
  sideways (`overflow: clip`); the tab buttons show a soft orange focus ring for
  keyboard users only, instead of the white browser outline; long values in tables
  wrap at word boundaries instead of mid-number; the status area ellipsizes.

### Verification
- `location.zip` (sha256 `dbbfc2e4…11436`, 257 KB): Likely malicious (100), "at
  least 275 GB", overlapping entries (256 names, one block), size lie (2 bytes
  claimed), forged directory. About 1.5 s, memory flat, nothing written; the file was
  only ever read as bytes and is not in the repository.
- Synthetic bombs in `tests/test_archives.py`, built at test time: recursive,
  overlapping with lying sizes, forged counts, a single lying member, the
  lower-bound path, zip slip and symlinks, gz/bz2/xz, ordinary archives (no false
  alarm), and a tracemalloc check that 200 MB of output keeps Python's peak under
  16 MB.
- 145 tests pass on Python 3.13 and 3.11.
- Checked in Chromium at 1340×860 with live data: no console errors, no horizontal
  overflow, menus, about card, Connections tab and the inspect → Files hand-off.

### Bugs found and fixed in this round
- Indicator search ran Python regexes over up to 64 MB of raw bytes: 15 s for a
  300 MB binary. It now searches printable runs only (like `strings`, with an offset
  map so "at offset" stays exact): 5.6 s. A test checks the offsets.
- An executable mentioning `127.0.0.1` scored "this PC has connected to it". Loopback,
  link-local, multicast and unspecified addresses no longer count.
- The about card rounded the score half-to-even (26) while the badge rounded half up
  (27). Both now round the same way.
- 30 catalog entries were one-liners ("Mesh VPN."). A test now requires a real
  explanation for every entry, and they were rewritten.
- Beacon scoring treated a laptop sleeping for 2 h as 1,025 missed check-ins. Gaps
  longer than 5 missed intervals are now pauses, reported and left out of the stats.

### Decisions made without asking
- The knowledge base is hand-written and offline. It ships no data from any outside
  service and makes no lookups. Unknown programs say so ("Vigil has no notes on
  this program") and fall back to what was observed.
- Package lookups read the package databases directly; only rpm needs a subprocess
  (`rpm -qf`, 3 s timeout), behind one small function, as CLAUDE.md asks.
- Inspecting a program's executable only works for processes Vigil can read
  (your own, or all of them as root), and says so otherwise.

### Known limitations
- The bomb caps mean a large enough bomb is reported as "at least N", not its exact
  size. The verdict is the same.
- Only zip, gzip, bzip2 and xz are measured. 7z and RAR need libraries outside the
  standard library; they are flagged by type only.
- The knowledge base covers common desktop programs and services, not everything.
- Kernel process names are cut at 15 characters (`environment-man`), so parents in
  the chain can be truncated; the executable path is shown where it can be read.

## Visual refinement: sleek, not "AI-looking" (2026-10-31, at the owner's request)

The owner found the look too obviously machine-made (the glowing "Likely malicious"
card in particular) and asked for something more modern and professional with the
same colours, glow kept only on the highlighted top-bar tab.

### Research
Write-ups on the "AI look" agree on the tells: neon glows on dark backgrounds,
gradient fills, tinted cards with coloured borders and a thick stripe down one side,
oversized radii, a big number in a ring as the hero, and decoration that moves
without meaning anything. Professional tools such as Linear go the other way: near
monochrome surfaces, borders of 5–8% white, one accent, and "don't compete for
attention you haven't earned".

### What changed
- Stylesheet rewritten: solid plum-black surfaces in four steps, hairline borders,
  6–8 px radii, no gradients, blurs or glows. The active tab marker keeps a soft glow.
- Severity is a small tinted label plus the score as a plain number; the File
  Inspector verdict is a neutral card with a label, the file name, "100 / 100", a
  thin meter and the top reasons as a list. The animated score ring is gone.
- Cards, notes and the "What is this?" card lost their coloured side stripes.
- Buttons are flat (orange only for the primary action), with no lift or ripple;
  the segmented control and scope filters are neutral.
- Graph: flat-shaded cubes and globes, flat pills, one thin selection hexagon, a
  dashed (not pulsing) alert ring, thinner and dimmer traffic particles, no hexagon
  background pattern or glow filter.
- Removed the drifting background canvas, the spinning logo, the spinning drop-zone
  border and the floating icon. Entrance animations are short fades.
- The side panel's title is now the program or address name (it showed a count).
- Event times read `Oct 31, 2026 · 03:38:23.534`.

### Verification
All tabs checked in Chromium at 1340×860 with live data, no console errors. Tests
pass (see below).

## File report in a multi-scanner layout; network background back (2026-10-31)

At the owner's request (with a VirusTotal report as the reference):
- **Analyzers** (`inspector.summarize_analyzers`): every report now carries one row
  per Vigil analyzer, with `flagged` (and the top reason), `nothing` or `skipped`
  (and why: wrong file type, no feeds downloaded, outside the app). An analyzer
  counts as having run if it applies to the file or to any archive member that was
  inspected. Statuses never say "clean"; a test enforces it.
- **Report layout**: score box (flagged analyzers out of those that ran, plus the
  score), summary card (status strip, SHA-256, name, tags, size, age, type badge),
  and tabs for Detection, Details, Indicators and Behaviour. Behaviour says plainly
  that it needs the detonation VM.
- **Network Map background** restored, on that view only: a faint hexagon grid and
  the slow constellation, paused when the map is hidden.

### Decisions made without asking
- No vendor rows. The grid shows only Vigil's own offline analyzers. External
  engines (ClamAV, YARA, VirusTotal hash lookups) need a new dependency, sudo or an
  outside service, so they wait for the owner's decision.

## Second opinions: ClamAV and hash lookups (2026-10-31, owner approved)

The owner chose ClamAV on the PC plus button-only hash lookups, and asked for
VirusTotal's API as well.

### What was built
- `vigil/engines.py`:
  - **ClamAV**: bytes streamed on stdin to `clamdscan` (daemon), falling back to
    `clamscan` with archive limits. Exit codes and `stdin: NAME FOUND` lines are
    parsed, and engine and signature versions are recorded.
  - **VirusTotal** API v3 file lookup by SHA-256.
  - **MalwareBazaar** `get_info` by SHA-256.
  - Each result is turned into findings with points and their source.
- `inspector.run_clamav` runs on every upload, every "Inspect executable" and the
  CLI. `inspector.apply_lookup` attaches a lookup to a saved report, rescores it and
  replaces any earlier lookup of the same service.
- Endpoints:
  - `POST /api/inspection/lookup` runs a lookup, only when the button is pressed.
  - `GET /api/keys` reports which keys are set (never the keys) and the ClamAV
    version.
  - `POST /api/keys` writes `data/settings.json` with mode 0600.
- UI:
  - ClamAV row in the analyzer grid.
  - "Vendor lookups" on the Detection tab, with VirusTotal's full engine list,
    detections first.
  - "VirusTotal n / m" in the score box.
  - "Second opinions on files" in the Intel tab: ClamAV status and install commands,
    key fields.
- Network: lookups go through `enrich.http`, which is now the one place that opens
  a URL (the existing guard test still enforces a single `urlopen`).

### Verification
- 156 tests pass on Python 3.13 and 3.11.
- New tests (all synthetic):
  - A stand-in ClamAV script run through the real subprocess and stdin path.
  - Fallback from clamdscan to clamscan, with the limits passed.
  - Scoring for malware, PUA and heuristic names.
  - Canned VirusTotal and MalwareBazaar answers: 200, 404, 429, a bad hash, a
    missing key.
  - Lookup replacement.
  - Keys saved with mode 0600 and never echoed back.
  - An upload makes no network request.
  - A lookup sends only the hash URL and the key.
- The layout was checked in Chromium with the canned VirusTotal answer injected in
  the browser (nothing stored).

### Known limitations
- **Not tested against a real ClamAV or the real APIs.** This container has no
  ClamAV, no API keys and no access to those services. The formats follow ClamAV's
  documented output and the published VirusTotal v3 and MalwareBazaar APIs.
- `clamscan` without the daemon loads its whole signature database for each file,
  which can take 20–60 s and about 1 GB of memory. The clamd daemon avoids this.
- A hash lookup only knows files someone has already submitted. A new or targeted
  file is often unknown.

## Fix: ClamAV and archive bombs (2026-10-31, reported by the owner)

The owner installed ClamAV and inspected `location.zip`; the upload hung. Cause:
Vigil's own check still took ~1.5 s, but the file was then handed to ClamAV, which
*does* unpack archives (with temporary files) and ground on the bomb until its own
limits. The earlier claim that "nothing is written to disk" was true of Vigil, not of
ClamAV; the docs now say so.

- `inspector.clamav_unsafe`: a file with any archive-bomb finding, or whose measured
  expansion exceeds 1 GB (or is only a lower bound), is never given to ClamAV. Its
  row reads "Not run: Vigil found an archive bomb, and ClamAV would try to unpack it".
- ClamAV now runs in a background thread, one scan at a time. The report returns
  at once with ClamAV "Scanning…"; the page polls and fills the row in.
- Tests: a bomb never reaches the scan function; a large expansion is gated; an upload
  returns "pending" before a (deliberately blocked) scan finishes, and the saved
  report has the result afterwards. 159 tests pass on 3.13 and 3.11.

## Themes, globes, "which tab is this address", connection security (2026-10-31)

At the owner's request.

### What was built
- **Themes** for the Network Map: Grid (hexagons plus triangles, rings, crosses and
  diamonds in the tile), Night (the starfield moved here, now with sparkles, rings,
  crosses, diamonds and a twinkle; paused unless Night is on and the map is visible)
  and Plain. Saved per browser in localStorage.
- **Globes**: a proper wireframe with four meridians, four parallels, an equator and a
  prime meridian.
- **`vigil/identify.py`**:
  - A pure-Python LZ4 block decoder for Firefox's `recovery.jsonlz4`, giving the open
    tabs of LibreWolf, Firefox, Floorp, Waterfox and Zen, including Flatpak and Snap
    paths.
  - Chromium-family history, read through SQLite's `immutable=1`, so it never locks or
    writes the browser's database.
  - HSTS hosts from `SiteSecurityServiceState.txt`.
  - A port-based transport table.
  - `resolve` (system resolver, threaded, with a timeout).
  - `tls_probe`: one handshake that accepts any certificate, to read it, then one that
    verifies chain and name.
  - A minimal X.509 DER parser: subject, issuer, validity, key type and size or curve,
    signature algorithm, SANs, policies (DV/OV/EV), SCT, must-staple, CA.
  - `tls_badges` with a level and a reason for each badge.
- **Server**:
  - `POST /api/identify` (network, button only; listed addresses skipped; at most 60
    addresses, 8 handshakes in parallel).
  - `GET /api/tabs`.
  - An `identities` table.
  - The graph and destination details carry host, tab, security summary and transport
    badges. Browser programs list their tabs with matched addresses.
- **UI**:
  - An Identify button and a "Identify: tab, certificate, TLS" right-click entry.
  - On the map, the host name above a destination's address, plus `tab:` and security
    chips.
  - Under a destination's name, a "Where is this?" line.
  - A Security tab (badges with explanations, certificate details) and an Open tabs
    tab for browsers.

### Verification
- 172 tests pass on Python 3.13 and 3.11.
- New tests:
  - LZ4 (literals, overlapping matches, corrupt offsets).
  - A synthetic LibreWolf profile: tab host and title only, query strings never kept.
  - Synthetic Chromium history (only the last two hours).
  - HSTS parsing.
  - A real TLS 1.3 handshake on 127.0.0.1 against a synthetic self-signed certificate
    (tests/fixtures/tls).
  - The parser over every system CA certificate.
  - Badge rules for old TLS, weak cipher, expired certificates, RSA 1024, SHA-1, name
    mismatch, EV, CT and HSTS.
  - Wildcard matching.
  - The endpoint with mocks: tab matched by DNS, a listed address never probed.
  - A guard that raw connections exist only in identify.py.
  - Graph and details make no network calls.
- A real Identify ran in the container: two TLS 1.3 handshakes, chains verified,
  badges shown. The certificates seen were the cloud sandbox's intercepting proxy's
  (`default.domain`), not the real sites': on the owner's PC the real certificates
  will appear.

### Known limitations
- A shared CDN address can serve many sites, so a certificate-name match can point to
  several tabs. Matches say whether they came from DNS or from the certificate.
- Some servers only answer TLS when they know the site name (SNI). Without a matching
  tab, Vigil handshakes without a name and may get a default certificate or a refusal,
  which is reported as such.
- Newer Firefox versions may keep HSTS state in a binary file; then the HSTS badge is
  simply absent.
- Chromium's open tabs are not read (its session format is undocumented); recent
  history is used instead.

## Alerts rework: titles, explanations, known services, Fix panel, allowlist (2026-10-31)

The owner's brief, parts A–F, plus better detection of zip bombs over 1 TB.

### Zip bombs over 1 TB (done first)
- **Extrapolation.** A stream stopped at the 1 GB counting cap is extrapolated from
  the compressed bytes it had consumed (`archives.extrapolate`). It was previously
  floored at its declared size, which a bomb can fake.
- **Zip64.** Records are parsed inside nested directories, and Zip64 end-record
  placeholders are no longer reported as forgery.
- **Sibling inference.** Unmeasured siblings take the expansion ratio their measured
  siblings showed, once measurement proves the declared sizes wrong.
- **Fallback parser.** When Python's `zipfile` rejects a crafted directory, Vigil's
  own record parser takes over.
- **location.zip.** It now reads **about 8.8 TB** (was "at least 275 GB"). Its inner
  file is named `32-256.zip`, i.e. 32 GiB × 256 = 8 TiB, so the extrapolation agrees
  with the bomb's own name.
- **Tests at real scale:**
  - A Zip64 overlapping bomb of about 1.3 TB (300 names over one 4 GB stream built
    from a repeated flushed deflate block, about 4 MB compressed).
  - The same bomb nested inside a stored outer zip.
  - A crafted end record Python rejects.
  - Sibling inference.
  - All run in about 5 s.
- The owner's new sample (said to be over 1 TB) was not uploaded to this session, so
  it is untested. These are the methods bombs of that class use (Zip64 overlap,
  nesting, lying sizes), and each is now covered.

### A. Titles
- `vigil/wording.py` builds titles from the pattern who / does what / to whom / how
  often:
  - **Who:** friendly names (LibreWolf, Syncthing, NetworkManager; scripts by script
    name), or "An unidentified program".
  - **To whom:** an Identify host name, else the ASN owner cleaned up ("HETZNER-AS" →
    "Hetzner") with the country, else an IPv4 address. Never a bare IPv6 ("an IPv6
    server").
  - **How often:** human rounding ("every ~7 min").
- Candidates are tried from richest to shortest until one fits in 60 characters.
- Tests check:
  - The spec's own examples (Syncthing, LibreWolf; the plain-HTTP unidentified case).
  - Every title ≤ 60 characters, with no banned words ("coefficient", "variation",
    "CV", "±", "poll", "check-ins", "%") and no IPv6 pattern.
  - A fuzz run of over 1,000 combinations of programs, destinations, signals, ports
    and directions.
  - The subtitle format.
- Findings now carry `stats` with the raw numbers and a `signal` kind, so wording uses
  facts, not regexes over sentences. Old alerts without stats fall back to their
  reason text.

### B. Explanation
- `wording.explain` returns:
  - the summary sentence;
  - one specific line per signal, with a 0–1 strength (points ÷ that signal's
    maximum);
  - "why that matters", once per kind of signal;
  - the likely explanation;
  - how sure Vigil is, with a reason;
  - next steps;
  - the technical details (every old reason, data source and raw stat).
- Tests: lines are unique, groups appear once, every sentence is ≤ 20 words, the raw
  numbers are preserved in the technical details, and plain-HTTP and unattributed
  lines appear.

### C. Known services
- `vigil/data/known_services.json` covers seven services, each with recognisers,
  "what", "why it's fine", privacy notes, and check/fix/undo templates.
- `vigil/services.py` scores matches:
  - process name +3, destination domain +3, port +1, interval +1, network owner +1;
  - a match needs a process name or a domain, except for services marked
    distinctive by port and interval (NetworkManager's plain HTTP every 5 min, and
    NTP);
  - confidence: ≥ 5 points High, 4 Medium, otherwise Low.
- A match makes severity Low (High or Medium confidence), adds "probably X" to the
  subtitle, and reports an adjusted score (−40, −25 or −10). The alert itself still
  appears.
- Decision: alerts are still raised on the unadjusted score, so a match can never make
  an alert disappear silently, as the brief requires.
- Unattributed alerts explain why: too short-lived for the poll interval, or another
  user's (root's) process. They offer "look every 0.5 s for 10 minutes"
  (`POST /api/monitor/fast`, a temporary monitor setting) and describe admin mode,
  which is off by default and never started by Vigil.

### D. Fix panel
- `vigil/fixes.py` covers:
  - **Distro detection.** os-release `ID`/`ID_LIKE` → arch, fedora, suse, debian, void,
    alpine or gentoo. Unknown distros get a generic note.
  - **Package owner.** `pacman -Qo`, `rpm -qf`, `dpkg -S`, `xbps-query -o`,
    `apk info --who-owns` or `equery belongs`.
  - **Firewall detection** from files only: a firewalld unit enabled, ufw
    `ENABLED=yes`, or nftables.
  - **One-destination blocks** with exact undos. The nftables undo deletes only
    Vigil's own table.
  - **Catalogue templates**, plus generic checks and uninstall.
- Decision: for interpreter programs (python, bash, …) the package check targets the
  script, and uninstall is never offered: it would have suggested removing Python.
- Rules are enforced by tests across 4 distros × 7 services × 4 firewalls: no `&&`, no
  piping into a shell, no curl/wget, no `*` in rm, and every fix has an undo.
- The modules that build fix commands (fixes, commands, wording, services) cannot run
  anything. A test fails if they import subprocess, os.system, popen, exec, spawn or
  pty, and another fails on any API route named run, exec or apply.

### E. Colour-coded commands
- `vigil/commands.py` tokenises every command into roles: admin, pkgmgr (with family),
  install, remove, package, path, flag, service, command, arg. Every token has a
  tooltip.
- It understands per-tool meanings: `pacman -S` installs but `dpkg -S` searches;
  `-Q` and `-qf` are read-only.
- The UI colours each role, with a legend under the panel and a tooltip on every
  token.
- Tests include `sudo pacman -S syncthing` → admin, pkgmgr:arch, install, package; the
  same for dnf, zypper, apt and apk; systemctl enable/disable; and rm with a path.

### F. Allowlist
- The form needs a reason (the server refuses without one) and a scope: this program
  and this destination, or this program everywhere.
- A live preview (`POST /api/allowlist/preview`) lists which open alerts would stop.
  It warns when "unidentified program everywhere" would cover every unattributed
  connection.
- A new **Settings** tab lists your rules with "Remove (undo)", plus the built-in
  rules, "look more often" and the admin-mode explanation.

### Verification
- 201 tests pass on Python 3.13 and 3.11.
- Three real alerts from this container's evidence store, in the new format, checked
  in Chromium at 1440×1000:
  1. **"beacon.py checks in with this PC every ~10 s"**, subtitle "**High** · first seen
     Oct 30, 23:47". The test beacon script.
     - Why tab: "beacon.py has contacted this PC about every 10 s since Oct 30, 23:46".
     - Six signal lines with bars: steady timer (very regular), first network use,
       first time to this server, kept up 2 h 33 min, same size (~501 bytes), runs
       from a hidden folder.
     - Three "why" paragraphs: timer, new, location.
     - "How sure: Medium".
     - Technical details collapsed.
     - Fix tab (this container is Ubuntu): Check it shows
       `dpkg -S /home/user/vigil/.devtmp/beacon.py` (the script, not Python), then
       `ss -tunp dst 127.0.0.1`. There are no Fix-it options: loopback can't be
       blocked, and a script's interpreter is never offered for removal. The legend
       is shown.
  2. **"beacon.py checks in with this PC every ~10 s"**, "High · first seen 03:11". A
     second run of the same script; the same layout, without the hidden-folder line.
  3. **"An unidentified program checks in with this PC every ~10 s"**, "**Medium** ·
     first seen 03:17".
     - Summary: "A program Vigil could not identify has contacted this PC about every
       10 s since 02:12".
     - Signals include "Vigil could not see which program this is: the connection
       closed before Vigil could see which program owned it".
     - "Why Vigil can't name the program": "Vigil looks every 2 s. This connection
       opened and closed in between…", with the "Look every 0.5 s for 10 minutes"
       button and the admin-mode card (colour-coded `sudo python3 -m vigil serve`,
       Copy only).
     - "How sure: Low".
     - The Allowlist form shows a reason field, two scope radios and the preview
       "This will stop 1 open alert".
- The catalogue matches NetworkManager, Syncthing and a browser from fixture data. The
  Fix panel renders check/fix/undo for all three on Arch, Fedora and openSUSE fixture
  os-release files, with package-manager families coloured arch/fedora/suse.

### Known limitations
- These alerts are loopback test traffic, so no real-world "probably X" match appears
  in the screenshots. The catalogue matches are covered by tests and fixtures.
- Firewall detection reads config files and does not ask the firewall whether it is
  running: an installed but stopped nftables still reads as "nftables".
- The firewalld block uses `--direct` rules (still supported, though firewalld calls
  them deprecated). They are runtime-only unless `--permanent` is added, which the
  option says.

## Zip bombs: decoy directories, and a survey of techniques (2026-10-31)

The owner's sample `64x4096-Z.zip` (378 KB, sha256 `003d8875…19df0`) was scored only
"Suspicious 60". Vigil saw the overlap but estimated nothing. Bytes-only analysis
shows how it works:
- It holds one inner zip, `64x4096.zip`, 81 MB once decompressed.
- That zip's central directory lists 4,096 names. Each points at byte 32, which is
  the middle of a local header, not a file, and each claims to be 1 byte. The Zip64
  field is a decoy too.
- The only real local header, at byte 0, declares a 64 GiB Zip64 member made from
  80.6 MB of deflate. Counting confirms it passes 4 GiB.
- Tools that trust the directory see 4 KB. Lenient extractors resolve every name to
  the real header: 4,096 × 64 GiB = 256 TiB.

**Flaw in Vigil:** it trusted the directory's offset and sizes, never checked that a
file header sits where the directory points, and fell back to the declared 1 byte.

**Fixes** (`archives.resolve_local`):
- Each sampled entry's offset must hold a `PK\x03\x04` signature; otherwise Vigil
  uses the nearest real header before it, as lenient extractors do, and reports
  "the directory points to byte N, which is not a file header".
- The local header's own (Zip64) sizes are read and compared with the directory's.
  The larger counts, and a disagreement is reported as a size lie.
- Members larger than the 64 MB Vigil keeps are measured from the part kept, then
  extrapolated using the declared compressed length.
- At least 4 MB is kept per sampled entry, since the directory's compressed size may
  also be a lie.

**Result:** Likely malicious (100), **about 281.5 TB** (exactly 4,096 × 64 GiB), in
1.1 s, without extracting anything. location.zip still reads 8.8 TB. A synthetic copy
of the technique (512 names over a 2 GB Zip64 member, nested and deflated) is a
regression test.

### Techniques and coverage
| Technique | How it works | Vigil |
| --- | --- | --- |
| Recursive (42.zip) | zips inside zips, each level multiplying | nested expansion to depth 6; unmeasured identical siblings sized from measured ones |
| Overlapping entries (Fifield's zbsm/zblg/zbxl) | many names share one deflate kernel | groups by data range, measures once, multiplies |
| Zip64 overlap (zbxl, 281 TB) | the same, with 64-bit sizes | Zip64 central and local fields parsed, top-level and nested |
| Size lies | declared size far below the real output | streamed counting, never trusting declared sizes |
| Forged end record | wrong entry counts or directory size | records found by signature; disagreement reported |
| Decoy directory (this sample) | directory points into the middle of a header, with false sizes | header signature check, nearest real header, local-vs-central comparison |
| Directory Python rejects | malformed fields that make parsers throw | Vigil's own record parser as fallback |
| Single huge stream (gz/bz2/xz) | one stream of zeros | counted to 1 GB, then extrapolated |
| Zip slip, symlinks | paths escaping the folder, links to system files | flagged per entry |
| Entry flood | hundreds of thousands of entries | flagged by count |

### Still not covered
- **Compression methods without a standard-library decoder:** Deflate64 (9), LZMA
  (14), Zstandard (93), XZ-in-zip (95) and PPMd (98). Vigil flags these by type and
  declared ratio only, because expanding them needs a new dependency (owner's
  decision).
- **Formats Vigil doesn't open:** 7z, RAR, ISO.
- **Streamed entries.** When the data-descriptor flag is set, the local header holds
  zeros; Vigil then relies on the directory's sizes and its measurement.
- **The 12 s time budget.** It ends measurement early on very deep recursive bombs;
  the remaining branches use sibling inference, and the report says so.

## Where the build stops

Steps 1–5 are done. **Step 6 (detonation VM) was not started**, as CLAUDE.md asks: it
needs sudo and a virtual machine set up on your PC (a hypervisor such as QEMU/KVM, a
throwaway guest image, and an isolated network). Before starting it, it would help to
know:
- which hypervisor you have or are willing to install;
- whether the guest should be Windows (for Office/PDF samples) or Linux;
- what network the guest may reach (none, or a sinkhole on your PC).

### GitHub
Pushed to https://github.com/EternalMangekyoSharingan/vigil, branch
`claude/build-steps-1-5` (the starter is on `main`). The history below is kept for
the record. Earlier, this session could not push. It had no repository attached, and creating one from
the container was refused by the session's GitHub proxy ("sessions are bound to their
configured repositories"). Every step is committed on branch `claude/build-steps-1-5`
(the starter is on `main`), and a git bundle of the full history was produced with
the work. To get it onto GitHub, either:
- create an empty `vigil` repo, attach it to a Claude Code session and ask for a
  push; or
- clone from the bundle and push yourself:
  `git clone -b claude/build-steps-1-5 vigil.bundle vigil && cd vigil && git remote set-url origin git@github.com:<you>/vigil.git && git push -u origin claude/build-steps-1-5 main`.
