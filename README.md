# Vigil

A personal blue-team lab for one Linux PC: a live **Network Map** (who is this PC
talking to, and which program) and, later, a **File Inspector** (what would this file
do). The plan is in [docs/SPEC.md](docs/SPEC.md); what has been built so far, with test
results and known limits, is in [docs/PROGRESS.md](docs/PROGRESS.md).

Status: build steps 1 (Network Map core), 2 (network scoring) and 3 (enrichment) are
done.

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
python3 -m vigil lookup 203.0.113.9          # offline: owner, country, feed listings
python3 -m vigil update-feeds                # download abuse.ch feeds (network, on request)
python3 -m vigil update-geo                  # download the country/ASN database (network)
python3 -m vigil update-geo --file ip2asn-combined.tsv.gz   # or load one you downloaded
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

## Scores and alerts

Every 30 seconds Vigil scores each *pair* (one program, one address, one service
port, one direction) over the last 24 hours. A score is the sum of findings. Each
finding shows its points, a plain reason, the check that produced it and the data
it used. For example:

```
+45  Periodic: every 60 s ± 3% (coefficient of variation 0.03 over 18 check-ins)
+25  Runs from /tmp/.x/agent: a world-writable temporary directory
+20  This program made its first outbound connection at 13:02:11
+15  New destination: first contacted at 13:02:11, after Vigil's baseline
+10  tcp/4444 is not a common service port
```

| Check | Points | Notes |
| --- | --- | --- |
| Beacon regularity | up to 45 | Coefficient of variation of connection start intervals; full points at ≤ 0.05, none at ≥ 0.35. Check-ins missed between polls are recognised as multiples of the period. Needs ≥ 6 check-ins. |
| Beacon persistence | up to 10 | How many check-ins were seen. |
| Beacon size consistency | up to 10 | Byte counts per connection from `sock_diag` netlink (the interface `ss` uses, no root needed). |
| Long connection | 15–30 | Starts at 1 hour (as in RITA), full at 8 hours. |
| New destination | 15 | First contacted after the baseline, within 24 hours. |
| New program | 20 | Program's first outbound connection after the baseline, within 24 hours. |
| Rare destination | 5 | Internet address only this program ever contacted, at most 5 times. |
| Uncommon port | 10 | Not a well-known service port. |
| Runs from /tmp, /var/tmp, /dev/shm | 25 | From `/proc/<pid>/exe`, or the script path for interpreters. |
| Runs from a hidden directory | 10 | Common tool directories (`~/.local`, `~/.cargo`, …) excepted. |
| Executable deleted while running | 10 | Normal right after an upgrade; said so in the reason. |

An **alert** is raised at **70**. A beacon alone scores at most 65, on purpose:
updaters and sync clients poll on timers too, so an alert needs a second signal.
Alerts appear in the Alerts tab, can be dismissed with a note, and are never
duplicated.

Short-lived connections that polling misses are not lost. Linux keeps a closed TCP
connection in `TIME_WAIT` for exactly 60 s and `/proc` shows the time left, so
Vigil dates each close to about 10 ms even if it never saw the connection open. A
beacon whose check-ins last milliseconds is still caught. It shows as "Closed
before attribution", because by then no process owns the socket.

There is one alert per program, address and direction. If a server is reached on
several ports, the alert lists them all and shows the highest-scoring port's findings.

**Allowlist.** Known-good periodic traffic is allowlisted, not alerted on.
Allowlisted pairs are still scored and shown, with the rule's reason. Built-in
rules cover loopback, NTP, DNS to a LAN resolver, mDNS, NetworkManager's
connectivity check, time daemons and system updaters (PackageKit, snapd, fwupd,
APT). They match the real executable path from `/proc`, so a copy named
`NetworkManager` in `/tmp` does not match. Add your own rules with "Allowlist…"
(a reason is required), or edit `data/allowlist.json`. Built-in rules can be
switched off.

## Threat feeds and country/ASN (Intel tab)

Vigil enriches addresses from **local copies** of public data and downloads them
**only when you ask**: the Intel tab's buttons, or `update-feeds` / `update-geo`.
Nothing is fetched automatically, and lookups never leave the machine. A download
is a plain GET of a public list: the source sees your public IP and that you fetched
it, nothing about your traffic.

| Source | What it adds | Points when matched |
| --- | --- | --- |
| abuse.ch Feodo Tracker | botnet C2 server addresses | 80 (alerts on its own) |
| abuse.ch SSLBL | botnet C2 servers seen over TLS | 80 |
| abuse.ch URLhaus | servers hosting malware (by URL host) | 60 |
| IPtoASN (public domain) | network owner (ASN), country and range for every address | 10 for the first connection to a new country |

Each finding names the feed, its download time, entry count and SHA-256, and warns
when the feed is more than 7 days old. The raw downloaded files are kept in
`data/feeds/`. If a download fails or the format is unrecognised, the previous data
stays in use and the error is shown. abuse.ch may require a free Auth-Key
(<https://auth.abuse.ch/>): set `VIGIL_ABUSECH_KEY` or add `"abusech_auth_key"` to
`data/settings.json`. It is sent only to abuse.ch hosts. To use a mirror or an
air-gapped copy, point any source at another URL, including `file://`:

```json
{"sources": {"feodo": "file:///srv/mirror/ipblocklist.json", "geo": "https://mirror.example/ip2asn-combined.tsv.gz"}}
```

Country names come from the `iso-codes` package when installed (most desktops have
it); otherwise two-letter codes are shown.

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
- No network calls, except the feed and database downloads you trigger. Nothing about
  your traffic leaves the machine. A test checks that `urlopen` appears in exactly
  one function, and another runs a full poll, score and lookup with networking
  patched to fail.
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
vigil/scoring.py     explainable scores, beacon detection, allowlist, alerts
vigil/enrich.py      threat feeds and country/ASN database (download on request)
vigil/server.py      127.0.0.1 web server, JSON API, background poller
vigil/__main__.py    command line
static/              the UI: plain HTML, CSS and JavaScript, hand-written SVG graph
tests/               unittest suite and synthetic fixtures
```
