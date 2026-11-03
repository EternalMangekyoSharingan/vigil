# Vigil

A personal blue-team lab for one Linux PC, as a **suite of small tools** that each
answer one question and run on their own, built on one shared core so findings,
explanations and fix commands look and work the same everywhere. The suite plan is in
[docs/SUITE.md](docs/SUITE.md), the original feature spec in [docs/SPEC.md](docs/SPEC.md),
and what has been built, with test results, decisions and known limits, in
[docs/PROGRESS.md](docs/PROGRESS.md).

## The tools

Every tool: Python 3.11+ standard library only, no root, its own page on 127.0.0.1,
the same dark UI kit, and the same finding format (exported to `data/<tool>/findings.jsonl`
for Vigil Cases).

| Tool | Question | Run it |
| --- | --- | --- |
| **Vigil Net** | Who is this PC talking to, and which program? | `python3 -m vigil.net` (same as `python3 -m vigil`) |
| **Vigil Pkg** | Is this AUR package safe to build and install? | `python3 -m vigil.pkg` → <http://127.0.0.1:8766/> |
| **Vigil Files** | Is this file or archive safe to open? | `python3 -m vigil.files` → <http://127.0.0.1:8767/> |
| **Vigil Persist** | What starts automatically, and what changed since last time? | `python3 -m vigil.persist` → <http://127.0.0.1:8768/> |
| **Vigil Tasks** | What is running, where did it come from, and should it be? | `python3 -m vigil.tasks` → <http://127.0.0.1:8769/> |
| **Vigil Cases** | What happened, across all of the above? | `python3 -m vigil.cases` → <http://127.0.0.1:8770/> |
| Vigil Lab | What would this file actually do? | not built yet: needs your PC and a VM |

## Vigil Cases: what happened, across all of the above?

```bash
python3 -m vigil.cases                          # the page, on http://127.0.0.1:8770/
python3 -m vigil.cases import                   # read every tool's latest findings (and Net's alerts)
python3 -m vigil.cases import other-pc.jsonl    # findings exported on another machine
python3 -m vigil.cases timeline                 # one timeline, oldest first, with finding keys
python3 -m vigil.cases new "Odd evening" --tags browser
python3 -m vigil.cases add 1 tasks:7fa262cf7943240c
python3 -m vigil.cases note 1 "It was me testing."
python3 -m vigil.cases export 1 --format md     # or csv (indicators), csv-findings, stix
python3 -m vigil export-findings                # Net: write its alerts as findings (Cases does this on import)
```

Every tool writes its latest findings to `data/<tool>/findings.jsonl` in the one shared
format. Cases imports them:
- invalid lines are skipped and counted, never half-imported;
- a finding seen again updates its last-seen time and count instead of duplicating;
- the Network Map's alerts are exported offline, with the same titles, explanations
  and Fix panels as its Alerts tab.

The **timeline** mixes findings from all tools, notes and case events, filtered by tool or
severity. **Cases** hold findings, notes, a summary, tags, a status (open, investigating,
closed) and a log. Exports:
- **CSV** of indicators and of findings, with cells that a spreadsheet could run as a
  formula neutralised;
- a **STIX 2.1** bundle: identity, one indicator per unique indicator, one note per
  finding and per analyst note, and a grouping, all with stable ids;
- a **Markdown report**: timeline, every finding with its evidence and its Check/Fix
  commands in code blocks, indicators defanged (`hxxp[://]`, `[.]`), notes and limits.

## Vigil Tasks: what is running, and should it be?

```bash
python3 -m vigil.tasks          # the page, on http://127.0.0.1:8769/ (refreshes every 5 s)
python3 -m vigil.tasks tree     # the process tree in the terminal, with flags
python3 -m vigil.tasks scan     # flagged processes only; also saved for Vigil Cases
```

An EDR-style process tree from `/proc`, read-only. For every process it shows:
- the binary path and its owning package (pacman or dpkg database);
- the SHA-256 of the running binary, read through `/proc/<pid>/exe`, which works even if
  the file was deleted;
- parent chain, command line, user and start time;
- its systemd unit (from its cgroup);
- open sockets, from the Network Map's collector.

Flags:
- **binary deleted while running** (High). If the file came back with a package update it
  is "updated while running", Low.
- **runs from memory only** (memfd), High.
- **runs from /tmp, /var/tmp or /dev/shm** (High), **~/.cache** (Medium), Downloads or a
  hidden folder (Medium).
- **LD_PRELOAD / LD_AUDIT** in its environment (High). Only these linker variables are
  read; the rest of a process's environment (tokens, passwords) is never kept or shown.
- **odd parents**: a browser, mail app, document viewer, office or chat app starting a
  shell, interpreter or network tool (High; `xdg-open` and friends are Low); a web server
  or database starting a shell (High).
- a user program wearing a kernel-thread name (`[kworker…]`), a network tool wired to a
  shell, and a program in a temp or cache folder listening on all interfaces.

**Vigil never stops or signals a process.** Each finding's Fix panel offers commands to copy:
- *Pause it (reversible)*: `kill -STOP PID`, undo `kill -CONT PID`;
- *Stop its service*: `systemctl [--user] stop UNIT`, undo `start`;
- *End it*: `kill PID`, with how to start it again.

Processes of other users get `sudo` versions. As a normal user, other users' processes show
without their binary, hash or environment, and the page says so.

## Vigil Persist: what starts by itself, and what changed?

```bash
python3 -m vigil.persist            # the page, on http://127.0.0.1:8768/ (scans when it opens)
python3 -m vigil.persist scan       # scan in the terminal; the first scan becomes the baseline
python3 -m vigil.persist scan --all # ...and list every autostart entry
python3 -m vigil.persist accept     # make what is there now the new baseline
```

A Linux "Autoruns". It reads, and never changes:
- systemd units and timers: yours, the system's and the packages'; generators too;
- cron: crontab, cron.d, cron.hourly to cron.monthly, the spool;
- XDG autostart, yours and the system's;
- shell start-up files: bash, zsh and fish, profile.d, environment.d, X start-up;
- `/etc/ld.so.preload` and the linker paths;
- PAM;
- sudoers, sudoers.d and doas;
- SSH: `authorized_keys`, `~/.ssh/rc` and config, sshd_config;
- kernel modules: modules-load.d and modprobe.d `install` lines, plus the **loaded**
  modules from /proc/modules with their taint marks;
- udev rules;
- rc.local and init.d, NetworkManager dispatcher scripts, pacman hooks and apt.conf.d,
  update-motd.d.

The first scan is the **baseline**. Later scans show what is **new**, **changed** (content,
permissions or link target) and **gone**, and **Accept as baseline** moves the baseline on.
Each file is checked against the package that installed it: on Arch, pacman's mtree
(SHA-256) gives the same answer as `pacman -Qkk`; on Debian and Ubuntu, dpkg's md5sums,
with conffiles treated as editable config. On RPM distros it says why that can't be done
without running rpm, and offers `rpm -Vf`. Content checks flag:
- programs started from temp, hidden or Downloads folders;
- download-and-run commands;
- `LD_PRELOAD`;
- NOPASSWD-for-everything and `!authenticate` sudo rules;
- `pam_permit`/`pam_exec` and login modules from odd places;
- modprobe `install` commands, and udev `RUN+=` shells;
- world-writable or user-owned system start-up files;
- unsigned or out-of-tree kernel modules.

A file a package shipped unchanged is **labelled, not alarmed**: its findings drop to Low and
name the package. Known programs (the known-services catalogue) are named, so "Syncthing's
own autostart entry" reads as such. Files only root can read are listed as hidden, and
changes to them are still noticed. Fixes are copy-only:
- `systemctl [--user] disable --now`, with `enable --now` to undo;
- moving a file aside, with moving it back to undo;
- reinstalling the package (`pacman -S`, `apt install --reinstall`, `dnf reinstall`,
  `zypper install -f`).

## Vigil Files: is this file or archive safe to open?

```bash
python3 -m vigil.files                         # the page, on http://127.0.0.1:8767/ (opens on Downloads)
python3 -m vigil.files inspect ~/Downloads/x   # triage one file in the terminal (exit 2/1/0)
python3 -m vigil.files ls ~/Downloads          # each file's real type and any warning
python3 -m vigil.files watch                   # check new files in Downloads as they arrive
python3 -m vigil.files quarantine FILE         # move it into quarantine (asks first)
python3 -m vigil.files quarantined             # list quarantined files
python3 -m vigil.files restore ID              # put one back, with its permissions and time
```

A safe explorer: it shows what each file **is** (from its first bytes) and never opens a
file with its default app, never extracts an archive and never runs anything.
- **Archives, from their index only**: zip, tar, tar.gz/.bz2/.xz (and .zst on Python 3.14+),
  7z (plain or LZMA-compressed header) and rar (RAR4, RAR5). It checks:
  - compression ratio (normal files compress about 2–10×; 100× is Medium, 1000× High);
  - total declared size, entry count and folder depth;
  - **overlapping entries** (data ranges shared between zip entries);
  - `../` and absolute paths, links that point out of the archive, hard links;
  - device files, named pipes, setuid/setgid bits, duplicate names;
  - password-protected (encrypted) names.

  Compressed tars are read through a decompressing stream with a **hard cap**
  (1 GB, 10 s), so a lying or bombed archive can't make it run away. The File Inspector
  engine also measures zip bombs by streamed counting (nested, Zip64, decoy directories).
- **Disguised files**:
  - double extensions (`invoice.pdf.exe`) and right-to-left override characters;
  - a type that doesn't match the extension;
  - a program or runnable file sitting in Downloads;
  - `.desktop` launchers that download, decode or run a shell, or pose as a document.
- **Documents**: PDF and Office triage from the spec (auto-actions, JavaScript, Launch,
  embedded files, macros, remote templates, DDE, and the URLs and IPs inside).
- **Quarantine** (you confirm each one): the file moves to `data/files/quarantine/<id>/`, with
  every permission removed, plus a record of its hash, original path, mode and time.
  **Restore** puts it back exactly, and refuses to overwrite anything. The page says whether
  that folder is on a `noexec` mount; making it one needs an admin, so Vigil relies on the
  removed permissions instead.
- **Safe preview**: plain text only, at most 64 kB, shown as text. Images, documents and
  programs are never rendered.
- **Watch Downloads**: a file is checked once it has stopped growing (`.part` and
  `.crdownload` are skipped). The page lists each one and, if you allow it, shows a desktop
  notification through the browser for anything Medium or High.
- **Hash lookups** (optional, Settings): VirusTotal or MalwareBazaar, only when you press the
  button. Only the SHA-256 is sent.

## Vigil Pkg: review an AUR package before you build it

```bash
python3 -m vigil.pkg                                   # the page, on http://127.0.0.1:8766/
python3 -m vigil.pkg review ~/.cache/paru/clone/foo    # the same review in the terminal
python3 -m vigil.pkg review ./foo --approve            # ...and remember this version as approved
python3 -m vigil.pkg review ./foo --aur                # also fetch AUR details (network: sends the name)
python3 -m vigil.pkg installed                         # audit foreign packages already installed
python3 -m vigil.pkg trusted                           # versions you approved
```

Point it at a PKGBUILD folder: your AUR helper's review folder (paru: `~/.cache/paru/clone/<pkg>`,
yay: `~/.cache/yay/<pkg>`) or a `git clone https://aur.archlinux.org/<pkg>.git`. Vigil reads
the files as **text**: it never runs `makepkg`, never sources the PKGBUILD and never
downloads the sources. The verdict is **Don't install**, **Review these lines** or **Looks
normal**, never "safe". Every finding names the exact file and line, says why it matters,
and offers copy-only Check / Fix / Undo commands. The terminal review exits with 2, 1 or 0
for those three verdicts, so it can sit in a script.

What it checks:
- **Look-alike names**: a popular name plus fix, patched, cracked, premium…; one-letter typos;
  names of packages removed for malware (librewolf-fix-bin, firefox-patch-bin,
  zen-browser-patched-bin; the 2018 acroread/balz/minergate).
- **Sources**: bare IP addresses, pastebins, link shorteners, file-sharing sites, plain
  `http://`, and sites that differ from the project's `url=`.
- **Checksums**: `SKIP` or missing checksums for downloaded release files and `-bin`
  programs (git sources are fine); MD5/SHA-1 only.
- **Network inside build steps**: curl, wget, git clone, pip install, raw sockets in
  `prepare()`/`build()`/`package()`; npm/go/cargo fetches as Low.
- **Run what you download**: piping into a shell, `bash <(curl …)`, eval, `base64 -d`
  (into a shell), long encoded text, chmod +x then run, `/dev/tcp`.
- **Code that runs on reading**: commands outside functions, `$(…)` at the top level.
- **.install scripts** (they run as root): downloads, services switched on, accounts and
  admin groups, passwords, cron, setuid, firewall or SELinux off, files outside the package.
- **Writes outside `$pkgdir`**, `sudo`, shell start-up files, `systemctl --user`, autostart.
- **Other files**: links (never followed), compiled programs in the repository, pacman
  hooks and `.desktop` files that download or decode.
- **History**: press **Approve** (or `--approve`) and the next review shows a diff, marks new
  lines, and flags a new maintainer; a `.SRCINFO` that disagrees with the PKGBUILD.
  **Check AUR details** (opt-in, sends only the package name to aur.archlinux.org) adds:
  orphaned, under a month old, changed hands (recently), maintainer's account looks new,
  no votes.
- **Installed**: foreign packages (like `pacman -Qm`, from the sync databases, or the
  packager field when they can't be read), known-malicious and look-alike names among them,
  and files changed since install (like `pacman -Qkk`: missing, type, link, mode, size,
  SHA-256 from each package's mtree; config files marked as backup are skipped). On other
  distros it says so and shows that distro's own read-only check (`rpm -Va`, `dpkg --verify`).

## Vigil Net (the Network Map)

The original Vigil app, moved to `vigil/net/` with no behaviour change: the Network Map
plus its Alerts, Files, Scan, Cleanup, Cases, Intel and Settings tabs. Everything below
this point, down to "Tests", describes it. `python3 -m vigil` still starts it, with the
same commands and options.

### Run it

Needs Python 3.11 or newer on Linux. Nothing to install; no root needed.

As a desktop app, in its own window:

```bash
python3 -m vigil app
```

To put Vigil in your application menu (for your user only, no root):

```bash
python3 -m vigil install-desktop
```

The window comes from what your machine already has, with no new dependency: a
native WebKitGTK window when PyGObject and WebKit2GTK are installed (most GNOME
desktops), otherwise Chromium, Chrome, Brave, Edge or Vivaldi in `--app` mode, which
gives a window with no tabs or address bar, a private profile in `data/app-profile`,
and the browser's background networking switched off. Failing both, it opens your
default browser. Pick one with `--window native|chromium|browser`, or point
`VIGIL_BROWSER` at a browser binary. Closing the window stops Vigil. Starting the app
while Vigil is already running opens a window onto the running one: one data
directory never gets two pollers.

Or as a local web page:

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
python3 -m vigil inspect suspicious.docm     # static triage of a file (read only, never run)
```

## What you see

The look follows an EDR process analyzer, drawn the way professional tools are: flat
near-black plum surfaces, 1px hairline borders, small corner radii, and colour used
only where it means something (orange for actions and selection, the teal-to-ice
cyan for live network activity, red and amber for severity). No gradients, blurs or
glows, except the marker under the active tab. Type is SF Pro where the system has
it (macOS) and otherwise Inter, which is bundled (OFL, 48 KB, variable). Code is in
JetBrains Mono (OFL, 40 KB).

- **Programs → destinations (Map view).** Each program holding a socket is an
  flat-shaded isometric cube on the left, with a state label above (`LIVE PROCESS`, `IDLE
  PROCESS`, `ALERT · …`), its name in an orange pill and count chips below. Each
  remote address is a globe on the right. Edges are thick bands. Particles flow
  along connections that are open now, in the direction of the traffic, and labels
  ride along each edge (`443 · 6 live`, `80 · 4 minutes ago`). A thin orange hexagon marks
  the selected node; a dashed red one marks alerts. An orange `new` chip marks
  things first seen after Vigil's baseline (its first poll).
- **Analyzer view.** Double-click a program, or press "Analyze process": the map
  rearranges into a diagonal cascade from the program's parents (oldest first) to the
  program and then the addresses it contacted. Edges between processes are labelled
  with the real time between their starts (`470 ms`, `3 min 12.4 s`).
- **Motion, kept functional.** Nodes move between layouts instead of jumping, edges
  draw in, and small particles flow along connections that are open right now, in the
  direction of the traffic.
- **Themes** (the Theme menu on the map): **Grid** (hexagons with a few other shapes),
  **Night** (a drifting, twinkling starfield of dots, sparkles, rings, crosses and
  diamonds with constellation lines; one canvas, ~30 fps, stopped when not visible) and
  **Plain**. The choice is remembered in this browser.
- **Which site is this?** Press **Identify** (toolbar, or right-click an address). Vigil:
  1. reads your open browser tabs from the browser's session file on this PC
     (LibreWolf, Firefox, Floorp, Waterfox, Zen; for Chromium, Chrome, Brave, Vivaldi
     and Edge, the last two hours of history). It keeps host names and titles, never
     full URLs;
  2. looks up those host names with your normal DNS resolver (the same lookups the
     browser already made) to see which addresses they point to;
  3. opens one TLS handshake to each HTTPS address on the map, sending no web request,
     to read its certificate. Addresses on a threat feed are never contacted.

  Destinations then show their host name above the address, a `tab: …` chip (for
  example `tab: VirusTotal - File - …` on the address LibreWolf is using for it) and a
  security chip. A browser's panel gets an **Open tabs** list with the addresses each
  tab uses.
- **Connection security** (a destination's Security tab). Every connection gets badges
  from its port alone, with no network: HTTPS, QUIC (HTTP/3), plain HTTP, plain DNS,
  DNS over TLS/QUIC, SSH, plaintext FTP/Telnet/POP3/IMAP/IRC, mail over TLS,
  WireGuard/OpenVPN, NTS, STUN/WebRTC, SMB/RDP exposure. After Identify, the TLS
  handshake adds:
  - **Protocol and cipher**: TLS version (1.3/1.2 good, older flagged), cipher
    strength (AEAD or not) and forward secrecy.
  - **Certificate trust**: whether the chain is trusted by your system's CAs for that
    host name, with the exact reason when not (self-signed, expired, wrong name…),
    expiry countdown, not-yet-valid, name mismatch.
  - **Certificate details**: validation level (DV/OV/EV, with the organisation), key
    type and size (RSA under 2048 flagged), weak SHA-1/MD5 signatures, Certificate
    Transparency proof, OCSP must-staple, HTTP/2 via ALPN.
  - **HSTS**: whether your browser has recorded the site as HTTPS-only (read from its
    own records).

  Each badge says what it means, and the certificate (issuer, validity, key,
  signature, names) is listed below. With the system's "reduce motion"
  setting it all stays still.
- **Direction.** A connection accepted on one of your listening ports is shown as
  inbound (`in 22`), keyed by the service port, not the client's random port.
- **Side panel (left).** Select a node to see its events, in the style of an EDR event
  list (`connection, opened` · `Oct 30, 2026 · 21:42:12.778` · addresses you can
  click). The Details tab has the executable, command line, user, parent chain, start
  time and destinations, and the Scores tab has the scored pairs. Every event says
  where it came from (for example `/proc/net/tcp inode 4069, owner from
  /proc/90/fd`).
- **First-seen tracking.** Vigil remembers every destination, program-to-destination
  pair and each program's first outbound connection in SQLite. The first poll is
  recorded as the baseline, so "new" means new since Vigil started watching.
- **Listening sockets** and their exposure (all interfaces, one interface, this
  machine only).
- **What is this?** The top of the panel says what the selected program *does*, not
  just what it is. It draws on Vigil's offline notes on about 50 common Linux programs
  and services (what it does, why it uses the network, what is normal, what deserves
  a second look) and on what Vigil observed: who started it and when, which ports it
  used and what those ports are for, and whether its executable belongs to an
  installed package (dpkg, pacman, rpm, Snap, Flatpak, AppImage, Nix) or was put there
  by hand. Addresses get the same treatment: where they are, who owns them (with the
  geo database), which programs use them and over what.
- **Right-click anything.** Programs, parents in the analyzer, destinations and every
  address in an event list or connection table have a context menu: analyze the
  process chain, inspect the executable, "what is this?", connections, events, why
  this score, show only this, copy path/PID/address. Arrow keys, Enter and Esc work.
- **Precision.** The Connections tab lists every connection a program made: when it
  opened (to the millisecond), how long it lasted, local and remote ends, the service
  on that port, state, socket inode and bytes sent and received. Gaps in the analyzer
  read `470 ms`, `40.82 s`, `3 min 12.4 s`; parents show their exact start time.

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

## File Inspector (Files tab)

Drop a file on the Files tab, or run `python3 -m vigil inspect FILE`. Vigil reads
the file's bytes and nothing else. **It never opens, runs, renders, imports or saves
the file.** Archives and compressed streams are expanded in memory only, with size
caps, and only the report is kept. The upload goes from your browser to Vigil on
127.0.0.1.

The report leads with a verdict: **Likely malicious** (score ≥ 70), **Suspicious**
(≥ 30) or **No suspicious indicators found**. It never says "safe".

The layout follows the familiar multi-scanner report. A score box shows how many of
Vigil's analyzers flagged the file, out of those that ran. Next to it are the
SHA-256, the name, tags for each check that fired, size, when it was inspected and
the file type. Under them are four tabs:
- **Detection**: the top finding, then a grid of Vigil's nine analyzers (name and
  type, archive and bomb analysis, Office macros, Office structure, RTF exploits,
  PDF, scripts and command lines, offline threat feeds, this PC's network history).
  Each row says what it found, "Nothing found", or why it did not run. Below the grid
  come the findings with their points, meaning and source.
- **Details**: hashes, the format-specific details and **what this check cannot tell
  you**.
- **Indicators**: the URLs, addresses and domains found inside.
- **Behaviour**: empty until the detonation VM exists (build step 6).

The rows are Vigil's own analyzers, all offline.

### Second opinions: ClamAV and hash lookups (optional)

- **ClamAV (local antivirus)** appears as a row in the analyzer grid. When it is
  installed, inspected files are passed to it on stdin, in the background: the report
  appears at once and the ClamAV row fills in when the scan finishes. Vigil uses
  `clamdscan` if the clamd daemon is running (fast: its signatures are already loaded)
  and otherwise `clamscan` with archive limits (400 MB scanned, 16 levels deep, 90 s).
  ClamAV unpacks archives to scan inside them (with temporary files it deletes
  afterwards), so a file Vigil has measured as an archive bomb, or one that would
  expand past 1 GB, is **not** given to ClamAV; its row says why. A malware signature counts 70 points, a "PUA." name 25 and
  a "Heuristics." name 20. Each finding records the engine and signature versions.
  If ClamAV isn't installed, the row says so and nothing else changes. To install it
  (needs sudo once, for the package):

  ```bash
  sudo apt install clamav clamav-daemon      # Debian, Ubuntu, Mint
  sudo dnf install clamav clamav-update clamd # Fedora
  sudo pacman -S clamav                       # Arch
  ```

  Then run `sudo freshclam` once, or enable the `clamav-freshclam` service, to
  download signatures. Enable `clamav-daemon`/`clamd` for fast scans.
- **Vendor lookups**: two buttons on the Detection tab, which do nothing until you
  press them.
  - **VirusTotal** sends the SHA-256 to VirusTotal's API and shows the full engine
    list (for example "2 / 58 engines flagged this file"), the threat label,
    categories, family labels and other names the file has been seen under. 5 or
    more detections count 70 points and 1–4 count 30. Needs a free personal API key
    (4 lookups a minute, 500 a day).
  - **MalwareBazaar** (abuse.ch) says whether this exact file is a known malware
    sample, and of which family (70 points). It uses the same free Auth-Key as the
    threat feeds.

  If the service has never seen the file, the report says that, which tells you
  nothing either way. Set keys in the Intel tab (stored in `data/settings.json`,
  readable only by you, never sent back to the page) or with the `VIGIL_VT_KEY` and
  `VIGIL_ABUSECH_KEY` environment variables. Files are never uploaded: an upload to
  VirusTotal would be available to its paying customers.

| Area | What is checked |
| --- | --- |
| Disguise | double extensions (`invoice.pdf.exe`), right-to-left override characters, padded names, content that doesn't match the extension (an executable named `.pdf`, RTF named `.doc`) |
| PDF | PDFiD-style keyword counts over the body *and* every inflated stream (so object streams can't hide them): `/JavaScript` with `/OpenAction`/`/AA`, `/Launch` (with its target), embedded files (and their names), `/XFA`, `/RichMedia`, `/JBIG2Decode`, hex-escaped names (`/J#61vaScript`), data appended after `%%EOF`; JavaScript text is shown |
| Office (OOXML) | VBA macros, with source decompressed from `vbaProject.bin` (MS-OVBA); auto-run entry points (`AutoOpen`, `Document_Open`, `Workbook_Open`, ActiveX events); behaviour (Shell, downloads, COM, file writes, Win32 API, memory, obfuscation); Excel 4.0 macro sheets and `Auto_Open`; remote templates (T1221); remote OLE objects, including the Follina `mhtml:`/`ms-msdt:` pattern; DDE/DDEAUTO fields; embedded objects and executables; ActiveX; macros in a `.docx` |
| Office (legacy OLE2) | the same VBA analysis for `.doc`/`.xls`/`.ppt`; BIFF8 macro sheets (including "very hidden") and `Auto_Open` names; packaged files (`Ole10Native`); encrypted documents |
| RTF | embedded objects, `\objupdate`, Equation Editor (CVE-2017-11882), `OLE2Link` (CVE-2017-0199), executables inside `\objdata`, malformed headers |
| Archive bombs | measured **without extracting**: each compressed stream is decompressed into a counter that keeps only 4 KB at the start and 1 MB at the end, so memory stays flat however large the output. Nested zips are read from that tail. Reported: total expanded size (exact, or "at least" when a 1 GB per-stream or 12 s cap is hit), many names sharing one block of compressed data (overlapping entries, the trick behind non-recursive bombs such as `42.zip`'s successors), sizes the directory lies about, forged end-of-directory records, ratios no real compressor produces, zip-slip paths (`../../.bashrc`), symlink members and entry floods. A bomb is never unpacked further |
| Compressed streams | `.gz`, `.bz2`, `.xz`: expansion measured the same way, then (when small enough) the content is inspected like any other file |
| Archives | every member inspected in turn (two levels deep); password-protected members reported |
| Scripts, shortcuts, HTML | PowerShell download cradles and hidden or encoded launches, `curl … \| sh`, reverse shells, LOLBins, temp-dir `chmod +x`, persistence; LNK arguments; HTML smuggling |
| Indicators | URLs, IPs, domains, e-mail addresses (and hashes in text), from raw bytes, UTF-16 strings, inflated streams, XML parts and macro source. Format namespaces (`schemas.openxmlformats.org`, …) and version strings are filtered out. Indicators are shown as text, never as links |
| Context | indicators matched against the downloaded threat feeds, and addresses **this PC has actually connected to** (linked to the Network Map; loopback and link-local addresses are ignored, every PC talks to those) |

Each finding carries a plain-language line saying what it means for you (for
example "Opening this archive would try to write about 275 GB. Do not extract it.").

**Example.** A real non-recursive zip bomb (257 KB, from a public GitHub collection)
holds one 40 MB zip whose 256 entries all point at the same compressed block and
each claim to be 2 bytes. Vigil reports it as Likely malicious (100): about 8.8 TB if
extracted (its inner file is named `32-256.zip`: 32 GiB × 256), overlapping entries,
lying sizes and a forged directory. It takes about 1.7 s, writes nothing to disk and
never unpacks it.

**Bombs over a terabyte.** Vigil counts at most 1 GB per stream. When a stream is cut
off there, Vigil extrapolates from how much compressed input produced that 1 GB:
bomb data compresses evenly, so this is reliable. It never reports less than it
counted.

It also handles:
- Zip64 records (how members over 4 GB are described), including inside nested zips.
- Siblings that weren't measured: they take the expansion that identical measured
  siblings showed.
- Directories Python's zip reader refuses: Vigil reads them with its own parser.
- Decoy directories: an entry pointing into the middle of a header is resolved to the
  nearest real file header, and that header's own sizes are compared with the
  directory's. A real sample (`64x4096-Z.zip`, 378 KB) reads as about 281.5 TB in
  about 1 s.

Tests build bombs of over 1 TB at real scale (300 Zip64 names over one 4 GB deflate
stream, and the same bomb nested inside another zip) and detect them in about a
second each.

**Inspect a running program's executable.** Right-click a program on the map, or
press "Inspect executable" in its panel. Vigil reads the binary through
`/proc/<pid>/exe` (so it works even if the file was deleted or replaced on disk) and
runs the same static triage. It never runs it. Programs get identity, string and
indicator checks only. Indicators are searched in the file's printable strings, the
way `strings` does, so a 300 MB binary takes about 5 s.

## Alerts: titles, explanations and the Fix panel

Each alert has a short title in plain English, at most 60 characters: **who** does
**what** to **whom**, **how often**. For example *"Syncthing checks in with Hetzner (DE)
every ~7 min"* or *"An unidentified program sends plain HTTP every ~5 min"*. The
destination is a domain, else the network owner and country, never a raw IPv6
address. Under it is one line: severity (Low / Medium / High), first seen, and the
likely explanation when one matches.

Open an alert for **Why was this flagged?**:
- One sentence on what is happening.
- What Vigil noticed: one line per signal, with a strength bar.
- Why that matters: each kind of signal explained once, innocent explanation
  included.
- The likely explanation, with confidence and what matched.
- How sure Vigil is.
- What to do next.
- The raw numbers (regularity, check-ins, missed polls, byte counts, sources), in a
  collapsed *Technical details*.

When Vigil can't name the program, it says exactly why: too short-lived for the poll
interval, or owned by root. It then offers to look every 0.5 s for 10 minutes, or
explains the optional admin mode, which is off by default.

**Known services** (`vigil/core/data/known_services.json`) recognise common background
traffic:
- NetworkManager's connectivity check
- Syncthing discovery and relays
- Firefox-family and Chromium-family background requests
- NTP time sync
- package mirror syncs
- desktop update checkers

A match lowers the severity and says *"probably X"*. It never hides the alert:
you decide whether to allowlist it.

The **Fix** tab lists **Check it** (read-only, always first), **Fix it** and **Undo**.
Each option says what it does, what you lose and its risk (Safe, Changes settings,
Admin needed), and shows its undo.

**Vigil never runs a fix.** Commands are text with a Copy button, and a test fails if
the fix modules can start a process.

How the commands are chosen:
- They match your distro, read from `/etc/os-release`: pacman, dnf, zypper, apt, xbps,
  apk or emerge.
- The firewall commands match firewalld, ufw or nftables, judged from config files.
- Blocks name one destination and are reversible.
- Browser fixes are step-by-step settings instructions.

Every command is colour-coded by token, with a tooltip and a legend:
- red: admin
- blue: package manager (a different colour per distro family)
- green: install or turn on
- orange: remove or turn off
- purple: package or app
- cyan: path
- grey: option
- yellow: systemctl

**Allowlist…** asks for a reason and a scope: this program and this destination, or
this program everywhere. It shows which alerts will stop before you save. Every rule
can be undone from **Settings**.

## Scan tab: what starts by itself, what is exposed, malware signatures, vulnerable packages

**Quick scan** (a few seconds, read-only) checks four things.
- **What starts by itself:**
  - systemd user and system units;
  - cron;
  - autostart entries;
  - shell startup files;
  - `/etc/ld.so.preload`;
  - SSH `authorized_keys`;
  - udev rules.

  It flags programs started from temporary or hidden folders, download-and-run
  commands and reverse shells. The first scan becomes the baseline; later scans flag
  anything **new or changed** (for example, a new SSH key).
- **What is open to the network:** listening ports on every network (not localhost),
  SSH allowing root or password logins, and no firewall.
- **Running programs:** files deleted or replaced while running, programs in `/tmp` or
  `/dev/shm`, and memory-only (memfd) programs. A deeper check compares installed files
  with their packages (`sudo pacman -Qkk`, `rpm -Va`, `dpkg --verify`).
- **Known vulnerabilities (Arch):** your installed versions compared with Arch's
  security advisories, using pacman's own version ordering. It shows "fixed in X" or
  "no fix yet", the CVEs, and `sudo pacman -Syu` to install fixes.

**Full scan** also runs **ClamAV** and **YARA** over Downloads, `/tmp`, `/var/tmp` and
`/dev/shm`, in the background.

Downloads happen only on the buttons: **Update YARA rules** fetches YARA-Forge's core
rule set, and **Update security advisories** fetches `security.archlinux.org/all.json`.
YARA itself is the `yara` package (`sudo pacman -S yara`).

## Cleanup tab

Vigil measures what could go and what each item costs you:
- **Caches:** `~/.cache` folder by folder, with what each holds, and the Trash.
- **Packages:**
  - pacman's package cache (`paccache -rk2` keeps the two newest versions);
  - orphaned packages, read from pacman's database;
  - unused Flatpak runtimes;
  - dnf, apt or zypper caches on other distros.
- **Logs:** the journal (`journalctl --vacuum-size=200M`) and crash dumps.
- **Your files** (old downloads, very large files, broken links): **listed only**,
  never given a delete command.

Every command names exact paths, with no wildcards.

## Sudo mode (Settings, off by default)

With sudo mode on, fix, cleanup and scan commands get a **Run** button next to Copy.
- Vigil shows the exact command and asks first.
- Admin commands run through **pkexec**: your system's own password window shows the
  command and takes your password. Vigil never sees it.
- Vigil only runs commands it generated itself. The server rebuilds them and refuses
  anything else, along with any shell syntax (pipes, `&&`, redirects, wildcards).
- One command per press, no shell, a 10-minute limit.
- Output and exit code are shown, and every run is written to the event log.
- `sudoedit` steps stay copy-only, because they open an editor.

## Cases and exports (Cases tab)

A case gathers one investigation: its evidence, the indicators in that evidence,
your notes, tags and a status (open → investigating → closed). Use **Add to case…**
on an alert, on a program or destination in the map's side panel, or on a file
report. Every change is kept in the case's activity log.

- **Evidence is copied in when added** (a snapshot), with the time. The case keeps
  what was seen even after old connections are pruned or an alert is deleted. Adding
  a program also hashes its running executable through `/proc/<pid>/exe` (a byte
  read; works even if the file was deleted), so the program becomes a file-hash
  indicator.
- **Indicators** are derived from the evidence (addresses, file hashes, and the URLs,
  domains and addresses found in files). They are deduplicated, with every source
  kept in the context. You can add your own, and untick any you don't want exported,
  such as a font vendor's URL found inside a malicious PDF. "Malicious" means listed
  by a downloaded feed, or taken from a file judged Likely malicious; the context
  says which.
- **Exports** (download buttons on the case):
  - **CSV** of the indicators. Cells that a spreadsheet would read as formulas are
    neutralised.
  - **STIX 2.1** bundle: an identity, one `indicator` per indicator with a STIX
    pattern, the notes, and a `grouping` for the case. IDs are deterministic
    (UUIDv5), so re-exporting updates objects downstream instead of duplicating them.
  - **Markdown report**: summary, every piece of evidence with its findings and where
    each came from, indicators, a merged timeline, notes and the limits. Indicators
    and any links in the text are defanged (`hxxp[://]`, `198.51.100[.]20`) so
    nothing is clickable.

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
- No network calls, except the ones you trigger: feed and database downloads, the
  hash-lookup buttons on a file report (which send the file's SHA-256 and your API
  key, never the file), and **Identify** (DNS lookups of your open tabs' host names
  and one TLS handshake per HTTPS address, never to a listed address). A test checks
  that raw connections exist only in `identify.py`, and another renders the map and
  every destination with Identify's network functions patched to fail. Nothing about your traffic leaves the machine. A test checks
  that `urlopen` appears in exactly one function, another runs a full poll, score and
  lookup with networking patched to fail, and another checks that an upload makes no
  request.
- ClamAV, when installed, gets the file's bytes on stdin; Vigil writes nothing. ClamAV
  never runs a file, but it unpacks archives to scan inside them, using temporary
  files it deletes afterwards. So Vigil never hands it a file it has measured as an
  archive bomb, or one that would expand past 1 GB.
- The evidence store (`data/vigil.db`) is created in a directory only you can read.

## Tests

The tests use only the standard library's `unittest`; pytest also runs them.

```bash
python3 -m unittest discover -s tests -t .      # every tool
python3 -m unittest discover -s tests/net -t .  # one tool
```

`tests/fixtures/` holds a **synthetic** miniature `/proc` (labelled as such; see its
README), synthetic feed files, and benign documents written by LibreOffice. Suspicious
sample files are *generated at test time* by `tests/synth.py` with harmless content,
so nothing in the repository looks like malware to antivirus. The `/proc` fixture
covers IPv4, IPv6, IPv4-mapped addresses, shared sockets, interpreters, deleted
executables, a hostile process name and every "hidden" case. Live tests open socket
pairs and check that the collector attributes them to the test process and that the
netlink byte counts are exact.

## Layout

```
vigil/core/          shared by every tool
  finding.py         the one finding format, validated; JSON-lines export
  wording.py         title rules (60 characters, plain English), friendly names, human numbers
  commands.py        colour-coded command tokeniser (display only)
  fixes.py           Check / Fix / Undo options, distro-aware, copy only
  system.py          distro detection (os-release), package owner lookup, firewall detection
  catalogue.py       known benign services (data/known_services.json)
  store.py           per-tool SQLite evidence store + findings.jsonl
  web.py             the 127.0.0.1-only web server every tool uses
  netfetch.py        the single function in the suite that can open a URL (on request only)
  runner.py          sudo mode (Network Map only): runs only Vigil-generated commands, via pkexec
  pkgdb.py           pacman and dpkg databases read directly: ownership, mtree / md5sums integrity, vercmp
vigil/ui/static/     shared UI kit: style.css, fonts, ui.js, fx.js, menu.js, findings.js
                     (finding card, Fix panel, colour-coded commands, verdict, code and diff
                     views), tree.js (tree view), icon
vigil/net/           Vigil Net: the Network Map and its tabs
  collector.py       read-only /proc parser: sockets, processes, what is hidden
  store.py           its SQLite evidence store (data/vigil.db); tracker turning polls into history
  scoring.py         explainable scores, beacon detection, allowlist, alerts
  enrich.py          threat feeds and country/ASN database (download on request)
  identify.py        browser tabs, host names, TLS handshake, certificate parsing, security badges
  wording.py         alert titles, subtitles and explanations
  fixes.py           alert Fix panels: one-address firewall blocks, service fixes
  scans.py           system scan: persistence, exposure, integrity, ClamAV/YARA folders, Arch advisories
  cleanup.py         cleanup survey: caches, package leftovers, logs, old files (read-only)
  knowledge.py       offline notes on programs and ports; plain-language summaries
  cases.py           the Network Map's own cases: CSV, STIX 2.1, Markdown
  desktop.py         desktop window (WebKitGTK / Chromium app mode), menu entry, data lock
  server.py          JSON API, background poller
  static/            its page: index.html, netmap.js (hand-written SVG graph), tab views
vigil/files/         Vigil Files, and the File Inspector engine Net's Files tab also uses
  triage.py          one file's full triage in the suite's finding format; safe preview
  listing.py         archive index listing: zip, tar(.gz/.bz2/.xz/.zst), 7z, rar; nothing extracted
  quarantine.py      quarantine and restore
  watch.py           Downloads watcher (polling)
  server.py static/  its page and command line
  inspector.py       static triage engine, verdict, indicators
  archives.py        archive-bomb measurement: streamed decompression, nothing extracted
  ole.py             OLE2 compound files and VBA macro decompression (read only)
  engines.py         second opinions: ClamAV on stdin; VirusTotal / MalwareBazaar hash lookups
vigil/pkg/           Vigil Pkg
  parse.py           PKGBUILD / .install / .SRCINFO reader: bash syntax as text, never run
  checks.py          every review check, the verdict
  names.py           look-alike and known-malicious package names
  review.py          safe folder reading, approved versions, opt-in AUR metadata
  installed.py       foreign packages, pacman -Qkk-style file check
  server.py static/  its page
vigil/persist/       Vigil Persist
  locations.py       every autostart location and the content checks for each
  scan.py            baseline and diff, package ownership and integrity, findings
  server.py static/  its page and command line
vigil/tasks/         Vigil Tasks
  procs.py           /proc walk: binaries, packages, hashes, units, sockets, tree; the flags
  findings.py        findings and copy-only stop commands
  server.py static/  its page (uses the shared tree view, ui/static/tree.js) and command line
vigil/cases/         Vigil Cases
  store.py           imported findings, cases, notes, log; the timeline
  importer.py        every tool's findings.jsonl, Net's alerts, pasted files
  export.py          CSV, STIX 2.1, Markdown report
  server.py static/  its page and command line
vigil/net/export.py  the Network Map's alerts as suite findings
vigil/core/export.py STIX patterns and ids, defanging, Markdown and CSV-injection guards
tests/core/          core tests and suite-wide safety rules
tests/<tool>/        each tool's tests
tests/fixtures/      synthetic fixtures (labelled), shared
```
