# Vigil 2: the native rewrite

This file is a prompt for Claude Code (see also the review in section 1 and the risks in section 10). Read all of it before writing anything. It is written
to you, the engineer doing the work, by the owner (Ula) and her reviewer.

---

## 0. Why we are doing this

Vigil today is a Python suite (about 18,000 lines of Python, 4,800 of JavaScript, 8,200 of
tests) that serves seven web pages on seven localhost ports. It works, and its rules and
wording are good. But it is a set of web pages you start from a terminal. It only sees the
system when it looks (every 2 to 5 seconds), it forgets everything when you close it, and it
cannot feel fast or "alive".

Vigil 2 is **one native Linux application**, written in Rust. It installs like any other app,
starts in a blink, keeps watching in the background with a tiny footprint, updates itself
through the system's own package manager, and sees events as they happen instead of polling.
It should feel like a premium security product, built for one person's PC. Someone new to
Linux should be guided to the right action. Someone who does all of this by hand should get
an instrument that is faster and deeper than their own terminal.

**The Python repo is your specification.** Every rule, explanation, check, wording choice and
test in it is there for a reason. Port the behaviour, not the code layout. When you are
unsure what something should do, read the Python, its tests and `docs/PROGRESS.md`.

---

## 1. What is weak or basic in Vigil 1 (fix all of this)

**Architecture**
- Seven HTTP servers on seven ports, so every move between tools is a full page reload, and
  state is not shared.
- It runs only while a terminal holds it open. Nothing watches when the window is closed,
  and there are no desktop notifications.
- Everything is **polling**: /proc every 2 s (Net) or 5 s (Tasks). Short-lived processes and
  connections are missed or show as "not attributed". Credential theft that opens, copies
  and closes a file within a second is invisible.
- **No DNS visibility.** Unconnected UDP has no remote address in /proc, so Vigil shows IPs,
  not "this program looked up evil.example". The owner runs a Pi-hole and Vigil ignores it.
- History is thin. You cannot ask "what was talking at 3 a.m. on Tuesday?".

**Detection depth**
- Hand-written heuristics only. No rule language, no Sigma, no YARA (ClamAV is shelled out
  to only if it is installed).
- Persist compares a baseline when you press Scan. It does not notice a new autostart entry
  the moment it is written.
- Tasks cannot show a process's history (parent that already exited, what it ran before),
  per-process bandwidth, namespaces, capabilities, seccomp or cgroup.
- Pkg covers the AUR only. The owner also runs Fedora and openSUSE. Flatpak permissions, pip
  and npm global packages, browser extensions, and the CVEs in installed packages are not
  covered.
- No security posture check: firewall state, SSH settings, open ports, sysctl hardening,
  Secure Boot, disk encryption, pending updates.
- Files is static only. The detonation lab (Vigil Lab) was never built.

**Experience**
- Text-heavy. Every card explains itself in full sentences, which is great the first time
  and slow the tenth. There is no "expert" view with dense tables, raw values and a query bar.
- One layout for everyone, no onboarding, no saved views, no favourites.
- The AI layer is bolted on: off by default, CLI-only investigations, lookups disabled.

---

## 2. Non-negotiable rules (carried over, plus new ones for a daemon)

1. **Never execute, open or import an inspected file on the host.** Static analysis reads
   bytes only. Detonation happens only inside the lab VM.
2. **Every finding explains itself**: what was noticed (with strength), evidence with where it
   came from (check, data, time), likely explanation, how sure, ATT&CK technique, and Check /
   Fix / Undo commands. No unexplained red dots. Never call anything "safe": say "no
   suspicious behaviour found" and list the limits.
3. **Few alerts, high confidence.** Known-good periodic traffic is allowlisted, not alerted.
4. **No fake data.** Synthetic test data lives under `tests/` and is labelled synthetic.
5. **No network calls the user did not enable.** Update checks, rule-pack downloads, feed
   updates, hash lookups and AI are each a separate switch, off until the user turns them on
   in onboarding or Settings, and each is logged. Never send traffic, IPs or files anywhere.
6. **Run mode** (formerly sudo mode) keeps its rules: off by default; only commands Vigil
   generated, re-checked by the daemon against the finding they came from; no shell; one
   command per press; the user confirms the exact text; admin rights only through polkit, so
   the system's own dialog takes the password and Vigil never sees it; every run is logged.
   Run sits next to Copy everywhere, greyed out with its reason when it cannot run.
7. **The privileged daemon is small and boring.** It collects, stores and answers queries.
   It never parses untrusted file formats (that happens in the unprivileged app or in a
   sandboxed worker), never runs a shell, and authenticates every client (`SO_PEERCRED` plus
   polkit for privileged actions). It drops every capability it does not need after start.
8. **Must run on any Linux distro.** Distro-specific code sits behind one small trait with a
   fallback. Test on Arch (hardened kernel), Fedora and openSUSE Tumbleweed at minimum.
9. **Dependencies are a decision.** Section 9 lists the allowed crates. Anything else: stop and
   ask, with what it does, its licence, its maintenance status and its transitive count.

---

## 3. Shape of the system

```
┌──────────────────────────── user session ────────────────────────────┐
│  vigil            the app (GPU UI, keyboard-first)                   │
│  vigil-cli        the same engine in a terminal (+ `vigil tui`)      │
│  vigil-notify     tiny user service: desktop notifications, tray     │
│        │  D-Bus (system bus, zbus), polkit for privileged actions    │
├────────┼─────────────────────────────────────────────────────────────┤
│  vigild           system service (systemd), minimal capabilities     │
│   ├─ sensor:  eBPF (Aya) → fallbacks: proc connector, sock_diag,     │
│   │           fanotify, inotify, /proc polling                       │
│   ├─ store:   SQLite (WAL), retention, rollups                       │
│   ├─ engine:  rules (built-in + YAML + Sigma subset), scoring,       │
│   │           storylines, baselines                                  │
│   └─ actions: Run mode, firewall (nftables), quarantine — polkit     │
└──────────────────────────────────────────────────────────────────────┘
```

**Cargo workspace**

| crate | job |
| --- | --- |
| `vigil-model` | finding format (port `core/finding.py` exactly, versioned), severities, ATT&CK map, wording rules, command tokens |
| `vigil-sensor` | event sources behind one `Source` trait; eBPF programs in `vigil-sensor-ebpf` (no_std, BPF target) |
| `vigil-store` | schema, migrations, retention, queries, the time machine |
| `vigil-engine` | every check from the Python tools, the rule loader, scoring, allowlist, decisions, storylines |
| `vigil-files` | static file and archive analysis, YARA-X, quarantine (runs unprivileged, in a seccomp'd worker) |
| `vigil-pkgs` | package databases (pacman, rpm, dpkg, flatpak, pip/npm global), AUR/PKGBUILD review, CVE matching |
| `vigild` | the daemon: sources → engine → store, D-Bus API, polkit actions |
| `vigil-ui` | the app |
| `vigil-cli` | CLI and TUI (ratatui) on the same D-Bus API |
| `xtask` | builds, packaging, fixtures, release |

**IPC.** D-Bus on the system bus via `zbus`, one interface per area
(`org.vigil.Events`, `.Findings`, `.Processes`, `.Network`, `.Files`, `.Actions`). Streams
are signals with back-pressure (the UI subscribes to what is on screen). Privileged methods
check polkit actions declared in `org.vigil.policy`. Never put secrets on the bus.

**Fallbacks are a feature.** Hardened kernels may block BPF
(`kernel.unprivileged_bpf_disabled`, lockdown, missing BTF). The daemon picks the best source
per signal and the UI's "What Vigil can and cannot see" panel says exactly which ones are live
and why, as Vigil 1 does today.

---

## 4. The sensor (the biggest upgrade)

Build with Aya. Kernel 5.8+ with BTF; degrade below that.

| signal | primary | fallback |
| --- | --- | --- |
| process exec / fork / exit, full argv, parent, uid, cgroup | tracepoints `sched_process_exec`, `sched_process_fork`, `sched_process_exit` | netlink proc connector, then /proc polling |
| outbound / inbound TCP with pid at the moment of connect | kprobes `tcp_v4_connect`, `tcp_v6_connect`, `inet_csk_accept`, `tcp_close` | netlink `sock_diag`, then /proc/net polling |
| UDP, including DNS questions and answers per process | kprobe `udp_sendmsg` / `udp_recvmsg`, parse DNS in userspace from a bounded copy | Pi-hole query log (opt-in, read via its API or FTL database), systemd-resolved monitor |
| sensitive file opens (SSH keys, browser profiles, wallets, keyrings, `.env`, cloud credentials) | BPF LSM `file_open` when available, else kprobe on `security_file_open`, filtered in-kernel by inode set | fanotify on those paths |
| autostart and config writes | fanotify / inotify on the Persist location set | rescan on a timer |
| module loads, BPF program loads, ptrace, setuid, memfd exec | tracepoints / LSM hooks | /proc and /sys polling |
| USB and input devices | udev monitor | — |

Budgets on the owner's laptop: **idle CPU under 0.5 %, daemon RSS under 60 MB, UI under
150 MB, event-to-screen latency under 100 ms.** Drop and count events rather than block the
kernel; show drop counts in the visibility panel.

---

## 5. The app

### 5.1 Pick the toolkit with a spike, not a guess

Two days, two candidates, same two screens:
1. the Network Map with 2,000 nodes and live animated edges, panning and zooming at the
   display's refresh rate;
2. the command palette plus a 100,000-row process table with type-ahead filtering.

- **GPUI + gpui-component** (Zed's GPU framework): fastest rendering, a real keybinding and
  action system, a dock layout. Pre-1.0 with breaking changes, thin docs: pin exact versions.
- **iced 0.14 / libcosmic**: Elm architecture, stable releases, used by the COSMIC desktop,
  better accessibility work in progress.

Default to GPUI if both pass. **Do not use Tauri or any webview**: on Linux the webview is
WebKitGTK, which is slower and less consistent than Chromium, and the owner asked for native.
Write down the measured numbers and the decision in `docs/DECISIONS.md`.

### 5.2 Design language

Keep Vigil's identity: dark plum base (`#110e15` → `#2d2637`), warm orange for action and
selection (`#ff9f43`), the wallpaper's teal → ice cyan (`#5dbdb9` → `#62f3ff`) for live
network activity, red and amber only for severity. Inter for UI text (SF Pro where present),
JetBrains Mono for code. Hairline borders, 10 px radii, one surface per card, never boxes
inside boxes. Colour only for meaning. Port the token set from `vigil/ui/static/style.css`
into a theme struct, and support a light theme and a high-contrast theme from day one.

### 5.3 Motion: gorgeous, never in the way

- **Launch / home ("the arrival").** Clicking the Vigil mark (top left), or pressing `g h`,
  plays about 700 ms: the three cube faces fly in from top, left and right on a spring
  (stagger 70 ms); the orange core ignites with a quick overshoot (scale 0 → 2.2 → 1);
  two rings sweep out (ice, then orange, 120 ms apart) over a faint grid that fades in from
  the centre; the word VIGIL resolves from wide tracking and slight blur. Then Home's cards
  rise into place, staggered by 30 ms. The web version in `vigil/ui/static/suite.js` and
  `style.css` (`.arrive`) is the reference. Pressing any key skips it.
- **Navigation.** The rail's active marker slides between items (spring, ~220 ms). Moving from
  a list item to its detail uses a shared-element transition: the row grows into the panel
  header. Tabs cross-fade with a 6 px slide. Nothing animates longer than 300 ms except the
  arrival.
- **Live data.** Particles flow along connections that are open now, counters roll to new
  values, new nodes ease in and closed ones fade out. Motion always carries information.
- **Rules.** Honour reduced motion (system setting plus Vigil's own Full / System / Reduced).
  No animation blocks input. Never repaint at frame rate while idle.

### 5.4 Layout

A left **rail** (icon + label per area, the mark at the top, Settings and the profile at the
bottom), a **top bar** (area title, its tabs, live status, Run mode chip, search), and a
**dockable** main area: list ↔ detail, resizable, with layouts saved per area. Detail panels
open beside the list, not on top of it, so the eye and the mouse travel little.

### 5.5 Keyboard (must be complete before anything ships)

Everything is reachable without a mouse, and every shortcut is shown in the palette and in
tooltips.

| keys | action |
| --- | --- |
| `Ctrl K` | command palette: areas, tabs, findings, processes, IPs, files, actions, settings |
| `1`–`9` | jump to an area; `g` then a letter (`g h` Home, `g n` Network, `g p` Processes …) |
| `j` / `k`, `↑` / `↓` | move in lists; `Enter` open; `Esc` back or close |
| `[` / `]` | previous / next tab; `Ctrl [` / `Ctrl ]` back / forward in history |
| `/` | filter this view; `?` shortcut sheet; `,` Settings |
| `c` | copy the selected command, `r` Run it (confirm dialog focused on Cancel) |
| `e` | set aside (Expected / Fixed / Not a problem, with a reason) |
| `a` | add to case; `p` pivot on the selected entity |
| `t` | open the time machine at the selection's time; `Space` play / pause live |
| `x` | toggle Guided / Expert for this view |

Users can rebind keys in Settings, and the bindings live in a TOML file.

### 5.6 Guided and Expert

The same data, two densities. Neither is dumbed down.
- **Guided** (default): plain-language cards from the Python wording modules, one recommended
  next step, Copy / Run, the reason for everything.
- **Expert**: dense sortable tables with configurable columns, raw values (hex, uid,
  inode, cgroup path), a query bar (`proc.name = "curl" and net.dst.country != "GB"`), saved
  queries, export to JSON / CSV / STIX, and the event stream itself.

---

## 6. Features: each area goes deep

**Home.** Posture score with what moves it, "since you last looked" digest, storylines,
recommended next steps, health of Vigil itself (sensors live, drops, rule-pack age).

**Network (Net).**
- Live map and a **time machine**: scrub any minute of the last 30 days (configurable) and
  replay what was talking.
- Per-process **DNS**: which program asked for which name and got which addresses. Pi-hole
  integration (opt-in): blocked lookups per program.
- Bandwidth per process and per destination; world view of destinations (offline geo DB).
- Beaconing detection (Vigil 1's scoring, ported), first-seen everything, JA4/TLS fingerprints
  where the sensor can see the ClientHello.
- **Block** a program or a destination with generated, reversible nftables rules (Run mode,
  polkit). Temporary blocks expire on their own.
- LAN view: devices on the home network (ARP / neighbour table, mDNS), new-device alerts.

**Processes (Tasks).**
- Live tree with lineage that survives exits (from exec/exit events), a timeline per process,
  "why is this running" (parent chain, systemd unit, the autostart entry that launched it,
  package, install date, signature check).
- Capabilities, namespaces, cgroup, seccomp mode, environment flags (`LD_PRELOAD`), memfd
  and deleted executables, open secrets, per-process network and DNS.
- Stop / suspend / resume **your own** processes with confirm (the owner's earlier decision
  in `docs/SUITE.md`); others stay copy-a-command or Run mode.
- YARA-X scan of a process's executable and mapped files (read from disk, never run).

**Autostart (Persist).** Real-time: a new systemd unit, cron entry, shell rc change, PAM
module, `ld.so.preload`, SSH key, kernel module, udev rule or BPF program raises a finding
within a second, with a diff against the baseline and package-checksum verification
(pacman, rpm, dpkg).

**Files.** Everything Vigil 1 does (archives without extraction, disguise checks, PDF /
Office triage, quarantine, Downloads watcher), plus YARA-X with a curated, signed rule pack,
ELF analysis (imports, packers, entropy, interpreter, RPATH), script deobfuscation preview,
and "send to Lab".

**Software (Pkg → Software).** AUR / PKGBUILD review (ported), plus Fedora and openSUSE
package audits, Flatpak permission review (which apps can read your home, talk on the system
bus …), pip / npm / cargo global installs, browser extensions (Firefox, Chromium) with
their permissions, and **CVE matching** of installed packages against OSV and the Arch
security tracker (opt-in feed, cached offline).

**Guard (new): hardening and posture.** Firewall state, listening ports and who owns them,
SSH server config, sudoers, sysctl hardening, Secure Boot, disk encryption, pending updates,
kernel lockdown, AppArmor / SELinux status. Each item: what it means, why it matters, Check /
Fix / Undo, Run mode.

**Canaries (new).** Plant decoy credentials (fake `~/.aws/credentials`, a fake SSH key, a
browser-profile decoy) and alert the instant any process reads them. Removable in one click.

**Cases.** Timeline across everything, storylines, notes, exports (Markdown, CSV, STIX 2.1),
plus a printable incident report and one-click "case from this storyline".

**Lab (later, opt-in).** Detonation in a throwaway VM (libvirt/QEMU) with the same sensor
inside, process tree, network, file writes, ATT&CK tags, evasion warnings. Stop and ask
before building it: it needs VM setup on the owner's PC.

**AI analyst (optional, off by default).** Keep Vigil 1's design in `docs/AI_PLATFORM.md`:
redacted, previewed, fenced evidence, tamper detection, commands checked against generated
ones, every request logged.

---

## 7. Installing, updating and staying healthy (the user should do almost nothing)

**Packages, not a Flatpak.** Vigil needs a system service, the host's real /proc and
capabilities. A Flatpak sandbox shows only its own processes in /proc and cannot load BPF, so
it cannot be the main package. Ship native packages and let the distro update them:

| distro | channel | automation |
| --- | --- | --- |
| Arch | AUR `vigil-bin` | a release job updates the PKGBUILD and checksums and pushes to the AUR |
| Fedora | COPR repo | Packit builds on every GitHub release |
| openSUSE, Debian, Ubuntu (and Arch, Fedora as a second source) | Open Build Service repo | OBS rebuilds and publishes on every release |
| anything else | signed tarball + install script | cargo-dist |

Each package installs: the binaries, a hardened systemd unit for `vigild` (`ProtectSystem`,
`NoNewPrivileges`, `CapabilityBoundingSet` limited to what the sensor needs,
`SystemCallFilter`, `MemoryMax`, `WatchdogSec`, `Restart=on-failure`), the user units, the
D-Bus and polkit files, a sysusers entry, the desktop file, AppStream metainfo and icons.

**Updates.** System updates (Discover, GNOME Software, `dnf`, `zypper`, `pacman`) bring new
versions with no extra step. In the app, an opt-in check against GitHub Releases shows "Vigil
x.y is available" with a changelog and an **Update** button that asks PackageKit over D-Bus to
update that one package. On Arch, where the AUR is outside PackageKit, the button becomes a
generated `paru -S vigil-bin` command with Copy and Run. Rule packs and intel feeds update
on their own schedule, signed with minisign and verified before use. Never self-replace
binaries from inside the app.

**First run.** A short onboarding: what Vigil watches, which sensors are live on this kernel
(with a fix for each missing one), which network features to switch on (all off by default),
Guided or Expert, and a first check-up. Then the tray icon and notifications take over.

**Self-maintenance.** Automatic retention and `VACUUM`, schema migrations with a backup
first, a health page, `vigil doctor` (checks BTF, capabilities, polkit agent, D-Bus, disk
use, clock, rule-pack age, and prints fixes), and crash reports that stay local unless the
user exports them.

**Release engineering.** GitHub Actions: `cargo fmt`, `clippy -D warnings`, tests, eBPF tests
in a VM (`virtme-ng`), `cargo deny` (licences, advisories, duplicates), `cargo audit`, an
SBOM, reproducible builds, signed artefacts. Conventional commits and release-plz for
versions and changelogs.

---

## 8. Order of work (one milestone at a time, each shippable)

Port the Python tests first for every milestone and keep them green. Reuse
`tests/fixtures/` (synthetic /proc, feeds, files, PKGBUILDs) as golden inputs, so Rust and
Python must agree on the same findings.

1. **Spike and skeleton.** Toolkit spike (5.1), workspace, CI, `vigil-model` with the
   finding format and wording rules, packaging skeleton that installs on Arch, Fedora and
   Tumbleweed. *Done when:* an empty app with rail, palette, Settings, the arrival animation
   and the full keyboard map installs from a package and starts in under 300 ms.
2. **Daemon and store.** `vigild`, D-Bus API, polkit, SQLite schema, /proc fallback sources.
   *Done when:* the CLI lists processes and connections through the daemon, as an
   unprivileged user, on all three distros.
3. **Processes and Network at parity**, then the eBPF sensor with fallbacks, DNS per process
   and the time machine. *Done when:* a 50 ms `curl` shows up attributed, with its DNS name.
4. **Autostart, Files, Software at parity**, then real-time Persist, YARA-X, CVE matching.
5. **Home, Cases, storylines, decisions, Run mode** across everything; notifications and tray.
6. **Guard, Canaries, firewall blocks, LAN view.**
7. **Expert mode**: query language, columns, saved views, exports.
8. **Polish**: motion pass, accessibility (AccessKit, screen reader labels, focus rings,
   contrast), light and high-contrast themes, performance budgets verified.
9. **Lab** (stop and ask first).

---

## 9. Allowed crates (ask before adding anything else)

`aya`, `aya-ebpf`, `aya-log` · `tokio` · `zbus` · `serde`, `serde_json`, `toml` ·
`rusqlite` (bundled SQLite) · `yara-x` · `nix` · `procfs` · `netlink-packet-*`,
`neli` (pick one) · `nftables` (JSON API) · `hickory-proto` (DNS parsing only) ·
`goblin` (ELF) · `zip`, `tar`, `flate2`, `xz2`, `zstd` (listing only, bounded) ·
`sha2`, `blake3` · `minisign-verify` · `time` · `thiserror`, `anyhow` · `tracing` ·
`clap` · `ratatui` · the chosen UI toolkit and its component crate · `notify-rust`,
`ksni` (tray) · `ureq` or `reqwest` (opt-in network only) · dev: `insta`, `proptest`,
`criterion`.

---

## 10. Problems with rewriting in Rust (read these before starting)

- **It is a big job.** About 23,000 lines of product code and 421 tests encode months of
  decisions. A rewrite risks losing them. Mitigation: port tests first, use the Python
  fixtures as golden inputs, and keep Vigil 1 working until Vigil 2 reaches parity.
- **The UI is rebuilt from scratch.** The SVG network graph, treemap, swimlanes, coloured
  command tokens and rich text all become custom rendering. Native toolkits are weaker than a
  browser at text selection, copy and accessibility, and both candidates are young
  (GPUI pre-1.0, iced with long release gaps).
- **A root daemon is a new attack surface.** Vigil 1 never needed root. Vigil 2's sensor
  does. The daemon must stay tiny, parse nothing untrusted, authenticate every caller and be
  sandboxed by systemd. Installing it needs root once.
- **eBPF may be blocked** on the owner's hardened Arch kernel (lockdown,
  `unprivileged_bpf_disabled`, missing BTF). The fallbacks are not optional.
- **More dependencies.** Vigil 1 is standard library only. Vigil 2 needs crates, so supply-
  chain checks (`cargo deny`, `cargo audit`, pinned versions, a short allowlist) matter.
- **Packaging is real work**: AUR, COPR, OBS, signing keys, CI. It is what makes "install and
  forget" possible, but someone has to own it, and an updater is itself an attack path, which
  is why updates go through the distro's package manager and are signature-checked.
- **Slower iteration.** Changing a colour today means editing CSS and refreshing. In Rust it
  means a rebuild. Hot-reload of the theme file and the spike's measurements help.
- **Learning curve.** The owner is learning C and systems programming. Rust, async and eBPF
  are a steep combination to review. Keep `unsafe` out of everything except the BPF crate,
  and explain each module in `docs/` as you build it.

---

## 11. How to work

1. Read this file, `CLAUDE.md`, `docs/SPEC.md`, `docs/SUITE.md`, `docs/AI_PLATFORM.md` and
   `docs/PROGRESS.md` before writing code.
2. Work in a new directory `vigil2/` on a branch `vigil2`; Vigil 1 stays untouched and runnable.
3. For each milestone: tests first, build, run, fix until green, update `docs/PROGRESS2.md`
   (what was built, measurements against the budgets, limits, decisions), commit, push.
4. Make sensible decisions yourself and record them in `docs/DECISIONS.md`.
5. **Stop and ask** when something needs sudo on the owner's PC, a crate outside section 9,
   a change to the safety rules, the Lab, or when tests still fail after several honest
   attempts. Never weaken a test to make it pass.
