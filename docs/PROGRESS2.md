# Vigil 2: progress

What was built for each milestone of docs/RUST_REWRITE.md, measured against the budgets, with
limits and decisions (the decisions themselves are in docs/DECISIONS.md).

---

## Milestone 1: spike and skeleton (2026-11-08)

### Built
- **Workspace** `vigil2/` with the crates from section 3 (`vigil-model`, `vigil-ui-core`,
  `vigil-ui`, `vigil-store`, `vigil-sensor`, `vigil-engine`, `vigild`, `vigil-cli`, `xtask`).
  `unsafe` is forbidden in every crate (`[workspace.lints]`).
- **vigil-model**: the finding format (`core/finding.py`), wording rules (`core/wording.py`),
  command tokens (`core/commands.py`), the Run-mode checks from `core/runner.py`, Fix panels
  (`core/fixes.py`), the ATT&CK map (`core/attack.py`), distro facts (`core/system.py`).
  Findings serialise to the exact JSON Vigil 1 writes, byte for byte.
- **Golden tests**: `vigil2/tests/golden/make_golden.py` runs Vigil 1's Python on synthetic inputs
  and writes the answers to `model.json`; the Rust tests must give the same answer for every one
  (74 commands, 12 findings built, 12 broken findings with their exact error text, 42 titles,
  24 sentences, numbers, names, ATT&CK tags, the os-release fixtures). CI regenerates the file and
  fails if it changed, so Vigil 1 and 2 cannot drift apart silently.
- **Toolkit spike** (`vigil2/spike/`): both candidates, both screens, a bench script and
  screenshots. Result and reasoning: D-002.
- **vigil-ui-core**: areas (9 on the rail, keys 1–9), the keymap (every binding from section 5.5,
  chords such as `g h`, rebinding through `keys.toml` with clash and prefix detection, and the rule
  that letters type into text fields), palette ranking, motion (springs, Vigil's ease curve, the
  arrival as a pure function of time, card rise, reduced motion), themes (dark, light, high
  contrast, a hot-reloaded `theme.toml`), and the app's own settings file.
- **vigil-ui** (GPUI): the shell. Rail with icons, labels and a spring-animated marker; the Vigil
  mark at the top and Settings and the profile at the bottom; a top bar with the area title,
  tabs, Guided/Expert, live status and Jump to…; the command palette; Settings; the shortcut
  sheet; the arrival (cube faces fly in on a spring, staggered 70 ms; the core overshoots
  0 → 2.2 → 1; ice then orange rings 120 ms apart over a grid fading in from the centre; VIGIL
  resolving from wide tracking); Home's cards rise after it, 30 ms apart. Any key skips it;
  reduced motion skips it. The app repaints only while something moves.
  Screens: `docs/vigil2/screens/app-*.png`.
- **Packaging skeleton** (`vigil2/packaging/`): hardened `vigild.service`, the user unit for
  notifications, D-Bus policy and activation, polkit actions, sysusers, desktop file, AppStream
  metainfo, icon, an AUR `vigil-bin` PKGBUILD, an RPM spec (Fedora COPR, openSUSE OBS) and Debian
  files for OBS. `cargo run -p xtask -- dist` stages the install tree all of them use.
- **CI** (`.github/workflows/vigil2.yml`): fmt, clippy `-D warnings`, tests, golden freshness,
  `cargo deny`, `cargo audit`, packaging checks.
- **xtask**: `dist`, `check-deps` (every direct dependency must be on the section 9 allowlist; it
  fails the build otherwise), `check-packaging` (the unit keeps its hardening, names agree across
  files and code, distro validators pass).

### Tests
`cargo test --workspace`: 34 tests, all pass (vigil-model 8 unit + 10 golden, vigil-ui-core 16).
`cargo clippy --workspace --all-targets -D warnings`: clean. `check-deps`, `check-packaging`: pass
(desktop-file-validate, appstreamcli, xmllint). `systemd-analyze security` on the unit: 2.0 OK.

### Measurements against the budgets
| budget | measured | where |
| --- | --- | --- |
| app starts in under 300 ms | 127–162 ms to first frame (6 runs); 741 ms on the very first cold run (font cache and shaders) | container, software rendering, `vigil --measure-startup` |
| never repaint at frame rate while idle | the shell requests frames only while the marker, the arrival or the cards move | code review; spike idle test: GPUI 0.5 % CPU |

### Limits (honest list)
- **Not installed from a package on Arch, Fedora or Tumbleweed.** The container is Ubuntu with no
  systemd running and no VMs; the files validate, `xtask dist` stages them, but the "installs from a
  package on all three distros" part of milestone 1 is not done. It needs a run on real systems
  (or the CI jobs for COPR/OBS once there is a release).
- The spike numbers come from software rendering. The toolkit choice must be confirmed on the
  owner's laptop (D-002).
- The arrival's "slight blur" on the word is drawn as extra transparency: GPUI has no blur filter
  on text.
- Areas show what they will contain and which milestone brings it. They show no data yet, on
  purpose (no fake data).
- Fonts: the app asks for Inter and falls back to the system font; Vigil 1's bundled Inter files
  are not embedded yet.

---

## Milestone 2: daemon and store (2026-11-08)

### Built
- **vigil-sensor**: the /proc source, ported from Vigil 1's collector (socket tables, fd
  scanning, process identity, parent chains, start times, hidden-socket reasons, hidepid), and the
  "what Vigil can and cannot see" report from kernel facts (BTF, unprivileged BPF, lockdown,
  LSMs). Golden test: the same sockets, processes and explanations as Vigil 1 on the synthetic
  /proc fixture, as root and as a simulated normal user.
- **vigil-store**: SQLite in WAL mode; append-only migrations with a backup before each upgrade;
  refuses files from a newer version; connections, programs, destinations, processes (keyed by pid
  and start time), events, findings; first-seen tracking that outlives retention; the time machine
  (`connections_at`, `connections_between`); retention with incremental vacuum.
- **vigild**: polling sensor thread, store, D-Bus API (`org.vigil.Daemon`, `.Processes`,
  `.Network`, `.Events` with a `Changed` signal, `.Findings`), caller credentials from the bus,
  polkit checks (`org.vigil.read`, cached 10 s per caller), development mode (`--bus session`,
  same uid only), sd_notify READY/WATCHDOG/STOPPING, clean stop on SIGTERM, logs with journald
  levels.
- **vigil-cli**: `status`, `processes`, `connections`, `at` (time machine), `events`, `whoami`,
  `doctor`, `--json`; every cell neutralised with `wording::printable`.
- **Docs**: `docs/vigil2/` explains each crate (README, model, sensor, store, daemon, cli, ui,
  packaging), including a short guide to reading Rust.

### Tests
`cargo test --workspace`: 46 tests, all pass (34 in milestone 1 plus 12 new: sensor golden (4), visibility (1), store (3),
vigild end to end on a private D-Bus (1: every interface, a live `Changed` signal, uid 65534
refused, clean SIGTERM), CLI (2), `printable` (1)). Clippy `-D warnings` clean; `check-deps` and
`check-packaging` pass.

### Done-when, checked
"The CLI lists processes and connections through the daemon, as an unprivileged user": done in
the container (Ubuntu 24.04) with the real pieces: a system D-Bus, polkitd, vigild started the way
the unit starts it (user `vigil`, CapEff = CAP_SYS_PTRACE + CAP_DAC_READ_SEARCH only, polkit
mode), and `vigil-cli` run as the normal user `ula`:
- without a desktop session polkit asked for an admin password and the request was refused with a
  readable reason (fail closed);
- with a rule standing in for the desktop session (container only, `tools/system-demo.sh`),
  `ula` listed every process and every connection, including root's `http.server` socket
  attributed to its program, which `ula` alone could never see;
- `vigil-cli doctor` passed every check.

### Measurements against the budgets
| budget | measured (container, 88 processes) |
| --- | --- |
| daemon idle CPU under 0.5 % | 0.45 % of one core over 60 s, polling every 2 s |
| daemon RSS under 60 MB | 9 MB |

### Limits (honest list)
- **Only one distro.** The done-when says "on all three distros"; it was checked on Ubuntu 24.04
  in a container. Arch (hardened kernel), Fedora and Tumbleweed still need a run
  (`tools/system-demo.sh` works in any throwaway VM).
- **The CPU budget is close.** Every look re-reads every process. On a desktop with several
  hundred processes this will likely pass 0.5 %. Milestone 3 replaces most polling with events
  (proc connector, eBPF); until then, caching process details by (pid, start time) is the next
  step if it is needed.
- **Polling misses short-lived things**, as Vigil 1 did: anything that starts and ends between two
  looks. That is milestone 3.
- **No runtime capability drop** (D-010, question for the owner).
- **No findings yet**: `Findings.List` is empty until the Network and Processes checks are ported
  (milestone 3).
- Byte counts per socket (sock_diag, which Vigil 1 had) are not ported yet.

### Supply chain (section 10, "More dependencies")
- The daemon's dependency tree is 83 crates (zbus 6, tokio, rusqlite with bundled SQLite, nix,
  serde, clap and what they need). The app's is about 570: GPUI brings a full GPU stack (wgpu),
  font shaping, and image codecs including an AV1 encoder. All 692 crates in the lock file are
  under licences on the `deny.toml` list. `cargo deny check` passes (advisories, bans, licences,
  sources); `cargo audit` runs in CI.
- `cargo deny` flagged zbus 5's `zvariant` and `zbus_names` as unmaintained (merged into zbus 6),
  so the daemon and CLI moved to zbus 6 and the polkit check was repeated against real polkit.
  Six unmaintained crates remain, all inside GPUI's tree and none in the daemon's; each is an
  explained exception in `deny.toml` (D-015).
- The privileged part (vigild) does not link GPUI or anything graphical: only the app does.

### Questions for the owner
1. D-003: allow the `regex` crate before porting Pkg and Files (milestone 4)?
2. D-010: allow the `caps` crate so the daemon can drop unused capabilities at run time?
3. D-002: run `vigil2/spike/run-bench.sh` on the laptop to confirm GPUI.

---

## The app on live data, and the new arrival (2026-11-08, start of milestone 3)

The owner asked for a better arrival, real data instead of placeholders, clickable controls
everywhere, and Apple-like transitions.

### Built
- **The arrival**, redrawn from geometry (D-016): traced circle → hexagon morph → inner edges →
  faces and core → a flight that lands exactly on the rail logo while the app appears. Plays on
  launch, on the mark and on `g h`; any key skips it.
- **Live data** (`live.rs`, D-017): the app finds the daemon by itself and refreshes on its
  `Changed` signal. Home, Network (map, connections, time machine), Processes (tree, table) and
  Cases → Timeline show what the daemon sees; a detail panel opens beside lists; the palette
  also finds processes and addresses.
- **Clickable everything**: rail, tabs, Guided/Expert, the live status (pause), Jump to…, palette
  rows, Settings controls (theme, motion, density take effect at once), map nodes, table rows,
  the parent chain, Copy buttons, Done, clicking outside an overlay to close it.
- **Motion** on SwiftUI-style springs: area and tab entrances, staggered rows, sliding detail
  panel, overlays in and out, rolling numbers, spring rail marker, hover and press states.
- When no daemon is running, the app says so and shows the two commands to start one, with Copy.

### Tests
48 pass (`cargo test --workspace`): new motion tests (hexagon geometry, continuity, exact
landing, springs) and the process-tree order. Clippy clean. Checked by running the app in the
container against the system daemon (polkit, user `vigil`) and taking screenshots
(`tools/ui-shots.sh`, `docs/vigil2/screens/app-*.png`).

### Limits
- The map draws up to 20 programs and labels up to 36 addresses; a busy machine needs grouping
  (milestone 7's Expert work).
- Text in the app is not selectable yet (GPUI); Copy buttons and `c` cover command lines.
- The map repaints continuously while it is on screen (its dots show open connections).
  Measured cost on a real GPU is still to be checked against the budgets.
- Findings, DNS, Autostart, Files, Software, Guard and Canaries still need their engines
  (milestones 3 to 6).

---

## The owner's review, round 2 (2026-11-09)

### Built
- **The mark and arrival from squares** (D-018).
- **Settings and popups** (D-020): Settings is a labelled popover beside the Android-style gear
  (Material "settings"), toggled by the gear or `,`; it slides out from behind the rail and back.
  Palette and shortcuts have titled headers and close buttons. Keyboard focus is kept on the app
  (some compositors started it unfocused, so no key worked).
- **Home** fills the window: the device's name (hover shows the file it came from), model and
  system, laptop or desktop, the battery (laptops) or driver health from the kernel's age and taint
  flags (desktops), and a quartered shield whose border catches a light every few seconds; live
  numbers with their recent history; network activity with program icons; the busiest programs
  (the daemon now reports CPU and memory per process); traffic by service and place; activity;
  coverage with hover details.
- **Network map**: still columns (this PC, programs with icons, the addresses they talk to), curved
  links, a dot grid, no moving parts, no overlaps; the selected program's links light up and a callout
  opens beside it; the map never resizes. Clicking a program points it out in the taskbar (D-021).
  The connections list shows each program's icon, the service (HTTPS, DNS ...), the place and the
  state with an icon (a tick for open).
- **Program icons** from `.desktop` files and the icon theme (system, user, Flatpak, Snap).
- **Packaging** (D-019): the tarball, installer, uninstaller, daily updater and the release workflow.

### Tests
51 pass. New: the square geometry and folding, device facts (name, model, battery, kernel age,
taint), launcher parsing for icons. Clippy clean; `check-deps` and `check-packaging` pass.

### Limits
- Driver health is an offline estimate (kernel age and taint flags); it cannot see vendor driver
  versions.
- Tested in the container on X with software rendering; KDE Wayland focus behaviour and the KWin
  attention script still need a run on the owner's laptop.
- The installer and updater were syntax-checked and the tarball's layout checked; a full install and
  an update cycle need a machine with systemd running (the container has none).

---

## The owner's review, round 3 (2026-11-09)

### Built
- **Layout everywhere** (D-022, and the owner's rules now in CLAUDE.md): a fixed inspector beside
  the map, Connections, Processes and Cases; overviews when nothing is selected; no floating cards.
- **Processes**: a virtual, sortable table (program with its arguments, PID, user, CPU, memory,
  started) that fills the width; jumps from Home, the map ("Show the process"), the palette and
  the parent chain scroll to the process and outline it. "Show the process" picks the program's
  main process (the browser, not one of its tabs).
- **Network map**: back to one compact radial screen: this PC in the centre, programs on an arc
  around it split left and right by load, each program's addresses in a column on its side, in the
  same order so links rarely cross. Vigil 1's hexagon grid background is back (Settings: Grid,
  Night, Plain, all still). A test checks that no two nodes overlap at three window sizes with up
  to 80 extra addresses.
- **Home**: battery and shield sit beside the device name; the busiest list is per program
  ("brave, 12 processes"); lists show as many rows as the window fits; flat sparklines are lines.
- **CPU** (D-022): the app paints only on new data; the daemon caches user names and writes less.
- **The mark** (D-023): teal shell, orange core cube.

### Tests
53 pass (new: the map layout test; the mark's merge and core geometry). Clippy clean.

### Limits
- CPU was measured in the container with software rendering. The owner's laptop (GPU) should be
  well below these numbers; the budget in section 4 (idle under 0.5 %) needs measuring there.
- With Brave-sized loads the map shows up to the rows that fit per side and a "+N more" node that
  opens the Connections tab for the rest.

---

## Milestone 3, step 1: Processes at parity (2026-11-09)

### Built
- `vigil-engine`: Vigil 1's process checks and secret detection (docs/vigil2/engine.md), with the
  finding builder (title, summary, reasons, source, ATT&CK, Check and Fix commands to copy).
- `vigild`: runs the checks every 10 s; stores findings; a new finding is also an event;
  `org.vigil.Findings.Recent(since)` for the app. Daemon CPU unchanged (0.57 % in the container
  with 90 processes).
- Sensor: open-file paths by readlink, and only the linker variables from the environment.
- App: flagged processes carry a severity chip; the Processes overview lists what is flagged;
  the inspector explains each finding (reasons and their strength, where it came from, ATT&CK)
  with copyable commands; Home counts findings; the timeline and Activity show them.
- Fixes found on the way: the Connections list and the timeline now scroll inside their cards.

### Tests
59 pass. New: the golden process checks (13 fixture processes, 34 synthetic cases, 23 flags,
41 secret paths), every flag makes a valid finding, the bus test sees the fixture's planted agent
flagged twice through `Findings.List` and `Findings.Recent`.

### Limits and next steps
- Checks run on 10 s looks: a program that starts and exits between them is not checked. The
  event sensors (netlink proc connector, then eBPF) are next, then DNS per process and Network's
  checks (beaconing and the rest of Vigil 1's scoring).
- No package database yet (D-024).

---

## Milestone 3, step 2: Network at parity (2026-11-13)

### Built
- `vigil-engine::net`: Vigil 1's scoring (beacons, long connections, first-seen, rarity, odd
  ports, where the program runs from), allowlist rules with `fnmatch` and CIDR matching, the
  70-point threshold, one alert per program/address/direction, and the alert's words and finding.
- Store schema 2 (`meta`: the baseline), queries for the scorer.
- `vigild`: scores the last 24 hours once a minute; built-in and user allowlist; alerts become
  findings and events. Clock times in findings use the local time zone (read before threads start).
- App: a flagged program carries its severity on the map; the inspector explains the alert;
  the network overview lists alerts.

### Tests
68 pass. New: the network golden tests (beacon statistics, observations, rules, five scored pairs
with their words), a whole scoring run (threshold, allowlist, one alert per program/address),
the store's baseline and scorer queries. Seen end to end in the container: a SYNTHETIC beaconing
history for the fixture's planted agent raised "agent checks in every ~1 min" (High).

### Limits
See docs/vigil2/engine.md (no byte counts, names, countries or feeds yet). Next: catching short-
lived processes and connections as they happen (process events), then DNS per program and eBPF.
