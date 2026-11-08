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
