# Vigil 2: decisions

Decisions made while building Vigil 2 (docs/RUST_REWRITE.md section 11, step 4). Each says
what was decided, why, and what would change it. Newest last.

---

## D-001 Where Vigil 2 lives (2026-11-08)

- Code: `vigil2/`, a Cargo workspace, on the branch `vigil2`. Vigil 1 (`vigil/`, `tests/`)
  is untouched and still runs.
- The branch starts from the UI-pass bundle (`a848985`, on top of `claude/vigil-suite`),
  so it carries Vigil 1's latest state and the rewrite prompt.
- Docs about Vigil 2 go in `docs/vigil2/`; this file and `docs/PROGRESS2.md` are where the
  prompt asked for them.

## D-002 UI toolkit: GPUI, provisionally (2026-11-08)

**The spike (section 5.1).** Both candidates were built with the same two screens and the same
synthetic data (`vigil2/spike/`): a 2,000-node map with ~2,400 animated edges, particles,
200 text labels, pan and zoom; and a palette with a 100,000-row process table and type-ahead
filtering. Each has a self-driving bench (`vigil2/spike/run-bench.sh`).

**Measured in the cloud container.** There is no GPU there: both render through Mesa's software
rasteriser (llvmpipe / lavapipe) under Xvfb. So these numbers compare the two toolkits with
each other; they say nothing about the owner's laptop.

| | GPUI 0.3.11 (gpui-pre) | iced 0.14 |
| --- | --- | --- |
| Map: frames per second | 10.9 | 17.3 |
| Map: CPU ms per frame (all threads, incl. software raster) | 259 | 197 |
| Table: frames per second | 21.2 (paced at a fixed 48 ms tick on Xvfb) | 125 |
| Table: CPU ms per frame | 24 | 17 |
| Type-ahead filter over 100,000 rows | 4.0 ms mean | 3.9 ms mean |
| Idle CPU (table, nothing moving) | 0.5 % | 0.0 % |
| Process start to first frame (best of 5) | 165 ms | 170 ms |
| RSS (includes Mesa's software renderer) | 187–242 MB | 175–208 MB |
| Release binary | 37 MB | 23 MB |
| Clean release build, 4 cores | ~6 min + 4.5 min platform crate | ~5 min |

Screens: `docs/vigil2/screens/spike-*.png`. Both drew both screens correctly.

**Decision.** The prompt says: default to GPUI if both pass. Neither reaches the display's
refresh rate on the map without a GPU, and iced used about 25 % less CPU per frame here, which is
well inside what a real GPU changes (the raster work moves off the CPU). GPUI brings what the
prompt values most for this app: a real keybinding and action system, a dock layout
(gpui-component), and AccessKit integration already in the crate (milestone 8 needs it). So the
app is built on **GPUI, provisionally**.

**What would change it.** The owner runs `vigil2/spike/run-bench.sh` on the laptop (Wayland or X,
real GPU). If GPUI misses the refresh rate on the map, or idles above 0.5 % CPU, while iced does
not, switch. The cost is bounded: everything that is not drawing (keymap, palette ranking,
motion, theme, settings) lives in `vigil-ui-core` and does not change.

**Pinning.** GPUI is pre-1.0 and published as `gpui-pre` (renamed to `gpui` in Cargo.toml);
versions are pinned exactly (`=0.3.11`). Upgrades are deliberate.

## D-003 No `regex` crate, for now (2026-11-08)

Vigil 1 uses Python's `re`. `regex` is not on the allowlist (section 9). The few patterns in the
shared wording rules and the command tokeniser are matched by hand in `vigil-model`, each with
the original pattern quoted above it, and the golden tests prove they agree with Python on every
case. **Question for the owner before milestone 4:** porting Pkg's PKGBUILD review and Files'
script checks (dozens of patterns) by hand would be slow and risky. Proposal: allow `regex`
(rust-lang project, MIT/Apache-2.0, actively maintained, 3 transitive crates: `regex-automata`,
`regex-syntax`, `aho-corasick`, plus `memchr`). It guarantees linear-time matching, which also
removes ReDoS as a risk on hostile input.

## D-004 Finding ids keep SHA-1 (2026-11-08)

Vigil 1's id is the first 16 hex digits of SHA-1 of "tool|check|subject". Vigil 2 must give the
same id, or decisions, cases and allowlists made in Vigil 1 would stop matching. No SHA-1 crate is
allowed, so `vigil-model/src/sha1.rs` implements it (60 lines, checked against the FIPS test
vectors and Python). It is a name, not a security control.

## D-005 Tertiary text is a step lighter (2026-11-08)

Vigil 1's `--text-3` (#716a82) measures 3.7:1 on the window background, below WCAG AA (4.5:1).
Vigil 2 uses #8a8299 (4.8–5.2:1 on cards). Every theme is tested for contrast
(`vigil-ui-core/src/theme.rs`). The identity colours (plum base, orange, teal to ice) are
unchanged.

## D-006 Logging without a logging crate (2026-11-08)

`tracing` is allowed but `tracing-subscriber` is not, and `tracing` alone prints nothing. The
daemon writes plain lines to stderr with the sd-daemon priority prefix (`<6>`, `<4>`, `<3>`), which
journald reads as log levels. No crate needed.

## D-007 The daemon: its own account, a few capabilities, no network (2026-11-08)

- Runs as the `vigil` system user (sysusers.d), never root, with ambient capabilities limited to
  what the sensors need (see the comments in `packaging/systemd/vigild.service`).
- `RestrictAddressFamilies=AF_UNIX AF_NETLINK` and `IPAddressDeny=any`: the daemon cannot open a
  network connection even if it were compromised. Opt-in downloads (rule packs, feeds, update
  checks) happen in the unprivileged app; the daemon only verifies their minisign signatures.
- `systemd-analyze security` rates the unit 2.0 ("OK").
- Install path `/usr/lib/vigil/vigild` on every distro, so the unit is the same everywhere.

## D-008 Who may ask the daemon what (2026-11-08)

- Every call: the daemon asks the bus for the caller's uid and pid (`GetConnectionCredentials`,
  which dbus-daemon and dbus-broker fill from `SO_PEERCRED`).
- Reading (processes, connections, findings): polkit action `org.vigil.read`, which allows the
  active and inactive local sessions without a prompt and asks for an admin password otherwise
  (for example over SSH).
- Changing settings (Run mode, network features, retention): `org.vigil.manage`, admin password,
  remembered briefly. Running a command or changing firewall rules: `org.vigil.run`,
  `org.vigil.firewall`, admin password every time.
- Development mode (`vigild --bus session`): runs as you on your session bus, answers only callers
  with your own uid, and has no privileged actions at all.

## D-009 Names (2026-11-08)

D-Bus names, the polkit actions and the desktop id use `org.vigil.*` as the prompt specifies.
`vigil.org` is not the project's domain; if Vigil is ever submitted to Flathub or a distro's
AppStream catalogue, the ids should move to `io.github.eternalmangekyosharingan.Vigil`. Changing
them now would be cheap; later it means migrating installed systems.

## D-010 The daemon cannot drop capabilities at run time yet (2026-11-08)

Rule 7 says the daemon drops every capability it does not need after start. Dropping
capabilities from a running process needs the `capset` system call. `nix` has no safe wrapper
for it, `unsafe` is forbidden, and the `caps` crate is not on the allowlist. What protects the
system today is the unit: `CapabilityBoundingSet` and `AmbientCapabilities` grant only
CAP_SYS_PTRACE, CAP_DAC_READ_SEARCH, CAP_NET_ADMIN, CAP_BPF and CAP_PERFMON, and milestone 2 only
uses the first two. **Question for the owner:** allow the `caps` crate (MIT/Apache-2.0, small,
maintained, two dependencies) so the daemon can drop CAP_NET_ADMIN, CAP_BPF and CAP_PERFMON
whenever the sensors that need them are not running? Until then, the unit could be narrowed to
the two capabilities in use; it was left wider so milestone 3 does not need a unit change.

## D-011 JSON on the bus (2026-11-08)

The daemon's methods return JSON text (D-Bus type `s`) in the shapes of `vigil_model::host` and
`vigil_model::finding`, not D-Bus structs. Reasons: the finding format stays byte-identical
everywhere (bus, exports, Vigil 1); one versioned schema instead of two; unknown fields survive.
Cost: generic D-Bus tools (busctl, d-feet) show a string rather than typed fields. Signals that
fire often (`Changed`) use plain D-Bus types.

## D-012 polkit action owner (2026-11-08)

Found by running against real polkit in the container: polkit refuses
`CheckAuthorization` about another user's request unless the caller is root or the action's
declared owner ("Only trusted callers (e.g. uid 0 or an action owner) can use
CheckAuthorization() for subjects belonging to other identities"). vigild runs as `vigil`, so
every action in `org.vigil.policy` carries
`<annotate key="org.freedesktop.policykit.owner">unix-user:vigil</annotate>`. The daemon failed
closed before the fix, as designed. The owner annotation needs polkit 0.114 or newer (every
current distro has it).

## D-013 Attacker-controlled text is neutralised before display (2026-11-08)

Process names, command lines and file names are chosen by whoever created them. Printed raw,
they can carry newlines (breaking tables), terminal escape sequences (rewriting the screen), or
Unicode direction overrides (disguising a name). `wording::printable` turns all of these into
visible marks; the CLI passes every cell through it, and the app will do the same.

## D-014 The daemon sees as root when it may (2026-11-08)

With CAP_SYS_PTRACE the daemon can read every process's open files, so it builds its snapshot
with root's view. Otherwise an unattributed socket of another user would be explained as "the
kernel hides other users' sockets", which would be false. `viewer.user` then reads
"vigil (with CAP_SYS_PTRACE)".

## D-015 zbus 6 for the daemon; GPUI's unmaintained crates accepted for the app (2026-11-08)

`cargo deny` reported that zbus 5's `zvariant`, `zvariant_derive` and `zbus_names` are no longer
maintained (merged into zbus 6). The privileged daemon must sit on maintained code, so vigild and
vigil-cli use zbus 6 (four small API changes). GPUI still pulls zbus 5 (through AccessKit and the
desktop portal crates), plus `paste`, `rustybuzz` and `ttf-parser`, which are also flagged
unmaintained (no known vulnerability). They reach only the unprivileged app. Each is listed in
`deny.toml` with its reason; re-check at every GPUI update, and drop the exception as soon as GPUI
moves on.

## D-016 The arrival, redrawn from geometry (2026-11-08)

The owner found the first arrival (faces flying in, rings, a grid) poor and asked for real
shape mathematics, clean and minimal, ending cleanly in the app. The new one is built from:
an ease-in-out arc sweep; a polar morph from circle to hexagon, r(θ) = lerp(1,
cos(π/6)/cos(((θ mod π/3) − π/6)), p), with p on a spring; inner edges growing from the centre;
an underdamped spring for the core; and a smootherstep flight along a cubic Bézier onto the rail
logo. It lasts 1.54 s instead of the prompt's "about 700 ms": the owner asked for the motion to
look good, and any key skips it. Tests check the geometry (straight hexagon edges, corners on
the circle), continuity (no step faster than 2.6 times the flight's average at 60 fps, a glide at
the end) and the hand-off (the last frame equals the rail logo exactly).

## D-017 The app reads the daemon on its own thread (2026-11-08)

The app talks to the daemon on a background thread with its own small async runtime, and the UI
reads the latest snapshot from a channel a few times a second. The UI never blocks on the bus,
and a slow or missing daemon only changes the status in the top bar. The app finds the daemon on
the system bus first, then on the session bus (development), unless `--bus` says otherwise.

## D-018 The mark is built from squares (2026-11-09)

The owner liked the cube's shape but wanted more to it, and an arrival that does more with
squares than a circle turning into a hexagon. Each face is now a 2 × 2 grid of tiles in slightly
different shades (light from the upper left), with a light rim on the top edges and a core with a
darker rim and a highlight. The arrival lays the twelve tiles out flat, then folds each face into
place by interpolating its 2 × 2 matrix (a shear and rotation), traces the outline, lights the
core and glides onto the rail logo (D-016's flight and hand-off are kept). Tests check that the
folded faces tile the hexagon exactly, that flat faces are true squares, continuity, and the exact
landing.

## D-019 Installing: a tarball with an installer and daily updates (2026-11-09)

The owner wants a package that installs in one step and updates itself. `cargo run -p xtask --
package` builds `vigil-<version>-<arch>-linux.tar.gz`; `sudo ./install.sh` copies the files, creates
the `vigil` account, starts the daemon, trusts the three programs in fapolicyd when it is running,
restores SELinux labels, and asks whether to turn on automatic updates. The release workflow builds
the same tarball on a `v*` tag (on Ubuntu 22.04, so it runs on any current distro) and publishes it
with its SHA-256.

Updates: `vigil-update.timer` runs `vigil-update` daily. It asks GitHub for the latest release,
downloads the tarball, checks it against the published SHA-256 and, once a signing key is installed
at `/usr/share/vigil/release.pub`, against its minisign signature, then runs the new installer. It
never replaces binaries from inside the app. **Open item for the owner:** the SHA-256 only proves the
download matches what GitHub serves. For real tamper resistance, create a minisign key, keep the
secret off GitHub, sign each release, and ship the public key; the updater then refuses anything
unsigned. Until then the trust anchor is the GitHub account. Automatic updates are a network
feature, so the installer asks first (rule 5); a private repository needs a token in
`/etc/vigil/update.conf`.

## D-020 Selecting never resizes the page; clicking again closes (2026-11-09)

Detail cards float over the content (lists) or sit beside the clicked node (the map). Every
selectable thing toggles: click to open, click again to close. Popups have a titled header and a
close button; Settings is a popover beside its gear, which stays highlighted while it is open, and
slides back behind the rail when it closes.

## D-021 Pointing out a program (2026-11-09)

Clicking a program on the map flags its windows in the taskbar. On KDE Plasma the app loads a
three-line KWin script over the session bus that sets `demandsAttention` on windows owned by the
program's processes; elsewhere it posts a desktop notification naming the program. Both stay on the
local session bus. GNOME offers no equivalent for another application's windows.

## D-022 An inspector beside every list; the app repaints only on new data (2026-11-09)

Supersedes the floating cards of D-020. The owner's round-3 review: details covered the columns
they described, the map's callout covered its own links, and the pages left large empty areas.
Now the Network map, Connections, Processes and Cases each keep a fixed inspector column (380 px)
on the right. With nothing selected it shows an overview of the page (top programs by CPU and
memory, connections by program and service, events by kind); selecting fills it in place and
clicking again returns to the overview. Nothing resizes and nothing is covered. The process list
is a virtual list (only visible rows are built), sortable by column, and any jump to a process
scrolls it to the middle of the view and outlines it.

CPU, measured in the container (software rendering, so absolute numbers are high): the app idle on
Home went from 45 % to 7.7 % of a core. Causes, all removed: the live dot pulsed on every look and
each pulse repainted the window for ~300 ms; numbers rolled after every look; the shield shone on
a timer; list rows had staggered entrances. The window now paints once per daemon look (every 2 s).
The daemon looked up every process's user name through NSS on every poll, which opened
`/etc/passwd` about 200 times a second; with fapolicyd running, fapolicyd had to vet each open
(the owner saw fapolicyd at 10 % CPU). User names are now cached for ten minutes, and process rows
are written to the store when new, with every row's `last_seen` refreshed once a minute.

## D-023 The mark: a teal shell holding an orange core cube (2026-11-09)

The owner found the tiled mark busy and the orange dot too slight. The mark is again a solid
isometric cube, now with a smaller orange cube in its near corner and a dark slot between them:
the orange is a shape of its own, still made of squares. The arrival keeps the square motion:
twelve tiles appear flat, the faces fold, the tiles close into solid faces, then the core grows
into its slot and the mark flies to the rail. The shield turned blue for "sees everything",
amber for a partial view and red for nothing, with solid and soft quarters split by a thin cross.
