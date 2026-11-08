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
