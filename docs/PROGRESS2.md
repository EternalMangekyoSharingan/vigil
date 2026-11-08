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
