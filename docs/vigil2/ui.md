# The app: vigil-ui-core and vigil-ui

## vigil-ui-core (no toolkit, fully tested)

| module | what it does |
| --- | --- |
| `areas.rs` | The nine areas on the rail (keys 1–9), their `g` letters, questions and tabs |
| `keymap.rs` | Every binding from section 5.5; chords (`g h`); rebinding in `~/.config/vigil/keys.toml`; refuses clashes and chords hidden behind a single key; letters type into text fields instead of triggering shortcuts |
| `palette.rs` | Ranking for the command palette: forgiving subsequence match with bonuses for word starts and runs ("prc tr" finds "Processes: Tree") |
| `motion.rs` | Springs, Vigil's ease curve, the arrival as a pure function of time (each part tested: faces 70 ms apart, core 0 → 2.2 → 1, rings 120 ms apart, everything settled at 700 ms), Home's cards rising 30 ms apart, reduced motion |
| `theme.rs` | Dark (Vigil 1's tokens), light and high-contrast themes, each tested for WCAG contrast; `theme.toml` overrides single colours and is reloaded live |
| `settings.rs` | The app's own preferences (`~/.config/vigil/ui.toml`): theme, motion, density, Guided or Expert per area. Security settings are not here: they live in the daemon behind polkit |

## vigil-ui (GPUI)

| file | what it does |
| --- | --- |
| `main.rs` | State, keyboard, the rail (spring marker), top bar, palette, Settings sheet, shortcut sheet, overlays that animate in *and* out, the arrival on launch |
| `live.rs` | The link to the daemon: a background thread finds `org.vigil.Daemon` (system bus, then session bus, or `--bus`), follows its `Changed` signal and hands snapshots to the UI; the UI never waits on the bus |
| `views.rs` | The areas: Home, Network (live map, connections, time machine), Processes (tree, table), Cases (timeline), the detail panel, and honest empty states for areas whose engines come later |
| `mark.rs` | One painter for the mark: every arrival frame and the rail logo, so the hand-off is pixel-exact |
| `ui.rs` | Cards, chips, buttons with hover and press states, and the enter animations |
| `icons.rs` | Vigil 1's line icons as SVG |

### What is live

- **Home**: processes, outbound connections, programs online, destinations seen and the
  daemon's memory, as numbers that roll to new values; "Talking now" (programs by connection
  count, click to open them); what Vigil can and cannot see; the latest events.
  "Since you last looked": programs that used the network for the first time in 24 hours.
- **Network**: a live map (this PC at the centre, programs on an inner ring, the addresses each
  talks to fanned out around it, dots flowing along open connections in the direction they were
  made; click a program); the connections list with a filter and a detail panel; the time machine
  (what was open 5 minutes, an hour, 6 hours, a day or a week ago).
- **Processes**: the tree (parents and children) and the table, filter with `/`, a detail panel
  with the command line, program file, start time, the clickable parent chain and the process's
  connections. `x` switches to Expert columns (uid, inode, full command line).
- **Cases → Timeline**: everything Vigil noticed or did, grouped by day.
- Autostart, Files, Software, Guard, Canaries, DNS, LAN, Secrets and Storylines say what they
  will do, in which milestone, and which Vigil 1 command does it today (with Copy).

### Motion

- **The arrival** (launch, the mark, `g h`): a stroke traces a circle; the circle becomes a
  hexagon by a polar morph while turning a twelfth of a turn; the cube's three inner edges grow
  from the centre; the faces fill and the core ignites on a bouncy spring; the word VIGIL resolves
  letter by letter; then the mark flies along a Bézier curve (smootherstep: zero speed and zero
  acceleration at both ends) and shrinks onto the rail logo while the backdrop dissolves, and
  Home's cards rise. The last frame is the logo itself. Any key skips it.
- **Everywhere else**: SwiftUI-style springs (response and damping fraction). Areas and tabs
  fade and rise in; list rows follow one another by 14 ms; the detail panel slides in; the
  palette and the Settings sheet animate in and out; the rail marker springs between areas;
  numbers roll; buttons and rows have hover and press states.
- Reduced motion (Settings, or the desktop's setting) turns all of it off. The app repaints at
  frame rate only while something moves (the map's dots count as moving).

Flags: `vigil --bus system|session|address=...`, `--no-arrival`, `--measure-startup`.
Screens: `docs/vigil2/screens/app-*.png`.
