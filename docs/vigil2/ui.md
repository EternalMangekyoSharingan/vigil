# The app: vigil-ui-core and vigil-ui

## vigil-ui-core (no toolkit, fully tested)

| module | what it does |
| --- | --- |
| `areas.rs` | The nine areas on the rail (keys 1–9), their `g` letters, questions and tabs |
| `keymap.rs` | Every binding from section 5.5; chords (`g h`); rebinding in `~/.config/vigil/keys.toml`; refuses clashes and chords hidden behind a single key; letters type into text fields instead of triggering shortcuts |
| `palette.rs` | Ranking for the command palette: forgiving subsequence match with bonuses for word starts and runs ("prc tr" finds "Processes: Tree") |
| `motion.rs` | Springs, Vigil's ease curve, the mark's geometry (shell, tiles, core cube) and the arrival as a pure function of time (tested frame by frame: tiles fold and close, the core overshoots once, the last frame is the rail logo), reduced motion |
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

Every list and the map keep an **inspector** beside them (D-022): an overview of the page when
nothing is selected, the selection's details when something is. Nothing floats over the data and
nothing resizes when you select; clicking again clears the selection.

- **Home**: the device's name with its battery (or driver health) and the shield beside it;
  processes, outbound connections, programs online, destinations seen and Vigil's own memory and
  CPU; network activity per program; the busiest programs (all of a program's processes as one
  line); traffic by service; activity; coverage. Lists show as many rows as the window fits.
  "Since you last looked": programs that used the network for the first time in 24 hours.
- **Network**: the map (this PC in the centre, programs on an arc around it with their icons,
  each program's addresses in a column on its side, nothing overlapping, nothing moving; Grid,
  Night or Plain background in Settings); the connections list; the time machine (what was open
  5 minutes, an hour, 6 hours, a day or a week ago). Clicking a program also flags its window in
  the taskbar (D-021).
- **Processes**: the tree and the table (virtual: only visible rows are built), sortable by
  program, PID, user, CPU, memory and start time; each row shows the program's arguments. Any jump
  (Home, the map's "Show the process", the palette, the parent chain, j/k) scrolls the process
  into view and outlines it.
- **Cases → Timeline**: everything Vigil noticed or did, grouped by day, with counts by kind.
- Autostart, Files, Software, Guard, Canaries, DNS, LAN, Secrets and Storylines say what they
  will do, in which milestone, and which Vigil 1 command does it today (with Copy).

### Motion

- **The arrival** (launch, the mark, `g h`): twelve square tiles appear flat as an unfolded cube,
  the three faces fold into place by shear, the tiles close into a solid teal shell, an outline is
  traced, the orange core cube grows into its slot, the word VIGIL resolves letter by letter, then
  the mark flies along a Bezier curve (smootherstep) onto the rail logo while the backdrop
  dissolves. The last frame is the logo itself. Any key skips it.
- **Everywhere else**, motion only where it carries information: areas fade in, overlays and
  Settings slide in and out, the rail marker moves between areas, the shield's border shines once
  after the arrival, on hover and when coverage changes. Data views never move: no rolling
  numbers, no pulses, no flowing dots, no staggered rows.
- The window repaints only when the daemon sends a new look (every 2 s) or you act; idle CPU stays
  near zero. Reduced motion (Settings, or the desktop's setting) turns the rest off.

Flags: `vigil --bus system|session|address=...`, `--no-arrival`, `--measure-startup`.
Screens: `docs/vigil2/screens/app-*.png`.
