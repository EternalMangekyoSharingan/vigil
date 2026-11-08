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

`src/main.rs` draws the shell; `src/icons.rs` serves Vigil 1's line icons as SVG.

- **Rail**: the mark (click: the arrival), nine areas with icon and label, a marker that slides
  on a spring, Settings and your initial at the bottom.
- **Top bar**: area title, its tabs, Guided/Expert, the daemon's status, Jump to… (Ctrl K).
- **Palette** (Ctrl K): areas, tabs, actions and settings; arrows and Enter; matches in orange.
- **Settings** (,) and **shortcuts** (?): read from the keymap, so they are always right.
- **The arrival** (the mark, or g h): drawn on a canvas from `motion::arrival(t)`. Any key skips
  it; reduced motion skips it.
- It repaints only while something moves, and checks `theme.toml` once a second.
- Areas say what they will show and which milestone brings it; no area shows made-up data.

`vigil --measure-startup` prints the time to the first frame and exits.
