# Vigil: rules for Claude

## What this is
A personal blue-team lab: a Network Map (who is this PC talking to, and which program),
then a File Inspector (what would this file do). The full plan is in docs/SPEC.md.
Work through its "Build order" one step at a time, in order.

## Where you are running
You may be running in a cloud container (Claude Code on the web), not on my PC.
- /proc there shows the container's own processes and connections, not mine. Build the
  collector against the real /proc format, and test it with fixture files of
  /proc/net/tcp, tcp6, udp and /proc/<pid>/ data in tests/fixtures/ (labelled synthetic).
- Also run the real collector once in the container and confirm it reads live data.
- I will pull the branch and run Vigil on my own Linux PC to see my real network.
- Commit and push your work to the session branch after every step, so nothing is lost.

## Stack
- Python 3.11+ standard library only for the backend (http.server/asyncio, sqlite3, json).
  Ask me before adding any dependency.
- Frontend: plain HTML + CSS + JavaScript (shared kit in vigil/ui/static/, each tool's page in vigil/<tool>/static/), no build step, no npm, no CDN links.
  Hand-written SVG or canvas graphs.
- Must run on any Linux distro. No distro-specific code unless unavoidable, and then
  behind one small function with a fallback.
- Keep the codebase small. Prefer one clear module over layers of abstraction.

## Safety rules (never break these)
- Never execute, open or import a file being inspected on this host. Static checks read
  bytes only. Running a file only ever happens inside the detonation VM (a later step).
- Bind the web server to 127.0.0.1 only.
- Monitoring is read-only: never change firewall rules, routes, DNS or kernel settings,
  never kill processes, never disable SELinux/AppArmor.
- Never run sudo or ask me to, without first explaining exactly why and what it touches.
  Everything must work as a normal user; show what is hidden without root instead.
- No network calls except ones I trigger on purpose (e.g. "update threat feeds").
  Never send my traffic, IPs or files to any outside service.

## Product rules (from the spec)
- Every flag and score shows its reasons. No unexplained red dots.
- Few alerts, high confidence. Known-good periodic traffic is allowlisted, not alerted on.
- Never call a file "safe". Say "no suspicious behaviour found" and list the limits.
- No fake data. Synthetic test data lives in tests/ and is labelled as synthetic.
- Every finding records where it came from (which check, which data, when).

## UI style
Dark graphite background, restrained blue/cyan accents, clear technical type.
Graph-first like an EDR process analyzer: nodes with small count chips, timed edges,
a side panel listing the selected node's events. No neon, no fake stats, no decoration
without a purpose.

Updated 2026-10-31 at the owner's request (supersedes the colours above): dark purple
base with warm orange as the main accent, and the teal/aqua/ice-cyan of the owner's
wallpaper for network activity; look and feel close to an EDR process analyzer
(isometric process cubes, name pills, timed edges, event panel on the left) and to
Darktrace's UI; plenty of purposeful motion (kept light, honouring reduced motion);
Apple-like type (SF Pro where present, bundled Inter otherwise). Vigil also runs as a
desktop app (`python3 -m vigil app`). Still no fake stats.

Updated again 2026-10-31 at the owner's request: same colours, but sleek and
professional, not "AI-looking". Flat surfaces with hairline borders, small radii,
no gradients, blurs, glows, coloured side stripes or score rings. The only glow is
the active top-bar tab marker. Colour only for meaning (actions/selection, live
traffic, severity). Motion only where it carries information. Exceptions the owner
asked for: the Network Map has background themes (Grid: hexagons and shapes; Night:
a drifting starfield; Plain), and the File Inspector report follows VirusTotal's layout (score box with
a small ring, summary card, tabs, a two-column grid of analyzer results).

## Sudo mode (owner's decision, 2026-10-31)
The owner asked for a sudo mode: Vigil may run its own generated fix, cleanup and scan
commands when the user presses Run, off by default. Keep these rules: only commands
Vigil generated (re-generated server-side), no shell, admin rights only through pkexec
(the system's password dialog; Vigil never handles passwords), one command per
press, every run logged. All other modules still never run fix commands.

## How to work (I may be away: don't wait for me)
1. Read existing code and docs/PROGRESS.md before changing anything.
2. For each step: build it, write tests (pytest is fine as a dev tool), run them,
   fix until they pass, update README.md, then git commit with the step number.
3. After each step, append to docs/PROGRESS.md: what was built, test results,
   known limitations, anything you were unsure about and what you decided.
4. Then move straight on to the next step without asking.
5. Make sensible decisions yourself and record them in PROGRESS.md instead of asking.
6. STOP and wait for me when:
   - you reach step 6 (detonation VM), because it needs sudo and VM setup;
   - anything would need sudo, a new dependency, or a change outside this folder;
   - tests for a step still fail after several honest attempts (record what failed).
7. Never weaken a test to make it pass. Never mark a step done with failing tests.
