> **Superseded (2026-11-03):** this describes Vigil before the suite split. The current state, layout
> and next steps are at the end of docs/PROGRESS.md ("The Vigil suite").

# Vigil — session handoff (2026-10-31)

Paste this into a new chat to continue. Repo: `EternalMangekyoSharingan/vigil`,
branch `claude/build-steps-1-5`. All work below is committed and pushed.
Latest commit: `444d48a`.

## Conventions (keep these)
- Python 3.11+ **standard library only**. Frontend: plain HTML/CSS/JS in `static/`,
  no build step, no npm, no CDN. Tests: `python3 -m unittest discover -s tests -t .`
  (must stay green on 3.13 **and** 3.11). All test data synthetic and labelled.
- Vigil never runs an inspected file. **Sudo mode** (opt-in, Settings) is the ONLY
  place commands run: only Vigil-generated commands, no shell, admin via `pkexec`
  (system password dialog — Vigil never sees the password), every run logged.
  See `vigil/runner.py` and `CLAUDE.md`.
- Commit trailer:
  `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`
  `Claude-Session: https://claude.ai/code/session_019ViPrRShr5miHfCQJbx7UL`
- `.gitignore` uses `/data/` (root only) — do NOT revert to bare `data/`, it hides
  `vigil/data/known_services.json` and crashes the app after clone.

## Done this session (committed + pushed)
1. **Fixed startup crash** (`b7e5794`): `.gitignore`'s `data/` hid the services
   catalogue → `FileNotFoundError` on the Alerts page. Scoped ignore to `/data/`,
   committed `vigil/data/known_services.json`, made `services.catalogue()` return
   `[]` on error instead of raising.
2. **"Why is this red?" backend** (`444d48a`): `wording.why_node(detail, threshold,
   is_program, base_ctx={"poll": N})` returns `{flagged, severity, headline, reasons[],
   listed[], programs[], destinations[], score, what_now[]}`. Wired into
   `api_program` and `api_destination` in `server.py` as `d["why"]`. Answers
   "why is GitHub red when I don't have it open?" → names the background program
   (e.g. "VS Code is contacting this address in the background — you don't need it
   open") + plain reasons. **Backend only; NOT yet shown in the UI.**

## Next steps (in priority order)

### A. Surface `data.why` in the Network Map panel (START HERE — small, high value)
- File: `static/netmap.js`, function `renderPanel()` (~line 724). After the
  `.crumbs` block / before the `.ptabs`, when `data.why` is truthy, render a
  "Why is this flagged?" banner: `headline` (bold), `reasons` as a list with the
  same strength bars used in `static/alerts.js` `renderWhy()`, `listed[]` as danger
  chips, and `what_now[]` as steps. Reuse CSS classes `.al-summary`, `.signals`,
  `.bar`/`.fill`, `.sev-word` (already in `static/style.css`).
- Add a test in `tests/test_alert_wording.py` (or a netmap/server test) asserting
  `api_destination`/`api_program` include `why` with the expected headline for a
  synthetic flagged pair. Also assert `why is None` when under threshold and not
  listed.
- Screenshot via the dev-server pattern (see below), verify, commit.

### B. Filelight-style file viewer for the Files tab
- User wants a visual disk/archive map, **not a pie chart**. Research says a
  **treemap** or **icicle/sunburst** reads better and is standard (used by Filelight,
  WinDirStat, Baobab). Recommend an **animated zoomable icicle or treemap** in
  hand-written SVG (no libs), with a **legend** (colour by file type/category),
  interactive (hover highlights + shows path/size, click to zoom in), animated
  transitions.
- Data source: for an inspected archive, Vigil already has the member tree
  (`report["details"]["members"]`, `["nested"]`, `["expansion"]`). Build a size tree
  from that. (Optionally also a real filesystem treemap reusing `cleanup._size`, but
  start with the archive since it needs no new scanning.)
- Keep it in the sleek flat theme (no glows). Follow the dataviz guidance: ≤ ~6
  legend categories, accessible colours, label only what fits.

### C. Offensive vulnerability tester framework (with equal power to FIX)
- Scope: the user's OWN machine/network, authorized self-testing (same posture as the
  existing read-only Scan tab). This is defensive/self-audit, not attacking third
  parties — keep it that way.
- Build a `vigil/vuln.py` framework: checks that actively probe the local host for
  weaknesses (open ports already in `scans.exposure`; weak SSH config; world-writable
  files in PATH; SUID binaries; outdated packages via `scans.advisories`; default/weak
  service configs; firewall gaps). Each finding MUST pair with a FIX option (reuse the
  `fixes.py` / `commands.py` tokeniser + sudo-mode Run flow — every fix has an undo).
- New tab "Harden" (or fold into Scan). Keep all the safety rails: fixes are
  Vigil-generated commands only, shown before running, pkexec for admin.
- Write synthetic-fixture tests like `tests/test_sudo_scan_cleanup.py`.

### D. Polish pass
- General UI consistency, the vector status icons (already done) everywhere, make sure
  Scan/Cleanup/Settings tabs look consistent with the flat theme.

## Dev workflow reminders
- This container has NO pkexec/yara/clamav/pacman — test those paths with synthetic
  fixtures + stand-in runners (see existing tests). Say so in PROGRESS.
- Live UI check: run `python3 -m vigil serve --port 8770 --data .devtmp/data-ui` in
  background, drive with Playwright (`chromium`, path `/opt/pw-browsers/chromium` if
  needed), screenshot, Read the PNG. The `.devtmp/` dir has beacon.py/listener.py to
  generate synthetic traffic and `upload/location.zip` (the zip-bomb sample — never
  commit it, analyse bytes only).
- Document each part in `docs/PROGRESS.md`. Update `README.md`.

## Known open items
- `why_node` UI not built yet (step A).
- The over-1TB zip bomb detection is done (`462a731`, `46a2e62`): decoy directories,
  Zip64, extrapolation. location.zip reads ~8.8 TB; 64x4096-Z.zip ~281.5 TB.
