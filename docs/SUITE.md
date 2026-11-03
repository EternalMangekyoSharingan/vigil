# Vigil Suite: Splitting Vigil into Focused Tools

Nov 3, 2026 · @Ula

Split Vigil into seven small tools that each answer one question and run on their own, built on one shared core so alerts, explanations and fix commands look and work the same everywhere. Build Vigil Pkg next: it is small, needs no root, and covers a real Arch risk.

## At a glance

*(Embedded diagram in the original: "Vigil suite · 7 tools, 1 shared core". Not included in the Markdown export.)*

Three tools watch the running system, three check files and software before you trust them, and all of them send findings to Cases. The shared core keeps alerts and fix commands identical everywhere.

## The tools

| Tool | Question it answers | Key features | Root needed? |
| --- | --- | --- | --- |
| **Vigil Net** (exists) | Who is this PC talking to, and which program? | Live network graph, beacon and long-connection detection, first-seen, threat-intel feeds, known-services catalogue | No (root-owned sockets shown as hidden) |
| **Vigil Tasks** | What is running, where did it come from, and should it be? | EDR-style process tree; per process: binary path, owning package, hash, parent, command line, open sockets, systemd unit, start time. Flags binaries deleted from disk while running, programs running from `/tmp` or `~/.cache`, `LD_PRELOAD` in the environment, odd parents (browser → shell) | No for your processes; optional for system ones |
| **Vigil Persist** | What starts automatically, and what changed since last time? | Linux "Autoruns": systemd units and timers, cron, XDG autostart, shell rc files, `/etc/ld.so.preload`, PAM, sudoers, SSH `authorized_keys`, kernel modules, udev rules. Baseline, then diff; checks each file against its package (`pacman -Qkk`) | Read-only; some files need root |
| **Vigil Files** | Is this file or archive safe to open? | Safe explorer that never opens files with their default app; archive inspection without extracting (zip bombs, path traversal); disguised files; PDF and Office triage; quarantine | No |
| **Vigil Pkg** | Is this AUR package safe to build and install? | PKGBUILD and `.install` static review before `makepkg`; name-squatting checks; diff against the version you last trusted; audit of foreign packages already installed | No |
| **Vigil Lab** | What would this file actually do? | Throwaway VM detonation, process tree with anomaly rules, ATT&CK tags, evasion warnings (later, needs VM setup) | Setup only |
| **Vigil Cases** | What happened, across all of the above? | One timeline of findings from every tool, notes, IOC export (CSV, STIX), Markdown reports | No |

Each tool is useful alone. Links between them are optional extras: Tasks shows a process's connections from Net, Files can send a sample to Lab, Pkg can hand downloaded sources to Files, and everything can be sent to Cases.

One decision for you: a task manager is expected to stop processes. Vigil's rule so far is "never act, only show commands". Suggested middle ground for Tasks: a Stop button only for your own processes, with a confirm step; everything else stays copy-a-command.

## Vigil Pkg: AUR and PKGBUILD review

The AUR is the clearest real risk on an Arch desktop. In July 2025, three packages (librewolf-fix-bin, firefox-patch-bin, zen-browser-patched-bin) installed a remote access trojan and stayed up about two days before removal ([LWN](https://lwn.net/Articles/1030603), [It's FOSS](https://itsfoss.com/news/arch-linux-chaos-rat/)). The names copied real packages and added "fix" or "patched" ([Korben](https://korben.info/en/malicious-packages-rat-arch-linux-aur.html)). In 2018 an abandoned PDF-viewer package was adopted by an attacker and made malicious ([ccstartup](https://ccstartup.com/blog/?p=385884)).

Vigil Pkg reads a PKGBUILD folder (from your AUR helper's review step, or a `git clone` of the AUR repo) and never runs `makepkg` or any part of the PKGBUILD. It parses the text only.

**What it checks**

- **Look-alike names:** close to a popular package plus words like fix, patched, cracked, all, pro, or a typo of a well-known name.
- **Sources:** downloads from raw IPs, pastebins, URL shorteners, personal file hosts, plain `http://`, or a domain that doesn't match the project's `url=`.
- **Checksums:** `SKIP` for downloaded files (fine for VCS sources like `git+`, suspicious for release tarballs and `-bin` archives).
- **Network inside build steps:** `curl`, `wget`, `git clone` or `pip install` inside `prepare()`, `build()` or `package()`. Sources belong in `source=`.
- **Run-what-you-download:** piping into `sh`/`bash`, `eval`, `base64 -d`, long encoded strings, `chmod +x` then run.
- **`.install` scripts:** post-install hooks that download things, enable services, add users, or touch files outside the package.
- **Writes outside `$pkgdir`**, `sudo` anywhere in a PKGBUILD, and edits to shell rc files or systemd units in your home folder.
- **Package history:** new maintainer, recently adopted orphan, very new account, first version, and a diff against the version you last approved (so updates are reviewed as changes, not from scratch).
- **Already installed:** list foreign packages (`pacman -Qm`), files changed since install (`pacman -Qkk`), and any package matching a known-malicious name list.

Each finding uses the shared alert format: a short title ("Downloads and runs a script from a pastebin"), a plain explanation, the exact PKGBUILD line, and a verdict of Looks normal / Review these lines / Don't install. It never says "safe". Fetching AUR metadata is an explicit, opt-in network call.

## Vigil Files: safe explorer

Vigil Files is a file browser that shows what a file *is* before anything opens it. It never launches files with their default app and never extracts an archive to find out what's inside.

**Archives (inspected from their index, not extracted)**

- **Zip bombs:** compression ratio (normal files compress about 2–10×, bombs 1000× or more), total declared size, entry count and nesting depth ([TrueFileSize](https://truefilesize.pages.dev/blog/preventing-zip-bomb-attacks/)). The classic 42.zip is 42 KB and expands to about 4.5 PB.
- **Overlapping-entry bombs:** these defeat depth checks by reusing data inside a single layer ([Abnormal](https://abnormal.ai/fr/learning/zip-bomb-download)), reaching over 28 million to one ([Freexian](https://www.freexian.com/lts/extended/updates/ela-141-1-unzip)). Vigil checks for entries whose data ranges overlap.
- **Lying headers:** declared sizes can be falsified, so any preview extraction runs with a hard output cap.
- **Path tricks:** `../` traversal, absolute paths, symlinks, device files, setuid bits.
- Formats: zip, tar (+gz/xz/zst/bz2), 7z and rar by listing only.

**Disguised files**

- Double extensions (`invoice.pdf.exe`), right-to-left override characters that reverse a name's ending, file type that doesn't match its extension, executables in Downloads, a `.desktop` file that runs a command.

**Documents**

- PDF and Office triage from the Vigil spec: auto-actions, JavaScript, Launch, embedded files, macros, remote templates, plus the URLs and IPs inside.

**Safety actions (user-confirmed, reversible)**

- **Quarantine:** move to a `noexec` folder, remove permissions, record the hash and original path; restore puts it back.
- **Safe preview:** text shown as plain text only; images and documents only through a converter with output limits, or not at all.
- **Watch Downloads:** new files are checked as they arrive, with a notification if something needs a look.
- Hash reputation lookup is opt-in and sends only the hash.

## Vigil Core: what every tool shares

The core is what stops seven tools from becoming seven different apps. Most of it already exists inside Vigil Net and gets moved out, not rewritten.

| Part | What it does | Used by |
| --- | --- | --- |
| Finding format | One record for every alert: short title, severity, one-sentence summary, signals with strength, likely explanation, confidence, fixes, evidence links, technical details | All tools, Cases |
| Wording rules | Title builder (max 60 characters, no jargon, friendly names), explanation sections, tests that enforce them | All tools |
| Fix commands | Check / Fix / Undo options, the colour-coded tokeniser (sudo red, pacman blue, install green, remove orange, package purple, paths cyan), copy-only | All tools |
| System facts | Distro detection from `/etc/os-release`, package owner lookup (`pacman -Qo` / `rpm -qf` / `dpkg -S`), friendly program names | All tools |
| Known-services catalogue | Benign patterns (NetworkManager check, Syncthing, browsers, NTP, updaters) so normal things get labelled, not alarmed | Net, Tasks, Persist |
| Evidence store | SQLite per tool plus a shared export format (JSON lines) that Cases imports | All tools, Cases |
| UI kit | Dark graphite theme, graph component, side panel, alert card, Fix panel, legend; plain HTML/CSS/JS | All tools |

Rules that stay suite-wide: Python standard library only, localhost only, read-only by default, never run a file being inspected, no outside calls unless you trigger them.

## Repo layout, build order and next prompt

Keep one repository with one folder per tool. Claude Code then sees the shared core while working on any tool, and a change to the alert format updates every tool at once. Each tool still runs alone: `python -m vigil.pkg`, `python -m vigil.files`, and so on.

```
vigil/
  CLAUDE.md            suite-wide rules
  docs/                SPEC.md, SUITE.md (this plan), PROGRESS.md
  vigil/core/          finding format, wording, fix commands, system facts, catalogue, store
  vigil/ui/            shared theme, graph, alert card, Fix panel
  vigil/net/           existing Network Map, moved here
  vigil/pkg/  vigil/files/  vigil/tasks/  vigil/persist/  vigil/lab/  vigil/cases/
  tests/<tool>/        each tool's tests, plus tests/core/
```

**Build order**

1. **Core extraction:** move the shared parts out of Net into `vigil/core` and `vigil/ui` without changing behaviour. All existing tests must still pass.
2. **Vigil Pkg:** small, no root, protects you right away.
3. **Vigil Files:** archive and disguise checks first, then document triage, then quarantine.
4. **Vigil Persist:** baseline and diff of autostart locations.
5. **Vigil Tasks:** process tree reusing Net's process data.
6. **Vigil Cases:** import findings from all tools; timeline and exports.
7. **Vigil Lab:** detonation VM, on your own PC.

**Prompt for Claude Code (step 1, then step 2)**

> Read CLAUDE.md, docs/SPEC.md and docs/SUITE.md. Vigil is becoming a suite of tools sharing one core. First restructure the repo to the layout in SUITE.md: move shared code (finding format, wording, fix-command tokeniser, distro detection, known-services catalogue, UI kit) into vigil/core and vigil/ui, and move the Network Map into vigil/net, with no behaviour changes and all tests passing. Commit. Then build Vigil Pkg as described in SUITE.md: static PKGBUILD and .install review that never runs makepkg or any PKGBUILD code, using the shared finding format, with tests built on synthetic PKGBUILD fixtures (including look-alike names, pastebin sources, SKIP checksums on release tarballs, curl piped to sh, network calls in build()). Log decisions in docs/PROGRESS.md and push after each step.

Save this doc as `docs/SUITE.md` in the repo (download it as Markdown) before running the prompt.

## Sources

- [Arch Linux AUR malware advisory coverage](https://lwn.net/Articles/1030603), LWN
- [Arch Linux CHAOS RAT in AUR packages](https://itsfoss.com/news/arch-linux-chaos-rat/), It's FOSS
- [Malicious packages with a RAT infiltrated the AUR](https://korben.info/en/malicious-packages-rat-arch-linux-aur.html), Korben
- [Arch Linux AUR hit by malware targeting developer secrets](https://ccstartup.com/blog/?p=385884), ccstartup
- [Arch Linux users told to purge Firefox forks](https://www.theregister.com/2025/07/22/arch_aur_browsers_compromised/), The Register
- [Preventing zip bomb attacks](https://truefilesize.pages.dev/blog/preventing-zip-bomb-attacks/), TrueFileSize
- [Zip bomb downloads](https://abnormal.ai/fr/learning/zip-bomb-download), Abnormal AI
- [ELA-141-1 unzip security update](https://www.freexian.com/lts/extended/updates/ela-141-1-unzip), Freexian
