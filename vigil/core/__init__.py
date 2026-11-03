"""Vigil Core: what every tool in the suite shares.

finding    the one finding format (and its JSON-lines export)
wording    title and sentence rules, friendly names, human numbers
commands   colour-coded command tokeniser (display only)
fixes      Check / Fix / Undo options, distro-aware, copy only
system     distro detection, package owner lookup, firewall detection
catalogue  known benign services, so normal things get labelled, not alarmed
store      per-tool SQLite evidence store plus findings.jsonl export
web        the 127.0.0.1-only web server and static files (with vigil/ui)
netfetch   the single function in the suite that may open a URL (user-triggered only)
runner     sudo mode: the only place a command is ever run (opt-in, Network Map only)
pkgdb      pacman local database reader and version comparison
"""
