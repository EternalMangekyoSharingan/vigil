"""Audit of packages already installed: foreign packages (`pacman -Qm`), files changed
since install (`pacman -Qkk`, done by reading the package database), and installed
names that match known-malicious or look-alike names. Read-only; nothing is run."""

import shlex
import time

from ..core import finding as fmt
from ..core import fixes as fx
from ..core import pkgdb, system
from ..core.wording import fit_title
from . import names

TOOL = "pkg"
BIN_DIRS = ("usr/bin/", "usr/lib/", "usr/lib64/", "usr/sbin/", "etc/systemd/", "usr/lib/systemd/", "etc/profile.d/",
            "etc/xdg/autostart/", "etc/ld.so", "etc/pam.d/", "etc/sudoers")


def _fixes(osr, name, remove=False):
    check = [fx.option("Show what pacman knows about it", "Version, packager, install date and why it was installed.",
                       "safe", [f"pacman -Qi {shlex.quote(name)}"]),
             fx.option("Check its files the way pacman does", "Lists every file that differs from what was installed.",
                       "safe", [f"pacman -Qkk {shlex.quote(name)}"])]
    fix = []
    if remove:
        fix.append(fx.option(f"Remove {name}", "Uninstalls the package and the dependencies only it needed.", "admin",
                             [f"sudo pacman -Rns {shlex.quote(name)}"], lose="The program and its files.",
                             undo_steps=[f"Rebuild {name} from its PKGBUILD if you really need it back "
                                         "(review it in Vigil Pkg first)."]))
    return fx.panel(osr, check=check, fix=fix)


def pacman_log(root="/"):
    """{package: [(timestamp, action, version)]} from /var/log/pacman.log (installed/upgraded/removed)."""
    import calendar
    import re
    import time as _t
    out = {}
    try:
        fh = open(f"{root.rstrip('/')}/var/log/pacman.log", encoding="utf-8", errors="replace")
    except OSError:
        return None
    rx = re.compile(r"^\[(\d{4}-\d\d-\d\d)[T ](\d\d:\d\d)(?::\d\d)?([+-]\d{4})?\] \[ALPM\] "
                    r"(installed|upgraded|downgraded|reinstalled|removed) (\S+) \((.*)\)")
    with fh:
        for line in fh:
            m = rx.match(line)
            if not m:
                continue
            day, hm, tz, action, name, ver = m.groups()
            ts = calendar.timegm(_t.strptime(f"{day} {hm}", "%Y-%m-%d %H:%M"))
            if tz:
                sign = 1 if tz[0] == "+" else -1
                ts -= sign * (int(tz[1:3]) * 3600 + int(tz[3:5]) * 60)
            out.setdefault(name, []).append((ts, action, ver.split(" -> ")[-1]))
    return out


def _day(ts):
    import time as _t
    return _t.strftime("%Y-%m-%d", _t.gmtime(ts))


def incident_hits(history):
    """[(incident, timestamp, action)] when a package was installed/updated inside a known window."""
    hits = []
    for ts, action, ver in history or []:
        if action == "removed":
            continue
        d = _day(ts)
        for inc in names.INCIDENTS:
            if inc["start"] <= d <= inc["end"]:
                hits.append((inc, ts, action, ver))
    return hits


def audit(root="/", osr=None, verify=True, now=None, limit=None):
    """Returns {"supported", "how", "foreign": [...], "findings": [...], "note"}."""
    osr = osr if osr is not None else system.os_release(f"{root.rstrip('/')}/etc/os-release" if root != "/" else "/etc/os-release")
    fam = system.family(osr)
    now = now or time.time()
    installed = pkgdb.pacman_installed(root)
    if not installed:
        other = {"fedora": "rpm -Va", "suse": "rpm -Va", "debian": "dpkg --verify"}.get(fam)
        return {"supported": False, "how": None, "foreign": [], "findings": [],
                "distro": (fx.distro_info(osr)),
                "note": "No pacman database on this PC, so there are no AUR packages to audit."
                        + (f" Your distro's own file check is `{other}` (read-only)." if other else ""),
                "check": [fx.option("Check installed files against the package database",
                                    "Lists files that changed since their package installed them.", "safe", [other])]
                if other else []}
    foreign, how = pkgdb.foreign(root)
    history = pacman_log(root)
    rows, findings = [], []
    for i, (name, info) in enumerate(sorted(foreign.items())):
        row = {"name": name, "version": info["version"], "packager": info["packager"],
               "installed": info["installdate"], "built": info["builddate"], "verify": None, "name_check": names.check(name)}
        hit = row["name_check"]
        subj = f"installed:{name}"
        hits = incident_hits((history or {}).get(name))
        row["history"] = [{"when": ts, "action": a, "version": v} for ts, a, v in ((history or {}).get(name) or [])][-10:]
        if hits or name in names.HIJACKED:
            listed = name in names.HIJACKED
            inc, ts, action, ver = hits[-1] if hits else (next(i for i in names.INCIDENTS if i["id"] == names.HIJACKED[name]), None, None, None)
            sev = "High" if hits and listed else "Medium" if hits or listed else "Low"
            when = f"{action} {ver} on {_day(ts)}" if ts else "not found in pacman.log"
            findings.append(fmt.make(
                TOOL, "installed_hijack_window",
                fmt_title(f"{name} was {action} during an AUR malware wave" if ts else f"{name} was named in an AUR malware wave",
                          "A package was updated during an AUR malware wave"),
                f"{name} was {when}, during {inc['what']}." if ts else
                f"{name} was named in reporting on {inc['what']}; check when you last updated it.", sev,
                signals=[(f"pacman.log: {when}", 0.8 if hits else 0.3)] + ([(f"{name} is named in reports of that wave", 0.7)] if listed else []),
                likely="Most packages updated in that window were fine; the ones taken over pushed malware for a few days. "
                       "Compare the version you built with the AUR history before trusting it.",
                confidence="Medium" if hits and listed else "Low",
                confidence_reason="Dates come from your own pacman.log; the window comes from public reporting.",
                subject=f"{subj}:window", fixes=_fixes(osr, name, remove=sev == "High"),
                evidence=[{"kind": "package", "value": f"{name} {info['version']}"},
                          {"kind": "log", "value": "/var/log/pacman.log", "note": when}],
                technical=[{"label": "incident", "value": inc["id"]}, {"label": "window", "value": f"{inc['start']} to {inc['end']}"}],
                data="/var/log/pacman.log", when=now))
        if hit and hit["kind"] == "known":
            findings.append(fmt.make(
                TOOL, "installed_known_malicious", fmt_title(f"Installed package {name} is known malware",
                                                             "An installed package is known malware"),
                f"{name} is installed, and that name was {hit['why']}.", "High",
                signals=[(f"{name} is on Vigil's list of malicious AUR names", 1.0)],
                likely="If you installed it in mid-2025 or earlier, assume the PC is compromised.",
                confidence="High", confidence_reason="The exact name was used for malware.", subject=subj,
                fixes=_fixes(osr, name, remove=True), evidence=[{"kind": "package", "value": f"{name} {info['version']}"}],
                data=f"{info['dir']}/desc", when=now))
        elif hit:
            findings.append(fmt.make(
                TOOL, "installed_lookalike", fmt_title(f"Installed {name} has a look-alike name",
                                                       "An installed package has a look-alike name"),
                f"{name} looks like {hit['like']}" + (f" with '{hit['word']}' added." if hit.get("word") else
                                                     " with one letter changed."), "Medium",
                signals=[(f"Name pattern: {hit['kind']} of {hit['like']}", hit["strength"])],
                likely="Probably an honest fork, but this is the pattern the 2025 AUR malware used.",
                confidence="Low", confidence_reason="A name alone proves nothing.", subject=subj,
                fixes=_fixes(osr, name), evidence=[{"kind": "package", "value": f"{name} {info['version']}"}],
                data=f"{info['dir']}/desc", when=now))
        if verify and (limit is None or i < limit):
            v = pkgdb.verify(info, root)
            row["verify"] = {"checked": v["checked"], "changed": len(v["changed"]), "error": v["error"]}
            if v["changed"]:
                important = [c for c in v["changed"] if c["path"].lstrip("/").startswith(BIN_DIRS)]
                sev = "Medium" if important else "Low"
                sample = (important + [c for c in v["changed"] if c not in important])[:12]
                findings.append(fmt.make(
                    TOOL, "installed_files_changed",
                    fmt_title(f"{len(v['changed'])} files of {name} changed since install",
                              f"Files of {name} changed since install", "Files of a package changed since install"),
                    f"{len(v['changed'])} of {v['checked']} files from {name} no longer match what pacman installed.",
                    sev, signals=[(f"{c['path']}: {c['detail']}", 0.7 if c in important else 0.3) for c in sample[:6]],
                    likely="Often a manual edit or a program updating itself; a changed program file is worth a look.",
                    confidence="Medium" if important else "Low",
                    confidence_reason="Programs and start-up files should not change on their own." if important
                    else "Changed data files are usually harmless.",
                    subject=f"{subj}:files", fixes=_fixes(osr, name),
                    evidence=[{"kind": "path", "value": c["path"], "note": c["detail"]} for c in sample],
                    technical=[{"label": "checked files", "value": str(v["checked"])},
                               {"label": "unreadable as this user", "value": str(v["unreadable"])}],
                    data=f"{info['dir']}/mtree", when=now))
        rows.append(row)
    return {"supported": True, "how": how, "foreign": rows, "findings": fmt.sort(findings),
            "distro": fx.distro_info(osr), "installed_count": len(installed), "pacman_log": history is not None,
            "note": None if how == "sync" else
            "Vigil could not read the sync databases, so 'foreign' means 'not built by an Arch packager' here."}


def fmt_title(*candidates):
    return fit_title(list(candidates))
