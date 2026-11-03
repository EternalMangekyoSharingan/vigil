"""Vigil Persist: what starts automatically, and what changed since last time?

scan() reads every autostart location (locations.py), checks each file against the
package that installed it (core.pkgdb.PackageFiles: pacman's mtree, dpkg's md5sums),
compares the whole set with the saved baseline, and returns findings in the suite's
format. Read-only: it never edits, disables or deletes anything.
"""

import os
import re
import shlex
import time

from ..core import catalogue
from ..core import finding as fmt
from ..core import fixes as fx
from ..core import system
from ..core.pkgdb import PackageFiles
from ..core.wording import FRIENDLY, fit_title
from . import locations

TOOL = "persist"
BASELINE = "autostart"
WHY = {
    "systemd": "systemd starts units at boot or login; malware adds one to come back after every restart.",
    "cron": "cron runs commands on a schedule; a new entry is a common way to keep something running.",
    "autostart": "Everything in an autostart folder starts when you log in to the desktop.",
    "shell": "Shell start-up files run every time you open a terminal or log in.",
    "preload": "Libraries listed in /etc/ld.so.preload are loaded into every program, including root's.",
    "pam": "PAM decides how logins are checked; a changed rule can let anyone in or record passwords.",
    "sudoers": "sudo rules decide who can become root, and whether they need a password.",
    "ssh": "SSH keys and settings decide who can log in to this account from elsewhere.",
    "modules": "Kernel modules run inside the kernel with full control of the machine.",
    "udev": "udev rules can run a command whenever a device appears.",
    "other": "Hooks like these run commands when the system boots, connects or updates.",
}
SEV_CAP_PACKAGE_OK = "Low"


class Scan:
    def __init__(self, home, root="/", proc="/proc", osr=None, baseline=None, now=None, pkgfiles=None):
        self.home, self.root, self.proc = home, root, proc
        self.osr = osr if osr is not None else system.os_release(os.path.join(root, "etc/os-release")
                                                                 if root != "/" else "/etc/os-release")
        self.fam = system.family(self.osr)
        self.baseline = baseline          # (ts, {path: {"sha256", "mode", "link", "kind", "group"}}) or (None, None)
        self.now = now or time.time()
        self.pkg = pkgfiles or PackageFiles(root)
        self.findings = []

    # ---- commands for the Fix panel ------------------------------------------------------------

    def _sudo(self, e):
        return "" if e["scope"] == "user" else "sudo "

    def fixes(self, e, severity, package=None, line=None):
        p = shlex.quote(e["path"])
        check = []
        if e["kind"] == "loaded kernel module":
            name = e["path"].split()[-1]
            check.append(fx.option("Details of this module", "Shows its file, author, signature and parameters.", "safe",
                                   [f"modinfo {shlex.quote(name)}"]))
            fix = [fx.option(f"Unload {name} now", "Removes the module until the next boot (fails if it is in use).",
                             "admin", [f"sudo modprobe -r {shlex.quote(name)}"], [f"sudo modprobe {shlex.quote(name)}"])]
            return fx.panel(self.osr, check=check, fix=fix if severity in ("High", "Medium") else [])
        check.append(fx.option("Read it", "Prints the file so you can see exactly what it starts.", "safe",
                               [f"{self._sudo(e) if not e['readable'] else ''}cat {p}"]))
        if line:
            check.append(fx.option(f"Show line {line}", "Prints just the line Vigil flagged.", "safe",
                                   [f"sed -n '{line}p' {p}"]))
        if e["path"].startswith(("/etc/", "/usr/")):
            check.append(fx.owner_check(e["path"], self.fam))
        if package:
            verify = {"arch": f"pacman -Qkk {package}", "debian": f"dpkg --verify {package}",
                      "fedora": f"rpm -V {package}", "suse": f"rpm -V {package}"}.get(self.fam)
            if verify:
                check.append(fx.option(f"Check all of {package}'s files", "Compares every file with what the "
                                       "package installed.", "safe", [verify]))
        unit = os.path.basename(e["path"])
        if e["group"] == "systemd" and unit.endswith((".service", ".timer")):
            user = " --user" if e["scope"] == "user" else ""
            check.append(fx.option("Is it running, and since when?", "systemd's own view of this unit.", "safe",
                                   [f"systemctl{user} status {shlex.quote(unit)}"]))
        fix = []
        if severity in ("High", "Medium"):
            if e["group"] == "systemd" and unit.endswith((".service", ".timer")):
                user = " --user" if e["scope"] == "user" else ""
                s = "" if user else "sudo "
                fix.append(fx.option(f"Stop {unit} and keep it from starting",
                                     "Stops it now and removes it from boot or login. The file stays, so you can look at it.",
                                     "settings" if user else "admin",
                                     [f"{s}systemctl{user} disable --now {shlex.quote(unit)}"],
                                     [f"{s}systemctl{user} enable --now {shlex.quote(unit)}"]))
            elif e.get("fs_path") and e["kind"] != "loaded kernel module":
                fix.append(fx.option("Move it aside so it no longer runs",
                                     "Renames the file; nothing reads the new name. Rename it back to undo.",
                                     "settings" if e["scope"] == "user" else "admin",
                                     [f"{self._sudo(e)}mv {p} {shlex.quote(e['path'] + '.vigil-disabled')}"],
                                     [f"{self._sudo(e)}mv {shlex.quote(e['path'] + '.vigil-disabled')} {p}"],
                                     lose="Whatever it started; for a shell file, your own settings in it too."))
            if package:
                reinstall = {"arch": f"sudo pacman -S {package}", "debian": f"sudo apt install --reinstall {package}",
                             "fedora": f"sudo dnf reinstall {package}", "suse": f"sudo zypper install -f {package}"}.get(self.fam)
                if reinstall:
                    fix.append(fx.option(f"Reinstall {package}", "Puts the package's own version of its files back.",
                                         "admin", [reinstall],
                                         undo_steps=["Nothing to undo: reinstalling only restores the package's files. "
                                                     "Keep a copy first if you want the changed one."]))
        return fx.panel(self.osr, check=check, fix=fix)

    def add(self, check, title, summary, sev, signals, e, *, likely=None, confidence="Medium", reason="",
            package=None, line=None, subject=None, technical=()):
        self.findings.append(fmt.make(
            TOOL, check, fit_title(title if isinstance(title, list) else [title]), summary, sev,
            signals=[fmt.signal(*s) for s in signals], likely=likely, confidence=confidence,
            confidence_reason=reason, subject=subject or f"{e['path']}:{check}",
            fixes=self.fixes(e, sev, package, line),
            evidence=[{"kind": "path", "value": e["path"]}] + ([{"kind": "line", "value": f"{e['path']}:{line}",
                                                                  "note": self._line(e, line)}] if line else []),
            technical=[{"label": "kind", "value": e["kind"]}, {"label": "sha256", "value": e.get("sha256") or "-"},
                       {"label": "mode", "value": oct(e["mode"]) if e.get("mode") is not None else "-"},
                       {"label": "owner uid", "value": str(e.get("uid"))}] + list(technical),
            data=e["path"], when=self.now))

    @staticmethod
    def _line(e, n):
        lines = (e.get("text") or "").splitlines()
        return lines[n - 1].strip()[:300] if n and n <= len(lines) else None

    # ---- the scan ---------------------------------------------------------------------------

    def run(self):
        entries, hidden = locations.collect(self.home, self.root, self.proc)
        base_ts, base = self.baseline if self.baseline else (None, None)
        current = {}
        for e in entries:
            pkg = self.pkg.owner(e["path"]) if e["kind"] != "loaded kernel module" and not e.get("link") else None
            e["package"] = pkg
            e["integrity"] = None
            if pkg and e["readable"] and not e.get("link"):
                e["integrity"] = self.pkg.verify(e["path"], e.get("data"))
                exp = self.pkg.expected(e["path"]) or {}
                e["conffile"] = exp.get("conffile", False)
            e["service"] = self.service_of(e)
            current[e["path"]] = {"sha256": e["sha256"], "mode": e["mode"], "link": e["link"], "kind": e["kind"],
                                  "group": e["group"], "scope": e["scope"], "package": pkg}
            self.content(e)
            self.integrity(e)
        diff = self.diff(base, current, {e["path"]: e for e in entries}) if base is not None else None
        rows = [{k: e.get(k) for k in ("path", "kind", "group", "scope", "size", "mode", "uid", "link", "readable",
                                       "sha256", "package", "integrity", "taint", "service")} for e in entries]
        return {"tool": TOOL, "entries": rows, "hidden": hidden, "findings": fmt.sort(self.findings),
                "diff": diff, "baseline_at": base_ts, "current": current, "scanned_at": self.now,
                "package_db": self.pkg.kind, "distro": fx.distro_info(self.osr),
                "groups": {g: sum(1 for e in entries if e["group"] == g) for g in locations.GROUP_NAMES},
                "counts": {s: sum(f["severity"] == s for f in self.findings) for s in fmt.SEVERITIES},
                "limits": self.limits(hidden)}

    def limits(self, hidden):
        out = ["Vigil only reads these files; it never disables, edits or deletes anything."]
        if hidden:
            out.append(f"{len(hidden)} files can only be read by root (for example {hidden[0]['path']}). Vigil lists "
                       "them, and notices when they appear, disappear or change size, but can't see inside them as you.")
        if self.pkg.kind == "rpm":
            out.append("This distro's package database (RPM) can't be read without running rpm, so files aren't "
                       "checked against their packages here; the Check commands include `rpm -Vf` for that.")
        elif self.pkg.kind is None:
            out.append("No package database was found, so nothing is checked against a package.")
        return out

    def service_of(self, e):
        """A known-services catalogue match from the program the entry starts."""
        progs = [os.path.basename(m.group(1)) for m in locations.EXEC_RE.finditer(e.get("text") or "")]
        for p in progs:
            hit = catalogue.match(process=p)
            if hit:  # the program's everyday name; the catalogue's name describes its traffic
                return {"id": hit["id"], "name": FRIENDLY.get(p.lower(), hit["name"]), "what": hit.get("what")}
        return None

    def capped(self, e, sev):
        """Package-shipped and unchanged: label, don't alarm."""
        if e.get("package") and e.get("integrity") == "ok":
            return SEV_CAP_PACKAGE_OK
        if e["path"].startswith("/usr/lib/") and not e.get("package") and self.pkg.kind in ("rpm", None) and sev == "High":
            return "Medium"
        return sev

    def content(self, e):
        for sev, st, text, line, tmpl in locations.flags(e):
            sev = self.capped(e, sev)
            shipped = e.get("package") and e.get("integrity") == "ok"
            name = os.path.basename(e["path"]) if e["kind"] != "loaded kernel module" else e["path"].split()[-1]
            title = [tmpl.format(name=name), tmpl.format(name=f"A {e['kind']}").capitalize()
                     if tmpl.startswith("{name}") else tmpl.format(name="it")]
            self.add("content", title, f"{e['path']} {text}.", sev, [(text, st, "content")], e,
                     likely=(f"It ships unchanged in the package {e['package']}, so this is the packager's choice."
                             if shipped else WHY[e["group"]]),
                     confidence="Low" if shipped else "High" if sev == "High" else "Medium",
                     reason="Read from the file itself." + (" The package vouches for it." if shipped else ""),
                     package=e.get("package"), line=line, subject=f"{e['path']}:content:{text[:60]}")

    def integrity(self, e):
        if e.get("integrity") != "changed":
            return
        conf = e.get("conffile")
        sev = "Low" if conf else "High" if e["group"] in ("preload", "pam", "sudoers", "systemd", "modules") else "Medium"
        self.add("package_changed", f"{os.path.basename(e['path'])} differs from its package's copy",
                 f"{e['path']} came from the package {e['package']}, and its contents no longer match what the "
                 f"package installed{' (it is a config file, so edits are expected)' if conf else ''}.", sev,
                 [(f"Contents differ from {e['package']}'s recorded checksum", 0.3 if conf else 0.8, "integrity")], e,
                 likely="An admin's own edit, or something altering a file the package manager trusts." if conf else
                 "Package files should only change when the package is updated; a change in between is unusual.",
                 confidence="Low" if conf else "High", package=e["package"],
                 reason="Compared with the checksum the package database recorded at install.")

    def diff(self, base, current, entries):
        added = sorted(set(current) - set(base))
        removed = sorted(set(base) - set(current))
        changed = sorted(p for p in set(current) & set(base)
                         if (current[p]["sha256"], current[p]["mode"], current[p]["link"]) !=
                         (base[p].get("sha256"), base[p].get("mode"), base[p].get("link")))
        for p in added:
            e = entries[p]
            svc = e.get("service")
            sev = "Medium"
            if e["kind"] == "loaded kernel module":
                sev = "Low"
            if e.get("package") and e.get("integrity") in ("ok", None) and e["path"].startswith("/usr/"):
                sev = "Info"          # arrived with a package update
            if svc and sev == "Medium":
                sev = "Low"
            self.add("new_since_baseline",
                     [f"New {e['kind']}: {os.path.basename(p) if not p.startswith('kernel module') else p.split()[-1]}",
                      f"New {e['kind']} since your baseline"],
                     f"{p} was not there when the baseline was taken" + (f"; it belongs to {e['package']}." if
                                                                          e.get("package") else "."),
                     sev, [("Not in the baseline", 0.6 if sev == "Medium" else 0.2, "new")]
                     + ([(f"Starts {svc['name']}, a known program", 0.1, "known")] if svc else []), e,
                     likely=(f"Probably {svc['name']}'s own start-up entry." if svc else
                             f"Installed by the package {e['package']}." if e.get("package") else WHY[e["group"]]),
                     confidence="Low" if sev in ("Low", "Info") else "Medium",
                     reason="A new entry is worth one look; most are software you just installed.",
                     package=e.get("package"), subject=f"{p}:new")
        for p in changed:
            e = entries[p]
            old = base[p]
            what = ("now points somewhere else" if old.get("link") != e["link"] else
                    "permissions changed" if old.get("sha256") == e["sha256"] else "contents changed")
            sev = "Low" if e["group"] == "shell" and e["scope"] == "user" and what == "contents changed" else "Medium"
            if e.get("package") and e.get("integrity") == "ok":
                sev = "Info"          # updated by its package
            if e["group"] in ("preload", "sudoers", "pam") or (e["group"] == "ssh" and e["kind"] == "SSH login keys"):
                sev = "High" if sev != "Info" else sev
            self.add("changed_since_baseline", [f"{os.path.basename(p)} changed since your baseline",
                                                "An autostart file changed since your baseline"],
                     f"{p}: {what} since the baseline.", sev, [(f"{what.capitalize()} since the baseline", 0.7, "changed")], e,
                     likely=(f"Updated by its package {e['package']}." if sev == "Info" else
                             "You may have edited it yourself; otherwise find out what did." if e["scope"] == "user"
                             else WHY[e["group"]]),
                     confidence="Low" if sev in ("Low", "Info") else "Medium",
                     reason="Compared with the saved baseline.", package=e.get("package"), subject=f"{p}:changed",
                     technical=[{"label": "baseline sha256", "value": old.get("sha256") or "-"},
                                {"label": "baseline mode", "value": oct(old["mode"]) if old.get("mode") is not None else "-"}])
        gone = [{"path": p, "kind": base[p].get("kind")} for p in removed]
        return {"added": added, "removed": gone, "changed": changed}


def scan(home, root="/", proc="/proc", osr=None, baseline=None, now=None):
    return Scan(home, root, proc, osr, baseline, now).run()
