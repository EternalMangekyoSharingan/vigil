"""Turn process flags into findings in the suite's format, with copy-only commands.

Stopping a process is copy-a-command only (the owner's open decision, see PROGRESS.md):
the Fix panel offers a reversible pause (SIGSTOP / SIGCONT), stopping its systemd unit
(with start as the undo), and kill. Vigil never sends a signal itself.
"""

import shlex
import time

from ..core import catalogue
from ..core import finding as fmt
from ..core import fixes as fx
from ..core.wording import fit_title
from . import procs as P

TOOL = "tasks"
TITLES = {
    "memory_only": ["{name} runs from memory with no file on disk", "A program runs from memory only"],
    "deleted_binary": ["{name} keeps running after its file was deleted", "A program's file was deleted"],
    "replaced_binary": ["{name} was updated while it was running", "A program was updated while running"],
    "temp_binary": ["{name} runs from a temporary folder", "A program runs from a temporary folder"],
    "cache_binary": ["{name} runs from a cache folder", "A program runs from a cache folder"],
    "downloads_binary": ["{name} runs straight from Downloads", "A program runs straight from Downloads"],
    "hidden_binary": ["{name} runs from a hidden folder", "A program runs from a hidden folder"],
    "ld_preload": ["{name} has a library forced into it", "A program has a library forced into it"],
    "odd_parent": ["{parent} started {child}", "{parent} started a shell", "An app started a shell"],
    "fake_kernel_name": ["{name} pretends to be a kernel thread", "A program pretends to be a kernel thread"],
    "reverse_shell": ["{name} looks like a reverse shell", "A program looks like a reverse shell"],
    "listens_from_odd_place": ["{name} listens for connections from an odd place", "A program listens from an odd place"],
    "masquerade_name": ["{name} pretends to be a system program", "A program pretends to be a system program"],
}
WHY = {
    "memory_only": "Programs normally run from a file; running only from memory is how fileless malware avoids leaving traces.",
    "deleted_binary": "Malware often deletes its own file after starting, so nothing is left to find on disk.",
    "replaced_binary": "After an update, running programs keep the old version until restarted. Harmless.",
    "temp_binary": "Temporary folders are where downloaded payloads land; installed software lives in /usr or /opt.",
    "cache_binary": "Cache folders hold data, not programs; a program here was put there by something.",
    "downloads_binary": "Fine for an AppImage you chose to run; otherwise worth knowing what it is.",
    "hidden_binary": "Hidden folders keep things out of sight; some tools install there, so does malware.",
    "ld_preload": "LD_PRELOAD injects code into a program; debuggers and some games use it, so do rootkits.",
    "odd_parent": "Browsers, mail and document apps open untrusted content; a shell under them is a classic sign of an exploit.",
    "fake_kernel_name": "Kernel threads have no program file; a user program with a kernel-thread name is hiding.",
    "reverse_shell": "A network tool wired to a shell hands control of this PC to someone elsewhere.",
    "listens_from_odd_place": "A program accepting connections from the whole network should be installed software.",
    "masquerade_name": "Malware borrows system program names so a glance at a process list looks normal; the July 2026 "
                       "AUR malware ran its Tor client as \"dbus-daemon\".",
}


def fixes(p, osr, viewer_uid):
    pid = p["pid"]
    own = p["uid"] == viewer_uid
    s = "" if own else "sudo "
    check = [fx.option("Its details", "PID, parent, user, start time and full command line.", "safe",
                       [f"ps -o pid,ppid,user,lstart,args -p {pid}"]),
             fx.option("Where its program file is", "Shows the file /proc says it runs; '(deleted)' if gone.", "safe",
                       [f"{s}ls -l /proc/{pid}/exe"]),
             fx.option("Its fingerprint (SHA-256)", "Hashes the running binary, even if its file was deleted.", "safe",
                       [f"{s}sha256sum /proc/{pid}/exe"])]
    if p.get("path") and p["path"].startswith(("/usr/", "/opt/", "/bin/", "/sbin/")):
        check.append(fx.owner_check(p["path"], fx.family(osr)))
    unit = (p.get("unit") or {}).get("unit")
    if unit and unit.endswith(".service"):
        user = " --user" if p["unit"].get("user") else ""
        check.append(fx.option(f"Its service, {unit}", "systemd's view: status, start time, recent log lines.", "safe",
                               [f"systemctl{user} status {shlex.quote(unit)}"]))
    fix = [fx.option("Pause it (reversible)", "Freezes the process without ending it, so you can look at it calmly.",
                     "settings" if own else "admin", [f"{s}kill -STOP {pid}"], [f"{s}kill -CONT {pid}"])]
    if unit and unit.endswith(".service"):
        user = " --user" if p["unit"].get("user") else ""
        su = "" if user else "sudo "
        fix.append(fx.option(f"Stop its service {unit}", "Stops the service (it may start again at the next boot).",
                             "settings" if user else "admin", [f"{su}systemctl{user} stop {shlex.quote(unit)}"],
                             [f"{su}systemctl{user} start {shlex.quote(unit)}"]))
    fix.append(fx.option("End it", "Asks the process to quit (SIGTERM). Unsaved work in it is lost.",
                         "settings" if own else "admin", [f"{s}kill {pid}"],
                         undo_steps=[f"Start it again if you need it: {' '.join(p['cmdline'])[:200] or p['name']}"],
                         lose="Whatever it was doing."))
    return fx.panel(osr, check=check, fix=fix)


def _attack(check, text):
    if check == "odd_parent":
        return ["T1505.003", "T1059.004"] if any(w in text for w in ("web server", "PHP", "database", "Redis")) \
            else ["T1203", "T1059.004"]
    return None  # the table in core/attack.py


def build(snap, osr, home=None, now=None):
    procs = snap["processes"]
    now = now or time.time()
    out, per_pid = [], {}
    for pid, p in procs.items():
        fl = P.flags(p, procs, home)
        per_pid[pid] = [{"check": c, "severity": sev, "text": t} for c, sev, _, t in fl]
        for check, sev, strength, text in fl:
            parent = procs.get(p["ppid"])
            child = P._base(p["exe"] or "") or p["comm"]
            svc = catalogue.match(process=child)
            names = dict(name=p["name"], parent=parent["name"] if parent else "Its parent", child=child)
            title = fit_title([t.format(**names) for t in TITLES[check]])
            chain = " → ".join(x["name"] for x in reversed(P.ancestry(procs, pid)))
            signals = [(text, strength, check)]
            if p["sockets"]:
                conn = [s for s in p["sockets"] if s["kind"] == "connection"]
                if conn:
                    signals.append((f"has {len(conn)} network connection(s), e.g. to {conn[0]['remote_ip']}:"
                                    f"{conn[0]['remote_port']}", 0.4, "network"))
            if not p["package"] and p["path"] and check not in ("replaced_binary",):
                signals.append(("its program file does not belong to any installed package", 0.3, "no_package"))
            out.append(fmt.make(
                TOOL, check, title, f"Process {pid} ({p['name']}, run by {p['user']}) {text}.", sev,
                signals=signals, likely=WHY[check] + (f" It looks like {svc['name']}." if svc else ""),
                confidence="High" if sev == "High" else "Medium" if sev == "Medium" else "Low",
                confidence_reason="Read from /proc for this process.", subject=f"{p.get('sha256') or p['path']}:{check}:{pid}",
                fixes=fixes(p, osr, snap["viewer_uid"]),
                evidence=[{"kind": "process", "value": f"pid {pid}", "note": chain},
                          {"kind": "path", "value": p["path"] or "(none)"}]
                + ([{"kind": "sha256", "value": p["sha256"]}] if p.get("sha256") else []),
                iocs=[{"type": "sha256", "value": p["sha256"]}] if p.get("sha256") and sev == "High" else [],
                technical=[{"label": "command line", "value": " ".join(p["cmdline"])[:500]},
                           {"label": "parent", "value": f"{parent['pid']} {parent['name']}" if parent else "-"},
                           {"label": "started", "value": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(p["started"]))
                            if p.get("started") else "-"},
                           {"label": "systemd unit", "value": (p.get("unit") or {}).get("unit") or "-"},
                           {"label": "package", "value": p["package"] or "none"}],
                data=f"/proc/{pid}", when=now, attack=_attack(check, text)))
    return fmt.sort(out), per_pid
