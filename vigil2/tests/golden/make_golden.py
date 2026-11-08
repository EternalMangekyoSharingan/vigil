"""Write the golden files that hold Vigil 2 (Rust) to Vigil 1's (Python) behaviour.

Run from the repository root:   python3 vigil2/tests/golden/make_golden.py

Every input here is SYNTHETIC (written for these tests, or read from tests/fixtures/,
which is synthetic too). The outputs are whatever Vigil 1 computes for them today; the
Rust tests in vigil2/crates/*/tests/golden.rs must produce the same values.
"""

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

from vigil.core import attack, commands, finding, fixes, system, wording  # noqa: E402

OUT = Path(__file__).resolve().parent
OSR = ROOT / "tests" / "fixtures" / "os-release"

TITLES = [
    "beacon.py checks in with this PC every ~10 s", "Something happened.", "High entropy payload",
    "Starts at 10:30 every day", "Talks to 2001:db8::5 every hour", "Uses 100% of the CPU",
    "x" * 61, "x" * 60, "", "   ", "Low CV on this one", "cv", "a regex was used", "EDR says hi",
    "c2 server found", "Talks to ::1 now", "Talks to fe80::1%eth0", "At 12:30:45 it ran", "IOC list",
    "The payload's size", "Polls a server", "poll", "check-ins every hour", "stdev is small", "±5",
    "Runs ::ffff:192.0.2.1 here", "deadbeef:cafe::1 talks", "Ratio 1:2:3 seen", "a:b:c", "::",
    "Downloads and runs a script from a pastebin", "Exfil over DNS", "exfiltration over DNS",
    "Heuristic flags", "TTP match", "stdout shown", "Variation is low", "Coefficient high",
    "Firefox talks to Google", "Ends with question?", "Ends with dot .", "Läuft überall",
]
SENTENCES = [
    "It downloads install.sh from paste.example and runs it.", "The archive expands to 1.5 GB, e.g. from a tiny file.",
    "No full stop", "One. Two.", "Two sentences here. Another one.", "", "  ", "Is this a question?",
    "Wow!", "Ends with an etc. And more.", "See i.e. this one.", "Version 2.0 is out.",
    "Mr. Smith arrived.", "It reads ~/.ssh/id_rsa now.", "No. 5 is here.", "vs. them, it won.",
    "First sentence! Second sentence.", "Hello? World.", "lower. case next.", "The file a.tar.gz grew.",
    "Approx. 5 MB was sent.", "Done.  ", "It talks to example.com. Then stops.", "Mixed 3.5x faster.",
]
FIT = [
    ["x" * 70, "Short one"], ["y" * 80], ["memfd:payload runs from memory", "A program runs from memory only"],
    ["100% ready.service started", "A service started"], ["", None, "Only this"], ["Ends.", "z" * 61],
    ["Ends.", "Fine title"], ["a" * 59 + "é", "b"], ["c" * 61, "d" * 62],
]
SECONDS = [0, 3, 7, 12, 54, 55, 60, 89, 90, 100, 420, 3299, 3300, 3600, 5399, 5400, 7200, 36000, 86400]
KB = [0, 5, 999, 1000, 1499, 1500, 999999, 1000000, 1500000, 25e6]
PROGRAMS = [
    ["/usr/lib/librewolf/librewolf", None, None], ["/usr/bin/python3", "/usr/bin/python3 /home/a/.cache/upd.py", None],
    ["/opt/x/agent (deleted)", None, None], [None, "/usr/bin/firefox -P", None], [None, None, None],
    ["/usr/bin/node", "/usr/bin/node /srv/app/server.js --port 1", None], ["/usr/bin/bash", "/usr/bin/bash", None],
    ["/usr/bin/unknownthing", None, "Pretty"], ["/usr/bin/CODE", None, None], ["", "", ""],
    ["/usr/bin/perl", "/usr/bin/perl -e 1", None], ["/usr/bin/java", "/usr/bin/java -jar /x/y.jar", None],
]
OWNERS = ["AMAZON-02", "Google LLC", "HETZNER-AS", "Some Company", "ACME-NET", "acmecorp", "ExampleNet-AS64500",
          "", None, "MyISP-ASN", "Deutsche Telekom AG", "COMCAST-7922", "Mixed-Case-Co"]
HOSTS = ["www.example.com", "*.cdn.example.net", "a.very.long.subdomain.of.something.example.org", "Example.COM",
         "short.io", "a.b.c.d.e.f.g.h.example.com"]

COMMANDS = sorted(set([
    "sudo pacman -S syncthing", "sudo pacman -Rns foo", "pacman -Qo /usr/bin/x", "rpm -qf /usr/bin/x",
    "dpkg -S /usr/bin/x", "sudo systemctl disable --now foo.service", "systemctl --user stop bar.service",
    "systemctl status sshd", "systemctl list-timers --all", "sudo dnf install x", "sudo dnf remove x",
    "sudo zypper install x", "sudo apt remove x", "sudo xbps-remove -R x", "xbps-query -o /x", "doas apk add x",
    "doas apk del x", "apk info --who-owns /x", "sudo emerge --ask --depclean x", "equery belongs /x",
    "rm ~/.config/autostart/evil.desktop", "rm '/tmp/a b'", "sudoedit /etc/sudoers", "pkexec rm /etc/ld.so.preload",
    "sudo ufw deny out to 192.0.2.1", "sudo firewall-cmd --permanent --add-rich-rule='rule family=ipv4 reject'",
    "sudo nft add table inet vigil", "flatpak uninstall --unused", "sudo timedatectl set-ntp true",
    "gsettings set org.gnome.software download-updates false", "cat /etc/ssh/sshd_config", "ss -tnp",
    "journalctl -u foo --since today", "sha256sum ./x", "su -c whoami", "sudo -u nobody id",
    "nmcli networking connectivity", "sudo pacman -Syu", "sudo pacman -Qkk", "pacman -Qi bash",
    "rpm -qi bash", "sudo dpkg --verify", "sudo apt-get purge x", "dnf5 install y", "sudo apt autoremove",
    "unknowntool --flag value", "sudo nft delete table inet vigil", "ufw status", "sudo systemctl mask x",
    "sudo systemctl unmask x", "sudo systemctl restart y", "sudo systemctl reload y", "\"quoted cmd\" arg",
    "sudo flatpak uninstall --unused", "systemctl --user enable --now x.timer", "xbps-install -S x",
]))
src = "\n".join(p.read_text() for p in (ROOT / "vigil").rglob("*.py"))
for m in re.finditer(r'"((?:sudo|pkexec|doas|pacman|systemctl|rpm|dpkg|journalctl|nft|ufw|firewall-cmd|flatpak|'
                     r'zypper|dnf|apt|cat|rm|xbps-query|equery|apk|timedatectl|nmcli|gsettings) [^"{}]+)"', src):
    if not re.search(r"\b(is|are|the|lists|prints|changes|reads|deletes|mode)\b", m.group(1)):
        COMMANDS.append(m.group(1))
COMMANDS = sorted(set(COMMANDS))

# ---- findings ---------------------------------------------------------------------------
GOOD = dict(tool="pkg", check="pipe_to_shell", title="Downloads and runs a script from a pastebin",
            summary="The build downloads a script from pastebin.com and runs it.", severity="High",
            signals=[["curl output piped into sh", 0.9]], likely="Malware or a careless packager.",
            confidence="High", confidence_reason="Running downloaded code is rarely needed.",
            subject="/tmp/x/PKGBUILD", data="PKGBUILD line 12", when=1000.0)


def args(**kw):
    a = json.loads(json.dumps(GOOD))
    a.update(kw)
    return a


OPT_OK = dict(title="Remove it", what="Removes the package.", risk="admin",
              commands=["sudo pacman -Rns foo"], undo=["sudo pacman -S foo"])
OPT_STEPS = dict(title="Edit by hand", what="Open the file and delete the line.", risk="settings",
                 commands=[], undo=[], steps=["Open it", "Delete line 3"], undo_steps=["Put the line back"])
CHECK_OPT = dict(title="Look first", what="Shows the file.", risk="safe", commands=["cat /etc/ld.so.preload"])

MAKE = [
    ("good", args()),
    ("another wording, same id", args(title="Another wording of the same thing")),
    ("low without signals", args(subject="/other", severity="Low", signals=[])),
    ("signals sorted and clamped", args(signals=[["weak", 0.2, "a"], ["strong", 1.7, "b"], ["neg", -1, None],
                                                 ["mid", 0.555]])),
    ("ld_preload default attack", dict(tool="tasks", check="ld_preload", title="game has a library forced into it",
                                       summary="x.", severity="High", signals=[["x", 1]], when=1)),
    ("explicit attack", dict(tool="persist", check="content", title="A thing", summary="x.", severity="Info",
                             attack=["T1053.003", "T9999"], when=1)),
    ("evidence and iocs", args(evidence=[{"kind": "line", "value": "curl x | sh", "note": "line 12"},
                                         {"kind": "pid", "value": 4410}],
                               iocs=[{"type": "url", "value": "https://paste.example/raw/x"}],
                               technical=[{"label": "Line", "value": 12}], tags=["aur", "build"])),
    ("with fixes arch", args(fixes={"osr": "arch", "check": [CHECK_OPT], "fix": [OPT_OK, OPT_STEPS]})),
    ("with fixes unknown distro", args(fixes={"osr": "unknown", "check": [CHECK_OPT], "fix": [OPT_OK]})),
    ("unicode subject", args(subject="/home/ü/файл", title="Läuft überall")),
    ("medium", args(severity="Medium", confidence="Low", confidence_reason="")),
    ("info no likely", args(severity="Info", likely=None, signals=[])),
]
BROKEN = [
    ("title longer", args(title="x" * 61)), ("one sentence", args(summary="Two sentences here. Another one.")),
    ("severity", args(severity="Critical")), ("confidence", args(confidence="Certain")),
    ("signals", args(signals=[])), ("percent", args(title="Uses 100% of the CPU")),
    ("ipv6", args(title="Talks to 2001:db8::5 every hour")),
    ("bad indicator", args(iocs=[{"type": "colour", "value": "red"}])),
    ("bad indicator empty", args(iocs=[{"type": "url", "value": ""}])),
    ("fix without undo", args(fixes={"osr": "arch", "fix": [dict(OPT_OK, undo=[])]})),
    ("many at once", args(title="", summary="no stop", severity="Bad", confidence="Nope")),
    ("bad attack", args(attack=["X9999"])),
]


def build(a):
    a = json.loads(json.dumps(a))
    fx = a.pop("fixes", None)
    if fx:
        osr = system.os_release(str(OSR / fx["osr"]))
        mk = lambda o: fixes.option(o["title"], o["what"], o["risk"], o.get("commands", []), o.get("undo", []),
                                    steps=o.get("steps"), undo_steps=o.get("undo_steps"))
        a["fixes"] = fixes.panel(osr, check=[mk(o) for o in fx.get("check", [])], fix=[mk(o) for o in fx.get("fix", [])])
    a["signals"] = [tuple(s) for s in a.get("signals", [])]
    return finding.make(**a)


def errors_of(a):
    try:
        build(a)
    except finding.FindingError as e:
        return str(e)
    return None


data = {
    "_note": "SYNTHETIC inputs; outputs computed by Vigil 1 (Python). Regenerate with make_golden.py.",
    "title_problems": {t: wording.title_problems(t) for t in TITLES},
    "one_sentence": {s: wording.one_sentence(s) for s in SENTENCES},
    "fit_title": [{"in": c, "out": wording.fit_title(c)} for c in FIT],
    "every": {str(s): wording.every(s) for s in SECONDS},
    "span": {str(s): [wording.span(s), wording.span(s, short=True)] for s in SECONDS},
    "kb": [[n, wording.kb(n)] for n in KB],
    "friendly_program": [{"in": p, "out": wording.friendly_program(*p)} for p in PROGRAMS],
    "owner_name": [[o, wording.owner_name(o)] for o in OWNERS],
    "short_host": {h: wording.short_host(h) for h in HOSTS},
    "tokenize": {c: commands.tokenize(c) for c in COMMANDS},
    "legend": commands.LEGEND,
    "finding_id": [[t, c, s, finding.finding_id(t, c, s)] for t, c, s in
                   [("pkg", "pipe_to_shell", "/tmp/x/PKGBUILD"), ("net", "beacon", "firefox|192.0.2.1:443"),
                    ("tasks", "ld_preload", "4410"), ("files", "x", ""), ("persist", "c", "/home/ü/файл")]],
    "make": [{"name": n, "args": a, "out": build(a)} for n, a in MAKE],
    "broken": [{"name": n, "args": a, "error": errors_of(a)} for n, a in BROKEN],
    "attack_by_check": {f"{t}/{c}": attack.for_check(t, c) for t, c in attack.BY_CHECK},
    "attack_persist": [[g, k, p, attack.for_persist(g, k, p)] for g, k, p in
                       [("systemd", "", "/etc/systemd/system/x.service"), ("systemd", "", "/x/backup.timer"),
                        ("cron", "boot script", ""), ("shell", "package manager hook", ""), ("nope", "", "")]],
    "techniques": {k: list(v) for k, v in attack.TECHNIQUES.items()},
    "tactics": attack.TACTICS,
    "os_release": {p.name: [system.os_release(str(p)), system.family(system.os_release(str(p)))]
                   for p in sorted(OSR.iterdir()) if p.name != "README.md"},
    "owner_check": {n: fixes.owner_check("/usr/bin/x", system.family(system.os_release(str(OSR / n))))
                    for n in ("arch", "fedora", "opensuse", "ubuntu", "unknown")},
}
(OUT / "model.json").write_text(json.dumps(data, indent=1, ensure_ascii=False, sort_keys=True) + "\n")
print(f"wrote {OUT / 'model.json'}: {len(COMMANDS)} commands, {len(MAKE)} findings, {len(BROKEN)} broken")


# ---- /proc: the Network collector on the synthetic fixture ------------------------------
# User names come from the machine's passwd file, which differs between machines, so both
# sides use the same made-up rule here: uid N is called "user-N" (root is "root").
import tempfile  # noqa: E402

from tests import helpers  # noqa: E402
from vigil.net import collector  # noqa: E402

collector.username = lambda uid: "root" if uid == 0 else f"user-{uid}"
collector.username.cache_clear = lambda: None


def proc_snapshot(viewer, blocked):
    with tempfile.TemporaryDirectory() as tmp:
        root = helpers.make_proc(tmp)
        if blocked:
            with helpers.non_root_view(root):
                snap = collector.snapshot(root, now=1000.0, viewer_uid=viewer)
        else:
            snap = collector.snapshot(root, now=1000.0, viewer_uid=viewer)
    for k in ("taken_at", "proc_root", "byte_counts", "hidepid"):
        snap.pop(k)
    snap["processes"] = {str(k): v for k, v in snap["processes"].items()}
    snap["unreadable_by_uid"] = {str(k): v for k, v in snap["unreadable_by_uid"].items()}
    return snap


identities = [
    [None, [], "kthreadd"], ["/usr/bin/python3.11", ["python3", "/home/a/x.py", "-v"], "python3"],
    ["/usr/bin/python3", ["python3", "-m", "http.server"], "python3"], ["/usr/bin/python3", ["python3", "-c", "x"], "python3"],
    ["/usr/bin/java", ["java", "-jar", "/opt/app.jar"], "java"], ["/opt/x (deleted)", ["/opt/x"], "x"],
    ["/usr/bin/bash", ["bash"], "bash"], ["/usr/bin/node", ["node", "--inspect", "srv.js"], "node"],
    [None, ["/usr/bin/foo", "a"], "foo"], ["/usr/bin/python3", ["python3", "-m"], "python3"],
]
addresses = ["0100007F:0277", "00000000:0016", "0000000000000000FFFF00000100007F:0050",
             "B80D0120000000000000000001000000:01BB", "00000000000000000000000001000000:1F90",
             "2E01A8C0:C350", "0101A8C0:0035", "FFFFFFFF:0000", "000080FE00000000FF005450B6AD1DFE:0000"]
proc_data = {
    "_note": "SYNTHETIC: Vigil 1's collector on tests/fixtures/proc. Regenerate with make_golden.py.",
    "root": proc_snapshot(0, False),
    "user1000": proc_snapshot(1000, True),
    "program_identity": [[e, c, comm, list(collector.program_identity(e, c, comm))] for e, c, comm in identities],
    "decode_address": [[a, list(collector.decode_address(a, "little"))] for a in addresses],
    "decode_address_bad": [b for b in ["0100007F", "01007F:0277", "ZZZZZZZZ:0050", "0100007F:XYZ"]],
    "scope_of": {ip: collector.scope_of(ip) for ip in ["127.0.0.1", "10.1.2.3", "192.0.2.1", "8.8.8.8", "::1", "fe80::1",
                                                         "ff02::fb", "0.0.0.0", "::", "100.64.1.1", "fd00::1",
                                                         "2001:db8::1", "2606:4700::1111", "224.0.0.251", "169.254.1.1",
                                                         "172.16.5.4", "172.32.0.1", "255.255.255.255"]},
}
(OUT / "proc.json").write_text(json.dumps(proc_data, indent=1, ensure_ascii=False, sort_keys=True) + "\n")
print(f"wrote {OUT / 'proc.json'}: {len(proc_data['root']['sockets'])} sockets, "
      f"{len(proc_data['root']['processes'])} processes")
