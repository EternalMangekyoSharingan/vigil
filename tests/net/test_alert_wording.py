"""Alert titles, explanations, the known-services catalogue, the Fix panel and the
command tokeniser. All alert data here is SYNTHETIC (built in the tests); os-release
files in tests/fixtures/os-release are synthetic copies of the real distros' format."""

import ipaddress
import itertools
import json
import os
import random
import re
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from vigil.core import commands, catalogue as services

from vigil.net import fixes, wording

OSR = Path(__file__).parent.parent / "fixtures" / "os-release"
NOW = time.time()
IPV6 = re.compile(r"[0-9a-f]{1,4}(:[0-9a-f]{0,4}){2,}", re.I)


def finding(signal, points, **stats):
    return {"check": signal, "points": points, "reason": f"raw {signal} reason", "data": "synthetic",
            "stats": dict(signal=signal, **stats)}


def timer(interval, cv=0.05, first=NOW - 7 * 3600):
    return finding("timer", 40, interval=interval, cv=cv, checkins=60, missed=2, pauses=[], first=first,
                   last=NOW, connections=60, poll=2)


def ctx(**kw):
    base = {"program": "/usr/bin/syncthing", "name": "syncthing", "hidden": None, "info": {"exe": "/usr/bin/syncthing"},
            "ip": "88.198.1.2", "port": 443, "proto": "tcp", "direction": "out", "score": 75,
            "findings": [timer(420)], "first_raised": NOW - 3600, "hosts": [],
            "geo": {"owner": "HETZNER-AS", "country": "DE", "asn": 24940}, "scope": "internet", "service": None, "poll": 2}
    base.update(kw)
    return base


def check_title(t):
    assert len(t) <= wording.TITLE_MAX, (len(t), t)
    low = t.lower()
    for w in wording.BANNED:
        assert not re.search(rf"(?<![a-z]){re.escape(w)}(?![a-z])", low), (w, t)
    assert not IPV6.search(t), t


class TitleTests(unittest.TestCase):
    def test_examples(self):
        self.assertEqual(wording.title(ctx()), "Syncthing checks in with Hetzner (DE) every ~7 min")
        c = ctx(program="hidden:closed", hidden="closed", info={}, name=None, port=80, findings=[timer(300)],
                geo=None, ip="95.217.163.246")
        check_title(wording.title(c))
        self.assertIn("plain HTTP", wording.title(c))
        self.assertTrue(wording.title(c).lower().startswith(("an unidentified program", "unidentified program")))
        lw = ctx(program="/usr/lib/librewolf/librewolf", name="librewolf", info={"exe": "/usr/lib/librewolf/librewolf"},
                 geo={"owner": "FASTLY", "country": "US"}, findings=[timer(600)])
        self.assertEqual(wording.title(lw), "LibreWolf checks in with Fastly (US) every ~10 min")

    def test_never_bare_ipv6_and_domain_first(self):
        c = ctx(ip="2a01:4f8:c010:1234::1", geo=None)
        self.assertEqual(wording.destination(c), "an IPv6 server")
        check_title(wording.title(c))
        c = ctx(hosts=["relays.syncthing.net"])
        self.assertEqual(wording.title(c), "Syncthing checks in with relays.syncthing.net every ~7 min")

    def test_human_rounding(self):
        self.assertEqual(wording.every(416), "every ~7 min")
        self.assertEqual(wording.every(9.7), "every ~10 s")
        self.assertEqual(wording.every(7300), "every ~2 h")
        self.assertEqual(wording.span(7 * 3600 + 42 * 60), "7 h 42 min")
        self.assertEqual(wording.span(11 * 3600 + 5 * 60, short=True), "11 hours")

    def test_fuzzed_titles_obey_the_rules(self):
        rnd = random.Random(7)
        names = ["/usr/bin/syncthing", "/usr/lib/librewolf/librewolf", "/opt/some/very-long-program-name-with-extra-words",
                 "/usr/bin/python3.13 /home/u/.local/bin/a-really-long-script-name-for-testing.py", "hidden:closed",
                 "hidden:other-user:0", "/usr/bin/NetworkManager"]
        sigs = [timer(rnd.randint(5, 90000)), finding("long", 25, duration=40000, opened_at=NOW - 40000, closed_at=None, at_least=False),
                finding("threat", 100, feed="Feodo Tracker", label="Emotet botnet C2"), finding("temp_dir", 25, path="/tmp/x"),
                finding("new_program", 20, at=NOW), finding("new_destination", 15, at=NOW, baseline=NOW - 99)]
        dests = [dict(ip="2a01:4f8::1", geo=None), dict(ip="1.2.3.4", geo=None),
                 dict(ip="1.2.3.4", geo={"owner": "MICROSOFT-CORP-MSN-AS-BLOCK", "country": "US"}),
                 dict(ip="1.2.3.4", geo=None, hosts=["an.extremely.long.subdomain.of.some-content-delivery-network.example"]),
                 dict(ip="192.168.1.20", geo=None, scope="lan"), dict(ip="fd00::5", geo=None, scope="lan")]
        n = 0
        for prog, dest, k in itertools.product(names, dests, range(1, 4)):
            for combo in itertools.combinations(sigs, k):
                for port, direction in ((443, "out"), (80, "out"), (22, "in")):
                    c = ctx(program=prog, hidden=prog.split(":")[1] if prog.startswith("hidden:") else None,
                            info={} if prog.startswith("hidden:") else {"exe": prog.split(" ")[0]}, name=None,
                            findings=list(combo), port=port, direction=direction, **dest)
                    check_title(wording.title(c))
                    n += 1
        self.assertGreater(n, 1000)

    def test_subtitle(self):
        svc = services.match(process="NetworkManager", port=80, proto="tcp", interval=300)
        c = ctx(program="/usr/bin/NetworkManager", info={"exe": "/usr/bin/NetworkManager"}, port=80,
                findings=[timer(300)], service=svc, first_raised=NOW - 60)
        sub = wording.subtitle(c, now=NOW)
        self.assertRegex(sub, r"^Low · first seen \d\d:\d\d · probably NetworkManager's connectivity check$")


class ExplanationTests(unittest.TestCase):
    def test_structure(self):
        f = [timer(420, cv=0.04), finding("duration", 10, span=7 * 3600 + 42 * 60, samples=66, first=0, last=1),
             finding("same_size", 8, mean=8100, cv=0.05, n=40), finding("new_destination", 15, at=NOW, baseline=NOW - 9)]
        x = wording.explain(ctx(findings=f), now=NOW)
        self.assertTrue(x["summary"].startswith("Syncthing has contacted Hetzner (DE) about every 7 min since"))
        texts = [s["text"] for s in x["signals"]]
        self.assertIn("Contacts it on a steady timer (about every 7 min, very regular)", texts)
        self.assertIn("Has kept this up for 7 h 42 min", texts)
        self.assertIn("Sends about the same amount each time (~8 kB)", texts)
        self.assertIn("First time this PC has talked to this server since Vigil started watching", texts)
        self.assertEqual(len(texts), len(set(texts)))                     # each line unique
        self.assertEqual([w["group"] for w in x["why"]], ["timer", "new"])  # each kind explained once
        self.assertTrue(all(0 <= s["strength"] <= 1 for s in x["signals"]))
        tech = json.dumps(x["technical"])
        self.assertIn('"cv": 0.04', tech)                                   # raw numbers kept, out of the way
        for s in [x["summary"]] + texts + [w["text"] for w in x["why"]]:
            for sentence in re.split(r"(?<=[.!?])\s+", s):   # "keep every sentence under ~20 words"
                self.assertLessEqual(len(sentence.split()), 20, sentence)
            self.assertNotIn("coefficient", s.lower())

    def test_plain_http_and_unattributed(self):
        c = ctx(program="hidden:closed", hidden="closed", info={}, port=80, findings=[timer(300)], geo=None)
        x = wording.explain(c)
        texts = [s["text"] for s in x["signals"]]
        self.assertIn("Uses unencrypted HTTP, so anyone on the network path can read it", texts)
        self.assertTrue(any("closed before Vigil could see" in t for t in texts))
        self.assertIn("Vigil looks every 2 s", x["attribution"]["why"])
        self.assertEqual([o["id"] for o in x["attribution"]["options"]], ["fast-poll", "root-helper"])


class CatalogueTests(unittest.TestCase):
    def test_networkmanager_check(self):
        m = services.match(process="NetworkManager", port=80, proto="tcp", interval=300,
                           hosts=["ping.archlinux.org"])
        self.assertEqual((m["id"], m["confidence"]), ("networkmanager-connectivity", "High"))
        self.assertIn("process name", m["matched"])
        hidden = services.match(process=None, port=80, proto="tcp", interval=300)
        self.assertEqual(hidden["id"], "networkmanager-connectivity")  # plain HTTP every 5 min is distinctive

    def test_syncthing(self):
        m = services.match(process="syncthing", port=443, proto="tcp", owner="HETZNER-AS", interval=1800)
        self.assertEqual((m["id"], m["confidence"]), ("syncthing", "High"))
        self.assertIn("network owner", m["matched"])

    def test_browser(self):
        m = services.match(process="librewolf", port=443, proto="tcp", hosts=["firefox.settings.services.mozilla.com"])
        self.assertEqual(m["id"], "firefox-family")
        self.assertEqual(services.match(process="chromium", port=5228, proto="tcp")["id"], "chromium-family")

    def test_no_false_match(self):
        self.assertIsNone(services.match(process="agent", port=4444, proto="tcp", interval=30))

    def test_catalogue_shape(self):
        for s in services.catalogue():
            for k in ("id", "name", "match", "what", "why_fine", "privacy", "check", "fix"):
                self.assertIn(k, s, s["id"])
            for o in s["fix"]:
                self.assertTrue(o.get("undo") or o.get("undo_steps"), f"{s['id']}: {o['title']} has no undo")

    def test_catalogue_is_shipped_in_the_package(self):
        # The file must be inside vigil/, not an ignored data/ dir, or `python -m vigil`
        # crashes after a clean clone (regression: .gitignore's data/ hid it).
        self.assertTrue(os.path.exists(services.CATALOGUE), services.CATALOGUE)
        self.assertIn(os.path.join("vigil", "core", "data"), str(services.CATALOGUE))

    def test_missing_catalogue_degrades_quietly(self):
        services.catalogue.cache_clear()
        with mock.patch.object(services, "CATALOGUE", "/no/such/file.json"):
            self.assertEqual(services.catalogue(), [])
            self.assertIsNone(services.match(process="syncthing", port=443, proto="tcp"))
        services.catalogue.cache_clear()


class FixPanelTests(unittest.TestCase):
    FAMS = {"arch": ("pacman -Qo /usr/bin/syncthing", "sudo pacman -Rns syncthing", "sudo pacman -S syncthing", "arch"),
            "fedora": ("rpm -qf /usr/bin/syncthing", "sudo dnf remove syncthing", "sudo dnf install syncthing", "fedora"),
            "opensuse": ("rpm -qf /usr/bin/syncthing", "sudo zypper remove syncthing", "sudo zypper install syncthing", "suse")}

    def opts(self, distro, service_id, exe="/usr/bin/syncthing", fw="nftables", ip="88.198.1.2"):
        return fixes.options({"ip": ip, "program": exe, "hidden": False}, fixes.os_release(OSR / distro), fw,
                             exe=exe, service=dict(services.by_id(service_id), confidence="High", matched="x"))

    def test_three_services_on_three_distros(self):
        for distro, (owner, remove, install, fam) in self.FAMS.items():
            with self.subTest(distro):
                o = self.opts(distro, "syncthing")
                self.assertEqual(o["distro"]["family"], fam)
                self.assertEqual(o["check"][0]["commands"][0]["text"], owner)
                uninstall = next(f for f in o["fix"] if f["title"] == "Uninstall Syncthing")
                self.assertEqual(uninstall["commands"][0]["text"], remove)
                self.assertEqual(uninstall["undo"][0]["text"], install)
                roles = [t["role"] for t in uninstall["commands"][0]["tokens"]]
                self.assertEqual(roles, ["admin", "pkgmgr", "remove", "package"])
                self.assertTrue(o["undo"])
                nm = self.opts(distro, "networkmanager-connectivity", exe="/usr/bin/NetworkManager")
                off = next(f for f in nm["fix"] if f["title"] == "Turn off NetworkManager's connectivity check")
                self.assertEqual([c["text"] for c in off["undo"]][0],
                                 "sudo rm /etc/NetworkManager/conf.d/99-vigil-no-connectivity.conf")
                self.assertIn("enabled=false", off["file"]["content"])
                br = self.opts(distro, "firefox-family", exe="/usr/lib/librewolf/librewolf")
                self.assertTrue(all(f.get("steps") for f in br["fix"] if "Block" not in f["title"]))  # in-app steps
                self.assertTrue(any(u.get("steps") for u in br["undo"]))

    def test_family_colours(self):
        fam = {d: self.opts(d, "syncthing")["fix"] for d in self.FAMS}
        got = {d: next(t["family"] for f in fs if f["title"] == "Uninstall Syncthing"
                       for t in f["commands"][0]["tokens"] if t["role"] == "pkgmgr") for d, fs in fam.items()}
        self.assertEqual(got, {"arch": "arch", "fedora": "fedora", "opensuse": "suse"})

    def test_command_rules(self):
        for distro in ("arch", "fedora", "opensuse", "ubuntu"):
            for sid in [s["id"] for s in services.catalogue()]:
                for fw in ("firewalld", "ufw", "nftables", None):
                    o = self.opts(distro, sid, fw=fw)
                    for sec in ("check", "fix", "undo"):
                        for opt in o[sec]:
                            for c in opt.get("commands", []) + opt.get("undo", []):
                                t = c["text"]
                                self.assertNotIn("&&", t)
                                self.assertNotRegex(t, r"\|\s*(ba|z|da)?sh\b")
                                self.assertNotRegex(t, r"curl|wget")
                                if re.search(r"\brm\b", t):
                                    self.assertNotIn("*", t)
                    for opt in o["fix"]:
                        self.assertTrue(opt.get("undo") or opt.get("undo_steps") or not opt.get("commands"), opt["title"])

    def test_never_offers_to_remove_an_interpreter(self):
        o = fixes.options({"ip": "88.198.1.2", "program": "/usr/bin/python3.13 /home/u/.local/bin/agent.py", "hidden": False},
                          fixes.os_release(OSR / "arch"), "ufw", exe="/usr/bin/python3.13", service=None)
        self.assertEqual(o["check"][0]["commands"][0]["text"], "pacman -Qo /home/u/.local/bin/agent.py")
        self.assertFalse([f for f in o["fix"] if "Uninstall" in f["title"]])

    def test_unknown_distro(self):
        o = self.opts("unknown", "syncthing")
        self.assertFalse(o["distro"]["known"])
        self.assertIn("Unknown distro", o["note"])
        self.assertFalse(any("pacman" in c["text"] or "dnf" in c["text"] for f in o["fix"] for c in f["commands"]))

    def test_firewall_detection_and_block(self):
        with tempfile.TemporaryDirectory() as root:
            self.assertIsNone(fixes.firewall(root))
            Path(root, "etc/ufw").mkdir(parents=True)
            Path(root, "etc/ufw/ufw.conf").write_text("ENABLED=yes\n")
            self.assertEqual(fixes.firewall(root), "ufw")
            w = Path(root, "etc/systemd/system/multi-user.target.wants")
            w.mkdir(parents=True)
            (w / "firewalld.service").write_text("")
            self.assertEqual(fixes.firewall(root), "firewalld")
        b = fixes.block_option("ufw", "203.0.113.9")
        self.assertEqual([c for c in b["commands"]], ["sudo ufw deny out to 203.0.113.9"])
        self.assertEqual(b["undo"], ["sudo ufw delete deny out to 203.0.113.9"])
        n = fixes.block_option("nftables", "2001:db8::1")
        self.assertIn("ip6 daddr 2001:db8::1", n["commands"][-1])


class TokenizerTests(unittest.TestCase):
    def roles(self, cmd):
        return [t["role"] + (f":{t['family']}" if "family" in t else "") for t in commands.tokenize(cmd)]

    def test_examples(self):
        self.assertEqual(self.roles("sudo pacman -S syncthing"), ["admin", "pkgmgr:arch", "install", "package"])
        self.assertEqual(self.roles("sudo pacman -Rns syncthing"), ["admin", "pkgmgr:arch", "remove", "package"])
        self.assertEqual(self.roles("sudo dnf install syncthing"), ["admin", "pkgmgr:fedora", "install", "package"])
        self.assertEqual(self.roles("sudo zypper remove syncthing"), ["admin", "pkgmgr:suse", "remove", "package"])
        self.assertEqual(self.roles("sudo apt remove syncthing"), ["admin", "pkgmgr:debian", "remove", "package"])
        self.assertEqual(self.roles("pacman -Qo /usr/bin/syncthing"), ["pkgmgr:arch", "flag", "path"])
        self.assertEqual(self.roles("dpkg -S /usr/bin/x"), ["pkgmgr:debian", "flag", "path"])  # -S is a search here
        self.assertEqual(self.roles("systemctl --user disable --now syncthing.service"),
                         ["service", "flag", "remove", "flag", "package"])
        self.assertEqual(self.roles("sudo systemctl enable --now dnf-makecache.timer"),
                         ["admin", "service", "install", "flag", "package"])
        self.assertEqual(self.roles("sudo rm /etc/NetworkManager/conf.d/99-vigil-no-connectivity.conf"),
                         ["admin", "remove", "path"])
        self.assertEqual(self.roles("doas apk del syncthing"), ["admin", "pkgmgr:alpine", "remove", "package"])

    def test_every_token_explained(self):
        for t in commands.tokenize("sudo nft add chain inet vigil out '{ type filter hook output priority 0 ; }'"):
            self.assertTrue(t["tip"])
        self.assertEqual(commands.tokenize("echo 'a b'")[1]["text"], "'a b'")  # quotes stay one token


class NeverExecutesTests(unittest.TestCase):
    def test_fix_modules_cannot_run_commands(self):
        banned = re.compile(r"\b(subprocess|os\.system|os\.popen|popen|os\.exec\w*|os\.spawn\w*|pty|shutil\.which)\b")
        # The modules moved into the suite layout (2026-11-03); the same set is checked,
        # now at its new paths, plus the shared core pieces they were split into.
        pkg = Path(fixes.__file__).parent.parent
        for mod in ("net/fixes.py", "core/fixes.py", "core/commands.py", "net/wording.py", "core/wording.py",
                    "core/catalogue.py", "net/cleanup.py", "core/pkgdb.py", "core/finding.py"):
            src = (pkg / mod).read_text()
            code = re.sub(r'""".*?"""', "", src, flags=re.S)  # docstrings may mention the rule
            self.assertIsNone(banned.search(code), f"{mod} must not be able to run anything")

    def test_only_the_runner_executes_and_only_in_sudo_mode(self):
        # The owner asked for a sudo mode (2026-10-31). Fix commands still cannot run from
        # the modules that build them; /api/run is the one route that runs anything, and
        # it goes through runner.py's checks (see test_sudo_scan_cleanup.py).
        from vigil.net import server
        src = Path(server.__file__).read_text()
        routes = re.findall(r'\("(?:GET|POST|DELETE)", "(/api/[^"]+)"\)', src)
        self.assertEqual([r for r in routes if re.search(r"run|exec|apply", r)], ["/api/run"])
        self.assertIn("if not self.sudo_mode():", src)

class ServerAlertTests(unittest.TestCase):
    """SYNTHETIC alerts written straight into a fresh evidence store."""

    def setUp(self):
        from vigil.net import server
        from ..helpers import make_proc
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.app = server.App(f"{self.tmp.name}/data", interval=60, proc_root=make_proc(self.tmp.name), start_monitor=False)
        self.addCleanup(self.app.store.close)
        db = self.app.store.db
        for key, name, exe in (("/usr/bin/syncthing", "syncthing", "/usr/bin/syncthing"),
                               ("/usr/bin/NetworkManager", "NetworkManager", "/usr/bin/NetworkManager"),
                               ("/usr/lib/librewolf/librewolf", "librewolf", "/usr/lib/librewolf/librewolf")):
            db.execute("INSERT INTO programs(key, name, hidden, info, first_seen, last_seen) VALUES(?,?,0,?,?,?)",
                       (key, name, json.dumps({"exe": exe, "pid": 1, "user": "u"}), NOW, NOW))
        rows = [("/usr/bin/syncthing", "88.198.1.2", 443, [timer(1800)]),
                ("/usr/bin/NetworkManager", "95.217.163.246", 80, [timer(300)]),
                ("/usr/lib/librewolf/librewolf", "151.101.1.1", 443, [timer(600)])]
        for i, (prog, ip, port, f) in enumerate(rows, 1):
            db.execute("INSERT INTO alerts(fingerprint,program,ip,port,proto,direction,ports,score,peak_score,findings,"
                       "status,first_raised,last_updated) VALUES(?,?,?,?,'tcp','out','[]',75,75,?,'open',?,?)",
                       (f"fp{i}", prog, ip, port, json.dumps(f), NOW - 600, NOW))
        db.commit()

    def test_alert_views_and_fix_panels(self):
        out = self.app.api_alerts({"status": "open"})
        titles = [a["view"]["title"] for a in out["alerts"]]
        for t in titles:
            check_title(t)
        self.assertIn("Syncthing checks in with 88.198.1.2 every ~30 min", titles)
        nm = next(a for a in out["alerts"] if a["program"].endswith("NetworkManager"))
        self.assertEqual(nm["view"]["severity"], "Low")
        self.assertIn("probably NetworkManager's connectivity check", nm["view"]["subtitle"])
        for distro, mgr in (("arch", "pacman"), ("fedora", "rpm"), ("opensuse", "rpm")):
            self.app.os_release_path = str(OSR / distro)
            for a in out["alerts"]:
                f = self.app.api_alert_fix({"id": a["id"]})
                with self.subTest(distro=distro, alert=a["view"]["title"]):
                    self.assertTrue(f["check"] and f["fix"] and f["undo"])
                    self.assertTrue(f["check"][0]["commands"][0]["text"].startswith(mgr))
                    self.assertEqual(f["check"][0]["commands"][0]["tokens"][0]["role"], "pkgmgr")

    def test_allowlist_preview_and_reason(self):
        a = next(x for x in self.app.api_alerts({"status": "open"})["alerts"] if x["program"].endswith("syncthing"))
        pair = {"program": a["program"], "ip": a["ip"], "direction": "out"}
        prev = self.app.api_allowlist_preview({}, json.dumps(pair).encode(), {})
        self.assertEqual([x["id"] for x in prev["alerts"]], [a["id"]])
        wide = self.app.api_allowlist_preview({}, json.dumps(dict(pair, ip="*")).encode(), {})
        self.assertEqual(len(wide["alerts"]), 1)
        from vigil.net.server import BadRequest
        with self.assertRaisesRegex((BadRequest, ValueError), "needs a reason"):  # HTTP 400
            self.app.api_allowlist_add({}, json.dumps(pair).encode(), {})

    def test_fast_poll(self):
        r = self.app.api_monitor_fast({}, b'{"minutes": 10}', {})
        self.assertGreater(r["fast_poll_until"], time.time() + 500)
        self.assertEqual(self.app.api_monitor_fast({}, b'{"minutes": 0}', {})["fast_poll_until"], 0.0)
