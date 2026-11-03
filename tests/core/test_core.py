"""Vigil Core: finding format, wording rules, system facts, evidence store, web kit.
All inputs are SYNTHETIC (fixtures in tests/fixtures, or built here)."""

import http.client
import json
import os
import tempfile
import threading
import unittest
from pathlib import Path

from vigil.core import finding, fixes, system, wording, web
from vigil.core.store import FindingStore

FIX = Path(__file__).parent.parent / "fixtures"
OSR = FIX / "os-release"


def good(**kw):
    args = dict(tool="pkg", check="pipe_to_shell", title="Downloads and runs a script from a pastebin",
                summary="The build downloads a script from pastebin.com and runs it.", severity="High",
                signals=[("curl output piped into sh", 0.9)], likely="Malware or a careless packager.",
                confidence="High", confidence_reason="Running downloaded code is rarely needed.",
                subject="/tmp/x/PKGBUILD", data="PKGBUILD line 12", when=1000.0)
    args.update(kw)
    return finding.make(**args)


class FindingFormatTests(unittest.TestCase):
    def test_valid_finding_has_every_field(self):
        f = good()
        for k in ("id", "tool", "check", "title", "summary", "severity", "signals", "likely", "confidence",
                  "fixes", "evidence", "iocs", "technical", "source", "format"):
            self.assertIn(k, f)
        self.assertEqual(f["source"], {"tool": "pkg", "check": "pipe_to_shell", "data": "PKGBUILD line 12", "when": 1000.0})
        self.assertEqual(f["id"], good(title="Another wording of the same thing").get("id"))  # stable by subject
        self.assertEqual(finding.problems(f), [])

    def test_rules_are_enforced(self):
        cases = {
            "title longer": dict(title="x" * 61),
            "one sentence": dict(summary="Two sentences here. Another one."),
            "severity": dict(severity="Critical"),
            "confidence": dict(confidence="Certain"),
            "signals": dict(signals=[]),
            "uses '%'": dict(title="Uses 100% of the CPU"),
            "IPv6": dict(title="Talks to 2001:db8::5 every hour"),
            "bad indicator": dict(iocs=[{"type": "colour", "value": "red"}]),
        }
        for word, kw in cases.items():
            with self.subTest(word):
                with self.assertRaises(finding.FindingError) as cm:
                    good(**kw)
                self.assertIn(word, str(cm.exception))

    def test_fix_without_undo_is_refused(self):
        osr = system.os_release(str(OSR / "arch"))
        bad = {"title": "Remove it", "what": "x", "risk": "admin", "commands": [fixes.command("sudo pacman -Rns foo")], "undo": []}
        with self.assertRaises(finding.FindingError):
            good(fixes=fixes.panel(osr, fix=[bad]))
        ok = fixes.option("Remove it", "Removes the package.", "admin", ["sudo pacman -Rns foo"], ["sudo pacman -S foo"])
        f = good(fixes=fixes.panel(osr, fix=[ok]))
        self.assertEqual(f["fixes"]["undo"][0]["commands"][0]["text"], "sudo pacman -S foo")

    def test_jsonl_round_trip_and_bad_lines(self):
        fs = [good(), good(subject="/other", severity="Low", signals=[])]
        text = finding.to_jsonl(fs)
        back, skipped = finding.from_jsonl(text + "not json\n" + json.dumps({"title": "x"}) + "\n")
        self.assertEqual(back, fs)
        self.assertEqual([n for n, _ in skipped], [3, 4])
        with self.assertRaises(finding.FindingError):
            finding.from_jsonl(json.dumps({"title": "x"}), strict=True)

    def test_worst_and_sort(self):
        fs = [good(subject="a", severity="Low", signals=[]), good(subject="b")]
        self.assertEqual(finding.worst(fs), "High")
        self.assertEqual([f["severity"] for f in finding.sort(fs)], ["High", "Low"])
        self.assertIsNone(finding.worst([]))


class WordingTests(unittest.TestCase):
    def test_fit_title(self):
        self.assertEqual(wording.fit_title(["x" * 70, "Short one"]), "Short one")
        t = wording.fit_title(["y" * 80])
        self.assertEqual(len(t), 60)
        self.assertTrue(t.endswith("…"))

    def test_title_problems(self):
        self.assertEqual(wording.title_problems("beacon.py checks in with this PC every ~10 s"), [])
        self.assertIn("ends with a full stop", wording.title_problems("Something happened."))
        self.assertTrue(wording.title_problems("High entropy payload"))  # jargon
        self.assertEqual(wording.title_problems("Starts at 10:30 every day"), [])  # a time is not IPv6

    def test_one_sentence(self):
        self.assertTrue(wording.one_sentence("It downloads install.sh from paste.example and runs it."))
        self.assertTrue(wording.one_sentence("The archive expands to 1.5 GB, e.g. from a tiny file."))
        self.assertFalse(wording.one_sentence("No full stop"))
        self.assertFalse(wording.one_sentence("One. Two."))

    def test_friendly_program(self):
        self.assertEqual(wording.friendly_program("/usr/lib/librewolf/librewolf"), "LibreWolf")
        self.assertEqual(wording.friendly_program("/usr/bin/python3", "/usr/bin/python3 /home/a/.cache/upd.py"), "upd.py")
        self.assertEqual(wording.friendly_program("/opt/x/agent (deleted)"), "agent")


class SystemFactsTests(unittest.TestCase):
    def test_distro_families_from_os_release(self):
        want = {"arch": "arch", "fedora": "fedora", "opensuse": "suse", "ubuntu": "debian", "unknown": None}
        for name, fam in want.items():
            with self.subTest(name):
                self.assertEqual(system.family(system.os_release(str(OSR / name))), fam)

    def test_owner_check_commands_per_distro(self):
        cmd = {"arch": "pacman -Qo /usr/bin/x", "fedora": "rpm -qf /usr/bin/x", "opensuse": "rpm -qf /usr/bin/x"}
        for name, text in cmd.items():
            o = fixes.owner_check("/usr/bin/x", system.family(system.os_release(str(OSR / name))))
            self.assertEqual(o["commands"][0]["text"], text)
            self.assertEqual(o["risk"], "safe")
        self.assertEqual(fixes.owner_check("/usr/bin/x", None)["commands"], [])

    def test_package_owner_from_a_fake_pacman_root(self):
        with tempfile.TemporaryDirectory() as root:
            d = Path(root, "var/lib/pacman/local/syncthing-1.27.0-1")
            d.mkdir(parents=True)
            (d / "files").write_text("%FILES%\nusr/\nusr/bin/\nusr/bin/syncthing\n")
            system._owner_cached.cache_clear()
            self.assertEqual(system.package_owner("/usr/bin/syncthing", root=root),
                             {"how": "an Arch package (pacman)", "package": "syncthing-1.27.0-1"})
            self.assertEqual(system.package_owner("/usr/local/bin/x", root=root), {"how": None, "package": None})
        with tempfile.TemporaryDirectory() as root:
            system._owner_cached.cache_clear()
            self.assertIsNone(system.package_owner("/usr/bin/x", root=root))  # no database at all


class StoreTests(unittest.TestCase):
    def test_runs_findings_export_and_baseline(self):
        with tempfile.TemporaryDirectory() as tmp:
            st = FindingStore("pkg", tmp)
            self.addCleanup(st.close)
            r1 = st.add_run("/a", [good(subject="/a")])
            st.add_run("/b", [good(subject="/b", severity="Low", signals=[])])
            st.add_run("/a", [])  # /a re-checked: nothing now
            self.assertEqual(st.run(r1)["findings"][0]["subject"], "/a")
            lines = Path(tmp, "findings.jsonl").read_text().splitlines()
            self.assertEqual([json.loads(x)["subject"] for x in lines], ["/b"])
            self.assertEqual(oct(os.stat(Path(tmp, "findings.jsonl")).st_mode & 0o777), "0o600")
            st.save_baseline("home", {"x": 1})
            self.assertEqual(st.baseline("home")[1], {"x": 1})
            self.assertEqual(st.baseline("none"), (None, None))
            st.set_meta("k", [1, 2])
            self.assertEqual(st.get_meta("k"), [1, 2])


class WebKitTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        Path(self.tmp.name, "index.html").write_text("<title>Tool</title>")

        class App:
            def routes(self):
                return {("GET", "/api/ping"): lambda q: {"pong": q.get("x")},
                        ("POST", "/api/echo"): lambda q, body, h: json.loads(body)}
        self.httpd = web.make_server(App(), 0, static_dirs=[self.tmp.name])
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.addCleanup(self.httpd.server_close)
        self.addCleanup(self.httpd.shutdown)

    def req(self, method, path, body=None, headers=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        c.request(method, path, body=body, headers={"Host": f"127.0.0.1:{self.port}", **(headers or {})})
        r = c.getresponse()
        data = r.read()
        c.close()
        return r.status, data

    def test_binds_loopback_only(self):
        self.assertEqual(self.httpd.server_address[0], "127.0.0.1")

    def test_tool_page_then_shared_kit(self):
        self.assertEqual(self.req("GET", "/"), (200, b"<title>Tool</title>"))
        s, data = self.req("GET", "/static/findings.js")   # from vigil/ui/static
        self.assertEqual(s, 200)
        self.assertIn(b"findingCard", data)
        self.assertEqual(self.req("GET", "/static/style.css")[0], 200)
        for bad in ("/static/../core/web.py", "/static/x/../findings.js", "/static/.hidden.js"):
            self.assertEqual(self.req("GET", bad)[0], 404, bad)

    def test_api_and_write_protection(self):
        self.assertEqual(json.loads(self.req("GET", "/api/ping?x=1")[1]), {"pong": "1"})
        self.assertEqual(self.req("POST", "/api/echo", b"{}")[0], 403)          # no X-Vigil header
        s, data = self.req("POST", "/api/echo", b'{"a": 1}', {"X-Vigil": "1", "Content-Type": "application/json"})
        self.assertEqual((s, json.loads(data)), (200, {"a": 1}))
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        c.request("GET", "/api/ping", headers={"Host": "evil.example"})
        self.assertEqual(c.getresponse().status, 403)                           # DNS rebinding
        c.close()


if __name__ == "__main__":
    unittest.main()
