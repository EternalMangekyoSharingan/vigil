"""Second opinions: ClamAV and hash lookups. Everything here is SYNTHETIC: a stand-in
ClamAV script written at test time, and canned VirusTotal / MalwareBazaar answers.
No real network request is made and no real ClamAV is needed."""

import json
import os
import stat
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest import mock

from vigil import engines, inspector

MARKER = b"VIGIL-SYNTHETIC-CLAM-MARKER"
SHA = "a" * 64


def fake_clam(tmp, name, mode="scan"):
    """A stand-in ClamAV binary: flags input containing MARKER, like clamscan's output format."""
    path = Path(tmp) / name
    body = {
        "scan": f'''
            import sys
            if "--version" in sys.argv:
                print("ClamAV 1.0.7/27445/Wed Oct 30 08:35:00 2024"); sys.exit(0)
            assert sys.argv[-1] == "-", sys.argv
            data = sys.stdin.buffer.read()
            if {MARKER!r} in data:
                print("stdin: Vigil.Synthetic.Test-1 FOUND"); sys.exit(1)
            print("stdin: OK"); sys.exit(0)
        ''',
        "nodaemon": '''
            import sys
            print("ERROR: Could not connect to clamd on LocalSocket /run/clamav/clamd.ctl"); sys.exit(2)
        ''',
    }[mode]
    path.write_text(f"#!{os.sys.executable}\n" + textwrap.dedent(body))
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return str(path)


class ClamAVTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def which(self, available):
        return lambda tool: available.get(tool)

    def test_stdin_scan_flags_and_passes(self):
        clamd = fake_clam(self.tmp.name, "clamdscan")
        which = self.which({"clamdscan": clamd})
        hit = engines.clamav_scan(b"xx" + MARKER + b"yy", which=which)
        self.assertEqual((hit["status"], hit["signatures"], hit["tool"]), ("flagged", ["Vigil.Synthetic.Test-1"], "clamdscan"))
        self.assertEqual(engines.clamav_scan(b"plain bytes", which=which)["status"], "nothing")

    def test_falls_back_to_clamscan_with_limits(self):
        clamd = fake_clam(self.tmp.name, "clamdscan", "nodaemon")
        clam = fake_clam(self.tmp.name, "clamscan")
        seen = []
        real_run = engines.subprocess.run

        def run(args, **kw):
            seen.append(args)
            return real_run(args, **kw)
        r = engines.clamav_scan(MARKER, runner=run, which=self.which({"clamdscan": clamd, "clamscan": clam}))
        self.assertEqual((r["status"], r["tool"]), ("flagged", "clamscan"))
        self.assertIn("--max-scansize=400M", seen[1])
        self.assertIn("--max-recursion=16", seen[1])

    def test_not_installed(self):
        self.assertEqual(engines.clamav_scan(b"x", which=lambda t: None)["status"], "unavailable")
        r = inspector.inspect_bytes(b"hello\n", "a.txt")
        inspector.run_clamav(r, b"hello\n", scan=lambda d: {"status": "unavailable", "reason": "ClamAV is not installed"})
        row = {a["id"]: a for a in r["analyzers"]}["clamav"]
        self.assertEqual((row["status"], row["label"]), ("skipped", "Not run: ClamAV is not installed"))
        self.assertTrue(any("ClamAV is not installed" in l for l in r["limits"]))

    def test_detection_scores_and_records_its_source(self):
        version = lambda: {"engine": "1.0.7", "db_version": "27445", "db_date": "Wed Oct 30 2024"}
        r = inspector.inspect_bytes(b"hello\n", "a.txt")
        inspector.run_clamav(r, b"", scan=lambda d: {"status": "flagged", "tool": "clamdscan",
                                                     "signatures": ["Win.Trojan.Synthetic-1"]}, version=version)
        f = next(f for f in r["findings"] if f["check"] == "antivirus")
        self.assertEqual(f["points"], 70)
        self.assertIn("signatures 27445", f["data"])
        self.assertEqual(r["verdict"], "Likely malicious")
        self.assertEqual({a["id"]: a for a in r["analyzers"]}["clamav"]["status"], "flagged")
        r2 = inspector.inspect_bytes(b"hello\n", "b.txt")
        inspector.run_clamav(r2, b"", scan=lambda d: {"status": "flagged", "tool": "clamscan",
                                                      "signatures": ["PUA.Win.Tool.Synthetic"]}, version=version)
        self.assertEqual(r2["score"], 25)


VT_OK = {"data": {"attributes": {
    "last_analysis_stats": {"malicious": 2, "suspicious": 0, "undetected": 56, "harmless": 0, "type-unsupported": 14},
    "last_analysis_results": {
        "EngineA": {"engine_name": "EngineA", "category": "undetected", "result": None},
        "EngineB": {"engine_name": "EngineB", "category": "malicious", "result": "Synthetic.ArchBomb"},
        "EngineC": {"engine_name": "EngineC", "category": "malicious", "result": "Synthetic.MailBomb"},
    },
    "popular_threat_classification": {"suggested_threat_label": "trojan.archbomb/mailbomb",
                                      "popular_threat_category": [{"value": "trojan", "count": 1}],
                                      "popular_threat_name": [{"value": "archbomb", "count": 1}]},
    "last_analysis_date": 1761800000, "first_submission_date": 1700000000,
    "tags": ["zip"], "names": ["32-256-zipped.zip"], "type_description": "ZIP", "reputation": -1}}}


class LookupTests(unittest.TestCase):
    def test_virustotal_parse(self):
        calls = []

        def req(url, headers=None, data=None):
            calls.append((url, headers, data))
            return 200, VT_OK
        r = engines.virustotal(SHA, "k" * 64, requester=req)
        self.assertEqual(calls[0][0], f"https://www.virustotal.com/api/v3/files/{SHA}")
        self.assertEqual(calls[0][1], {"x-apikey": "k" * 64})
        self.assertIsNone(calls[0][2])  # a GET: only the hash (in the URL) and the key leave
        self.assertEqual((r["malicious"], r["engines"]), (2, 58))
        self.assertEqual(r["results"][0]["category"], "malicious")  # detections first
        self.assertEqual(r["label"], "trojan.archbomb/mailbomb")

    def test_virustotal_errors(self):
        self.assertFalse(engines.virustotal(SHA, "k", requester=lambda *a, **k: (404, None))["found"])
        with self.assertRaisesRegex(engines.LookupError_, "4 lookups a minute"):
            engines.virustotal(SHA, "k", requester=lambda *a, **k: (429, None))
        with self.assertRaisesRegex(engines.LookupError_, "no VirusTotal API key"):
            engines.virustotal(SHA, None)
        with self.assertRaisesRegex(engines.LookupError_, "not a SHA-256"):
            engines.virustotal("../../etc", "k")

    def test_malwarebazaar(self):
        def req(url, headers=None, data=None):
            self.assertEqual(data, {"query": "get_info", "hash": SHA})
            self.assertEqual(headers, {"Auth-Key": "m" * 48})
            return 200, {"query_status": "ok", "data": [{"signature": "SyntheticFamily", "tags": ["zip"],
                                                         "file_type": "zip", "first_seen": "2024-01-01"}]}
        r = engines.malwarebazaar(SHA, "m" * 48, requester=req)
        self.assertEqual(r["signature"], "SyntheticFamily")
        nf = engines.malwarebazaar(SHA, "m", requester=lambda *a, **k: (200, {"query_status": "hash_not_found"}))
        self.assertFalse(nf["found"])

    def test_apply_lookup_scores_and_replaces(self):
        r = inspector.inspect_bytes(b"hello\n", "a.txt")
        inspector.apply_lookup(r, "virustotal", engines.virustotal(SHA, "k", requester=lambda *a, **k: (200, VT_OK)))
        f = [f for f in r["findings"] if f["check"] == "virustotal"]
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["points"], 30)
        self.assertIn("2 of 58 VirusTotal engines detect it (trojan.archbomb/mailbomb)", f[0]["reason"])
        clean = json.loads(json.dumps(VT_OK))
        clean["data"]["attributes"]["last_analysis_stats"]["malicious"] = 0
        inspector.apply_lookup(r, "virustotal", engines.virustotal(SHA, "k", requester=lambda *a, **k: (200, clean)))
        f = [f for f in r["findings"] if f["check"] == "virustotal"]
        self.assertEqual((len(f), f[0]["points"]), (1, 0))  # replaced, not added
        self.assertNotRegex(json.dumps(r).lower(), r"\bsafe\b|\bclean\b")


class BombGateTests(unittest.TestCase):
    def test_a_bomb_is_never_handed_to_clamav(self):
        from .test_archives import SMALL, deflate, raw_zip, MB

        def scan(data):
            raise AssertionError("ClamAV must not see an archive bomb")
        with SMALL:
            block = deflate(b"\0" * (8 * MB))
            r = inspector.inspect_bytes(raw_zip([(f"f/{i}", 0, 2) for i in range(12)], [("f/0", block, 8 * MB)]), "b.zip")
        inspector.run_clamav(r, b"", scan=scan)
        self.assertEqual(r["engines"]["clamav"]["status"], "skipped")
        row = {a["id"]: a for a in r["analyzers"]}["clamav"]
        self.assertEqual(row["label"], "Not run: Vigil found an archive bomb, and ClamAV would try to unpack it")

    def test_large_expansion_is_not_scanned_either(self):
        r = inspector.inspect_bytes(b"hello\n", "a.txt")
        r["details"]["expansion"] = {"estimated": 3 << 30, "lower_bound": False}
        self.assertFalse(inspector.clamav_plan(r, available=lambda: True))
        self.assertIn("over 1 GB", r["engines"]["clamav"]["reason"])


class ServerLookupTests(unittest.TestCase):
    def setUp(self):
        from vigil import server
        from .helpers import make_proc
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.app = server.App(f"{self.tmp.name}/data", interval=60, proc_root=make_proc(self.tmp.name),
                              start_monitor=False)
        self.addCleanup(self.app.store.close)

    def test_keys_are_stored_privately_and_never_returned(self):
        out = self.app.api_keys_set({}, json.dumps({"service": "virustotal", "key": "f" * 64}).encode(), {})
        self.assertIs(out["virustotal"], True)
        self.assertNotIn("f" * 64, json.dumps(out))
        path = Path(self.tmp.name) / "data" / "settings.json"
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(json.loads(path.read_text())["virustotal_api_key"], "f" * 64)
        from vigil.server import BadRequest
        with self.assertRaises(BadRequest):
            self.app.api_keys_set({}, json.dumps({"service": "virustotal", "key": "x y"}).encode(), {})
        self.app.api_keys_set({}, json.dumps({"service": "virustotal", "key": ""}).encode(), {})
        self.assertNotIn("virustotal_api_key", json.loads(path.read_text()))

    def test_lookup_runs_only_on_request_and_updates_the_report(self):
        with mock.patch.dict(os.environ, {"VIGIL_VT_KEY": "k" * 64}), \
                mock.patch.object(engines.enrich, "http") as http, \
                mock.patch.object(engines, "clamav_scan", return_value={"status": "unavailable", "reason": "x"}):
            report = self.app.api_inspect({}, b"hello\n", {"X-Filename": "a.txt"})
            http.assert_not_called()  # an upload makes no network request
            http.return_value = (200, json.dumps(VT_OK).encode())
            out = self.app.api_inspection_lookup({}, json.dumps({"id": report["id"], "service": "virustotal"}).encode(), {})
            url = http.call_args[0][0]
            self.assertEqual(url, f"https://www.virustotal.com/api/v3/files/{report['hashes']['sha256']}")
            self.assertIsNone(http.call_args[1]["data"])
        self.assertEqual(out["lookups"]["virustotal"]["malicious"], 2)
        saved = self.app.api_inspection({"id": report["id"]})
        self.assertEqual(saved["score"], out["score"])
        row = self.app.store.one("SELECT score FROM inspections WHERE id=?", (report["id"],))
        self.assertEqual(row["score"], out["score"])


    def test_clamav_runs_after_the_upload_returns(self):
        import threading
        release = threading.Event()

        def slow_scan(data):
            release.wait(5)
            return {"status": "flagged", "tool": "clamdscan", "signatures": ["Win.Trojan.Synthetic-1"]}
        with mock.patch.object(engines, "clamav_available", return_value=True), \
                mock.patch.object(engines, "clamav_scan", side_effect=slow_scan), \
                mock.patch.object(engines, "clamav_version", return_value={"engine": "1.0.7"}), \
                mock.patch.object(inspector.engines, "clamav_available", return_value=True):
            report = self.app.api_inspect({}, b"hello\n", {"X-Filename": "a.txt"})
            self.assertEqual(report["engines"]["clamav"]["status"], "pending")  # returned before the scan
            self.assertEqual({a["id"]: a for a in report["analyzers"]}["clamav"]["label"], "Scanning…")
            release.set()
            for t in self.app.clamav_threads:
                t.join(5)
        saved = self.app.api_inspection({"id": report["id"]})
        self.assertEqual(saved["engines"]["clamav"]["status"], "flagged")
        self.assertEqual(saved["verdict"], "Likely malicious")


if __name__ == "__main__":
    unittest.main()
