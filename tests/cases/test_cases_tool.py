"""Vigil Cases: import from every tool, one timeline, notes, CSV / STIX 2.1 / Markdown.
All findings are SYNTHETIC: made here with core.finding, produced by the other tools
from their synthetic fixtures, or Network Map alerts written into a fresh store."""

import csv
import io
import json
import re
import shutil
import tempfile
import time
import unittest
from pathlib import Path

from vigil.cases import export, importer
from vigil.cases.server import App
from vigil.cases.store import CaseError, CaseStore
from vigil.core import finding, fixes
from vigil.core.web import BadRequest

FIX = Path(__file__).parent.parent / "fixtures"
ARCH = {"ID": "arch", "PRETTY_NAME": "Arch Linux"}
STIX_ID = re.compile(r"^[a-z][a-z0-9-]+--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
STIX_TS = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$")


def f(tool, check, title, sev="High", when=1000.0, subject=None, iocs=(), summary=None, cmds=()):
    panel = fixes.panel(ARCH, check=[fixes.option("Look", "Read it.", "safe", list(cmds))]) if cmds else None
    return finding.make(tool, check, title, summary or f"{title}.", sev,
                        signals=[(f"{check} signal", 0.8)] if sev in ("High", "Medium") else [],
                        confidence="High", confidence_reason="Synthetic.", subject=subject or title,
                        iocs=iocs, when=when, data="synthetic", fixes=panel)


def write(root, tool, findings, extra=""):
    d = Path(root, tool)
    d.mkdir(parents=True, exist_ok=True)
    (d / "findings.jsonl").write_text(finding.to_jsonl(findings) + extra)


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.store = CaseStore(self.root / "cases")
        self.addCleanup(self.store.close)
        write(self.root, "pkg", [f("pkg", "source_pastebin", "Downloads part of the build from a pastebin", when=1000,
                                   iocs=[{"type": "url", "value": "https://pastebin.com/raw/Vg1lT3st"}])])
        write(self.root, "files", [f("files", "archive_ratio", "Archive expands far more than normal files do", when=2000,
                                     iocs=[{"type": "sha256", "value": "a" * 64}])],
              extra="this line is not JSON\n" + json.dumps({"title": "missing everything"}) + "\n")
        write(self.root, "persist", [f("persist", "content", "updater.service starts a program from a temp folder",
                                       sev="Medium", when=3000)])
        write(self.root, "tasks", [f("tasks", "odd_parent", "firefox started bash", when=4000,
                                     iocs=[{"type": "ipv4", "value": "198.51.100.9"}])])

    def test_import_all_tools_skips_bad_lines_and_is_idempotent(self):
        res = {r["source"]: r for r in importer.import_all(self.store, self.root, refresh_net=False)}
        self.assertEqual({k: v["added"] for k, v in res.items()}, {"pkg": 1, "files": 1, "persist": 1, "tasks": 1})
        self.assertEqual(res["files"]["skipped"], 2)
        again = importer.import_all(self.store, self.root, refresh_net=False)
        self.assertEqual(sum(r["added"] + r["updated"] for r in again), 0)
        later = f("tasks", "odd_parent", "firefox started bash", when=9000, iocs=[{"type": "ipv4", "value": "198.51.100.9"}])
        importer.import_text(self.store, finding.to_jsonl([later]), "tasks")
        row = self.store.finding(f"tasks:{later['id']}")
        self.assertEqual((row["first_seen"], row["last_seen"], row["times"]), (4000, 9000, 2))

    def test_one_timeline_with_filters_notes_and_case_events(self):
        importer.import_all(self.store, self.root, refresh_net=False)
        t = self.store.timeline()
        self.assertEqual([e["tool"] for e in t if e["kind"] == "finding"], ["tasks", "persist", "files", "pkg"])
        self.assertEqual({e["tool"] for e in self.store.timeline(tool="files")}, {"files"})
        self.assertEqual({e["severity"] for e in self.store.timeline(severity="Medium")}, {"Medium"})
        c = self.store.create("Odd evening", tags=["Browser", "browser", "x y"], now=5000)
        self.assertEqual(c["tags"], ["browser", "x-y"])
        key = next(e["key"] for e in t if e.get("tool") == "tasks")
        self.store.attach(c["id"], key, now=5100)
        self.store.attach(c["id"], key, now=5200)                       # twice: once
        self.store.note("Checked: it was me testing.", case_id=c["id"], now=5300)
        self.store.note("Firefox was updated that day.", finding_key=key, now=5400)
        self.store.update(c["id"], status="investigating", now=5500)
        ct = self.store.timeline(case_id=c["id"])
        kinds = [(e["kind"], e.get("text") or e.get("title")) for e in ct]
        self.assertEqual(kinds[0], ("case", "Status: open → investigating"))
        self.assertIn(("note", "Checked: it was me testing."), kinds)
        self.assertIn(("note", "Firefox was updated that day."), kinds)
        self.assertIn(("finding", "firefox started bash"), kinds)
        self.assertEqual(sum(1 for k in kinds if k[1] and k[1].startswith("Added finding")), 1)
        self.assertNotIn("pkg", {e.get("tool") for e in ct})
        self.store.detach(c["id"], key)
        self.assertEqual(self.store.case(c["id"])["findings"], [])

    def test_refusals(self):
        with self.assertRaises(CaseError):
            self.store.create("  ")
        c = self.store.create("x")
        with self.assertRaises(CaseError):
            self.store.update(c["id"], status="solved")
        with self.assertRaises(CaseError):
            self.store.note("", case_id=c["id"])
        with self.assertRaises(CaseError):
            self.store.note("orphan")
        with self.assertRaises(LookupError):
            self.store.attach(c["id"], "pkg:nope")


class ExportTests(StoreTests):
    def findings(self):
        importer.import_all(self.store, self.root, refresh_net=False)
        evil = f("files", "inspector_disguise", "File name hides what the file really is", when=4500,
                 summary="It is called =HYPERLINK(\"http://203.0.113.5\") and **bold** <b>html</b>.",
                 iocs=[{"type": "domain", "value": "evil.example.org"}, {"type": "url", "value": "http://203.0.113.5/x.exe"}],
                 cmds=["file -- '/home/a/=cmd|x'", "echo ```weird```"])
        importer.import_text(self.store, finding.to_jsonl([evil]), "files")
        return self.store.findings()

    def test_csv_indicators_and_findings(self):
        fs = self.findings()
        rows = list(csv.DictReader(io.StringIO(export.csv_indicators(fs))))
        self.assertEqual({(r["type"], r["value"]) for r in rows},
                         {("url", "https://pastebin.com/raw/Vg1lT3st"), ("sha256", "a" * 64), ("ipv4", "198.51.100.9"),
                          ("domain", "evil.example.org"), ("url", "http://203.0.113.5/x.exe")})
        self.assertTrue(all(STIX_TS.match(r["first_seen_utc"]) for r in rows))
        frows = list(csv.DictReader(io.StringIO(export.csv_findings(fs))))
        self.assertEqual(len(frows), 5)
        disguise = next(r for r in frows if r["check"] == "inspector_disguise")
        self.assertTrue(disguise["summary"].startswith("It is called"))
        for r in frows:                       # nothing a spreadsheet would run as a formula
            for v in r.values():
                self.assertFalse(v[:1] in ("=", "+", "-", "@"), v)

    def test_stix_bundle_is_well_formed(self):
        fs = self.findings()
        c = self.store.create("Case for STIX", tags=["aur"])
        for x in fs:
            self.store.attach(c["id"], x["key"])
        self.store.note("Analyst note.", case_id=c["id"])
        case = self.store.case(c["id"])
        b = export.stix(case, case["findings"])
        self.assertEqual(b["type"], "bundle")
        self.assertTrue(STIX_ID.match(b["id"]))
        ids = {o["id"] for o in b["objects"]}
        self.assertEqual(len(ids), len(b["objects"]))
        types = [o["type"] for o in b["objects"]]
        self.assertEqual(types.count("indicator"), 5)
        self.assertEqual(types.count("note"), 6)            # 5 findings + 1 analyst note
        self.assertEqual(types.count("grouping"), 1)
        required = {"identity": ("name", "identity_class"), "indicator": ("pattern", "pattern_type", "valid_from"),
                    "note": ("content", "object_refs"), "grouping": ("context", "object_refs"),
                    "attack-pattern": ("name", "external_references")}
        for o in b["objects"]:
            self.assertEqual(o["spec_version"], "2.1")
            self.assertTrue(STIX_ID.match(o["id"]) and o["id"].startswith(o["type"] + "--"), o["id"])
            for k in ("created", "modified"):
                self.assertTrue(STIX_TS.match(o[k]), o[k])
            for k in required[o["type"]]:
                self.assertIn(k, o)
            for ref in o.get("object_refs", []) + ([o["created_by_ref"]] if "created_by_ref" in o else []):
                self.assertIn(ref, ids)
            if o["type"] == "attack-pattern":
                ref = o["external_references"][0]
                self.assertEqual(ref["source_name"], "mitre-attack")
                self.assertRegex(ref["external_id"], r"^T\d{4}(\.\d{3})?$")
            if o["type"] == "indicator":
                self.assertRegex(o["pattern"], r"^\[[a-z0-9-]+:[a-z.'A-Z0-9-]+ = '.+'\]$")
        pats = {o["pattern"] for o in b["objects"] if o["type"] == "indicator"}
        self.assertIn("[ipv4-addr:value = '198.51.100.9']", pats)
        self.assertIn("[file:hashes.'SHA-256' = '" + "a" * 64 + "']", pats)
        self.assertEqual(export.stix(case, case["findings"], now=1)["objects"][-1]["id"], b["objects"][-1]["id"])  # stable

    def test_markdown_report_is_defanged_and_escaped(self):
        fs = self.findings()
        c = self.store.create("Report <script>", summary="We looked at **everything**.")
        for x in fs:
            self.store.attach(c["id"], x["key"])
        self.store.note("See http://203.0.113.5 for the sample.", case_id=c["id"])
        case = self.store.case(c["id"])
        text = export.markdown(case, case["findings"], self.store.timeline(case["id"]))
        self.assertIn("# Report \\<script\\>", text)
        for sev in ("## Timeline", "## Findings", "## Indicators (defanged)", "## Notes", "## Limits"):
            self.assertIn(sev, text)
        prose = re.sub(r"(`{3,})sh\n.*?\n\1", "", text, flags=re.S)     # outside code blocks
        self.assertNotRegex(prose, r"(?i)\bhttps?://")
        self.assertIn("hxxp[://]203.0.113.5", text)
        self.assertIn("evil.example\\[.\\]org", text)            # renders as evil.example[.]org
        self.assertIn("````sh\nfile -- '/home/a/=cmd|x'\necho ```weird```\n````", text)   # fence longer than content
        self.assertIn("\\*\\*bold\\*\\*", text)


class NetExportTests(unittest.TestCase):
    def test_network_map_alerts_become_findings(self):
        from vigil.net import export as net_export
        from vigil.net import server
        from ..net.test_alert_wording import timer, NOW
        from ..helpers import make_proc
        with tempfile.TemporaryDirectory() as tmp:
            app = server.App(f"{tmp}/data", interval=60, proc_root=make_proc(tmp), start_monitor=False)
            db = app.store.db
            db.execute("INSERT INTO programs(key, name, hidden, info, first_seen, last_seen) VALUES(?,?,0,?,?,?)",
                       ("/usr/bin/syncthing", "syncthing", json.dumps({"exe": "/usr/bin/syncthing", "pid": 1, "user": "u"}), NOW, NOW))
            db.execute("INSERT INTO alerts(fingerprint,program,ip,port,proto,direction,ports,score,peak_score,findings,"
                       "status,first_raised,last_updated) VALUES('fp1','/usr/bin/syncthing','88.198.1.2',443,'tcp','out',"
                       "'[]',75,75,?,'open',?,?)", (json.dumps([timer(1800)]), NOW - 600, NOW))
            db.commit()
            app.store.close()
            path, n, skipped = net_export.export(f"{tmp}/data")
            self.assertEqual((n, skipped), (1, 0))
            fs, bad = finding.from_jsonl(Path(path).read_text())
            self.assertEqual(bad, [])
            x = fs[0]
            self.assertEqual((x["tool"], x["check"], x["subject"]), ("net", "alert", "fp1"))
            self.assertIn("Syncthing", x["title"])
            self.assertIn({"type": "ipv4", "value": "88.198.1.2"}, x["iocs"])
            self.assertTrue(x["fixes"]["check"])
            st = CaseStore(f"{tmp}/data/cases")
            res = importer.import_all(st, f"{tmp}/data")
            self.assertEqual(res[0]["exported"], 1)
            self.assertEqual([e["tool"] for e in st.timeline()], ["net"])
            st.close()
        with tempfile.TemporaryDirectory() as tmp:
            self.assertIsNone(net_export.export(tmp))                 # never ran: nothing created
            self.assertEqual(list(Path(tmp).iterdir()), [])


class EndToEndTests(unittest.TestCase):
    def test_findings_from_the_real_tools(self):
        """Pkg, Files, Persist and Tasks run on their own synthetic fixtures, then Cases imports."""
        from vigil.pkg import review
        from vigil.files.server import App as FilesApp
        from vigil.persist.server import App as PersistApp
        from vigil.tasks.server import App as TasksApp
        from ..persist.test_persist import Fake
        from ..tasks.test_tasks import world, FakeRoot
        from ..files.test_archives import raw_zip, deflate
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp, "data")
            st = review.open_store(root / "pkg")
            review.review_folder(str(FIX / "pkg/squat"), store=st, osr=ARCH)
            st.close()
            fa = FilesApp(root / "files")
            z = Path(tmp, "x.zip")
            z.write_bytes(raw_zip([("../a", 0, 1)], [("../a", deflate(b"a"), 1)]))
            fa.inspect(str(z))
            fa.close()
            fake = Fake(tmp)
            pa = PersistApp(root / "persist", home=str(fake.home), root=str(fake.root), proc=str(fake.proc),
                            os_release_path=str(FIX / "os-release/arch"))
            pa.scan()
            fake.h(".config/systemd/user/u.service", "[Service]\nExecStart=/tmp/u\n")
            pa.scan()
            pa.close()
            tmp2 = Path(tmp, "t")
            tmp2.mkdir()
            ta = TasksApp(root / "tasks", proc_root=str(world(str(tmp2)).root), root=str(FakeRoot(str(tmp2)).root),
                          os_release_path=str(FIX / "os-release/arch"))
            ta.api_scan({}, b"{}", {})
            ta.close()
            app = App(root / "cases", root)
            self.addCleanup(app.close)
            post = lambda r, d: app.routes()[("POST", r)]({}, json.dumps(d).encode(), {})
            get = lambda r, q=None: app.routes()[("GET", r)](q or {})
            res = post("/api/import", {})["results"]
            self.assertEqual({r["source"] for r in res if "added" in r}, {"pkg", "files", "persist", "tasks"})
            self.assertTrue(all(r["skipped"] == 0 for r in res if "skipped" in r))
            ev = get("/api/timeline")["events"]
            self.assertEqual({e["tool"] for e in ev}, {"pkg", "files", "persist", "tasks"})
            c = post("/api/cases", {"title": "Everything at once"})
            for e in ev:
                post("/api/case/attach", {"id": c["id"], "key": e["key"]})
            post("/api/note", {"case": c["id"], "text": "All synthetic."})
            for fmt_, ctype in (("md", "text/markdown"), ("stix", "application/stix+json"), ("csv", "text/csv"),
                                ("csv-findings", "text/csv")):
                data, got_type, headers = get("/api/export", {"case": str(c["id"]), "format": fmt_})
                self.assertTrue(got_type.startswith(ctype))
                self.assertIn("attachment;", headers["Content-Disposition"])
                self.assertTrue(data)
            with self.assertRaises(BadRequest):
                get("/api/export", {"format": "pdf"})
            with self.assertRaises(BadRequest):
                post("/api/cases", {"title": ""})
            from vigil.cases.server import make_server
            from ..helpers import page_check
            page_check(self, make_server, app, [("/", b"<title>Vigil Cases</title>"), ("/static/cases-app.js", b"timeline")])


if __name__ == "__main__":
    unittest.main()
