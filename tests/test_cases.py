"""Cases and exports. All evidence here is SYNTHETIC (built by the tests)."""

import csv
import hashlib
import io
import json
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

from vigil import cases as cases_mod, inspector
from vigil.cases import CaseError, Cases
from vigil.enrich import Enricher
from vigil.scoring import Allowlist, Scorer
from vigil.store import Store, Tracker
from . import synth
from .helpers import FIXTURES, proc, sock, snap

AGENT = "/tmp/.x/agent"
STIX_TS = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$")
STIX_ID = re.compile(r"^([a-z0-9-]+)--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def validate_stix(bundle):
    """Structural STIX 2.1 checks: ids, timestamps, required properties, references."""
    assert bundle["type"] == "bundle" and STIX_ID.match(bundle["id"]), bundle["id"]
    ids = {o["id"] for o in bundle["objects"]}
    assert len(ids) == len(bundle["objects"]), "duplicate ids"
    required = {"indicator": {"pattern", "pattern_type", "valid_from"},
                "grouping": {"context", "object_refs"}, "note": {"content", "object_refs"},
                "identity": {"name"}}
    for o in bundle["objects"]:
        m = STIX_ID.match(o["id"])
        assert m and m.group(1) == o["type"], o["id"]
        assert o["spec_version"] == "2.1"
        for k in ("created", "modified"):
            assert STIX_TS.match(o[k]), (k, o[k])
        missing = required[o["type"]] - set(o)
        assert not missing, (o["type"], missing)
        if o["type"] == "indicator":
            assert re.match(r"^\[[a-z0-9-]+:[a-zA-Z0-9_.'-]+ = '.*'\]$", o["pattern"]), o["pattern"]
            assert STIX_TS.match(o["valid_from"])
            assert o.get("labels", ["x"]), "labels must not be empty when present"
        for ref in o.get("object_refs", []) + ([o["created_by_ref"]] if "created_by_ref" in o else []):
            assert ref in ids, f"dangling reference {ref}"


class CasesTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(os.path.join(self.tmp.name, "v.db"))
        self.tracker = Tracker(self.store)
        self.enricher = Enricher(self.store, self.tmp.name)
        self.cases = Cases(self.store, self.tracker, self.enricher)

    def tearDown(self):
        self.enricher._close_geo()
        self.store.close()
        self.tmp.cleanup()

    def make_alert(self):
        """A dropper beaconing to a Feodo-listed address, through tracker and scorer."""
        self.enricher.import_feed("feodo", (FIXTURES / "feeds/feodo-ipblocklist.json").read_bytes(),
                                  "fixture")
        agent = dict(proc(7000, AGENT, "agent"), exe=AGENT)
        self.tracker.ingest(snap(0, [], []))
        for i in range(8):
            t = 1000 + 60 * i
            s = sock("198.51.100.20", 4444, 5000 + i, AGENT, 7000, local_port=41000 + i)
            self.tracker.ingest(snap(t, [s], [agent]))
            self.tracker.ingest(snap(t + 2, [], [agent]))
        scorer = Scorer(self.store, Allowlist(os.path.join(self.tmp.name, "a.json")), 2)
        scorer.extra.append(self.enricher)
        scorer.run(now=1600)
        return self.store.one("SELECT * FROM alerts")


class LifecycleTests(CasesTestBase):
    def test_create_update_note_log(self):
        c = self.cases.create("Beacon from /tmp agent", tags="C2, linux, c2", summary="", now=10)
        self.assertEqual((c["status"], c["tags"]), ("open", ["c2", "linux"]))
        c = self.cases.update(c["id"], status="investigating", tags=["c2"], summary="Seen at 13:02",
                              now=20)
        c = self.cases.note(c["id"], "Asked the user; nobody installed this.", now=30)
        c = self.cases.update(c["id"], status="closed", now=40)
        self.assertEqual(c["closed_at"], 40)
        self.assertEqual([e["kind"] for e in c["log"]],
                         ["created", "change", "change", "change", "note", "change"])
        self.assertIn("Status open → investigating", [e["text"] for e in c["log"]])
        self.assertEqual(self.cases.list()[0]["status"], "closed")

    def test_validation(self):
        with self.assertRaises(CaseError):
            self.cases.create("  ")
        c = self.cases.create("x")
        with self.assertRaises(CaseError):
            self.cases.update(c["id"], status="done")
        with self.assertRaises(CaseError):
            self.cases.note(c["id"], "")
        with self.assertRaises(LookupError):
            self.cases.get(999)
        for typ, value in (("ip", "1.2.3"), ("url", "javascript:alert(1)"), ("sha256", "abc"),
                           ("domain", "no_tld"), ("bitcoin", "1abc")):
            with self.subTest(typ=typ), self.assertRaises(CaseError):
                self.cases.add_ioc(c["id"], typ, value)


class EvidenceTests(CasesTestBase):
    def test_alert_snapshot_and_indicator(self):
        alert = self.make_alert()
        c = self.cases.create("C2")
        c = self.cases.add_item(c["id"], "alert", alert["id"], now=2000)
        item = c["items"][0]
        self.assertTrue(item["title"].startswith(f"Alert #{alert['id']}: agent → 198.51.100.20"))
        self.assertEqual(item["snapshot"]["enrichment"]["intel"][0]["label"], "SyntheticBot")
        ioc = c["iocs"][0]
        self.assertEqual((ioc["type"], ioc["value"], ioc["malicious"]), ("ipv4", "198.51.100.20", 1))
        self.assertIn("alert #", ioc["context"])
        with self.assertRaises(CaseError):  # no duplicates
            self.cases.add_item(c["id"], "alert", alert["id"])
        # The case keeps its evidence after the source rows are gone.
        self.store.prune(now=10**10, keep_days=1)
        with self.store.lock, self.store.db:
            self.store.db.execute("DELETE FROM alerts")
        again = self.cases.get(c["id"])
        self.assertEqual(again["items"][0]["snapshot"]["alert"]["score"], alert["score"])

    def test_inspection_program_destination(self):
        self.make_alert()
        report = inspector.save(self.store, inspector.inspect_bytes(synth.docm_dropper(), "inv.docm"),
                                "test")
        benign = inspector.save(self.store, inspector.inspect_bytes(
            (FIXTURES / "files/benign.docx").read_bytes(), "newsletter.docx"), "test")
        c = self.cases.create("Phish")
        c = self.cases.add_item(c["id"], "inspection", report["id"])
        c = self.cases.add_item(c["id"], "inspection", benign["id"])
        c = self.cases.add_item(c["id"], "program", AGENT)
        c = self.cases.add_item(c["id"], "destination", "198.51.100.20")
        kinds = {(i["type"], i["value"]): i for i in c["iocs"]}
        self.assertEqual(kinds[("sha256", report["hashes"]["sha256"])]["malicious"], 1)
        self.assertEqual(kinds[("sha256", benign["hashes"]["sha256"])]["malicious"], 0)
        self.assertIn(("url", "http://198.51.100.20/stage2.ps1"), kinds)
        # Same address from the program and the destination: one indicator, merged context.
        ip = kinds[("ipv4", "198.51.100.20")]
        self.assertIn("contacted by agent", ip["context"])
        self.assertIn("destination contacted by agent", ip["context"])
        prog = [i for i in c["items"] if i["kind"] == "program"][0]
        self.assertIn("Could not read /proc/7000/exe", prog["snapshot"]["executable"]["note"])

        removed = self.cases.remove_item(c["id"], c["items"][0]["id"])
        self.assertNotIn(("url", "http://198.51.100.20/stage2.ps1"),
                         {(i["type"], i["value"]) for i in removed["iocs"]})

    def test_live_executable_hash(self):
        # Our own process: /proc/self's exe is readable, so its executable gets hashed.
        me = proc(os.getpid(), sys.executable, "python")
        self.tracker.ingest(snap(0, [sock("127.0.0.1", 9, 1, sys.executable, os.getpid(),
                                          local_ip="127.0.0.1")], [me]))
        c = self.cases.add_item(self.cases.create("me")["id"], "program", sys.executable)
        exe = c["items"][0]["snapshot"]["executable"]
        want = hashlib.sha256(Path(os.path.realpath(sys.executable)).read_bytes()).hexdigest()
        self.assertEqual(exe["sha256"], want)
        self.assertIn(("sha256", want), {(i["type"], i["value"]) for i in c["iocs"]})

    def test_manual_indicators_and_exclusion(self):
        c = self.cases.create("x")
        c = self.cases.add_ioc(c["id"], "ip", " 2001:DB8::1 ", "seen in proxy log")
        c = self.cases.add_ioc(c["id"], "domain", "Evil.Example")
        self.assertEqual({(i["type"], i["value"]) for i in c["iocs"]},
                         {("ipv6", "2001:db8::1"), ("domain", "evil.example")})
        with self.assertRaises(CaseError):
            self.cases.add_ioc(c["id"], "domain", "evil.example")
        dom = [i for i in c["iocs"] if i["type"] == "domain"][0]
        c = self.cases.set_excluded(c["id"], dom["id"], True)
        self.assertNotIn("evil.example", self.cases.export_csv(c["id"]))
        self.assertIn("Excluded domain evil.example from exports", [e["text"] for e in c["log"]])


class ExportTests(CasesTestBase):
    def build(self):
        alert = self.make_alert()
        report = inspector.save(self.store, inspector.inspect_bytes(synth.docm_dropper(), "inv.docm"),
                                "test")
        c = self.cases.create("C2 | dropper", tags=["c2"], summary="Beacon from a /tmp agent.")
        self.cases.add_item(c["id"], "alert", alert["id"])
        self.cases.add_item(c["id"], "inspection", report["id"])
        self.cases.add_ioc(c["id"], "url", "http://198.51.100.1/a'b", "=HYPERLINK(\"x\") from a log")
        self.cases.note(c["id"], "Isolated the machine.")
        return c["id"]

    def test_csv(self):
        cid = self.build()
        rows = list(csv.DictReader(io.StringIO(self.cases.export_csv(cid))))
        self.assertGreaterEqual(len(rows), 5)
        byval = {r["value"]: r for r in rows}
        self.assertEqual(byval["198.51.100.20"]["assessed_malicious"], "yes")
        self.assertTrue(byval["198.51.100.20"]["first_seen_utc"].endswith("Z"))
        self.assertEqual(byval["http://198.51.100.1/a'b"]["context"][0], "'")  # formula neutralised

    def test_stix(self):
        cid = self.build()
        b1 = self.cases.export_stix(cid, now=5000)
        validate_stix(b1)
        types = [o["type"] for o in b1["objects"]]
        self.assertEqual((types.count("identity"), types.count("grouping"), types.count("note")), (1, 1, 1))
        inds = {o["pattern"]: o for o in b1["objects"] if o["type"] == "indicator"}
        self.assertIn("[ipv4-addr:value = '198.51.100.20']", inds)
        self.assertIn("[url:value = 'http://198.51.100.1/a\\'b']", inds)  # quote escaped
        self.assertTrue(any(p.startswith("[file:hashes.'SHA-256' = '") for p in inds))
        self.assertEqual(inds["[ipv4-addr:value = '198.51.100.20']"]["indicator_types"],
                         ["malicious-activity"])
        # Stable ids, so a re-export updates rather than duplicates downstream.
        b2 = self.cases.export_stix(cid, now=6000)
        self.assertEqual({o["id"] for o in b1["objects"]}, {o["id"] for o in b2["objects"]})
        self.assertNotEqual(b1["id"], b2["id"])

    def test_markdown(self):
        cid = self.build()
        text = self.cases.export_markdown(cid)
        self.assertTrue(text.startswith(f"# Case {cid}: C2 \\| dropper"))
        for heading in ("## Summary", "## Evidence", "## Indicators", "## Timeline", "## Limits"):
            self.assertIn(heading, text)
        self.assertIn("`198.51.100[.]20`", text)
        self.assertIn("hxxp[://]198.51.100.20/stage2.ps1", text)
        self.assertNotRegex(text, r"(?<!x)http://198\.51\.100\.20")  # nothing clickable
        self.assertIn("Listed by abuse.ch Feodo Tracker", text)
        self.assertIn("— _threat\\_intel:", text)  # each finding keeps its check and data
        self.assertIn("Isolated the machine.", text)
        self.assertIn("Alert #", text)

    def test_defang(self):
        self.assertEqual(cases_mod.defang("198.51.100.20"), "198.51.100[.]20")
        self.assertEqual(cases_mod.defang("https://a.example/x"), "hxxps[://]a.example/x")
        self.assertEqual(cases_mod.defang("e3b0c442"), "e3b0c442")


class ApiTests(unittest.TestCase):
    def test_round_trip(self):
        from vigil import server
        from .helpers import make_proc
        import http.client
        import threading
        with tempfile.TemporaryDirectory() as tmp:
            app = server.App(f"{tmp}/data", proc_root=make_proc(tmp), start_monitor=False)
            app.monitor.poll_once()
            httpd = server.make_server(app, port=0)
            port = httpd.server_address[1]
            threading.Thread(target=httpd.serve_forever, daemon=True).start()

            def call(method, path, payload=None, **hdr):
                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                headers = {"Host": f"127.0.0.1:{port}", "X-Vigil": "1",
                           "Content-Type": "application/json", **hdr}
                conn.request(method, path, json.dumps(payload).encode() if payload is not None
                             else None, {k: v for k, v in headers.items() if v is not None})
                res = conn.getresponse()
                body = res.read()
                conn.close()
                return res, body

            try:
                res, _ = call("POST", "/api/cases", {"title": "x"}, **{"X-Vigil": None})
                self.assertEqual(res.status, 403)
                res, body = call("POST", "/api/cases", {"title": "Fixture case", "tags": "test"})
                cid = json.loads(body)["id"]
                res, body = call("POST", "/api/case/item", {"id": cid, "kind": "destination",
                                                            "ref": "198.51.100.30"})
                self.assertEqual(res.status, 200, body)
                res, body = call("POST", "/api/case/item", {"id": cid, "kind": "destination",
                                                            "ref": "198.51.100.30"})
                self.assertEqual(res.status, 400)  # already there
                res, _ = call("POST", "/api/case/item", {"id": cid, "kind": "destination",
                                                         "ref": "192.0.2.123"})
                self.assertEqual(res.status, 404)
                res, body = call("GET", f"/api/case/export?id={cid}&format=stix")
                self.assertEqual(res.getheader("Content-Type"), "application/stix+json;version=2.1")
                self.assertEqual(res.getheader("Content-Disposition"),
                                 f'attachment; filename="vigil-case-{cid}.stix.json"')
                validate_stix(json.loads(body))
                res, body = call("GET", f"/api/case/export?id={cid}&format=md")
                self.assertIn(b"## Evidence", body)
                res, _ = call("GET", f"/api/case/export?id={cid}&format=pdf")
                self.assertEqual(res.status, 400)
                res, _ = call("GET", "/api/case?id=999")
                self.assertEqual(res.status, 404)
                res, body = call("POST", "/api/case/update", {"id": cid, "status": "closed"})
                self.assertEqual(json.loads(body)["status"], "closed")
            finally:
                httpd.shutdown()
                httpd.server_close()
                app.enricher._close_geo()
                app.store.close()


if __name__ == "__main__":
    unittest.main()
