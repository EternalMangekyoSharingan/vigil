"""Your decisions about findings (expected / fixed / not a problem), and how Home, the Cases
timeline, storylines and the analyst respect them. All findings are SYNTHETIC."""

import json
import os
import stat
import tempfile
import threading
import unittest
from pathlib import Path

from vigil.cases import importer
from vigil.cases.server import App as CasesApp
from vigil.core import decisions, finding
from vigil.core.web import BadRequest
from vigil.suite import overview
from vigil.suite.server import Home


def f(tool, check, title, sev, when=1000.0, subject=None, evidence=()):
    return finding.make(tool, check, title, f"{title}.", sev, signals=[("x", 0.6)] if sev in ("High", "Medium") else [],
                        confidence="Medium", confidence_reason="Synthetic.", subject=subject or title, when=when,
                        evidence=list(evidence))


def write(root, tool, fs):
    d = Path(root, tool)
    d.mkdir(parents=True, exist_ok=True)
    (d / "findings.jsonl").write_text(finding.to_jsonl(fs))


def key(x):
    return f"{x['tool']}:{x['id']}"


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.d = decisions.Decisions(self.tmp.name)

    def test_needs_a_status_a_reason_and_a_key(self):
        with self.assertRaises(decisions.DecisionError):
            self.d.set("tasks:abc", "ignore", "because")
        with self.assertRaises(decisions.DecisionError):
            self.d.set("tasks:abc", "expected", "   ")
        with self.assertRaises(decisions.DecisionError):
            self.d.set("nokey", "expected", "fine")
        self.assertEqual(self.d.all(), {})

    def test_set_get_clear_and_file_mode(self):
        e = self.d.set("tasks:abc", "expected", "  my backup job  ", title="t", severity="Medium", now=50.0)
        self.assertEqual(e, {"status": "expected", "reason": "my backup job", "title": "t", "severity": "Medium", "ts": 50.0})
        self.assertEqual(self.d.get("tasks:abc")["status"], "expected")
        mode = stat.S_IMODE(os.stat(self.d.path).st_mode)
        self.assertEqual(mode, 0o600)
        self.assertEqual(self.d.clear("tasks:abc")["reason"], "my backup job")
        self.assertIsNone(self.d.clear("tasks:abc"))
        self.assertEqual(self.d.all(), {})

    def test_a_corrupt_file_reads_as_empty_and_is_replaced(self):
        Path(self.d.path).write_text("{not json")
        self.assertEqual(self.d.all(), {})
        self.d.set("pkg:1", "not_a_problem", "test fixture")
        self.assertEqual(list(json.loads(Path(self.d.path).read_text())), ["pkg:1"])

    def test_worse_or_seen_again_after_fixed_reopens(self):
        self.d.set("tasks:a", "expected", "known", severity="Medium", now=100.0)
        self.d.set("tasks:b", "fixed", "removed it", severity="High", now=100.0)
        self.assertTrue(self.d.applies("tasks:a", "Medium"))
        self.assertTrue(self.d.applies("tasks:a", "Low"))                 # milder still counts as decided
        self.assertIsNone(self.d.applies("tasks:a", "High"))             # worse: back
        self.assertTrue(self.d.applies("tasks:a", "Medium", seen=10_000))  # expected things may keep being seen
        self.assertTrue(self.d.applies("tasks:b", "High", seen=102.0))    # the scan that ran as you decided
        self.assertIsNone(self.d.applies("tasks:b", "High", seen=500.0))  # fixed, then seen again: back
        self.assertIsNone(self.d.applies("tasks:zzz", "Low"))

    def test_concurrent_writers_lose_nothing(self):
        def worker(n):
            for i in range(10):
                decisions.Decisions(self.tmp.name).set(f"tasks:{n}-{i}", "expected", "load test")
        ts = [threading.Thread(target=worker, args=(n,)) for n in range(4)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        self.assertEqual(len(self.d.all()), 40)

    def test_routes(self):
        r = decisions.routes(self.d)
        out = r[("POST", "/api/decide")]({}, json.dumps({"key": "net:x", "status": "fixed", "reason": "blocked it",
                                                         "severity": "High"}).encode(), {})
        self.assertEqual(out["decision"]["status"], "fixed")
        with self.assertRaises(BadRequest):
            r[("POST", "/api/decide")]({}, json.dumps({"key": "net:x", "status": "fixed"}).encode(), {})
        self.assertIn("net:x", r[("GET", "/api/decisions")]({})["decisions"])
        self.assertTrue(r[("POST", "/api/undecide")]({}, json.dumps({"key": "net:x"}).encode(), {})["removed"])


class HomeTests(unittest.TestCase):
    def test_set_aside_leaves_needs_a_look_and_the_counts(self):
        with tempfile.TemporaryDirectory() as tmp:
            hi = f("tasks", "memory_only", "A program runs from memory only", "High", 3000)
            med = f("persist", "content", "A sudo rule skips the password", "Medium", 2000)
            write(tmp, "tasks", [hi])
            write(tmp, "persist", [med])
            home = Home(tmp)
            self.addCleanup(home.close)
            post = lambda route, d: home.routes()[("POST", route)]({}, json.dumps(d).encode(), {})
            post("/api/decide", {"key": key(hi), "status": "expected", "reason": "my own test program",
                                 "title": hi["title"], "severity": "High"})
            o = overview.overview(tmp, {})
            self.assertEqual([n["key"] for n in o["needs_look"]], [key(med)])
            self.assertEqual(o["posture"]["High"], 0)
            self.assertEqual(o["verdict"]["cls"], "warn")
            self.assertEqual(o["set_aside_total"], 1)
            self.assertEqual(o["set_aside"][0]["decision"]["reason"], "my own test program")
            tasks = next(t for t in o["tools"] if t["id"] == "tasks")
            self.assertEqual(tasks["counts"]["High"], 0)
            post("/api/undecide", {"key": key(hi)})
            self.assertEqual(overview.overview(tmp, {})["posture"]["High"], 1)

    def test_fixed_comes_back_when_a_later_scan_sees_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            hi = f("tasks", "memory_only", "A program runs from memory only", "High", 3000)
            write(tmp, "tasks", [hi])
            decisions.Decisions(tmp).set(key(hi), "fixed", "killed it", severity="High", now=3001)
            self.assertEqual(overview.overview(tmp, {})["posture"]["High"], 0)
            again = dict(hi, source=dict(hi["source"], when=9000))
            write(tmp, "tasks", [again])
            o = overview.overview(tmp, {})
            self.assertEqual(o["posture"]["High"], 1)
            self.assertEqual(o["set_aside_total"], 0)


class CasesTests(unittest.TestCase):
    AGENT = "/tmp/.x/agent"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.tasks = f("tasks", "temp_binary", "agent runs from a temporary folder", "Medium", 3000,
                       evidence=[{"kind": "path", "value": self.AGENT}])
        self.persist = f("persist", "content", "updater.service starts a program from a temp folder", "Medium", 1000,
                         evidence=[{"kind": "path", "value": self.AGENT}])
        self.low = f("files", "x", "A note about a file", "Low", 2000)
        write(root, "tasks", [self.tasks])
        write(root, "persist", [self.persist])
        write(root, "files", [self.low])
        self.app = CasesApp(root / "cases", root)
        self.addCleanup(self.app.close)
        importer.import_all(self.app.store, root, refresh_net=False)
        self.routes = self.app.routes()

    def post(self, route, d):
        return self.routes[("POST", route)]({}, json.dumps(d).encode(), {})

    def get(self, route, **q):
        return self.routes[("GET", route)](q)

    def test_timeline_marks_filters_and_searches(self):
        self.post("/api/decide", {"key": key(self.tasks), "status": "not_a_problem", "reason": "my compiler output",
                                  "severity": "Medium"})
        ev = {e["key"]: e for e in self.get("/api/timeline")["events"] if e["kind"] == "finding"}
        self.assertEqual(len(ev), 3)                                           # nothing disappears silently
        self.assertEqual(ev[key(self.tasks)]["decision"]["reason"], "my compiler output")
        self.assertIsNone(ev[key(self.persist)]["decision"])
        self.assertEqual({e["key"] for e in self.get("/api/timeline", view="open")["events"]},
                         {key(self.persist), key(self.low)})
        self.assertEqual([e["key"] for e in self.get("/api/timeline", view="aside")["events"]], [key(self.tasks)])
        self.assertEqual([e["key"] for e in self.get("/api/timeline", q="UPDATER.service")["events"]], [key(self.persist)])
        self.assertEqual(self.get("/api/timeline", q="no such words")["events"], [])

    def test_finding_detail_storylines_and_analyst_scope(self):
        self.assertEqual(len(self.get("/api/stories")["stories"]), 1)
        self.post("/api/decide", {"key": key(self.tasks), "status": "expected", "reason": "my build agent",
                                  "severity": "Medium"})
        d = self.get("/api/finding", key=key(self.tasks))
        self.assertTrue(d["decision_applies"])
        self.assertEqual(d["decision"]["status"], "expected")
        self.assertIn("fixed", d["statuses"])
        self.assertEqual(self.get("/api/stories")["stories"], [])              # one tool left: no storyline
        self.assertEqual(len(self.get("/api/stories", all="1")["stories"]), 1)
        fs, stories, case, label = self.app._scope({})
        self.assertEqual([x["id"] for x in fs], [self.persist["id"]])
        self.assertIn("1 set aside by you", label)
        # a case you built yourself keeps everything you put in it
        c = self.app.store.create("mine")
        self.app.store.attach(c["id"], key(self.tasks))
        fs, _, _, _ = self.app._scope({"case": c["id"]})
        self.assertEqual([x["id"] for x in fs], [self.tasks["id"]])


if __name__ == "__main__":
    unittest.main()
