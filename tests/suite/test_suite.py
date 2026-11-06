"""Vigil Home and the launcher. Findings are SYNTHETIC, written as each tool would."""

import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from vigil.core import finding, suite
from vigil.suite import checkup, overview
from vigil.suite.server import Home, launch, make_server


def f(tool, check, title, sev, when=1000.0, subject=None):
    return finding.make(tool, check, title, f"{title}.", sev, signals=[("x", 0.5)] if sev in ("High", "Medium") else [],
                        confidence="Medium", confidence_reason="Synthetic.", subject=subject or title, when=when)


def write(root, tool, fs):
    d = Path(root, tool)
    d.mkdir(parents=True, exist_ok=True)
    (d / "findings.jsonl").write_text(finding.to_jsonl(fs))


class OverviewTests(unittest.TestCase):
    def test_first_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            o = overview.overview(tmp, {})
            self.assertTrue(o["first_run"])
            self.assertEqual(o["verdict"]["word"], "Not checked yet")
            self.assertTrue(all(t["hint"] for t in o["tools"]))
            self.assertEqual([t["id"] for t in o["tools"]], ["net", "tasks", "persist", "files", "pkg", "cases"])

    def test_posture_and_needs_a_look(self):
        with tempfile.TemporaryDirectory() as tmp:
            write(tmp, "tasks", [f("tasks", "memory_only", "A program runs from memory only", "High", 3000)])
            write(tmp, "persist", [f("persist", "content", "A sudo rule skips the password for everything", "Medium", 2000),
                                   f("persist", "content", "Something minor", "Low", 1000, "x")])
            write(tmp, "cases", [f("tasks", "memory_only", "Imported copy", "High", 3000, "copy")])
            o = overview.overview(tmp, {"tasks": True})
            self.assertEqual((o["posture"]["High"], o["posture"]["Medium"], o["posture"]["Low"]), (1, 1, 1))
            self.assertEqual([n["severity"] for n in o["needs_look"]], ["High", "Medium"])
            self.assertEqual(o["needs_look"][0]["key"].split(":")[0], "tasks")
            self.assertEqual(o["needs_look"][0]["attack"][0]["id"], "T1620")
            self.assertEqual(o["verdict"]["cls"], "danger")
            tasks = next(t for t in o["tools"] if t["id"] == "tasks")
            self.assertTrue(tasks["running"])
            self.assertEqual(tasks["url"], "http://127.0.0.1:8769/")


class CheckupTests(unittest.TestCase):
    def test_a_failing_step_does_not_stop_the_others(self):
        class R:
            def step(self, sid):
                time.sleep(0.05)              # long enough that the job is still running below
                if sid == "files":
                    raise OSError("synthetic failure")
                return f"{sid} ok"
        job = checkup.Job()
        self.assertTrue(job.start(R(), [s for s, _ in checkup.STEPS]))
        self.assertFalse(job.start(R(), ["tasks"]))          # one at a time
        deadline = time.time() + 5
        while job.snapshot()["running"] and time.time() < deadline:
            time.sleep(0.02)
        st = {s["id"]: s for s in job.snapshot()["steps"]}
        self.assertEqual(st["files"]["status"], "failed")
        self.assertIn("synthetic failure", st["files"]["detail"])
        self.assertEqual({s["status"] for k, s in st.items() if k != "files"}, {"done"})

    def test_runner_with_real_tools_on_synthetic_data(self):
        from ..persist.test_persist import Fake
        from ..tasks.test_tasks import world, FakeRoot
        from vigil.persist.server import App as PersistApp
        from vigil.tasks.server import App as TasksApp
        from vigil.files.server import App as FilesApp
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp, "data")
            fake = Fake(tmp)
            t2 = Path(tmp, "t")
            t2.mkdir()
            home = Path(tmp, "home2")
            (home / "Downloads").mkdir(parents=True)
            (home / "Downloads" / "invoice.pdf.exe").write_bytes(b"MZ" + b"\0" * 58 + b"\x40\0\0\0PE\0\0" + b"\0" * 64)
            apps = {"persist": PersistApp(root / "persist", home=str(fake.home), root=str(fake.root), proc=str(fake.proc)),
                    "tasks": TasksApp(root / "tasks", proc_root=str(world(str(t2)).root), root=str(FakeRoot(str(t2)).root)),
                    "files": FilesApp(root / "files", home=str(home))}
            r = checkup.Runner(root, apps)
            try:
                self.assertIn("baseline", r.step_persist())
                self.assertIn("worth a look", r.step_tasks())
                self.assertIn("1 new or changed files checked, 1 need a look", r.step_files())
                self.assertIn("0 new or changed files checked", r.step_files())      # unchanged: skipped
                self.assertEqual(r.step_net(), "the Network Map hasn't run yet")
                self.assertIn("new findings imported", r.step_cases())
            finally:
                for a in r.apps.values():
                    a.close()
            o = overview.overview(root, {})
            self.assertFalse(o["first_run"])
            self.assertGreater(o["posture"]["High"], 0)


class HomeServerTests(unittest.TestCase):
    def test_routes_and_page(self):
        from ..helpers import page_check
        with tempfile.TemporaryDirectory() as tmp:
            home = Home(tmp)
            self.addCleanup(home.close)
            o = home.routes()[("GET", "/api/overview")]({})
            self.assertTrue(o["first_run"])
            from vigil.core.web import BadRequest
            with self.assertRaises(BadRequest):
                home.routes()[("POST", "/api/checkup")]({}, json.dumps({"steps": ["nope"]}).encode(), {})
            page_check(self, make_server, home, [("/", b"<title>Vigil Home</title>"), ("/static/home.js", b"Check this PC"),
                                                 ("/static/suite.js", b"Switch tool")])

    def test_launcher_starts_tools_and_links_busy_ports(self):
        ports = {t["id"]: t["port"] for t in suite.TOOLS}
        try:
            for t in suite.TOOLS:
                t["port"] = 0          # any free port, so the test never collides
            with tempfile.TemporaryDirectory() as tmp:
                httpd, stop = launch(tmp, with_net=False, only=["pkg", "cases"])
                try:
                    self.assertEqual(httpd.server_address[0], "127.0.0.1")
                    self.assertEqual(sorted(httpd.app.running), ["cases", "pkg"])
                finally:
                    httpd.server_close()
                    stop()
        finally:
            for t in suite.TOOLS:
                t["port"] = ports[t["id"]]

    def test_every_tool_page_loads_the_switcher(self):
        root = Path(__file__).resolve().parent.parent.parent / "vigil"
        for js in ("pkg/static/pkg.js", "files/static/files-app.js", "persist/static/persist.js", "tasks/static/tasks.js",
                   "cases/static/cases-app.js", "net/static/app.js", "suite/static/home.js"):
            self.assertIn('import "./suite.js";', (root / js).read_text(), js)
        js_ports = (root / "ui/static/suite.js").read_text()
        for t in suite.TOOLS:                                   # the page's port list mirrors the registry
            self.assertIn(f'id: "{t["id"]}", name: "{t["name"]}", port: {t["port"]}', js_ports)


if __name__ == "__main__":
    unittest.main()
