"""Shared settings and Run in every tool (core.settings, core.web built-in routes).
Everything here is SYNTHETIC: temporary data folders, made-up findings and a stand-in
command runner. No real command is run and no password is involved."""

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from vigil.core import runner, settings, web
from vigil.core.store import FindingStore

FIX = {"check": [{"title": "Read it", "commands": [{"text": "cat /etc/hostname", "tokens": []}]}],
       "fix": [{"title": "Turn it off", "commands": [{"text": "sudo systemctl disable --now demo.service", "tokens": []}],
                "undo": [{"text": "sudo systemctl enable --now demo.service", "tokens": []}]}],
       "undo": []}


def synthetic_finding(fid="f1"):
    return {"id": fid, "tool": "persist", "severity": "Medium", "title": "SYNTHETIC", "fixes": FIX,
            "source": {"tool": "persist", "check": "synthetic", "data": "test", "when": 1.0}}


class StoreApp:
    """An app shaped like Persist/Files/Pkg: findings in a FindingStore."""

    def __init__(self, root):
        self.store = FindingStore("persist", Path(root) / "persist")
        self.data_root = Path(root)
        self.tool_id = "persist"

    def run_allowed(self, source, ref):
        return runner.commands_in(self.store.finding(ref)) if source == "finding" else set()

    def routes(self):
        return {}


class CopyOnlyApp:
    def __init__(self, root):
        self.data_root = Path(root)
        self.tool_id = "cases"

    def routes(self):
        return {}


def call(app, method, path, body=None):
    h = web.builtin_routes(app)[(method, path)]
    return h({}) if method == "GET" else h({}, json.dumps(body or {}).encode(), {})


class SettingsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = self.tmp.name

    def test_defaults_and_shared_file_keeps_other_keys(self):
        Path(self.root, "settings.json").write_text(json.dumps({"sources": {"geo": "http://mirror"}}))
        self.assertEqual(settings.public(self.root), {"run_mode": False, "density": "comfortable", "motion": "system"})
        settings.update(self.root, {"run_mode": True, "density": "compact"})
        raw = json.loads(Path(self.root, "settings.json").read_text())
        self.assertTrue(raw["sudo_mode"])                       # the Network Map's old key, so Net agrees
        self.assertEqual(raw["sources"], {"geo": "http://mirror"})
        self.assertEqual(Path(self.root, "settings.json").stat().st_mode & 0o777, 0o600)

    def test_rejects_unknown_values(self):
        with self.assertRaises(ValueError):
            settings.update(self.root, {"density": "huge"})

    def test_routes_report_whether_a_tool_can_run(self):
        self.assertTrue(call(StoreApp(self.root), "GET", "/api/vigil/settings")["can_run"])
        self.assertFalse(call(CopyOnlyApp(self.root), "GET", "/api/vigil/settings")["can_run"])

    def test_switching_run_mode_is_logged(self):
        call(CopyOnlyApp(self.root), "POST", "/api/vigil/settings", {"run_mode": True})
        log = Path(self.root, "run-log.jsonl").read_text()
        self.assertIn("Run mode switched on", log)


class RunTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.app = StoreApp(self.tmp.name)
        self.addCleanup(self.app.store.close)
        self.app.store.add_run("autostart", [synthetic_finding()])
        self.calls = []
        fake = lambda argv, **kw: self.calls.append(argv) or SimpleNamespace(returncode=0, stdout=b"ok", stderr=b"")
        real_run = runner.run    # likewise its default `runner`
        p1 = mock.patch.object(runner, "run", lambda c, a, store=None: real_run(c, a, store=store, runner=fake))
        real = runner.argv_for   # its default `which` is bound at import; give it a fake one
        p2 = mock.patch.object(runner, "argv_for", lambda c, which=None: real(c, which=lambda n: f"/usr/bin/{n}"))
        p1.start(); p2.start()
        self.addCleanup(p1.stop); self.addCleanup(p2.stop)

    def run_cmd(self, cmd, ref="f1", app=None):
        return call(app or self.app, "POST", "/api/vigil/run", {"command": cmd, "source": "finding", "ref": ref})

    def test_off_by_default(self):
        with self.assertRaisesRegex(web.BadRequest, "Run mode is off"):
            self.run_cmd("cat /etc/hostname")
        self.assertEqual(self.calls, [])

    def test_runs_only_commands_from_that_stored_finding(self):
        settings.update(self.tmp.name, {"run_mode": True})
        self.assertEqual(self.run_cmd("cat /etc/hostname")["exit"], 0)
        self.run_cmd("sudo systemctl enable --now demo.service")        # an Undo command
        self.assertEqual(self.calls[-1][:2], ["/usr/bin/pkexec", "/usr/bin/systemctl"])
        for cmd, ref in (("rm -rf /home", "f1"), ("cat /etc/hostname", "other"), ("cat /etc/hostname", None)):
            with self.subTest(cmd=cmd, ref=ref), self.assertRaises(web.BadRequest):
                self.run_cmd(cmd, ref)
        self.assertEqual(len(self.calls), 2)
        log = Path(self.tmp.name, "run-log.jsonl").read_text()
        self.assertIn("Ran (Run mode): cat /etc/hostname", log)

    def test_copy_only_tools_never_run(self):
        settings.update(self.tmp.name, {"run_mode": True})
        with self.assertRaisesRegex(web.BadRequest, "copy only"):
            self.run_cmd("cat /etc/hostname", app=CopyOnlyApp(self.tmp.name))

    def test_commands_in(self):
        self.assertEqual(runner.commands_in(synthetic_finding()), {
            "cat /etc/hostname", "sudo systemctl disable --now demo.service", "sudo systemctl enable --now demo.service"})
        self.assertEqual(runner.commands_in(None), set())


class ToolWiringTests(unittest.TestCase):
    """Every tool app says where shared settings live; Cases and Home never run commands."""

    def test_apps(self):
        from vigil.cases import server as cases
        from vigil.persist import server as persist
        from vigil.tasks import server as tasks
        with tempfile.TemporaryDirectory() as d:
            p = persist.App(Path(d) / "persist")
            t = tasks.App(Path(d) / "tasks")
            c = cases.App(Path(d) / "cases", d)
            try:
                for a in (p, t, c):
                    self.assertEqual(Path(a.data_root), Path(d))
                self.assertTrue(hasattr(p, "run_allowed") and hasattr(t, "run_allowed"))
                self.assertFalse(hasattr(c, "run_allowed"))
                self.assertEqual(t.run_allowed("finding", "no-such-id"), set())
            finally:
                for a in (p, t, c):
                    a.close()


if __name__ == "__main__":
    unittest.main()
