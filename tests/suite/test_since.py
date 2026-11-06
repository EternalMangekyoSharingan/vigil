"""Home: what is new since the last check-up. Findings are SYNTHETIC."""

import json
import tempfile
import unittest
from pathlib import Path

from vigil.suite import overview
from vigil.suite.server import Home

from .test_suite import f, write


class SinceTests(unittest.TestCase):
    def test_new_since_the_last_checkup(self):
        with tempfile.TemporaryDirectory() as tmp:
            old = f("tasks", "memory_only", "A program runs from memory only", "High", 1000)
            write(tmp, "tasks", [old])
            self.assertIsNone(overview.overview(tmp, {})["new_since"])          # no check-up yet
            overview.remember_seen(tmp, now=1500.0)
            o = overview.overview(tmp, {})
            self.assertEqual(o["new_since"], {"ts": 1500.0, "count": 0, "needs": 0})
            new = f("persist", "content", "A sudo rule skips the password", "Medium", 2000)
            low = f("persist", "content", "Something minor", "Low", 2000, "minor")
            write(tmp, "persist", [new, low])
            o = overview.overview(tmp, {})
            self.assertEqual(o["new_since"], {"ts": 1500.0, "count": 2, "needs": 1})
            self.assertEqual({n["title"]: n["new"] for n in o["needs_look"]},
                             {old["title"]: False, new["title"]: True})
            self.assertEqual(oct(Path(tmp, overview.SEEN).stat().st_mode & 0o777), "0o600")

    def test_first_checkup_marks_nothing_new_and_a_corrupt_file_is_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            overview.remember_seen(tmp)                                          # nothing ran yet
            write(tmp, "tasks", [f("tasks", "memory_only", "A program runs from memory only", "High")])
            o = overview.overview(tmp, {})
            self.assertIsNone(o["new_since"])
            self.assertFalse(o["needs_look"][0]["new"])
            Path(tmp, overview.SEEN).write_text("[1, 2")
            self.assertIsNone(overview.overview(tmp, {})["new_since"])

    def test_starting_a_checkup_remembers_first(self):
        with tempfile.TemporaryDirectory() as tmp:
            write(tmp, "tasks", [f("tasks", "memory_only", "A program runs from memory only", "High")])
            home = Home(tmp)
            self.addCleanup(home.close)

            class Never:
                def step(self, sid):
                    return "skipped"
            home.runner = Never()
            home.routes()[("POST", "/api/checkup")]({}, json.dumps({"steps": ["tasks"]}).encode(), {})
            seen = json.loads(Path(tmp, overview.SEEN).read_text())
            self.assertEqual(len(seen["keys"]), 1)


if __name__ == "__main__":
    unittest.main()
