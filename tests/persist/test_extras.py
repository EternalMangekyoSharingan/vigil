"""Vigil Persist additions: known malware names, ATT&CK tags per location, scan history and
the copy-only daily schedule. SYNTHETIC fake root and home."""

import json
import tempfile
import unittest
from pathlib import Path

from vigil.persist.server import App

from .test_persist import Fake, FIX


class ExtrasTests(unittest.TestCase):
    def test_known_bad_name_and_attack_tags(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = Fake(tmp)
            f.h(".config/systemd/user/rat-agent.service", "[Service]\nExecStart=/usr/bin/true\n")
            f.w("etc/cron.d/x", "* * * * * root /tmp/x\n")
            rep = f.scan()
            t = {x["title"]: x for x in rep["findings"]}
            bad = t["rat-agent.service has the name of known malware"]
            self.assertEqual(bad["severity"], "High")
            self.assertEqual(bad["attack"][0]["id"], "T1543.002")
            self.assertEqual(t["x starts a program from a temp folder"]["attack"][0]["id"], "T1053.003")

    def test_history_and_schedule(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = Fake(tmp)
            app = App(Path(tmp, "data"), home=str(f.home), root=str(f.root), proc=str(f.proc),
                      os_release_path=str(FIX / "os-release/arch"))
            self.addCleanup(app.close)
            app.scan()
            f.h(".config/autostart/new.desktop", "[Desktop Entry]\nExec=/usr/bin/true\n")
            app.scan()
            runs = app.routes()[("GET", "/api/runs")]({})["runs"]
            self.assertEqual(runs[0]["summary"]["diff"]["added"], 1)
            sched = app.routes()[("GET", "/api/schedule")]({})
            opt = sched["option"]
            self.assertEqual(opt["commands"][-1]["text"], "systemctl --user enable --now vigil-persist.timer")
            self.assertEqual(opt["undo"][0]["text"], "systemctl --user disable --now vigil-persist.timer")
            unit = sched["files"][0]["content"]
            self.assertIn("-m vigil.persist", unit)
            self.assertIn(" scan", unit)
            self.assertIn("OnCalendar=daily", sched["files"][1]["content"])


if __name__ == "__main__":
    unittest.main()
