"""Storylines and pivots across tools, on SYNTHETIC findings shaped like each tool's."""

import json
import tempfile
import unittest
from pathlib import Path

from vigil.cases import correlate, importer
from vigil.cases.server import App
from vigil.core import finding


def row(f):
    return {"key": f"{f['tool']}:{f['id']}", "tool": f["tool"], "severity": f["severity"], "title": f["title"],
            "first_seen": f["source"]["when"], "body": f}


def mk(tool, check, title, sev, when, **kw):
    return finding.make(tool, check, title, f"{title}.", sev, signals=kw.pop("signals", [("x", 0.6)]), confidence="Medium",
                        confidence_reason="Synthetic.", subject=title, when=when, **kw)


AGENT = "/tmp/.x/agent"
TASKS = mk("tasks", "temp_binary", "agent runs from a temporary folder", "Medium", 3000,
           evidence=[{"kind": "process", "value": "pid 7000"}, {"kind": "path", "value": AGENT + " (deleted)"}],
           technical=[{"label": "command line", "value": f"{AGENT} --daemon"}])
PERSIST = mk("persist", "content", "updater.service starts a program from a temp folder", "Medium", 1000,
             evidence=[{"kind": "path", "value": "/home/alice/.config/systemd/user/updater.service"}],
             signals=[(f"starts a program from a temporary folder ({AGENT})", 0.9)],
             attack=["T1543.002"])
NET = mk("net", "alert", "agent checks in with 198.51.100.9 every ~60 s", "Medium", 4000,
         evidence=[{"kind": "program", "value": AGENT}, {"kind": "destination", "value": "198.51.100.9:443/tcp (out)"}],
         iocs=[{"type": "ipv4", "value": "198.51.100.9"}], attack=["T1071.001", "T1029"])
FILES = mk("files", "inspector_pipe_to_shell", "Contains a script that downloads and runs code", "High", 500,
           evidence=[{"kind": "file", "value": "/home/alice/Downloads/setup.sh"}],
           iocs=[{"type": "url", "value": "http://198.51.100.9/agent"}])
# Unrelated findings that share only noise (an interpreter, a LAN address)
NOISE1 = mk("tasks", "odd_parent", "firefox started bash", "High", 2000,
            evidence=[{"kind": "path", "value": "/usr/bin/bash"}], iocs=[{"type": "ipv4", "value": "192.168.1.1"}])
NOISE2 = mk("pkg", "pipe_to_shell", "Downloads a script and runs it straight away", "High", 2100,
            evidence=[{"kind": "file", "value": "/usr/bin/bash"}], iocs=[{"type": "ipv4", "value": "192.168.1.1"}])


class StoryTests(unittest.TestCase):
    def test_entities(self):
        e = correlate.entities(TASKS)
        self.assertIn(("path", AGENT), e)
        self.assertNotIn(("path", "/usr/bin/bash"), correlate.entities(NOISE1))
        self.assertNotIn(("ip", "192.168.1.1"), correlate.entities(NOISE1))
        self.assertIn(("ip", "198.51.100.9"), correlate.entities(NET))
        self.assertIn(("ip", "198.51.100.9"), correlate.entities(FILES))      # from the URL's host
        self.assertIn(("unit", "updater.service"), correlate.entities(PERSIST))

    def test_one_storyline_across_four_tools(self):
        stories = correlate.stories([row(x) for x in (TASKS, PERSIST, NET, FILES, NOISE1, NOISE2)])
        self.assertEqual(len(stories), 1)
        s = stories[0]
        self.assertEqual(s["tools"], ["files", "net", "persist", "tasks"])
        self.assertEqual(s["severity"], "High")
        self.assertEqual([st["tool"] for st in s["steps"]], ["files", "persist", "tasks", "net"])   # time order
        self.assertEqual(s["anchor"], {"kind": "path", "value": AGENT})
        self.assertEqual(s["title"], "What happened around agent")
        self.assertIn("persistence", s["tactics"])
        self.assertEqual(s["tactics"], sorted(s["tactics"], key=correlate.attack_map.TACTICS.index))
        self.assertIn("agent", s["steps"][2]["linked_by"])

    def test_escalation_and_single_tool_groups(self):
        s = correlate.stories([row(x) for x in (TASKS, PERSIST, NET)])[0]
        self.assertTrue(s["escalated"])                          # three Mediums across three tools
        self.assertEqual(s["severity"], "High")
        self.assertEqual(correlate.stories([row(TASKS)]), [])    # one tool: no storyline

    def test_api_pivot_and_case_from_story(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = App(Path(tmp, "cases"), Path(tmp))
            self.addCleanup(app.close)
            importer.import_text(app.store, finding.to_jsonl([TASKS, PERSIST, NET, FILES, NOISE1]), "synthetic")
            get = lambda r, q: app.routes()[("GET", r)](q)
            st = get("/api/stories", {})["stories"][0]
            self.assertEqual(get("/api/story", {"id": st["id"]})["id"], st["id"])
            piv = get("/api/pivot", {"kind": "ip", "value": "198.51.100.9"})["findings"]
            self.assertEqual({p["tool"] for p in piv}, {"net", "files"})
            fd = get("/api/finding", {"key": f"tasks:{TASKS['id']}"})
            self.assertIn({"kind": "path", "value": AGENT, "display": "agent"}, fd["entities"])
            c = app.routes()[("POST", "/api/story/case")]({}, json.dumps({"id": st["id"]}).encode(), {})
            self.assertEqual(len(c["findings"]), 4)
            self.assertIn("storyline", c["tags"])
            self.assertEqual(c["summary"], st["summary"])


if __name__ == "__main__":
    unittest.main()
