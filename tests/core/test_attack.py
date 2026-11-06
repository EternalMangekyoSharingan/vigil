"""ATT&CK tags on findings: every mapped id is known, and findings carry them."""

import re
import unittest
from pathlib import Path

from vigil.core import attack, finding


class AttackTests(unittest.TestCase):
    def test_every_mapped_technique_is_named(self):
        for (tool, check), ids in attack.BY_CHECK.items():
            for t in ids:
                self.assertIn(t, attack.TECHNIQUES, f"{tool}/{check}")
        for ids in attack.BY_PERSIST_GROUP.values():
            for t in ids:
                self.assertIn(t, attack.TECHNIQUES)
        for tid, (name, tactic) in attack.TECHNIQUES.items():
            self.assertRegex(tid, attack.ID_RE)
            self.assertIn(tactic, attack.TACTICS, tid)

    def test_mapped_checks_exist_in_the_code(self):
        src = "".join(p.read_text() for p in (Path(attack.__file__).parent.parent).rglob("*.py"))
        for tool, check in attack.BY_CHECK:
            name = check.removeprefix("inspector_")
            self.assertTrue(re.search(rf'["\']{re.escape(name)}["\']', src), f"{tool}/{check} is never raised")

    def test_findings_carry_tags_and_reject_bad_ids(self):
        f = finding.make("tasks", "ld_preload", "game has a library forced into it", "x.", "High",
                         signals=[("x", 1)], when=1)
        self.assertEqual(f["attack"][0]["id"], "T1574.006")
        self.assertEqual(f["attack"][0]["url"], "https://attack.mitre.org/techniques/T1574/006/")
        explicit = finding.make("persist", "content", "A thing", "x.", "Info", attack=["T1053.003"], when=1)
        self.assertEqual(explicit["attack"][0]["tactic"], "persistence")
        f["attack"].append({"id": "X9999"})
        self.assertIn("bad ATT&CK id 'X9999'", finding.problems(f))
        self.assertEqual(attack.for_persist("systemd", path="/x/backup.timer")[0]["id"], "T1053.006")


if __name__ == "__main__":
    unittest.main()
