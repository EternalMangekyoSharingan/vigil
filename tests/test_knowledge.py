"""Offline knowledge base: program and port notes, package ownership, plain-language summaries.
All program records here are SYNTHETIC."""

import unittest
from unittest import mock

from vigil import knowledge


class KnowledgeTests(unittest.TestCase):
    def test_lookup_by_exe_name_and_alias(self):
        ff = knowledge.lookup_program("/usr/lib/firefox/firefox", "firefox", "/usr/lib/firefox/firefox")
        self.assertEqual(ff["id"], "firefox")
        for field in ("title", "what", "net", "normal", "watch"):
            self.assertTrue(ff[field], field)
        self.assertIsNone(knowledge.lookup_program("/tmp/.x/agent", "agent", "/tmp/.x/agent"))

    def test_every_entry_explains_what_it_does(self):
        for key, entry in knowledge.PROGRAMS.items():
            with self.subTest(key):
                self.assertGreater(len(entry["what"]), 30, "a one-word description is not an explanation")
                self.assertTrue(entry["net"] and entry["normal"])
        for alias, target in knowledge.ALIASES.items():
            self.assertIn(target, knowledge.PROGRAMS, alias)

    def test_ports(self):
        self.assertEqual(knowledge.port_info("tcp", 443)["service"], "HTTPS")
        self.assertIsNotNone(knowledge.port_info("udp", 53))
        self.assertIsNone(knowledge.port_info("tcp", 1))

    def test_package_owner_prefixes(self):
        self.assertEqual(knowledge.package_owner("/snap/firefox/123/usr/lib/firefox/firefox")["how"], "a Snap package")
        self.assertIn("AppImage", knowledge.package_owner("/tmp/.mount_Foo123/AppRun")["how"])
        self.assertIsNone(knowledge.package_owner(None))

    def test_about_unknown_program_from_tmp(self):
        d = {"key": "/tmp/.x/agent", "name": "agent", "hidden": False,
             "info": {"pid": 7000, "user": "alice", "exe": "/tmp/.x/agent (deleted)", "exe_deleted": True,
                      "started": 1000.0, "ancestry": [{"name": "bash", "pid": 6990}, {"name": "sshd", "pid": 812}]},
             "pairs": [{"ip": "203.0.113.50", "proto": "tcp", "port": 443, "direction": "out", "connections": 3,
                        "name": "agent"}],
             "findings": []}
        with mock.patch.object(knowledge, "_owner_cached", return_value={"how": None, "package": None}):
            a = knowledge.about_program(d, now=1000.0 + 3 * 3600 + 5)
        self.assertIsNone(a["knowledge"])
        self.assertIn("agent (pid 7000) runs as alice, started 3 hours ago by bash (under sshd).", a["facts"])
        self.assertIn("not part of any installed package", a["provenance"])
        self.assertTrue(any("deleted or replaced" in f for f in a["facts"]))
        self.assertTrue(any("HTTPS (tcp/443): 3 connections" in f for f in a["facts"]))
        self.assertEqual(a["ports"][0]["service"], "HTTPS")

    def test_about_destination(self):
        d = {"ip": "192.168.1.1", "scope": "lan", "enrichment": {},
             "pairs": [{"name": "firefox", "proto": "udp", "port": 53}]}
        a = knowledge.about_destination(d)
        self.assertEqual(a["facts"][0], "192.168.1.1 is on your local network.")
        self.assertIn("firefox over", a["facts"][1])


if __name__ == "__main__":
    unittest.main()
