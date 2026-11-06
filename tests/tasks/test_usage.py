"""Vigil Tasks additions: CPU and memory per process, and programs using system names."""

import tempfile
import unittest
from pathlib import Path

from vigil.core.pkgdb import PackageFiles
from vigil.tasks import findings as F
from vigil.tasks import procs as P

from .test_tasks import FakeProc, FakeRoot

ARCH = {"ID": "arch"}


class UsageTests(unittest.TestCase):
    def test_cpu_between_snapshots_and_memory(self):
        with tempfile.TemporaryDirectory() as tmp:
            fp = FakeProc(tmp)
            fp.add(1, 0, "systemd", "/usr/lib/systemd/systemd", uid=0)
            fp.add(50, 1, "busy", "/usr/bin/busy")
            (fp.root / "50" / "statm").write_text("1000 2560 0 0 0 0 0\n")
            stat = (fp.root / "50" / "stat").read_text().split()
            stat[13], stat[14] = "100", "50"
            (fp.root / "50" / "stat").write_text(" ".join(stat) + "\n")
            pf = PackageFiles(tmp)
            s1 = P.snapshot(str(fp.root), pf, root=tmp, now=1000.0)
            self.assertEqual(s1["processes"][50]["ticks"], 150)
            self.assertEqual(s1["processes"][50]["rss"], 2560 * P.PAGE)
            prev = P.cpu_usage(s1, {})
            self.assertIsNone(s1["processes"][50]["cpu"])
            stat[13] = str(100 + P.CLK)                       # one more second of CPU time
            (fp.root / "50" / "stat").write_text(" ".join(stat) + "\n")
            s2 = P.snapshot(str(fp.root), pf, root=tmp, now=1002.0)
            P.cpu_usage(s2, prev)
            self.assertEqual(s2["processes"][50]["cpu"], 50.0)

    def test_system_names_from_odd_places(self):
        with tempfile.TemporaryDirectory() as tmp:
            fp = FakeProc(tmp)
            fp.add(1, 0, "systemd", "/usr/lib/systemd/systemd", uid=0)
            fp.add(60, 1, "dbus-daemon", "/home/alice/.local/share/.cache/dbus-daemon")
            fp.add(61, 1, "dbus-daemon", "/usr/bin/dbus-daemon")
            fp.add(62, 1, "sshd", "/var/tmp/sshd")
            fr = FakeRoot(tmp)
            snap = P.snapshot(str(fp.root), PackageFiles(str(fr.root)), root=str(fr.root))
            fs, _ = F.build(snap, ARCH, "/home/alice")
            masq = {int(f["evidence"][0]["value"].split()[1]): f for f in fs if f["check"] == "masquerade_name"}
            self.assertEqual(sorted(masq), [60, 62])
            self.assertEqual(masq[60]["severity"], "High")
            self.assertEqual(masq[60]["title"], "dbus-daemon pretends to be a system program")
            self.assertEqual(masq[60]["attack"][0]["id"], "T1036.005")
            self.assertIn("dbus-daemon", masq[60]["likely"])


if __name__ == "__main__":
    unittest.main()
