"""Vigil Persist: plain-language names for well-known entries, and user units that borrow a
system service's name. The system and home folder are SYNTHETIC (tests/persist Fake)."""

import tempfile
import unittest

from vigil.persist import known

from .test_persist import Fake


class LookupTests(unittest.TestCase):
    def test_names_instances_and_families(self):
        self.assertEqual(known.lookup("/usr/lib/systemd/system/NetworkManager.service")["what"],
                         "Connects you to Wi-Fi, Ethernet and VPNs.")
        self.assertEqual(known.lookup("/etc/systemd/system/getty.target.wants/getty@tty1.service")["name"], "getty@.service")
        self.assertIn("GNOME's settings", known.lookup("/etc/xdg/autostart/org.gnome.SettingsDaemon.Power.desktop")["what"])
        self.assertIsNone(known.lookup("/home/alice/.config/systemd/user/updater.service"))
        for name, (what, scope) in known.KNOWN.items():
            self.assertIn(scope, ("system", "user", "any"), name)
            self.assertTrue(what.endswith("."), name)                 # a sentence, shown as is
            self.assertLessEqual(len(what), 110, name)

    def test_borrowed_only_for_system_names_in_user_unit_folders(self):
        u = lambda p: {"path": p, "scope": "user"}
        self.assertEqual(known.borrowed(u("/home/a/.config/systemd/user/NetworkManager.service"))["name"],
                         "NetworkManager.service")
        self.assertIsNone(known.borrowed(u("/home/a/.config/systemd/user/pipewire.service")))      # a real user unit
        self.assertIsNone(known.borrowed(u("/home/a/.config/autostart/nm-applet.desktop")))        # an override copy
        self.assertIsNone(known.borrowed(u("/home/a/.config/systemd/user/sshd.service.d/x.conf")))
        self.assertIsNone(known.borrowed({"path": "/etc/systemd/system/NetworkManager.service", "scope": "system"}))


class ScanTests(unittest.TestCase):
    def test_scan_names_entries_and_flags_a_borrowed_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake = Fake(tmp)
            fake.w("usr/lib/systemd/system/fstrim.timer", "[Timer]\nOnCalendar=weekly\n")
            fake.h(".config/systemd/user/dbus-broker.service", "[Service]\nExecStart=/usr/bin/dbus-broker-launch\n")
            fake.h(".config/systemd/user/systemd-timesyncd.service",
                   "[Service]\nExecStart=/home/alice/.local/bin/timesyncd\n")
            r = fake.scan()
            by = {e["path"]: e for e in r["entries"]}
            self.assertEqual(by["/usr/lib/systemd/system/fstrim.timer"]["known"]["what"],
                             "Tells SSDs which blocks are free, once a week.")
            self.assertEqual(by[str(fake.home / ".config/systemd/user/dbus-broker.service")]["known"]["scope"], "any")
            f = [x for x in r["findings"] if x["source"]["check"] == "borrowed_name"]
            self.assertEqual([x["title"] for x in f], ["Not the real systemd-timesyncd.service"])
            self.assertEqual(f[0]["severity"], "Medium")
            self.assertEqual([a["id"] for a in f[0]["attack"]], ["T1036.005", "T1543.002"])
            self.assertIn("keeps the clock right", f[0]["summary"])


if __name__ == "__main__":
    unittest.main()
