"""Vigil Pkg additions: the AUR helper inbox, pacman.log incident windows, hijacked names.
SYNTHETIC: fake helper caches and a fake pacman root built in temporary folders."""

import os
import shutil
import tempfile
import unittest
from pathlib import Path

from vigil.pkg import inbox, installed, names, review
from vigil.pkg.server import App

FIX = Path(__file__).parent.parent / "fixtures"
ARCH = {"ID": "arch", "PRETTY_NAME": "Arch Linux"}


class InboxTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name, "home")
        shutil.copytree(FIX / "pkg/benign", self.home / ".cache/paru/clone/hello-vigil")
        shutil.copytree(FIX / "pkg/squat", self.home / ".cache/yay/librewolf-fix-bin")
        (self.home / ".cache/yay/not-a-package").mkdir(parents=True)
        os.symlink(FIX / "pkg/builder", self.home / ".cache/paru/clone/linked")      # links are not followed

    def test_find(self):
        pkgs, helpers = inbox.find(str(self.home))
        self.assertEqual(sorted(p["name"] for p in pkgs), ["hello-vigil", "librewolf-fix-bin"])
        self.assertEqual(helpers, ["paru", "yay"])

    def test_inbox_reviews_and_tracks_approval(self):
        app = App(Path(self.tmp.name, "data"), os_release_path=str(FIX / "os-release/arch"), home=str(self.home))
        self.addCleanup(app.close)
        r = app.api_inbox({"review": "1"})
        by = {p["pkgbase"]: p for p in r["packages"]}
        self.assertEqual(by["librewolf-fix-bin"]["verdict"], "Don't install")
        self.assertEqual(by["hello-vigil"]["verdict"], "Looks normal")
        self.assertEqual({p["state"] for p in r["packages"]}, {"new"})
        runs = len(app.store.runs())
        app.api_inbox({"review": "1"})                         # unchanged folders are not re-reviewed
        self.assertEqual(len(app.store.runs()), runs)
        app.routes()[("POST", "/api/trust")]({}, b'{"pkgbase": "hello-vigil"}', {})
        by = {p["pkgbase"]: p for p in app.api_inbox({})["packages"]}
        self.assertEqual(by["hello-vigil"]["state"], "approved")
        pb = self.home / ".cache/paru/clone/hello-vigil/PKGBUILD"
        pb.write_text(pb.read_text() + "\n# changed upstream\n")
        by = {p["pkgbase"]: p for p in app.api_inbox({})["packages"]}
        self.assertEqual(by["hello-vigil"]["state"], "changed")


class PacmanLogTests(unittest.TestCase):
    def test_incident_window_and_hijacked_name(self):
        from .test_pkg import make_pacman_root
        with tempfile.TemporaryDirectory() as tmp:
            root = make_pacman_root(tmp)
            d = root / "var/lib/pacman/local/openconnect-sso-0.8.0-1"
            d.mkdir(parents=True)
            (d / "desc").write_text("%NAME%\nopenconnect-sso\n\n%VERSION%\n0.8.0-1\n\n%PACKAGER%\nUnknown Packager\n\n")
            (root / "var/log").mkdir(parents=True)
            (root / "var/log/pacman.log").write_text(
                "[2026-05-01T10:00:00+0200] [ALPM] installed hello-vigil (1.4.2-1)\n"
                "[2026-07-30T21:15:00+0200] [ALPM] upgraded openconnect-sso (0.7.9-1 -> 0.8.0-1)\n"
                "[2026-06-10 08:00] [ALPM] upgraded hello-vigil (1.4.1-1 -> 1.4.2-1)\n"
                "[2026-07-30T21:16:00+0200] [ALPM] running '30-systemd-update.hook'...\n")
            log = installed.pacman_log(str(root))
            self.assertEqual([a for _, a, _ in log["openconnect-sso"]], ["upgraded"])
            rep = installed.audit(str(root), ARCH, verify=False, now=1.0)
            self.assertTrue(rep["pacman_log"])
            by = {f["evidence"][0]["value"].split()[0]: f for f in rep["findings"] if f["check"] == "installed_hijack_window"}
            self.assertEqual(by["openconnect-sso"]["severity"], "High")          # named, and updated in the window
            self.assertIn("2026-07-30", by["openconnect-sso"]["summary"])
            self.assertEqual(by["hello-vigil"]["severity"], "Medium")            # updated during the June window
            self.assertEqual(by["hello-vigil"]["attack"][0]["id"], "T1195.002")

    def test_review_flags_hijacked_names(self):
        text = (FIX / "pkg/benign/PKGBUILD").read_text().replace("pkgname=hello-vigil", "pkgname=icloudpd")
        rep = review.review_files({"PKGBUILD": text}, osr=ARCH, save=False)
        f = next(f for f in rep["findings"] if f["check"] == "known_hijacked")
        self.assertEqual(f["severity"], "Medium")
        self.assertIn("2026-07-29", f["summary"])
        self.assertTrue(all(i["start"] <= i["end"] for i in names.INCIDENTS))


if __name__ == "__main__":
    unittest.main()
