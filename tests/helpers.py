"""Shared test helpers. Everything these build is SYNTHETIC test data."""

import contextlib
import os
import shutil
from pathlib import Path
from unittest import mock

from vigil.net import collector

FIXTURES = Path(__file__).parent / "fixtures"


def make_proc(tmp):
    """Copy the synthetic /proc fixture into `tmp` and create its symlinks."""
    dst = Path(tmp) / "proc"
    shutil.copytree(FIXTURES / "proc", dst)
    for line in (dst / "links.txt").read_text().splitlines():
        if not line or line.startswith("#"):
            continue
        path, target = line.split(" -> ", 1)
        link = dst / path
        link.parent.mkdir(parents=True, exist_ok=True)
        os.symlink(target, link)
    return str(dst)


def unreadable_pids(proc):
    lines = Path(proc, "unreadable.txt").read_text().splitlines()
    return {int(x) for x in lines if x.strip().isdigit()}


@contextlib.contextmanager
def non_root_view(proc):
    """Simulate the kernel refusing /proc/<pid>/fd and exe for other users' processes.

    Tests usually run as root in containers, where real permissions would not bite.
    """
    blocked = unreadable_pids(proc)
    real_listdir, real_readlink = collector._listdir, collector._readlink

    def pid_of(path):
        head = os.path.relpath(path, proc).split(os.sep)[0]
        return int(head) if head.isdigit() else None

    def listdir(path):
        if path.endswith("/fd") and pid_of(path) in blocked:
            raise PermissionError(13, "Permission denied", path)
        return real_listdir(path)

    def readlink(path):
        if pid_of(path) in blocked:
            raise PermissionError(13, "Permission denied", path)
        return real_readlink(path)

    with mock.patch.object(collector, "_listdir", listdir), \
            mock.patch.object(collector, "_readlink", readlink):
        yield


def sock(remote_ip, remote_port, inode, program=None, pid=None, *, proto="tcp",
         state="ESTABLISHED", local_ip="192.168.1.50", local_port=50000, uid=1000,
         kind="connection", hidden=None, direction="out"):
    """A collector-shaped socket dict."""
    s = {"table": proto, "proto": proto, "local_ip": local_ip, "local_port": local_port,
         "remote_ip": remote_ip, "remote_port": remote_port, "state": state, "uid": uid,
         "inode": inode, "kind": kind, "direction": direction, "pid": pid,
         "pids": [pid] if pid else [],
         "program": program, "hidden": None}
    if program is None:
        reason = hidden or ("closed" if inode == 0 else "other-user")
        s["hidden"] = {"reason": reason, "label": collector.HIDDEN_LABELS[reason],
                       "explanation": f"synthetic {reason}"}
    return s


def proc(pid, key, name=None, uid=1000, user="alice", parent="bash"):
    return {"pid": pid, "key": key, "name": name or os.path.basename(key), "comm": name or key,
            "exe": key, "exe_deleted": False, "cmdline": [key], "uid": uid, "user": user,
            "ppid": 1, "parent": parent, "ancestry": [{"pid": 1, "name": parent}], "started": 0}


def snap(t, sockets, processes=()):
    """A collector-shaped snapshot taken at time t."""
    procs = {p["pid"]: p for p in processes}
    hidden = {}
    for s in sockets:
        if s["hidden"]:
            hidden[s["hidden"]["reason"]] = hidden.get(s["hidden"]["reason"], 0) + 1
    return {"taken_at": t, "proc_root": "synthetic", "sockets": sockets, "processes": procs,
            "viewer": {"uid": 1000, "user": "alice", "root": False}, "pids_visible": len(procs),
            "unreadable_by_uid": {}, "hidden_counts": hidden, "missing_tables": [],
            "hidepid": None}
