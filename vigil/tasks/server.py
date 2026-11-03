"""Vigil Tasks' page and JSON API (127.0.0.1 only, via core.web)."""

import os
import threading
from pathlib import Path

from ..core import system, web
from ..core.pkgdb import PackageFiles
from ..core.store import FindingStore
from . import findings as F
from . import procs as P

STATIC = Path(__file__).resolve().parent / "static"
FIELDS = ("pid", "ppid", "name", "comm", "path", "exe_deleted", "user", "uid", "started", "package", "sha256", "unit",
          "kernel", "children", "threads", "state", "cmdline")


class App:
    def __init__(self, data_dir, proc_root="/proc", root="/", os_release_path="/etc/os-release", home=None):
        self.store = FindingStore("tasks", data_dir)
        self.proc_root, self.root = proc_root, root
        self.os_release_path = os_release_path
        self.home = home
        self.pkg = PackageFiles(root)
        self.hasher = P.Hasher()
        self.lock = threading.Lock()

    def close(self):
        self.store.close()

    def take(self):
        with self.lock:
            snap = P.snapshot(self.proc_root, self.pkg, self.hasher, root=self.root)
            fs, per_pid = F.build(snap, system.os_release(self.os_release_path), self.home)
        return snap, fs, per_pid

    def api_tree(self, q):
        snap, fs, per_pid = self.take()
        nodes = {}
        for pid, p in snap["processes"].items():
            n = {k: p.get(k) for k in FIELDS}
            n["cmdline"] = " ".join(p["cmdline"])[:300]
            n["flags"] = per_pid.get(pid, [])
            n["net"] = sum(1 for s in p["sockets"] if s["kind"] == "connection")
            n["listen"] = sum(1 for s in p["sockets"] if s["kind"] == "listen")
            nodes[pid] = n
        return {"nodes": nodes, "roots": snap["roots"], "findings": fs, "taken_at": snap["taken_at"],
                "viewer_uid": snap["viewer_uid"], "package_db": snap["package_db"],
                "unreadable_exe": snap["unreadable_exe"],
                "note": None if snap["viewer_uid"] == 0 else
                "Vigil runs as you, so other users' processes (root's system services) show without their program "
                "file, hash or environment. Their names, parents and command lines are still visible."}

    def api_process(self, q):
        snap, fs, per_pid = self.take()
        pid = int(q.get("pid", 0))
        p = snap["processes"].get(pid)
        if not p:
            raise LookupError(f"process {pid} is not running")
        return dict({k: p.get(k) for k in FIELDS}, sockets=p["sockets"], ld=p["ld"],
                    ancestry=P.ancestry(snap["processes"], pid), flags=per_pid.get(pid, []),
                    findings=[f for f in fs if f["evidence"][0]["value"] == f"pid {pid}"])

    def api_scan(self, q, body, headers):
        snap, fs, _ = self.take()
        run = self.store.add_run("processes", fs, {"processes": len(snap["processes"]),
                                                  "counts": {s: sum(f["severity"] == s for f in fs) for s in
                                                             ("High", "Medium", "Low", "Info")}})
        return {"run_id": run, "findings": fs}

    def routes(self):
        return {("GET", "/api/tree"): self.api_tree, ("GET", "/api/process"): self.api_process,
                ("POST", "/api/scan"): self.api_scan}


def make_server(app, port=8769, verbose=False):
    return web.make_server(app, port, verbose, static_dirs=[STATIC])


def serve(data_dir, port=8769, verbose=False):
    web.serve_tool(App(data_dir), "Vigil Tasks", port, verbose, static_dirs=[STATIC])
