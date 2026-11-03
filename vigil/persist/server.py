"""Vigil Persist's page and JSON API (127.0.0.1 only, via core.web)."""

import os
import threading
from pathlib import Path

from ..core import system, web
from ..core.store import FindingStore
from ..core.web import _json_body
from . import scan as scanner

STATIC = Path(__file__).resolve().parent / "static"


class App:
    def __init__(self, data_dir, home=None, root="/", proc="/proc", os_release_path=None):
        self.store = FindingStore("persist", data_dir)
        self.home = home or os.path.expanduser("~")
        self.root, self.proc = root, proc
        self.os_release_path = os_release_path or (os.path.join(root, "etc/os-release") if root != "/" else "/etc/os-release")
        self.last = None
        self.lock = threading.Lock()

    def close(self):
        self.store.close()

    def scan(self):
        """Scan; the first scan becomes the baseline. Returns the report."""
        with self.lock:
            base = self.store.baseline(scanner.BASELINE)
            rep = scanner.scan(self.home, self.root, self.proc, osr=system.os_release(self.os_release_path),
                               baseline=base if base[1] is not None else None)
            if base[1] is None:
                self.store.save_baseline(scanner.BASELINE, rep["current"])
                rep["baseline_at"] = self.store.baseline(scanner.BASELINE)[0]
                rep["baseline_created"] = True
            rep["run_id"] = self.store.add_run("autostart", rep["findings"],
                                               {"counts": rep["counts"], "entries": len(rep["entries"]),
                                                "diff": {k: len(v) for k, v in (rep["diff"] or {}).items()}})
            self.last = rep
            return {k: v for k, v in rep.items() if k != "current"}

    def accept(self):
        """Make the current state the new baseline (the user's explicit choice)."""
        with self.lock:
            if not self.last:
                raise ValueError("scan first, then accept")
            self.store.save_baseline(scanner.BASELINE, self.last["current"])
            return {"ok": True, "baseline_at": self.store.baseline(scanner.BASELINE)[0]}

    def api_status(self, q):
        ts, base = self.store.baseline(scanner.BASELINE)
        return {"tool": "persist", "home": self.home, "baseline_at": ts, "baseline_entries": len(base or {}),
                "runs": self.store.runs(20)}

    def routes(self):
        return {("GET", "/api/status"): self.api_status,
                ("POST", "/api/scan"): lambda q, b, h: self.scan(),
                ("POST", "/api/accept"): lambda q, b, h: (_json_body(b), self.accept())[1],
                ("GET", "/api/run"): lambda q: self.store.run(int(q.get("id", 0)))}


def make_server(app, port=8768, verbose=False):
    return web.make_server(app, port, verbose, static_dirs=[STATIC])


def serve(data_dir, port=8768, verbose=False):
    web.serve_tool(App(data_dir), "Vigil Persist", port, verbose, static_dirs=[STATIC])
