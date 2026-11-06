"""The one-click check-up: every tool's read-only check, one after another, in the
background. A step that fails is reported and the rest still run.

Steps (each also runnable alone from Home):
    tasks    what is running (Vigil Tasks)
    persist  what starts by itself, diffed against the baseline (Vigil Persist)
    files    new or changed files in Downloads (Vigil Files)
    pkg      AUR packages waiting in the helper's cache, and installed foreign packages (Vigil Pkg)
    net      the Network Map's alerts, exported as findings (Vigil Net, if it has run)
    cases    everything imported into one timeline, with storylines (Vigil Cases)
"""

import os
import threading
import time
from pathlib import Path

STEPS = [
    ("tasks", "Look at running programs"),
    ("persist", "Check what starts by itself"),
    ("files", "Check new files in Downloads"),
    ("pkg", "Review AUR packages and installed foreign packages"),
    ("net", "Collect the Network Map's alerts"),
    ("cases", "Put everything on one timeline"),
]
SWEEP_MAX = 300                   # files looked at per Downloads sweep
SWEEP_SIZE_MAX = 1024 * 1024 * 1024


class Job:
    def __init__(self):
        self.lock = threading.Lock()
        self.state = {"running": False, "steps": [], "started": None, "finished": None}

    def snapshot(self):
        with self.lock:
            return {k: (list(map(dict, v)) if k == "steps" else v) for k, v in self.state.items()}

    def start(self, runner, steps):
        with self.lock:
            if self.state["running"]:
                return False
            self.state = {"running": True, "started": time.time(), "finished": None,
                          "steps": [{"id": s, "label": dict(STEPS)[s], "status": "waiting", "detail": ""} for s in steps]}
        threading.Thread(target=self._run, args=(runner, steps), daemon=True, name="vigil-checkup").start()
        return True

    def _set(self, sid, **kw):
        with self.lock:
            for s in self.state["steps"]:
                if s["id"] == sid:
                    s.update(kw)

    def _run(self, runner, steps):
        for sid in steps:
            self._set(sid, status="running", started=time.time())
            try:
                detail = runner.step(sid)
                self._set(sid, status="done", detail=detail or "", finished=time.time())
            except Exception as exc:  # a broken step must never stop the others
                self._set(sid, status="failed", detail=f"{type(exc).__name__}: {exc}", finished=time.time())
        with self.lock:
            self.state["running"] = False
            self.state["finished"] = time.time()


class Runner:
    """Runs each step against the tool apps (shared with the suite's servers when running)."""

    def __init__(self, data_root, apps, home=None):
        self.root = Path(data_root)
        self.apps = apps              # {"tasks": App, ...}; created on demand when missing
        self.home = home or os.path.expanduser("~")
        self.lock = threading.Lock()

    def app(self, tool):
        with self.lock:
            if tool not in self.apps:
                if tool == "tasks":
                    from ..tasks.server import App
                    self.apps[tool] = App(self.root / "tasks")
                elif tool == "persist":
                    from ..persist.server import App
                    self.apps[tool] = App(self.root / "persist")
                elif tool == "files":
                    from ..files.server import App
                    self.apps[tool] = App(self.root / "files")
                elif tool == "pkg":
                    from ..pkg.server import App
                    self.apps[tool] = App(self.root / "pkg")
                elif tool == "cases":
                    from ..cases.server import App
                    self.apps[tool] = App(self.root / "cases", self.root)
            return self.apps[tool]

    def step(self, sid):
        return getattr(self, f"step_{sid}")()

    def step_tasks(self):
        r = self.app("tasks").api_scan({}, b"{}", {})
        bad = [f for f in r["findings"] if f["severity"] in ("High", "Medium")]
        return f"{len(r['findings'])} flags, {len(bad)} worth a look"

    def step_persist(self):
        r = self.app("persist").scan()
        d = r.get("diff") or {}
        if r.get("baseline_created"):
            return f"{len(r['entries'])} autostart entries; this scan is your baseline"
        return (f"{len(r['entries'])} autostart entries; {len(d.get('added', []))} new, "
                f"{len(d.get('changed', []))} changed since the baseline")

    def step_files(self):
        app = self.app("files")
        folder = app.downloads if os.path.isdir(app.downloads) else None
        if not folder:
            return "no Downloads folder"
        seen = app.store.get_meta("sweep", {}) or {}
        checked = flagged = 0
        now_seen = {}
        entries = sorted(os.scandir(folder), key=lambda e: -e.stat(follow_symlinks=False).st_mtime)[:SWEEP_MAX]
        for e in entries:
            if not e.is_file(follow_symlinks=False) or e.name.startswith("."):
                continue
            st = e.stat(follow_symlinks=False)
            sig = [st.st_size, st.st_mtime_ns]
            now_seen[e.path] = sig
            if seen.get(e.path) == sig or st.st_size > SWEEP_SIZE_MAX:
                continue
            rep = app.inspect(e.path)
            checked += 1
            flagged += rep["verdict"] != "No suspicious indicators found"
        app.store.set_meta("sweep", now_seen)
        return f"{checked} new or changed files checked, {flagged} need a look ({len(now_seen)} in Downloads)"

    def step_pkg(self):
        app = self.app("pkg")
        parts = []
        inbox = app.api_inbox({"review": "1"})
        if inbox["helpers"]:
            n = sum(1 for p in inbox["packages"] if p.get("verdict") and p["verdict"] != "Looks normal")
            parts.append(f"{len(inbox['packages'])} packages in your AUR helper's cache, {n} worth a look")
        rep = app.api_installed({"verify": "1"})
        if rep["supported"]:
            parts.append(f"{len(rep['foreign'])} foreign packages installed")
        else:
            parts.append("no pacman database (not Arch)")
        return "; ".join(parts)

    def step_net(self):
        from ..net import export
        r = export.export(self.root)
        if not r:
            return "the Network Map hasn't run yet"
        return f"{r[1]} alerts collected"

    def step_cases(self):
        app = self.app("cases")
        from ..cases import importer
        res = importer.import_all(app.store, self.root, refresh_net=False)
        added = sum(r.get("added", 0) for r in res)
        stories = app.api_stories({})["stories"]
        return f"{added} new findings imported; {len(stories)} storylines"
