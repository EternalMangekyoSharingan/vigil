"""Watch Downloads: new files are checked as they arrive.

Polling, standard library only (inotify needs ctypes, which inspection modules don't
load): every few seconds the folder's top level is listed; a file counts as arrived when
its size and mtime have stayed the same for two looks (so half-downloaded files and
browser .part files are skipped). Each arrival is inspected with triage.inspect_path
and becomes an event. The page shows events as they come and, if you allow it, a
desktop notification through the browser; the terminal command prints them.
"""

import os
import threading
import time

PARTIAL = (".part", ".crdownload", ".download", ".tmp", ".partial", ".opdownload")


class Watcher(threading.Thread):
    def __init__(self, folder, on_new, interval=3.0, clock=time.time):
        super().__init__(daemon=True, name="vigil-files-watch")
        self.folder = os.path.abspath(os.path.expanduser(folder))
        self.on_new = on_new          # callback(path) -> report
        self.interval = interval
        self.clock = clock
        self.seen = {}                # name -> (size, mtime) already handled
        self.pending = {}             # name -> (size, mtime) seen once, waiting to settle
        self.events = []
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self.errors = 0
        self.prime()

    def prime(self):
        """Files already there when watching starts are not 'new'."""
        for name, sig in self._scan().items():
            self.seen[name] = sig

    def _scan(self):
        out = {}
        try:
            with os.scandir(self.folder) as it:
                for e in it:
                    if e.name.startswith(".") or e.name.endswith(PARTIAL):
                        continue
                    try:
                        st = e.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    if e.is_file(follow_symlinks=False):
                        out[e.name] = (st.st_size, st.st_mtime_ns)
        except OSError:
            self.errors += 1
        return out

    def tick(self):
        """One look. Returns the events created."""
        now = self._scan()
        made = []
        for name, sig in now.items():
            if self.seen.get(name) == sig:
                continue
            if self.pending.get(name) == sig:      # unchanged for two looks: it has arrived
                self.pending.pop(name)
                self.seen[name] = sig
                path = os.path.join(self.folder, name)
                try:
                    rep = self.on_new(path)
                    ev = {"at": self.clock(), "path": path, "verdict": rep["verdict"], "counts": rep.get("counts"),
                          "top": rep["findings"][0]["title"] if rep.get("findings") else None,
                          "run_id": rep.get("run_id")}
                except Exception as exc:  # a bad file must not stop the watcher
                    ev = {"at": self.clock(), "path": path, "verdict": None, "error": f"{type(exc).__name__}: {exc}"}
                made.append(ev)
            else:
                self.pending[name] = sig
        for name in list(self.seen):
            if name not in now:
                self.seen.pop(name)
        with self.lock:
            self.events.extend(made)
            self.events = self.events[-200:]
        return made

    def since(self, ts):
        with self.lock:
            return [e for e in self.events if e["at"] > ts]

    def run(self):
        while not self.stop_event.wait(self.interval):
            self.tick()

    def stop(self):
        self.stop_event.set()
