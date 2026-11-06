"""Vigil Files' page and JSON API (127.0.0.1 only, via core.web)."""

import hashlib
import os
import re
import stat
import threading
import time
import urllib.parse
from pathlib import Path

from ..core import finding as fmt
from ..core import system, web
from ..core.store import FindingStore
from ..core.web import BadRequest, _json_body
from . import engines, inspector, triage
from .quarantine import Quarantine, QuarantineError
from .watch import Watcher

STATIC = Path(__file__).resolve().parent / "static"
LIST_MAX = 2000
UPLOAD_MAX = 256 * 1024 * 1024
SWEEP_MAX = 300


def safe_name(name):
    """A file name from the browser, made harmless: no folders, no control characters."""
    name = os.path.basename((name or "").replace("\\", "/"))
    name = "".join(c for c in name if c.isprintable() and c not in "/\0")[:200].strip(". ")
    return name or "upload.bin"


def downloads_dir(home=None):
    """The user's Downloads folder: XDG_DOWNLOAD_DIR from user-dirs.dirs, else ~/Downloads."""
    home = home or os.path.expanduser("~")
    try:
        with open(os.path.join(home, ".config/user-dirs.dirs"), encoding="utf-8") as fh:
            for line in fh:
                m = re.match(r'^\s*XDG_DOWNLOAD_DIR="?([^"\n]+)"?', line)
                if m:
                    return m.group(1).replace("$HOME", home)
    except OSError:
        pass
    return os.path.join(home, "Downloads")


class App:
    def __init__(self, data_dir, os_release_path="/etc/os-release", home=None, requester=None):
        self.data_dir = Path(data_dir)
        self.store = FindingStore("files", self.data_dir)
        self.quarantine = Quarantine(self.data_dir / "quarantine")
        self.os_release_path = os_release_path
        self.downloads = downloads_dir(home)
        self.watcher = None
        self.requester = requester or engines.request_json   # tests replace the network
        self.sweep = {"running": False, "folder": None, "total": 0, "done": 0, "results": [], "started": None}
        self.sweep_lock = threading.Lock()

    def close(self):
        if self.watcher:
            self.watcher.stop()
        self.store.close()

    def osr(self):
        return system.os_release(self.os_release_path)

    def inspect(self, path):
        rep = triage.inspect_path(path, osr=self.osr(), downloads=self.downloads)
        rep["run_id"] = self.store.add_run(rep["path"], rep["findings"],
                                           {"verdict": rep["verdict"], "sha256": rep["hashes"].get("sha256"),
                                            "type": rep["type"].get("description"), "counts": rep.get("counts")})
        return rep

    # ---- API -----------------------------------------------------------------------------

    def api_status(self, q):
        return {"tool": "files", "downloads": self.downloads, "watching": bool(self.watcher and self.watcher.is_alive()),
                "watch_folder": self.watcher.folder if self.watcher else None, "quarantine": self.quarantine.status(),
                "runs": self.store.runs(30), "keys": {k: bool(self.key(k)) for k in ("virustotal", "malwarebazaar")}}

    def api_browse(self, q):
        """A safe explorer: names, sizes and the real type (from the first bytes). Nothing is opened
        with an application; folders are listed, files are read only to name their type."""
        default = self.downloads if os.path.isdir(self.downloads) else os.path.expanduser("~")
        folder = os.path.abspath(os.path.expanduser(q.get("path") or default))
        if not os.path.isdir(folder):
            raise BadRequest(f"{folder} is not a folder")
        rows = []
        with os.scandir(folder) as it:
            entries = sorted(it, key=lambda e: e.name.lower())
        for e in entries[:LIST_MAX]:
            try:
                st = e.stat(follow_symlinks=False)
            except OSError:
                continue
            row = {"name": e.name, "path": e.path, "size": st.st_size, "mtime": st.st_mtime,
                   "kind": "link" if stat.S_ISLNK(st.st_mode) else "dir" if stat.S_ISDIR(st.st_mode)
                   else "file" if stat.S_ISREG(st.st_mode) else "other", "runnable": bool(st.st_mode & 0o111),
                   "type": None, "flag": None}
            if row["kind"] == "file":
                try:
                    with open(e.path, "rb") as fh:
                        head = fh.read(8192)
                    fam = inspector.detect_type(head)
                    row["type"] = inspector.TYPE_NAMES.get(fam, fam)
                    quick = inspector.disguise_findings(e.name, fam)
                    if e.name.endswith(".desktop"):
                        row["flag"] = {"severity": "Medium", "text": "A launcher: double-clicking it runs a command"}
                    elif quick:
                        worst = max(quick, key=lambda f: f["points"])
                        row["flag"] = {"severity": triage.severity_of(worst["points"]), "text": worst["reason"]}
                except OSError:
                    row["type"] = "unreadable"
            rows.append(row)
        return {"folder": folder, "parent": os.path.dirname(folder), "entries": rows,
                "truncated": len(entries) > LIST_MAX}

    def api_inspect(self, q, body, headers):
        path = _json_body(body).get("path")
        if not path:
            raise BadRequest("give a file path")
        return self.inspect(os.path.expanduser(path))

    def api_upload(self, q, body, headers):
        """A file dropped on the page: saved to data/files/inbox/<sha256>/<name>, mode 0600 (never
        runnable), then inspected like any other file. Nothing is opened or run."""
        name = safe_name(urllib.parse.unquote(headers.get("X-Filename") or ""))
        if not body:
            raise BadRequest("empty file")
        digest = hashlib.sha256(body).hexdigest()
        d = self.data_dir / "inbox" / digest
        d.mkdir(parents=True, exist_ok=True, mode=0o700)
        p = d / name
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(body)
        os.chmod(p, 0o600)
        return self.inspect(str(p))

    def api_sweep_start(self, q, body, headers):
        """Check every file in one folder (not its subfolders), in the background."""
        folder = os.path.abspath(os.path.expanduser(_json_body(body).get("path") or self.downloads))
        if not os.path.isdir(folder):
            raise BadRequest(f"{folder} is not a folder")
        with self.sweep_lock:
            if self.sweep["running"]:
                raise BadRequest("a folder check is already running")
            files = sorted((e.path for e in os.scandir(folder) if e.is_file(follow_symlinks=False)
                            and not e.name.startswith(".")), key=lambda x: x.lower())[:SWEEP_MAX]
            self.sweep = {"running": True, "folder": folder, "total": len(files), "done": 0, "results": [],
                          "started": time.time()}
        threading.Thread(target=self._sweep, args=(files,), daemon=True, name="vigil-files-sweep").start()
        return self.api_sweep({})

    def _sweep(self, files):
        for path in files:
            try:
                rep = self.inspect(path)
                row = {"path": path, "name": rep["name"], "verdict": rep["verdict"], "counts": rep.get("counts"),
                       "type": rep["type"].get("description"), "size": rep["size"],
                       "top": next((f["title"] for f in rep["findings"] if f["severity"] in ("High", "Medium")), None)}
            except Exception as exc:  # one unreadable file must not stop the sweep
                row = {"path": path, "name": os.path.basename(path), "verdict": None, "error": f"{type(exc).__name__}: {exc}"}
            with self.sweep_lock:
                self.sweep["results"].append(row)
                self.sweep["done"] += 1
        with self.sweep_lock:
            self.sweep["running"] = False
            self.sweep["finished"] = time.time()

    def api_sweep(self, q):
        with self.sweep_lock:
            return dict(self.sweep, results=list(self.sweep["results"]))

    def api_preview(self, q):
        return triage.preview(q.get("path", ""))

    def api_run(self, q):
        return self.store.run(int(q.get("id", 0)))

    def api_quarantine_list(self, q):
        return {"items": self.quarantine.items(), "status": self.quarantine.status()}

    def api_quarantine(self, q, body, headers):
        d = _json_body(body)
        try:
            return self.quarantine.put(d.get("path", ""), d.get("reason", ""), d.get("sha256"))
        except (QuarantineError, OSError) as exc:
            raise BadRequest(str(exc))

    def api_restore(self, q, body, headers):
        d = _json_body(body)
        try:
            return self.quarantine.restore(d.get("id"), d.get("to") or None)
        except (QuarantineError, OSError) as exc:
            raise BadRequest(str(exc))

    def api_quarantine_delete(self, q, body, headers):
        try:
            return self.quarantine.delete(_json_body(body).get("id"))
        except (QuarantineError, OSError) as exc:
            raise BadRequest(str(exc))

    def api_watch(self, q, body, headers):
        d = _json_body(body)
        if self.watcher:
            self.watcher.stop()
            self.watcher = None
        if d.get("on"):
            folder = os.path.expanduser(d.get("folder") or self.downloads)
            if not os.path.isdir(folder):
                raise BadRequest(f"{folder} is not a folder")
            self.watcher = Watcher(folder, self.inspect, interval=float(d.get("interval", 3)))
            self.watcher.start()
        return self.api_status({})

    def api_watch_events(self, q):
        if not self.watcher:
            return {"events": [], "watching": False}
        return {"events": self.watcher.since(float(q.get("since", 0))), "watching": True, "now": time.time()}

    def key(self, service):
        env = {"virustotal": "VIGIL_VT_KEY", "malwarebazaar": "VIGIL_ABUSECH_KEY"}[service]
        return os.environ.get(env) or self.store.get_meta(f"key:{service}")

    def api_keys(self, q, body, headers):
        d = _json_body(body)
        if d.get("service") not in ("virustotal", "malwarebazaar"):
            raise BadRequest("unknown service")
        self.store.set_meta(f"key:{d['service']}", (d.get("key") or "").strip() or None)
        return self.api_status({})

    def api_lookup(self, q, body, headers):
        """Opt-in: send ONLY the file's SHA-256 to VirusTotal or MalwareBazaar."""
        d = _json_body(body)
        sha, service = (d.get("sha256") or "").lower(), d.get("service")
        fn = {"virustotal": engines.virustotal, "malwarebazaar": engines.malwarebazaar}.get(service)
        if not fn:
            raise BadRequest("unknown service")
        try:
            result = fn(sha, self.key(service), requester=self.requester)
        except engines.LookupError_ as exc:
            raise BadRequest(str(exc))
        out = []
        for f in engines.lookup_findings(service, result, fmt.scored):
            sev = triage.severity_of(f["points"])
            name = {"virustotal": "VirusTotal", "malwarebazaar": "MalwareBazaar"}[service]
            out.append(fmt.make("files", f"lookup_{service}", f"{name} knows this file" if f["points"] else
                                f"{name} engines don't detect this file",
                                f["reason"].rstrip(".") + ".", sev,
                                signals=[(f["reason"], min(1.0, f["points"] / 70))] if sev != "Info" else [],
                                confidence="High" if sev == "High" else "Low",
                                confidence_reason="Based on other people's scans of the exact same file.",
                                subject=f"{sha}:{service}", data=f["data"],
                                iocs=[{"type": "sha256", "value": sha}]))
        return {"service": service, "result": result, "findings": out}

    def routes(self):
        return {("GET", "/api/status"): self.api_status, ("GET", "/api/browse"): self.api_browse,
                ("POST", "/api/inspect"): self.api_inspect, ("GET", "/api/preview"): self.api_preview,
                ("GET", "/api/run"): self.api_run, ("GET", "/api/quarantine"): self.api_quarantine_list,
                ("POST", "/api/quarantine"): self.api_quarantine, ("POST", "/api/restore"): self.api_restore,
                ("POST", "/api/quarantine/delete"): self.api_quarantine_delete,
                ("POST", "/api/watch"): self.api_watch, ("GET", "/api/watch/events"): self.api_watch_events,
                ("POST", "/api/keys"): self.api_keys, ("POST", "/api/lookup"): self.api_lookup,
                ("POST", "/api/upload"): self.api_upload, ("POST", "/api/sweep"): self.api_sweep_start,
                ("GET", "/api/sweep"): self.api_sweep}


def make_server(app, port=8767, verbose=False):
    return web.make_server(app, port, verbose, max_body=UPLOAD_MAX, static_dirs=[STATIC])


def serve(data_dir, port=8767, verbose=False):
    web.serve_tool(App(data_dir), "Vigil Files", port, verbose, static_dirs=[STATIC], max_body=UPLOAD_MAX)
