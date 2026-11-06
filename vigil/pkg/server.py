"""Vigil Pkg's page and JSON API (127.0.0.1 only, via core.web)."""

import json
import os
import threading
from pathlib import Path

from ..core import system, web
from ..core.web import BadRequest, _json_body
from . import inbox, installed, parse, review

STATIC = Path(__file__).resolve().parent / "static"
MAX_FILES_BODY = 8 * 1024 * 1024


class App:
    def __init__(self, data_dir, os_release_path="/etc/os-release", fs_root="/", fetcher=None, home=None):
        self.data_dir = Path(data_dir)
        self.store = review.open_store(self.data_dir)
        self.trusted = review.Trusted(self.store)
        self.os_release_path, self.fs_root = os_release_path, fs_root
        self.fetcher = fetcher            # tests replace the network; None means the real one
        self.home = home or os.path.expanduser("~")
        self.lock = threading.Lock()
        self.last = {}                    # pkgbase -> (files, folder) of the last review, for Approve

    def close(self):
        self.store.close()

    def osr(self):
        return system.os_release(self.os_release_path)

    def _input(self, body):
        d = _json_body(body)
        if d.get("path"):
            files, notes = review.read_folder(d["path"])
            return files, os.path.abspath(os.path.expanduser(d["path"])), notes, d
        files = d.get("files")
        if isinstance(files, dict) and isinstance(files.get("PKGBUILD"), str):
            if sum(len(v) for v in files.values() if isinstance(v, str)) > MAX_FILES_BODY:
                raise BadRequest("files too large")
            return {k: v for k, v in files.items() if isinstance(v, str)}, None, [], d
        raise BadRequest("give a folder path, or the PKGBUILD text")

    def api_status(self, q):
        osr = self.osr()
        return {"tool": "pkg", "data": str(self.data_dir), "distro": {"name": osr.get("PRETTY_NAME"), "family": system.family(osr)},
                "trusted": self.trusted.all(), "runs": self.store.runs(30)}

    def api_review(self, q, body, headers):
        files, folder, notes, d = self._input(body)
        rep = review.review_files(files, folder=folder, notes=notes, store=self.store, osr=self.osr())
        self.last[rep["package"]["pkgbase"]] = (files, folder)
        return rep

    def api_aur(self, q, body, headers):
        """Opt-in network call: AUR metadata for the package (sends its name only)."""
        files, folder, notes, d = self._input(body)
        from . import parse
        s = parse.Script(files["PKGBUILD"])
        name = s.get("pkgbase") or (s.array("pkgname") or [None])[0]
        if not name:
            raise BadRequest("no pkgname in the PKGBUILD")
        kw = {"fetcher": self.fetcher} if self.fetcher else {}
        try:
            info = review.aur_info(name, **kw)
        except RuntimeError as exc:
            raise BadRequest(str(exc))
        rep = review.review_files(files, folder=folder, notes=notes, store=self.store, osr=self.osr(),
                                  aur=info if info.get("found") else None)
        rep["aur_lookup"] = {"package": name, "found": info.get("found", False)}
        return rep

    def api_trust(self, q, body, headers):
        d = _json_body(body)
        pkgbase = d.get("pkgbase")
        if pkgbase not in self.last:
            raise BadRequest("review the package first, then approve that version")
        files, folder = self.last[pkgbase]
        from . import parse
        s = parse.Script(files["PKGBUILD"])
        self.trusted.approve(pkgbase, files, f"{s.get('pkgver')}-{s.get('pkgrel')}")
        return {"ok": True, "trusted": self.trusted.all()}

    def api_forget(self, q, body, headers):
        self.trusted.forget(_json_body(body).get("pkgbase"))
        return {"ok": True, "trusted": self.trusted.all()}

    def api_run(self, q):
        return self.store.run(int(q.get("id", 0)))

    def api_installed(self, q):
        rep = installed.audit(self.fs_root, self.osr(), verify=q.get("verify", "1") == "1")
        if rep["supported"]:
            self.store.add_run("installed", rep["findings"], {"foreign": len(rep["foreign"]), "how": rep["how"]})
        return rep

    def api_inbox(self, q):
        """Packages your AUR helper downloaded, with their review state. review=1 reviews the
        new or changed ones (text only), so the list shows a verdict for each."""
        pkgs, helpers = inbox.find(self.home)
        seen = self.store.get_meta("inbox", {}) or {}
        out = []
        for p in pkgs:
            try:
                text = open(os.path.join(p["path"], "PKGBUILD"), encoding="utf-8", errors="replace").read()
            except OSError:
                continue
            sc = parse.Script(text)
            base = sc.get("pkgbase") or (sc.array("pkgname") or [p["name"]])[0]
            ver = f"{sc.get('pkgver')}-{sc.get('pkgrel')}"
            t = self.trusted.get(base)
            state = ("approved" if t and (t.get("files") or {}).get("PKGBUILD") == text else
                     "changed" if t else "new")
            row = dict(p, pkgbase=base, version=ver, state=state,
                       approved_version=t.get("version") if t else None)
            key = f"{p['path']}|{p['mtime']}"
            cached = seen.get(p["path"])
            if cached and cached.get("key") == key:
                row.update(verdict=cached.get("verdict"), counts=cached.get("counts"), top=cached.get("top"))
            elif q.get("review") == "1":
                try:
                    rep = review.review_folder(p["path"], store=self.store, osr=self.osr())
                    self.last[rep["package"]["pkgbase"]] = review.read_folder(p["path"])[0], p["path"]
                    top = next((f["title"] for f in rep["findings"] if f["severity"] in ("High", "Medium")), None)
                    row.update(verdict=rep["verdict"], counts=rep["counts"], top=top)
                    seen[p["path"]] = {"key": key, "verdict": rep["verdict"], "counts": rep["counts"], "top": top}
                except (OSError, ValueError) as exc:
                    row.update(verdict=None, error=str(exc))
            out.append(row)
        if q.get("review") == "1":
            self.store.set_meta("inbox", seen)
        return {"helpers": helpers, "packages": out, "home": self.home}

    def routes(self):
        return {("GET", "/api/status"): self.api_status, ("GET", "/api/inbox"): self.api_inbox,
                ("POST", "/api/review"): self.api_review,
                ("POST", "/api/aur"): self.api_aur,
                ("POST", "/api/trust"): self.api_trust,
                ("POST", "/api/forget"): self.api_forget,
                ("GET", "/api/run"): self.api_run,
                ("GET", "/api/installed"): self.api_installed}


def make_server(app, port=8766, verbose=False):
    return web.make_server(app, port, verbose, max_body=MAX_FILES_BODY + 65536, static_dirs=[STATIC])


def serve(data_dir, port=8766, verbose=False):
    web.serve_tool(App(data_dir), "Vigil Pkg", port, verbose, static_dirs=[STATIC], max_body=MAX_FILES_BODY + 65536)


def as_json(rep):
    return json.dumps(rep, indent=2, default=str)
