"""Vigil Home (127.0.0.1:8760) and the launcher that runs every tool in one process.

    python3 -m vigil.suite            start Home and every tool, each on its own port
    python3 -m vigil.suite --no-net   ...without the Network Map's background monitor

A tool whose port is already taken (you started it on its own) is left alone and linked.
"""

import os
import sys
import threading
from pathlib import Path

from ..core import decisions as decisions_mod
from ..core import web
from ..core.store import default_data_dir
from ..core.suite import BY_ID, TOOLS
from ..core.web import BadRequest, _json_body
from . import checkup, overview

STATIC = Path(__file__).resolve().parent / "static"


class Home:
    def __init__(self, data_root, apps=None, running=None):
        self.root = Path(data_root)
        self.data_root = self.root
        self.tool_id = "home"
        self.apps = apps if apps is not None else {}
        self.running = running if running is not None else {}
        self.job = checkup.Job()
        self.runner = checkup.Runner(self.root, self.apps)

    def close(self):
        for a in self.apps.values():
            close = getattr(a, "close", None)
            if close:
                close()

    def stories(self):
        if "cases" not in self.apps and not (self.root / "cases" / "cases.db").exists():
            return []          # never create Cases' store just to look at it
        try:
            return self.runner.app("cases").api_stories({})["stories"][:5]
        except Exception:  # Home must render even if Cases' store is unreadable
            return []

    def api_overview(self, q):
        return overview.overview(self.root, self.running, self.job, self.stories())

    def api_checkup(self, q, body, headers):
        d = _json_body(body)
        steps = d.get("steps") or [s for s, _ in checkup.STEPS]
        bad = [s for s in steps if s not in dict(checkup.STEPS)]
        if bad:
            raise BadRequest(f"unknown step {bad[0]}")
        if not self.job.snapshot()["running"]:
            overview.remember_seen(self.root)   # before the check-up: so Home can say what is new after it
        started = self.job.start(self.runner, steps)
        return dict(self.job.snapshot(), started_now=started)

    def routes(self):
        r = {("GET", "/api/overview"): self.api_overview, ("POST", "/api/checkup"): self.api_checkup,
             ("GET", "/api/checkup"): lambda q: self.job.snapshot()}
        r.update(decisions_mod.routes(decisions_mod.Decisions(self.root)))
        return r


def make_server(app, port=8760, verbose=False):
    return web.make_server(app, port, verbose, static_dirs=[STATIC])


def _serve(httpd):
    threading.Thread(target=httpd.serve_forever, daemon=True, name=f"vigil-{httpd.server_address[1]}").start()


def launch(data_root=None, with_net=True, verbose=False, only=None):
    """Start every tool in this process. Returns (home httpd, cleanup function)."""
    root = Path(data_root or default_data_dir())
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    apps, running, servers, cleanups = {}, {}, [], []
    wanted = only or [t["id"] for t in TOOLS if t["id"] != "home"]

    def start(tid, make_app, make_srv):
        port = BY_ID[tid]["port"]
        try:
            app = make_app()
        except Exception as exc:
            print(f"  {BY_ID[tid]['name']:8} could not start: {exc}", file=sys.stderr)
            return
        try:
            httpd = make_srv(app, port, verbose)
        except OSError:
            print(f"  {BY_ID[tid]['name']:8} port {port} is busy (already running on its own?) — linked, not started")
            getattr(app, "close", lambda: None)()
            return
        apps[tid], running[tid] = app, True
        servers.append(httpd)
        _serve(httpd)
        print(f"  {BY_ID[tid]['name']:8} http://127.0.0.1:{port}/")

    if "tasks" in wanted:
        from ..tasks import server as s
        start("tasks", lambda: s.App(root / "tasks"), s.make_server)
    if "persist" in wanted:
        from ..persist import server as s
        start("persist", lambda: s.App(root / "persist"), s.make_server)
    if "files" in wanted:
        from ..files import server as s
        start("files", lambda: s.App(root / "files"), s.make_server)
    if "pkg" in wanted:
        from ..pkg import server as s
        start("pkg", lambda: s.App(root / "pkg"), s.make_server)
    if "cases" in wanted:
        from ..cases import server as s
        start("cases", lambda: s.App(root / "cases", root), s.make_server)
    if with_net and "net" in wanted:
        from ..net import server as ns
        from ..net.desktop import DataLock
        lock = DataLock(root)
        if lock.acquire():
            def make_net():
                return ns.App(str(root))
            try:
                httpd = ns.make_server(None, BY_ID["net"]["port"], verbose)
                httpd.app = make_net()
                lock.publish(httpd.server_address[1])
                servers.append(httpd)
                _serve(httpd)
                running["net"] = True
                cleanups.append(lambda: (httpd.app.monitor.stop(), lock.release()))
                print(f"  {'Net':8} http://127.0.0.1:{BY_ID['net']['port']}/")
            except OSError:
                lock.release()
                print(f"  Net      port {BY_ID['net']['port']} is busy — linked, not started")
        else:
            running["net"] = True
            print(f"  Net      already running (port {lock.running_port()}) — linked")
    home = Home(root, apps, running)
    httpd = make_server(home, BY_ID["home"]["port"], verbose)

    def stop():
        for s in servers:
            s.shutdown()
            s.server_close()
        for c in cleanups:
            c()
        home.close()
    return httpd, stop
