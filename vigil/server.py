"""Local web UI and JSON API, plus the background poller. Listens on 127.0.0.1 only."""

import json
import re
import sys
import threading
import time
import traceback
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from . import collector
from .store import Store, Tracker

HOST = "127.0.0.1"  # never configurable: Vigil is not a network service
STATIC = Path(__file__).resolve().parent.parent / "static"
STATIC_NAME = re.compile(r"^[a-z0-9_-]+\.(html|css|js|svg)$")
CONTENT_TYPES = {"html": "text/html; charset=utf-8", "css": "text/css; charset=utf-8",
                 "js": "text/javascript; charset=utf-8", "svg": "image/svg+xml"}
CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
       "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
SCOPE_NAMES = ("internet", "lan", "loopback", "link-local", "multicast", "reserved")


class Monitor(threading.Thread):
    """Polls /proc every `interval` seconds and feeds the tracker."""

    def __init__(self, tracker, interval=2.0, proc_root="/proc", keep_days=14):
        super().__init__(name="vigil-monitor", daemon=True)
        self.tracker, self.interval, self.proc_root = tracker, interval, proc_root
        self.keep_days = keep_days
        self.stopping = threading.Event()
        self.last_poll = self.last_duration = self.last_error = None
        self.last_stats = {}
        self.polls = 0
        self._last_prune = 0.0

    def poll_once(self):
        started = time.time()
        snap = collector.snapshot(self.proc_root, now=started)
        self.last_stats = self.tracker.ingest(snap)
        self.last_poll, self.last_duration = started, time.time() - started
        self.polls += 1
        if started - self._last_prune > 3600:
            self.tracker.store.prune(started, self.keep_days)
            self._last_prune = started

    def run(self):
        while not self.stopping.is_set():
            try:
                self.poll_once()
                self.last_error = None
            except Exception as exc:  # keep polling; surface the error in the UI
                self.last_error = f"{type(exc).__name__}: {exc}"
                traceback.print_exc()
            self.stopping.wait(self.interval)

    def stop(self):
        self.stopping.set()


class App:
    """Everything the request handlers need."""

    def __init__(self, data_dir, interval=2.0, proc_root="/proc", start_monitor=True):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.store = Store(str(self.data_dir / "vigil.db"))
        self.tracker = Tracker(self.store)
        self.monitor = Monitor(self.tracker, interval, proc_root)
        if start_monitor:
            self.monitor.start()

    # ---- API ---------------------------------------------------------------

    def api_status(self, q):
        m, snap = self.monitor, self.tracker.latest
        status = {"now": time.time(), "interval": m.interval, "polls": m.polls,
                  "last_poll": m.last_poll, "last_duration": m.last_duration,
                  "last_error": m.last_error, "db": str(self.store.path),
                  "baseline_at": self.store.get_meta("baseline_at")}
        if snap:
            # Loopback-to-loopback sockets never leave the machine (and include the UI's
            # own requests), so they are counted apart from the ones that matter.
            hidden, examples, loopback_hidden = {}, {}, 0
            for s in snap["sockets"]:
                if not s["hidden"]:
                    continue
                if (collector.scope_of(s["local_ip"]) == "loopback" and
                        collector.scope_of(s["remote_ip"]) in ("loopback", "unspecified")):
                    loopback_hidden += 1
                    continue
                reason = s["hidden"]["reason"]
                hidden[reason] = hidden.get(reason, 0) + 1
                examples.setdefault(reason, s["hidden"]["explanation"])
            hidden = [{"reason": r, "count": n, "label": collector.HIDDEN_LABELS[r],
                       "explanation": examples[r]} for r, n in sorted(hidden.items())]
            status.update({
                "loopback_hidden": loopback_hidden,
                "viewer": snap["viewer"], "pids_visible": snap["pids_visible"],
                "sockets": len(snap["sockets"]),
                "attributed": sum(1 for s in snap["sockets"] if s["program"]),
                "hidden": hidden, "missing_tables": snap["missing_tables"],
                "hidepid": snap["hidepid"],
                "unreadable": [{"uid": uid, "user": collector.username(uid), "processes": n}
                               for uid, n in sorted(snap["unreadable_by_uid"].items())]})
        return status

    def api_graph(self, q):
        window = int(q.get("window", "900"))
        scopes = [s for s in q.get("scopes", "internet,lan").split(",") if s in SCOPE_NAMES]
        return self.tracker.graph(window=window, scopes=scopes)

    def api_program(self, q):
        return self.tracker.program_detail(q.get("key", "")) or _not_found()

    def api_destination(self, q):
        return self.tracker.destination_detail(q.get("ip", "")) or _not_found()

    def api_listeners(self, q):
        return {"listeners": self.tracker.listeners()}

    def routes(self):
        return {
            ("GET", "/api/status"): self.api_status,
            ("GET", "/api/graph"): self.api_graph,
            ("GET", "/api/program"): self.api_program,
            ("GET", "/api/destination"): self.api_destination,
            ("GET", "/api/listeners"): self.api_listeners,
        }


class NotFound(Exception):
    pass


class BadRequest(Exception):
    pass


def _not_found():
    raise NotFound()


class Handler(BaseHTTPRequestHandler):
    server_version = "Vigil"
    sys_version = ""
    # Keep-alive: the UI polls every few seconds, and a fresh TCP connection per poll
    # would fill the map's own "closed before attribution" count with Vigil's traffic.
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # quiet unless asked
        if self.server.verbose:
            sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def _send(self, code, body, ctype="application/json; charset=utf-8", extra=None):
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def _host_ok(self):
        """Refuse requests whose Host is not us: blocks DNS-rebinding attacks from web pages."""
        port = self.server.server_address[1]
        return self.headers.get("Host", "") in (f"127.0.0.1:{port}", f"localhost:{port}")

    def _write_ok(self):
        """State-changing requests must come from Vigil's own page (custom header + origin)."""
        port = self.server.server_address[1]
        origin = self.headers.get("Origin")
        if origin and origin not in (f"http://127.0.0.1:{port}", f"http://localhost:{port}"):
            return False
        return self.headers.get("X-Vigil") == "1"

    def _dispatch(self, method):
        if not self._host_ok():
            return self._send(403, {"error": "unexpected Host header"})
        url = urllib.parse.urlsplit(self.path)
        q = dict(urllib.parse.parse_qsl(url.query))
        app = self.server.app
        handler = app.routes().get((method, url.path))
        if method != "GET":
            self.close_connection = True  # never leave an unread body on a kept-alive socket
        if handler:
            if method != "GET" and not self._write_ok():
                return self._send(403, {"error": "request did not come from the Vigil page"})
            try:
                if method == "GET":
                    result = handler(q)
                else:
                    length = int(self.headers.get("Content-Length") or 0)
                    if length > self.server.max_body:
                        raise BadRequest(f"body larger than {self.server.max_body} bytes")
                    result = handler(q, self.rfile.read(length), self.headers)
            except NotFound:
                return self._send(404, {"error": "not found"})
            except (BadRequest, ValueError) as exc:
                return self._send(400, {"error": str(exc)})
            if isinstance(result, tuple):  # (bytes, content type, extra headers)
                return self._send(200, result[0], result[1], result[2] if len(result) > 2 else None)
            return self._send(200, result)
        if method == "GET":
            return self._static(url.path)
        return self._send(404, {"error": "not found"})

    def _static(self, path):
        name = "index.html" if path in ("/", "/index.html") else path.removeprefix("/static/")
        if not STATIC_NAME.match(name) or not (STATIC / name).is_file():
            return self._send(404, {"error": "not found"})
        ctype = CONTENT_TYPES[name.rsplit(".", 1)[1]]
        self._send(200, (STATIC / name).read_bytes(), ctype)

    def do_GET(self):
        self._dispatch("GET")

    def do_HEAD(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    def do_PUT(self):
        self._dispatch("PUT")

    def do_DELETE(self):
        self._dispatch("DELETE")


def make_server(app, port=8765, verbose=False, max_body=100 * 1024 * 1024):
    httpd = ThreadingHTTPServer((HOST, port), Handler)
    httpd.daemon_threads = True
    httpd.app, httpd.verbose, httpd.max_body = app, verbose, max_body
    return httpd


def serve(data_dir, port=8765, interval=2.0, verbose=False):
    app = App(data_dir, interval)
    httpd = make_server(app, port, verbose)
    print(f"Vigil is watching. Open http://{HOST}:{httpd.server_address[1]}/  (Ctrl+C to stop)")
    print(f"Evidence store: {app.store.path}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        app.monitor.stop()
        httpd.server_close()
