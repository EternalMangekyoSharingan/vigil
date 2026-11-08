"""The local web server every Vigil tool uses: 127.0.0.1 only, strict headers, and a
page that can only talk to its own server.

A tool supplies an app object with `routes()` -> {(method, path): handler}. GET
handlers take (query); others take (query, body bytes, headers). Handlers return a
JSON-able value, or (bytes, content type[, extra headers]). Anything else under
/static/ is served from the tool's folder, then the shared UI kit (vigil/ui/static).
"""

import json
import re
import sys
import traceback
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HOST = "127.0.0.1"  # never configurable: Vigil is not a network service
UI_STATIC = Path(__file__).resolve().parent.parent / "ui" / "static"
STATIC_NAME = re.compile(r"^(?:fonts/)?[A-Za-z0-9_-]+\.(html|css|js|svg|woff2|txt)$")
CONTENT_TYPES = {"html": "text/html; charset=utf-8", "css": "text/css; charset=utf-8",
                 "js": "text/javascript; charset=utf-8", "svg": "image/svg+xml",
                 "woff2": "font/woff2", "txt": "text/plain; charset=utf-8"}
CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
       "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")


def static_file(dirs, name):
    """The first file called `name` in `dirs`, or None. Names are a strict pattern
    (one optional fonts/ folder, no dots before the extension), so no traversal."""
    if not STATIC_NAME.match(name):
        return None
    for d in dirs:
        p = Path(d) / name
        if p.is_file():
            return p
    return None


class NotFound(Exception):
    pass


class BadRequest(Exception):
    pass


def _not_found():
    raise NotFound()


# ---- routes every tool gets: shared settings and Run ------------------------------------------
# GET  /api/vigil/settings  -> Run mode, interface preferences, and whether this tool can run
# POST /api/vigil/settings  -> change them (data/settings.json, shared by every tool)
# POST /api/vigil/run       -> Run mode: run one command this tool generated (core.runner rules)
# A tool can run commands only if its app has run_allowed(source, ref) -> set of command texts,
# re-generated or looked up server-side; text from the page is never trusted.

def _data_root(app):
    from .store import default_data_dir
    return getattr(app, "data_root", None) or default_data_dir()


def builtin_routes(app):
    from . import runner, settings

    def get_settings(q):
        return dict(settings.public(_data_root(app)), can_run=hasattr(app, "run_allowed"))

    def set_settings(q, body, headers):
        req = _json_body(body)
        before = settings.run_mode(_data_root(app))
        out = settings.update(_data_root(app), req)
        if out["run_mode"] != before:
            log = getattr(app, "run_log", None) or settings.RunLog(_data_root(app), getattr(app, "tool_id", "?"))
            log.event(None, "setting", f"Run mode switched {'on' if out['run_mode'] else 'off'}", "Settings panel")
        return dict(out, can_run=hasattr(app, "run_allowed"))

    def run(q, body, headers):
        if not hasattr(app, "run_allowed"):
            raise BadRequest("this tool shows commands to copy only")
        if not settings.run_mode(_data_root(app)):
            raise BadRequest("Run mode is off: switch it on in Settings, or copy the command")
        req = _json_body(body)
        allowed = app.run_allowed(str(req.get("source") or ""), req.get("ref"))
        log = getattr(app, "run_log", None) or settings.RunLog(_data_root(app), getattr(app, "tool_id", "?"))
        try:
            return runner.run(str(req.get("command") or ""), allowed, store=log)
        except runner.Refused as exc:
            raise BadRequest(str(exc)) from None

    return {("GET", "/api/vigil/settings"): get_settings, ("POST", "/api/vigil/settings"): set_settings,
            ("POST", "/api/vigil/run"): run}


def _json_body(body):
    try:
        data = json.loads(body or b"{}")
    except ValueError:
        raise BadRequest("body must be JSON")
    if not isinstance(data, dict):
        raise BadRequest("body must be a JSON object")
    return data


class Handler(BaseHTTPRequestHandler):
    server_version = "Vigil"
    sys_version = ""
    # Keep-alive: the UI polls every few seconds, and a fresh TCP connection per poll
    # would fill the map's own "closed before attribution" count with Vigil's traffic.
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # quiet unless asked
        if self.server.verbose:
            sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def _send(self, code, body, ctype="application/json; charset=utf-8", extra=None,
              cache="no-store"):
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", cache)
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
        handler = app.routes().get((method, url.path)) or builtin_routes(app).get((method, url.path))
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
            except (NotFound, LookupError) as exc:
                return self._send(404, {"error": str(exc) or "not found"})
            except (BadRequest, ValueError) as exc:
                return self._send(400, {"error": str(exc)})
            except Exception as exc:  # report it rather than dropping the connection
                traceback.print_exc()
                return self._send(500, {"error": f"{type(exc).__name__}: {exc}"})
            if isinstance(result, tuple):  # (bytes, content type, extra headers)
                return self._send(200, result[0], result[1], result[2] if len(result) > 2 else None)
            return self._send(200, result)
        if method == "GET":
            return self._static(url.path)
        return self._send(404, {"error": "not found"})

    def _static(self, path):
        name = "index.html" if path in ("/", "/index.html") else path.removeprefix("/static/")
        found = static_file(self.server.static_dirs, name)
        if not found:
            return self._send(404, {"error": "not found"})
        ext = name.rsplit(".", 1)[1]
        cache = "max-age=604800, immutable" if ext == "woff2" else "no-store"
        self._send(200, found.read_bytes(), CONTENT_TYPES[ext], cache=cache)

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


class Server(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):
        if isinstance(sys.exc_info()[1], ConnectionError):
            return  # a browser or test closed a kept-alive connection: not an error
        super().handle_error(request, client_address)


def make_server(app, port=8765, verbose=False, max_body=100 * 1024 * 1024, static_dirs=None):
    """A server on 127.0.0.1 only. `static_dirs`: the tool's own static folder first,
    then the shared UI kit, so every tool gets the same theme, fonts and components."""
    httpd = Server((HOST, port), Handler)
    httpd.daemon_threads = True
    httpd.app, httpd.verbose, httpd.max_body = app, verbose, max_body
    httpd.static_dirs = [Path(d) for d in (static_dirs or [])] + [UI_STATIC]
    return httpd


def serve_tool(app, name, port, verbose=False, static_dirs=None, max_body=100 * 1024 * 1024):
    """Run one tool's page until Ctrl+C. Used by every tool except Net, which has its
    own lock and monitor thread."""
    try:
        httpd = make_server(app, port, verbose, max_body=max_body, static_dirs=static_dirs)
    except OSError as exc:
        sys.exit(f"Cannot listen on {HOST}:{port}: {exc.strerror}. Is it already running? "
                 "Choose another port with --port.")
    print(f"{name} is ready. Open http://{HOST}:{httpd.server_address[1]}/  (Ctrl+C to stop)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
        close = getattr(app, "close", None)
        if close:
            close()
