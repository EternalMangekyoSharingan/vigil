"""Local web UI and JSON API, plus the background poller. Listens on 127.0.0.1 only."""

import ipaddress
import json
import re
import sys
import threading
import time
import traceback
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from . import cases, collector, enrich, inspector, scoring
from .store import Store, Tracker

HOST = "127.0.0.1"  # never configurable: Vigil is not a network service
STATIC = Path(__file__).resolve().parent.parent / "static"
STATIC_NAME = re.compile(r"^(?:fonts/)?[A-Za-z0-9_-]+\.(html|css|js|svg|woff2|txt)$")
CONTENT_TYPES = {"html": "text/html; charset=utf-8", "css": "text/css; charset=utf-8",
                 "js": "text/javascript; charset=utf-8", "svg": "image/svg+xml",
                 "woff2": "font/woff2", "txt": "text/plain; charset=utf-8"}
CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
       "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
SCOPE_NAMES = ("internet", "lan", "loopback", "link-local", "multicast", "reserved")


class Monitor(threading.Thread):
    """Polls /proc every `interval` seconds and feeds the tracker."""

    def __init__(self, tracker, interval=2.0, proc_root="/proc", keep_days=14, scorer=None,
                 score_every=30.0):
        super().__init__(name="vigil-monitor", daemon=True)
        self.tracker, self.interval, self.proc_root = tracker, interval, proc_root
        self.keep_days = keep_days
        self.scorer, self.score_every = scorer, score_every
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
        if self.scorer and (self.scorer.last_run is None or
                            started - self.scorer.last_run >= self.score_every):
            self.scorer.run(started)
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
        self.allowlist = scoring.Allowlist(str(self.data_dir / "allowlist.json"))
        self.scorer = scoring.Scorer(self.store, self.allowlist, interval)
        self.enricher = enrich.Enricher(self.store, self.data_dir)
        self.scorer.extra.append(self.enricher)
        self.cases = cases.Cases(self.store, self.tracker, self.enricher, proc_root)
        self.monitor = Monitor(self.tracker, interval, proc_root, scorer=self.scorer)
        if start_monitor:
            self.monitor.start()

    # ---- API ---------------------------------------------------------------

    def api_status(self, q):
        m, snap = self.monitor, self.tracker.latest
        status = {"now": time.time(), "interval": m.interval, "polls": m.polls,
                  "last_poll": m.last_poll, "last_duration": m.last_duration,
                  "last_error": m.last_error, "db": str(self.store.path),
                  "baseline_at": self.store.get_meta("baseline_at"),
                  "alert_threshold": self.scorer.threshold,
                  "last_scored_at": self.store.get_meta("last_scored_at"),
                  "alerts_open": self.store.one("SELECT COUNT(*) n FROM alerts"
                                                " WHERE status='open'")["n"]}
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
                "byte_counts": snap.get("byte_counts", False),
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
        g = self.tracker.graph(window=window, scopes=scopes)
        for d in g["destinations"]:
            d["label"] = self.enricher.label(d["ip"])
            d["intel"] = sorted({h["feed"] for h in self.enricher.intel(d["ip"])})
        return g

    def api_program(self, q):
        return self.tracker.program_detail(q.get("key", "")) or _not_found()

    def api_destination(self, q):
        d = self.tracker.destination_detail(q.get("ip", "")) or _not_found()
        d["enrichment"] = self.enricher.describe(d["ip"])
        return d

    def api_intel_status(self, q):
        return self.enricher.status()

    def api_intel_update(self, q, body, headers):
        """Downloads happen here and only here: the user pressed an update button."""
        what = _json_body(body).get("what")
        if what == "feeds":
            results = self.enricher.update_feeds()
        elif what == "geo":
            results = [self.enricher.update_geo()]
        else:
            raise BadRequest("what must be feeds or geo")
        self.scorer.run()
        return {"results": results, "status": self.enricher.status()}

    def api_inspect(self, q, body, headers):
        """Static triage of uploaded bytes. The file stays in memory; only the report is kept."""
        name = urllib.parse.unquote(headers.get("X-Filename") or "upload")[:255] or "upload"
        report = inspector.inspect_bytes(body, name)
        inspector.link_context(report, self.store, self.enricher)
        return inspector.save(self.store, report, "upload via the Vigil page")

    def api_inspections(self, q):
        return {"inspections": self.store.query(
            "SELECT id, name, size, sha256, type, verdict, score, inspected_at, source"
            " FROM inspections ORDER BY inspected_at DESC LIMIT 200")}

    def api_inspection(self, q):
        row = self.store.one("SELECT report FROM inspections WHERE id=?", (int(q.get("id") or 0),))
        return json.loads(row["report"]) if row else _not_found()

    def api_inspection_delete(self, q, body, headers):
        with self.store.lock, self.store.db:
            cur = self.store.db.execute("DELETE FROM inspections WHERE id=?", (int(q.get("id") or 0),))
        if not cur.rowcount:
            raise NotFound()
        return {"ok": True}

    # ---- cases ----------------------------------------------------------------------

    def api_cases(self, q):
        return {"cases": self.cases.list()}

    def api_case_create(self, q, body, headers):
        req = _json_body(body)
        return self.cases.create(req.get("title"), req.get("tags") or [], req.get("summary") or "")

    def api_case(self, q):
        return self.cases.get(int(q.get("id") or 0))

    def api_case_update(self, q, body, headers):
        req = _json_body(body)
        return self.cases.update(int(req.get("id") or 0), **{k: req.get(k) for k in
                                                             ("title", "status", "tags", "summary")})

    def api_case_note(self, q, body, headers):
        req = _json_body(body)
        return self.cases.note(int(req.get("id") or 0), req.get("text"))

    def api_case_item(self, q, body, headers):
        req = _json_body(body)
        return self.cases.add_item(int(req.get("id") or 0), req.get("kind"), req.get("ref"))

    def api_case_item_remove(self, q, body, headers):
        return self.cases.remove_item(int(q.get("id") or 0), int(q.get("item") or 0))

    def api_case_ioc(self, q, body, headers):
        req = _json_body(body)
        return self.cases.add_ioc(int(req.get("id") or 0), str(req.get("type") or ""),
                                  str(req.get("value") or ""), str(req.get("context") or ""))

    def api_case_ioc_exclude(self, q, body, headers):
        req = _json_body(body)
        return self.cases.set_excluded(int(req.get("id") or 0), int(req.get("ioc") or 0),
                                       bool(req.get("excluded")))

    def api_case_export(self, q):
        cid, fmt = int(q.get("id") or 0), q.get("format")
        if fmt == "csv":
            data, ctype, ext = self.cases.export_csv(cid).encode(), "text/csv; charset=utf-8", "csv"
        elif fmt == "stix":
            data = json.dumps(self.cases.export_stix(cid), indent=2).encode()
            ctype, ext = "application/stix+json;version=2.1", "stix.json"
        elif fmt == "md":
            data, ctype, ext = self.cases.export_markdown(cid).encode(), "text/markdown; charset=utf-8", "md"
        else:
            raise BadRequest("format must be csv, stix or md")
        return data, ctype, {"Content-Disposition": f'attachment; filename="vigil-case-{cid}.{ext}"'}

    def api_lookup(self, q):
        """Everything Vigil knows offline about one address."""
        try:
            ip = str(ipaddress.ip_address(q.get("ip", "").strip()))
        except ValueError:
            raise BadRequest("not an IP address")
        return {"ip": ip, "scope": collector.scope_of(ip), **self.enricher.describe(ip),
                "seen": self.tracker.destination_detail(ip)}

    def api_listeners(self, q):
        return {"listeners": self.tracker.listeners()}

    def api_alerts(self, q):
        status = q.get("status", "open")
        where, args = ("", ()) if status == "all" else ("WHERE a.status=?", (status,))
        rows = self.store.query(
            f"SELECT a.*, p.name, p.hidden FROM alerts a LEFT JOIN programs p ON p.key=a.program"
            f" {where} ORDER BY a.status='open' DESC, a.score DESC, a.last_updated DESC", args)
        for r in rows:
            r["findings"] = json.loads(r["findings"])
            r["ports"] = json.loads(r["ports"] or "[]")
        return {"alerts": rows, "threshold": self.scorer.threshold}

    def api_alert_update(self, q, body, headers):
        req = _json_body(body)
        status = req.get("status")
        if status not in ("open", "dismissed"):
            raise BadRequest("status must be open or dismissed")
        alert = self.store.one("SELECT * FROM alerts WHERE id=?", (int(req.get("id", 0)),))
        if not alert:
            raise NotFound()
        note = str(req.get("note") or "")[:2000]
        now = time.time()
        with self.store.lock, self.store.db:
            self.store.db.execute("UPDATE alerts SET status=?, note=?, last_updated=? WHERE id=?",
                                  (status, note, now, alert["id"]))
            self.store._event(now, "alert_status",
                              f"Alert #{alert['id']} marked {status}" + (f": {note}" if note else ""),
                              "analyst (Vigil UI)", program=alert["program"], ip=alert["ip"],
                              port=alert["port"], proto=alert["proto"],
                              detail={"alert_id": alert["id"], "status": status})
        return {"ok": True}

    def api_allowlist(self, q):
        return {"rules": self.allowlist.rules()}

    def api_allowlist_add(self, q, body, headers):
        rule = self.allowlist.add(_json_body(body))
        self.scorer.run()  # so the map and alerts reflect the rule immediately
        return {"rule": rule}

    def api_allowlist_enable(self, q, body, headers):
        if not self.allowlist.enable(str(_json_body(body).get("id", ""))):
            raise NotFound()
        self.scorer.run()
        return {"ok": True}

    def api_allowlist_remove(self, q, body, headers):
        if not self.allowlist.remove(q.get("id", "")):
            raise NotFound()
        self.scorer.run()
        return {"ok": True}

    def routes(self):
        return {
            ("GET", "/api/status"): self.api_status,
            ("GET", "/api/graph"): self.api_graph,
            ("GET", "/api/program"): self.api_program,
            ("GET", "/api/destination"): self.api_destination,
            ("GET", "/api/listeners"): self.api_listeners,
            ("GET", "/api/alerts"): self.api_alerts,
            ("POST", "/api/alerts/update"): self.api_alert_update,
            ("GET", "/api/allowlist"): self.api_allowlist,
            ("POST", "/api/allowlist"): self.api_allowlist_add,
            ("DELETE", "/api/allowlist"): self.api_allowlist_remove,
            ("POST", "/api/allowlist/enable"): self.api_allowlist_enable,
            ("GET", "/api/intel"): self.api_intel_status,
            ("POST", "/api/intel/update"): self.api_intel_update,
            ("GET", "/api/lookup"): self.api_lookup,
            ("POST", "/api/inspect"): self.api_inspect,
            ("GET", "/api/inspections"): self.api_inspections,
            ("GET", "/api/inspection"): self.api_inspection,
            ("DELETE", "/api/inspection"): self.api_inspection_delete,
            ("GET", "/api/cases"): self.api_cases,
            ("POST", "/api/cases"): self.api_case_create,
            ("GET", "/api/case"): self.api_case,
            ("POST", "/api/case/update"): self.api_case_update,
            ("POST", "/api/case/note"): self.api_case_note,
            ("POST", "/api/case/item"): self.api_case_item,
            ("DELETE", "/api/case/item"): self.api_case_item_remove,
            ("POST", "/api/case/ioc"): self.api_case_ioc,
            ("POST", "/api/case/ioc/exclude"): self.api_case_ioc_exclude,
            ("GET", "/api/case/export"): self.api_case_export,
        }


class NotFound(Exception):
    pass


class BadRequest(Exception):
    pass


def _not_found():
    raise NotFound()


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
        if not STATIC_NAME.match(name) or not (STATIC / name).is_file():
            return self._send(404, {"error": "not found"})
        ext = name.rsplit(".", 1)[1]
        cache = "max-age=604800, immutable" if ext == "woff2" else "no-store"
        self._send(200, (STATIC / name).read_bytes(), CONTENT_TYPES[ext], cache=cache)

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
    from .desktop import DataLock
    lock = DataLock(data_dir)
    if not lock.acquire():  # two pollers would record every connection twice
        running = lock.running_port()
        sys.exit("Vigil is already running with this data directory"
                 + (f": open http://{HOST}:{running}/" if running else "."))
    try:
        httpd = make_server(None, port, verbose)
    except OSError as exc:
        lock.release()
        sys.exit(f"Cannot listen on {HOST}:{port}: {exc.strerror}. Is Vigil already running? "
                 f"Choose another port with --port.")
    app = httpd.app = App(data_dir, interval)
    lock.publish(httpd.server_address[1])
    print(f"Vigil is watching. Open http://{HOST}:{httpd.server_address[1]}/  (Ctrl+C to stop)")
    print(f"Evidence store: {app.store.path}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        app.monitor.stop()
        httpd.server_close()
        lock.release()
