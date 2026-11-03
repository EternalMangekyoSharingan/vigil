"""Local web UI and JSON API, plus the background poller. Listens on 127.0.0.1 only."""

import ipaddress
import concurrent.futures
import json
import os
import re
import sys
import threading
import time
import zipfile
import traceback
import urllib.parse
from pathlib import Path

from ..core import catalogue as services, commands, pkgdb, runner, web
from ..core.web import CSP, CONTENT_TYPES, HOST, STATIC_NAME, BadRequest, Handler, NotFound, _json_body, _not_found  # noqa: F401
from ..files import engines, inspector
from . import cleanup, fixes, identify, wording, cases, collector, enrich, knowledge, scans, scoring
from .store import Store, Tracker


EXE_MAX = 512 * 1024 * 1024  # largest executable read for "inspect executable"
STATIC = Path(__file__).resolve().parent / "static"
SCOPE_NAMES = ("internet", "lan", "loopback", "link-local", "multicast", "reserved")


def make_server(app, port=8765, verbose=False, max_body=100 * 1024 * 1024):
    return web.make_server(app, port, verbose, max_body, static_dirs=[STATIC])


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
        self.fast_until = 0.0  # "look more often": poll every 0.5 s until then

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
            self.stopping.wait(0.5 if time.time() < self.fast_until else self.interval)

    def stop(self):
        self.stopping.set()


class App:
    """Everything the request handlers need."""

    def __init__(self, data_dir, interval=2.0, proc_root="/proc", start_monitor=True):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.store = Store(str(self.data_dir / "vigil.db"))
        self.report_lock = threading.Lock()     # load-modify-save of a stored report
        self.clamav_slot = threading.Semaphore(1)
        self.clamav_threads = []
        self.os_release_path = "/etc/os-release"  # tests point these at fixtures
        self.fs_root = "/"
        self.home = os.path.expanduser("~")
        self.last_cleanup = None
        self.scan = {"running": False, "results": None}
        self.scan_lock = threading.Lock()
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
                                                " WHERE status='open'")["n"],
                  "fast_poll_until": m.fast_until, "sudo_mode": self.sudo_mode()}
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
        for p in g["programs"]:
            k = knowledge.lookup_program(p["info"].get("exe"), p["name"], p["key"])
            p["title"] = k["title"] if k else None
        ids = self.identities([d["ip"] for d in g["destinations"]])
        for d in g["destinations"]:
            d["label"] = self.enricher.label(d["ip"])
            d["intel"] = sorted({h["feed"] for h in self.enricher.intel(d["ip"])})
            d["transport"] = _transports(d.get("ports") or [])
            i = ids.get(d["ip"])
            if i:  # from the last "Identify": best host name, a tab, the TLS summary
                d["host"] = (i["hosts"] or [None])[0]
                d["tab"] = (i["tabs"] or [{}])[0].get("title")
                d["security"] = {"level": i["level"], "label": i["badges"][0]["label"] if i["badges"] else None}
        return g

    def identities(self, ips):
        if not ips:
            return {}
        rows = self.store.query(f"SELECT ip, data FROM identities WHERE ip IN ({','.join('?' * len(ips))})", tuple(ips))
        return {r["ip"]: json.loads(r["data"]) for r in rows}

    def api_tabs(self, q):
        """Open browser tabs (local session files; no network). Host and title only."""
        return {"tabs": identify.open_tabs()}

    def api_identify(self, q, body, headers):
        """Who is behind each address, and how secure the connection is. Network: only because
        the user pressed Identify. Looks up the host names of open tabs with the system
        resolver, then makes one TLS handshake per HTTPS destination to read its certificate.
        Never contacts an address a threat feed lists."""
        req = _json_body(body)
        scopes = [x for x in (req.get("scopes") or ["internet"]) if x in ("internet", "reserved")]
        g = self.tracker.graph(window=int(req.get("window") or 900), scopes=scopes)
        dests = {d["ip"]: d for d in g["destinations"]}
        wanted = [ip for ip in (req.get("ips") or list(dests)) if ip in dests][:60]
        tabs = identify.open_tabs()
        resolved = identify.resolve({t["host"] for t in tabs})
        by_ip = {}
        for host, ips in resolved.items():
            for ip in ips:
                by_ip.setdefault(ip, set()).add(host)
        hsts = identify.hsts_hosts()
        skipped = [ip for ip in wanted if self.enricher.intel(ip)]
        targets = [ip for ip in wanted if ip not in skipped and "tcp/443" in (dests[ip].get("ports") or [])]

        def probe(ip):
            sni = sorted(by_ip.get(ip, []), key=len)[0] if by_ip.get(ip) else None
            return ip, identify.tls_probe(ip, 443, sni=sni)
        probes = {}
        with concurrent.futures.ThreadPoolExecutor(8) as ex:
            for ip, t in ex.map(probe, targets):
                probes[ip] = t
        now = time.time()
        out = []
        for ip in wanted:
            if ip in skipped:
                continue
            t = probes.get(ip)
            dns_hosts = sorted(by_ip.get(ip, []))
            san = ((t or {}).get("cert") or {}).get("san") or []
            hosts = dns_hosts + [h for h in san if h not in dns_hosts]
            matched = []
            for tab in tabs:
                via = "dns" if tab["host"] in by_ip.get(ip, ()) else \
                    "certificate" if any(identify.name_matches(tab["host"], p) for p in san) else None
                if via:
                    matched.append(dict(tab, via=via))
            matched.sort(key=lambda x: (x["via"] != "dns", x["kind"] != "tab", -(x["last_accessed"] or 0)))
            is_hsts = any(h in hsts or any(h.endswith("." + x) for x in hsts) for h in dns_hosts + [m["host"] for m in matched])
            badges = identify.tls_badges(t, hsts=is_hsts) if t else []
            data = {"ip": ip, "hosts": hosts, "dns_hosts": dns_hosts, "tabs": matched[:20], "tls": t,
                    "badges": badges, "level": identify.summary_level(badges) if badges else None,
                    "checked_at": now}
            with self.store.lock, self.store.db:
                self.store.db.execute("INSERT OR REPLACE INTO identities(ip, data, checked_at) VALUES(?,?,?)",
                                      (ip, json.dumps(data), now))
            out.append(data)
        return {"identified": len(out), "probed": len(probes), "tabs": len(tabs),
                "skipped_listed": skipped, "results": out}

    def api_program(self, q):
        d = self.tracker.program_detail(q.get("key", "")) or _not_found()
        d["about"] = knowledge.about_program(d, self.enricher)
        exe = ((d.get("info") or {}).get("exe") or d["name"]).lower()
        browsers = {b.lower() for b, _ in identify.FIREFOX_FAMILY} | {b.lower() for b, _ in identify.CHROMIUM_FAMILY}
        if any(b in exe for b in browsers | {"chrome", "brave", "firefox"}):  # a browser: list its tabs (local)
            tabs = [t for t in identify.open_tabs() if t["browser"].lower() in exe
                    or (t["browser"] == "Chrome" and "chrome" in exe)]
            ids = self.store.query("SELECT ip, data FROM identities")
            where = {}
            for r in ids:
                i = json.loads(r["data"])
                for t in i["tabs"]:
                    where.setdefault(t["host"], set()).add(r["ip"])
            d["tabs"] = [dict(t, ips=sorted(where.get(t["host"], ()))) for t in tabs]
        for c in d.get("connections") or []:
            pi = knowledge.port_info(c["proto"], c["remote_port"] if c["direction"] == "out" else c["local_port"])
            c["port_name"] = pi["service"] if pi else None
        d["why"] = wording.why_node(d, self.scorer.threshold, True, base_ctx={"poll": self.monitor.interval})
        return d

    def api_program_inspect(self, q, body, headers):
        """Static triage of a program's executable, read through /proc/<pid>/exe.

        Bytes only: the binary is never run. Works for deleted executables too.
        """
        d = self.tracker.program_detail(str(_json_body(body).get("key", ""))) or _not_found()
        info = d.get("info") or {}
        if d.get("hidden") or not info.get("pid"):
            raise BadRequest("this program has no attributable process, so there is no executable to read")
        path = f"{self.monitor.proc_root}/{info['pid']}/exe"
        try:
            with open(path, "rb") as fh:
                data = fh.read(EXE_MAX + 1)
        except OSError as exc:
            raise BadRequest(f"cannot read {path} ({exc.strerror}): the process has exited, or it "
                             f"belongs to another user") from None
        if len(data) > EXE_MAX:
            raise BadRequest(f"the executable is larger than {EXE_MAX // 2**20} MB")
        name = os.path.basename((info.get("exe") or d["name"]).removesuffix(" (deleted)"))
        report = inspector.inspect_bytes(data, name)
        scan = inspector.clamav_plan(report)
        report["about_program"] = {"key": d["key"], "pid": info["pid"], "exe": info.get("exe"),
                                   "owner": knowledge.package_owner(info.get("exe"))}
        inspector.link_context(report, self.store, self.enricher)
        inspector.save(self.store, report, f"executable of {d['name']} (pid {info['pid']}), "
                                           f"read via /proc/{info['pid']}/exe")
        if scan:
            self.clamav_later(report["id"], data)
        return report

    def api_destination(self, q):
        d = self.tracker.destination_detail(q.get("ip", "")) or _not_found()
        d["enrichment"] = self.enricher.describe(d["ip"])
        d["about"] = knowledge.about_destination(d, self.enricher)
        d["transport"] = _transports(sorted({f"{p['proto']}/{p['port']}" for p in d.get("pairs") or []}))
        d["identity"] = self.identities([d["ip"]]).get(d["ip"])
        d["why"] = wording.why_node(d, self.scorer.threshold, False, base_ctx={"poll": self.monitor.interval})
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
        scan = inspector.clamav_plan(report)
        inspector.link_context(report, self.store, self.enricher)
        inspector.save(self.store, report, "upload via the Vigil page")
        if scan:
            self.clamav_later(report["id"], body)
        return report

    def clamav_later(self, report_id, data):
        """Run ClamAV after the report is returned, so a slow scan never holds up the page.
        One scan at a time: clamscan without the daemon can use about 1 GB of memory."""
        def work():
            with self.clamav_slot:
                result = engines.clamav_scan(data)
            with self.report_lock:
                row = self.store.one("SELECT report FROM inspections WHERE id=?", (report_id,))
                if row:  # the report may have been deleted meanwhile
                    inspector.resave(self.store, inspector.clamav_apply(json.loads(row["report"]), result))
        t = threading.Thread(target=work, name=f"clamav-{report_id}", daemon=True)
        self.clamav_threads.append(t)
        t.start()

    def api_inspection_lookup(self, q, body, headers):
        """Hash lookup on VirusTotal or MalwareBazaar. Network: only because the user pressed
        the button. Sends the file's SHA-256 (and the API key), never the file."""
        req = _json_body(body)
        service = req.get("service")
        if service not in ("virustotal", "malwarebazaar"):
            raise BadRequest("service must be virustotal or malwarebazaar")
        row = self.store.one("SELECT report FROM inspections WHERE id=?", (int(req.get("id") or 0),))
        if not row:
            raise NotFound()
        sha = json.loads(row["report"])["hashes"]["sha256"]
        try:
            if service == "virustotal":
                result = engines.virustotal(sha, self.lookup_key("virustotal"))
            else:
                result = engines.malwarebazaar(sha, self.enricher.auth_key())
        except engines.LookupError_ as exc:
            raise BadRequest(str(exc)) from None
        with self.report_lock:  # a background ClamAV scan may have updated it meanwhile
            report = json.loads(self.store.one("SELECT report FROM inspections WHERE id=?",
                                               (int(req.get("id") or 0),))["report"])
            inspector.apply_lookup(report, service, result)
            return inspector.resave(self.store, report)

    def lookup_key(self, service):
        if service == "virustotal":
            return os.environ.get("VIGIL_VT_KEY") or self.enricher.settings().get("virustotal_api_key")
        return self.enricher.auth_key()

    def api_keys(self, q):
        """Which keys are set (never the keys themselves), and whether ClamAV is installed."""
        return {"virustotal": bool(self.lookup_key("virustotal")),
                "abusech": bool(self.lookup_key("abusech")),
                "clamav": engines.clamav_version()}

    def api_keys_set(self, q, body, headers):
        """Save or clear an API key in data/settings.json (readable by this user only)."""
        req = _json_body(body)
        field = {"virustotal": "virustotal_api_key", "abusech": "abusech_auth_key"}.get(req.get("service"))
        if not field:
            raise BadRequest("service must be virustotal or abusech")
        key = str(req.get("key") or "").strip()
        if key and not re.fullmatch(r"[A-Za-z0-9_\-]{16,128}", key):
            raise BadRequest("that does not look like an API key")
        settings = self.enricher.settings()
        if key:
            settings[field] = key
        else:
            settings.pop(field, None)
        path = self.enricher.data_dir / "settings.json"
        tmp = path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            json.dump(settings, fh, indent=2)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
        return self.api_keys(q)

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
            ctx = self.alert_context(r)
            r["view"] = wording.present(ctx)
            r["service_id"] = (ctx["service"] or {}).get("id")
        return {"alerts": rows, "threshold": self.scorer.threshold,
                "fast_poll_until": self.monitor.fast_until}

    def alert_context(self, a):
        """Everything wording.py needs about one alert, from local data only."""
        prog = self.store.one("SELECT * FROM programs WHERE key=?", (a["program"],)) or {}
        info = json.loads(prog.get("info") or "{}")
        hidden = None
        if a["program"].startswith("hidden:"):
            hidden = a["program"].split(":")[1]
        geo = self.enricher.geo(a["ip"]) if a.get("ip") else None
        ident = self.identities([a["ip"]]).get(a["ip"]) or {}
        timer = next((f.get("stats") for f in a["findings"] if (f.get("stats") or {}).get("signal") == "timer"), None)
        ctx = {"program": a["program"], "name": prog.get("name") or a.get("name"), "hidden": hidden, "info": info,
               "ip": a["ip"], "port": a["port"], "proto": a["proto"], "direction": a["direction"],
               "score": a["score"], "findings": a["findings"], "first_raised": a["first_raised"],
               "hosts": ident.get("hosts") or [], "geo": geo, "scope": collector.scope_of(a["ip"]),
               "poll": self.monitor.interval}
        ctx["service"] = services.match(
            process=None if hidden else services.process_name(a["program"], info),
            port=a["port"], proto=a["proto"], hosts=ctx["hosts"], owner=(geo or {}).get("owner"),
            interval=(timer or {}).get("interval"))
        return ctx

    def api_alert_fix(self, q):
        """Check / Fix / Undo commands for one alert: text to copy. Vigil never runs them."""
        a = self.store.one("SELECT a.*, p.name FROM alerts a LEFT JOIN programs p ON p.key=a.program WHERE a.id=?",
                           (int(q.get("id") or 0),)) or _not_found()
        a["findings"] = json.loads(a["findings"])
        ctx = self.alert_context(a)
        exe = (ctx["info"].get("exe") or "").removesuffix(" (deleted)") or None
        return fixes.options({"ip": a["ip"], "program": a["program"], "hidden": bool(ctx["hidden"])},
                             fixes.os_release(self.os_release_path), fixes.firewall(self.fs_root),
                             exe=exe, service=ctx["service"])

    # ---- sudo mode -------------------------------------------------------------------------

    def sudo_mode(self):
        return bool(self.enricher.settings().get("sudo_mode"))

    def api_settings_set(self, q, body, headers):
        """Switch sudo mode on or off (off by default)."""
        req = _json_body(body)
        settings = self.enricher.settings()
        settings["sudo_mode"] = bool(req.get("sudo_mode"))
        path = self.enricher.data_dir / "settings.json"
        fd = os.open(f"{path}.tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            json.dump(settings, fh, indent=2)
        os.replace(f"{path}.tmp", path)
        self.store.event(time.time(), "setting", f"Sudo mode switched {'on' if settings['sudo_mode'] else 'off'}",
                          "Settings tab")
        return {"sudo_mode": settings["sudo_mode"]}

    def allowed_commands(self, source, ref):
        """Re-generate, server-side, the commands a page section showed: only these may run."""
        if source == "fix":
            f = self.api_alert_fix({"id": ref})
            return {c["text"] for sec in ("check", "fix", "undo") for o in f[sec] for c in (o.get("commands") or []) + (o.get("undo") or [])}
        if source == "cleanup":
            items = (self.last_cleanup or {}).get("items") or []
            return cleanup.commands_for(items)
        if source == "scan":
            res = self.scan.get("results") or {}
            return {c for r in res.get("findings", []) for c in r.get("commands", []) + r.get("check", [])}
        return set()

    def api_run(self, q, body, headers):
        """Sudo mode: run one generated command after the user pressed Run. pkexec asks for
        the password in the system's own dialog; Vigil never sees it."""
        if not self.sudo_mode():
            raise BadRequest("sudo mode is off: switch it on in Settings, or copy the command")
        req = _json_body(body)
        try:
            return runner.run(str(req.get("command") or ""), self.allowed_commands(req.get("source"), req.get("ref")),
                              store=self.store)
        except runner.Refused as exc:
            raise BadRequest(str(exc)) from None

    # ---- cleanup and scans -------------------------------------------------------------------

    def api_cleanup(self, q):
        self.last_cleanup = cleanup.survey(self.home, self.fs_root, fixes.os_release(self.os_release_path))
        items = [dict(i, commands_tokens=_tokens(i["commands"])) for i in self.last_cleanup["items"]]
        return dict(self.last_cleanup, items=items, sudo_mode=self.sudo_mode())

    def api_scan_status(self, q):
        res = self.scan.get("results")
        if res is None:
            try:
                with open(self.data_dir / "scan-last.json") as fh:
                    res = self.scan["results"] = json.load(fh)
            except (OSError, ValueError):
                res = None
        if res:
            res = dict(res, findings=[dict(f, commands_tokens=_tokens(f.get("commands", [])),
                                           check_tokens=_tokens(f.get("check", []))) for f in res["findings"]])
        return {"running": self.scan["running"], "results": res, "tools": scans.tools(str(self.data_dir)),
                "sudo_mode": self.sudo_mode(), "folders": scans.default_folders(self.home)}

    def api_scan(self, q, body, headers):
        """Quick scan now (startup items, exposure, running programs, advisories); a full scan
        also runs ClamAV and YARA over folders, in the background."""
        req = _json_body(body)
        full = req.get("kind") == "full"
        with self.scan_lock:
            if self.scan["running"]:
                raise BadRequest("a scan is already running")
            self.scan["running"] = True
        try:
            osr = fixes.os_release(self.os_release_path)
            fam = fixes.family(osr)
            state_path = self.data_dir / "scan-state.json"
            try:
                with open(state_path) as fh:
                    prev = json.load(fh)
            except (OSError, ValueError):
                prev = {}
            findings, state = scans.persistence(self.home, self.fs_root, prev)
            snap = collector.snapshot(self.monitor.proc_root)
            findings += scans.exposure(snap, self.fs_root) + scans.integrity(snap, fam)
            adv_at = None
            if fam == "arch":
                adv_at, adv = scans.advisories(str(self.data_dir), pkgdb.pacman_installed(self.fs_root))
                findings += adv
            with open(f"{state_path}.tmp", "w") as fh:
                json.dump(state, fh)
            os.replace(f"{state_path}.tmp", state_path)
            res = {"kind": "full" if full else "quick", "started": time.time(), "finished": None if full else time.time(),
                   "findings": findings, "notes": [], "baseline": not prev, "advisories_at": adv_at,
                   "folders": [f for f in (req.get("folders") or scans.default_folders(self.home)) if os.path.isdir(f)]}
            if not prev:
                res["notes"].append("First scan: this becomes the baseline. Later scans flag what is new or changed.")
            if fam != "arch":
                res["notes"].append("The security-advisory check covers Arch Linux only for now.")
            self.scan["results"] = res
        except Exception:
            self.scan["running"] = False
            raise
        if not full:
            self._save_scan()
            self.scan["running"] = False
            return res
        threading.Thread(target=self._full_scan, name="vigil-scan", daemon=True).start()
        return res

    def _full_scan(self):
        res = self.scan["results"]
        try:
            t = scans.tools(str(self.data_dir))
            f, note = scans.clamav_folders(res["folders"])
            res["findings"] += f
            if note:
                res["notes"].append(note)
            f, note = scans.yara_folders(res["folders"], t["yara_rules"])
            res["findings"] += f
            if note:
                res["notes"].append(note)
        except Exception as exc:
            res["notes"].append(f"The scan stopped early: {type(exc).__name__}: {exc}")
        finally:
            res["finished"] = time.time()
            self._save_scan()
            self.scan["running"] = False

    def _save_scan(self):
        res = self.scan["results"]
        with open(self.data_dir / "scan-last.json.tmp", "w") as fh:
            json.dump(res, fh)
        os.replace(self.data_dir / "scan-last.json.tmp", self.data_dir / "scan-last.json")
        n = sum(1 for r in res["findings"] if r["severity"] in ("high", "medium"))
        self.store.event(time.time(), "scan", f"{res['kind'].capitalize()} system scan: {n} item(s) worth a look",
                          "Scan tab")

    def api_scan_update(self, q, body, headers):
        """Downloads, only because the user pressed the button."""
        what = _json_body(body).get("what")
        try:
            if what == "yara":
                return scans.update_yara(str(self.data_dir))
            if what == "advisories":
                return scans.update_advisories(str(self.data_dir))
        except (RuntimeError, ValueError, zipfile.BadZipFile) as exc:
            raise BadRequest(f"download failed: {exc}") from None
        raise BadRequest("what must be yara or advisories")

    def api_monitor_fast(self, q, body, headers):
        """Poll every 0.5 s for a while, to catch short-lived connections' owners."""
        minutes = max(0, min(30, int(_json_body(body).get("minutes", 10))))
        self.monitor.fast_until = time.time() + minutes * 60 if minutes else 0.0
        return {"fast_poll_until": self.monitor.fast_until}

    def api_allowlist_preview(self, q, body, headers):
        """Which open alerts a proposed rule would silence, before it is saved."""
        rule = _json_body(body)
        try:
            rule = scoring.validate_rule(dict(rule, reason=rule.get("reason") or "preview"))
        except ValueError as exc:
            raise BadRequest(str(exc)) from None
        rule["enabled"] = True
        hits = []
        for a in self.store.query("SELECT a.*, p.name FROM alerts a LEFT JOIN programs p ON p.key=a.program WHERE status='open'"):
            pair = {"program": a["program"], "ip": a["ip"], "port": a["port"], "proto": a["proto"], "direction": a["direction"]}
            if scoring.rule_matches(rule, pair):
                a["findings"] = json.loads(a["findings"])
                hits.append({"id": a["id"], "title": wording.title(self.alert_context(a))})
        return {"alerts": hits}

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
            ("POST", "/api/program/inspect"): self.api_program_inspect,
            ("GET", "/api/destination"): self.api_destination,
            ("GET", "/api/tabs"): self.api_tabs,
            ("POST", "/api/identify"): self.api_identify,
            ("GET", "/api/listeners"): self.api_listeners,
            ("GET", "/api/alerts"): self.api_alerts,
            ("POST", "/api/alerts/update"): self.api_alert_update,
            ("GET", "/api/alert/fix"): self.api_alert_fix,
            ("POST", "/api/monitor/fast"): self.api_monitor_fast,
            ("POST", "/api/settings"): self.api_settings_set,
            ("POST", "/api/run"): self.api_run,
            ("GET", "/api/cleanup"): self.api_cleanup,
            ("GET", "/api/scan"): self.api_scan_status,
            ("POST", "/api/scan"): self.api_scan,
            ("POST", "/api/scan/update"): self.api_scan_update,
            ("POST", "/api/allowlist/preview"): self.api_allowlist_preview,
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
            ("POST", "/api/inspection/lookup"): self.api_inspection_lookup,
            ("GET", "/api/keys"): self.api_keys,
            ("POST", "/api/keys"): self.api_keys_set,
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


def _tokens(cmds):
    return [{"text": c, "tokens": commands.tokenize(c)} for c in cmds]


def _transports(ports):
    """Passive security badges from ports alone ("tcp/443" -> HTTPS)."""
    out = []
    for p in ports:
        proto, _, num = p.split(" ")[0].partition("/")
        t = identify.transport(proto, int(num)) if num.isdigit() else None
        if t and t not in out:
            out.append(dict(t, port=p))
    return out


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
