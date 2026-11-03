"""Vigil Cases' page and JSON API (127.0.0.1 only, via core.web)."""

import json
import re
from pathlib import Path

from ..core import web
from ..core.store import default_data_dir
from ..core.web import BadRequest, _json_body
from . import export, importer
from .store import CaseError, CaseStore

STATIC = Path(__file__).resolve().parent / "static"
IMPORT_MAX = 64 * 1024 * 1024


class App:
    def __init__(self, data_dir, data_root=None):
        self.store = CaseStore(data_dir)
        self.data_root = Path(data_root) if data_root else Path(data_dir).parent

    def close(self):
        self.store.close()

    def _body(self, body):
        try:
            return _json_body(body)
        except BadRequest:
            raise

    def wrap(self, fn):
        def handler(q, body=None, headers=None):
            try:
                return fn(q, self._body(body)) if body is not None else fn(q)
            except CaseError as exc:
                raise BadRequest(str(exc))
        return handler

    def api_status(self, q):
        return {"tool": "cases", "data_root": str(self.data_root), "sources": importer.sources(self.data_root),
                "findings": self.store.q("SELECT tool, severity, COUNT(*) n FROM findings GROUP BY tool, severity"),
                "imports": self.store.q("SELECT * FROM imports ORDER BY id DESC LIMIT 10")}

    def api_import(self, q, d):
        if d.get("text"):
            if len(d["text"]) > IMPORT_MAX:
                raise BadRequest("too large")
            return {"results": [importer.import_text(self.store, d["text"], d.get("source") or "pasted")]}
        return {"results": importer.import_all(self.store, self.data_root, refresh_net=d.get("net", True))}

    def api_timeline(self, q):
        return {"events": self.store.timeline(q.get("case") or None, q.get("tool") or None, q.get("severity") or None)}

    def api_finding(self, q):
        return self.store.finding(q.get("key", ""))

    def api_cases(self, q):
        return {"cases": self.store.cases()}

    def api_case(self, q):
        return self.store.case(q.get("id", 0))

    def api_case_create(self, q, d):
        return self.store.create(d.get("title", ""), d.get("tags", []), d.get("summary", ""))

    def api_case_update(self, q, d):
        fields = {k: d[k] for k in ("title", "status", "tags", "summary") if k in d}
        return self.store.update(d.get("id"), **fields)

    def api_attach(self, q, d):
        return self.store.attach(d.get("id"), d.get("key", ""))

    def api_detach(self, q, d):
        return self.store.detach(d.get("id"), d.get("key", ""))

    def api_note(self, q, d):
        return self.store.note(d.get("text", ""), d.get("case") or None, d.get("key") or None)

    def api_export(self, q):
        case = self.store.case(q["case"]) if q.get("case") else None
        findings = case["findings"] if case else self.store.findings()
        timeline = self.store.timeline(case["id"] if case else None)
        name = re.sub(r"[^A-Za-z0-9_-]+", "-", (case or {}).get("title") or "all-findings").strip("-")[:60] or "case"
        fmt_ = q.get("format", "md")
        if fmt_ == "csv":
            data, ctype, ext = export.csv_indicators(findings), "text/csv; charset=utf-8", "indicators.csv"
        elif fmt_ == "csv-findings":
            data, ctype, ext = export.csv_findings(findings), "text/csv; charset=utf-8", "findings.csv"
        elif fmt_ == "stix":
            data = json.dumps(export.stix(case, findings), indent=2)
            ctype, ext = "application/stix+json; charset=utf-8", "stix.json"
        elif fmt_ == "md":
            data, ctype, ext = export.markdown(case, findings, timeline), "text/markdown; charset=utf-8", "report.md"
        else:
            raise BadRequest("format must be csv, csv-findings, stix or md")
        return (data.encode(), ctype, {"Content-Disposition": f'attachment; filename="vigil-{name}-{ext}"'})

    def routes(self):
        w = self.wrap
        return {("GET", "/api/status"): w(self.api_status), ("POST", "/api/import"): w(self.api_import),
                ("GET", "/api/timeline"): w(self.api_timeline), ("GET", "/api/finding"): w(self.api_finding),
                ("GET", "/api/cases"): w(self.api_cases), ("GET", "/api/case"): w(self.api_case),
                ("POST", "/api/cases"): w(self.api_case_create), ("POST", "/api/case/update"): w(self.api_case_update),
                ("POST", "/api/case/attach"): w(self.api_attach), ("POST", "/api/case/detach"): w(self.api_detach),
                ("POST", "/api/note"): w(self.api_note), ("GET", "/api/export"): w(self.api_export)}


def make_server(app, port=8770, verbose=False):
    return web.make_server(app, port, verbose, max_body=IMPORT_MAX + 65536, static_dirs=[STATIC])


def serve(data_dir, port=8770, verbose=False, data_root=None):
    web.serve_tool(App(data_dir, data_root or default_data_dir()), "Vigil Cases", port, verbose,
                   static_dirs=[STATIC], max_body=IMPORT_MAX + 65536)
