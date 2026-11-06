"""Vigil Cases' page and JSON API (127.0.0.1 only, via core.web)."""

import json
import re
from pathlib import Path

from ..core import web
from ..core.store import default_data_dir
from ..core.web import BadRequest, _json_body
from ..ai import analyst, context, providers
from . import correlate, export, importer
from .store import CaseError, CaseStore

STATIC = Path(__file__).resolve().parent / "static"
IMPORT_MAX = 64 * 1024 * 1024


class App:
    def __init__(self, data_dir, data_root=None):
        self.store = CaseStore(data_dir)
        self.ask = None          # tests replace the provider; None means the real one
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
        f = self.store.finding(q.get("key", ""))
        f["entities"] = [{"kind": k, "value": v, "display": correlate.display((k, v))}
                         for k, v in sorted(correlate.entities(f["body"]))]
        return f

    def api_stories(self, q):
        return {"stories": correlate.stories(self.store.findings())}

    def api_story(self, q):
        sid = q.get("id", "")
        for st in correlate.stories(self.store.findings()):
            if st["id"] == sid:
                return st
        raise LookupError(f"no storyline {sid}")

    def api_story_case(self, q, d):
        st = self.api_story({"id": d.get("id", "")})
        c = self.store.create(d.get("title") or st["title"], tags=["storyline"] + [t for t in st["tools"]],
                              summary=st["summary"])
        for k in st["keys"]:
            self.store.attach(c["id"], k)
        return self.store.case(c["id"])

    # ---- the analyst ----------------------------------------------------------------------

    def _scope(self, d):
        """(findings, stories, case, label) for a scope: a case, a storyline, or everything worth a look."""
        rows = self.store.findings()
        all_stories = correlate.stories(rows)
        if d.get("case"):
            case = self.store.case(d["case"])
            keys = {f["key"] for f in case["findings"]}
            fs = [r["body"] for r in rows if r["key"] in keys]
            return fs, [s for s in all_stories if set(s["keys"]) & keys], case, f"case #{case['id']}"
        if d.get("story"):
            st = next((s for s in all_stories if s["id"] == d["story"]), None)
            if not st:
                raise LookupError("no such storyline")
            keys = set(st["keys"])
            return [r["body"] for r in rows if r["key"] in keys], [st], None, f"storyline {st['id']}"
        fs = [r["body"] for r in rows if r["severity"] in ("High", "Medium")][:150]
        return fs, all_stories[:10], None, "everything High or Medium"

    def api_ai_status(self, q):
        s = self.store.get_meta_ai()
        return dict(providers.status(), settings=s,
                    log=self.store.q("SELECT id, ts, provider, model, scope, question, bytes_sent, findings, redactions,"
                                     " refused, error FROM ai_log ORDER BY id DESC LIMIT 20"))

    def api_ai_brief(self, q, d):
        fs, stories, case, label = self._scope(d)
        b = context.bundle(fs, stories, case, redact=True)
        parts = analyst.brief(fs, stories, b["injection"])
        return {"scope": label, "brief": parts, "text": analyst.as_text(parts)}

    def api_ai_preview(self, q, d):
        fs, stories, case, label = self._scope(d)
        b = context.bundle(fs, stories, case, redact=self.store.get_meta_ai()["redact"])
        return {"scope": label, "bytes": b["bytes"], "findings": b["findings"], "redactions": b["redactions"],
                "injection": b["injection"], "text": b["text"]}

    def api_ai_settings(self, q, d):
        cur = self.store.get_meta_ai()
        if "enabled" in d:
            cur["enabled"] = bool(d["enabled"])
        if "redact" in d:
            cur["redact"] = bool(d["redact"])
        self.store.set_meta_ai(cur)
        return self.api_ai_status({})

    def api_ai_ask(self, q, d):
        """Send the previewed bundle and the question to Claude. Only on an explicit press, only when enabled."""
        settings = self.store.get_meta_ai()
        if not settings["enabled"]:
            raise BadRequest("AI answers are off. Turn them on in the Analyst tab first.")
        question = (d.get("question") or "What happened, how sure are we, and what should I check first?").strip()[:2000]
        fs, stories, case, label = self._scope(d)
        b = context.bundle(fs, stories, case, redact=settings["redact"])
        row = {"provider": "claude", "model": providers.MODEL, "scope": label, "question": question,
               "bytes_sent": b["bytes"], "findings": b["findings"], "redactions": b["redactions"]}
        try:
            r = (self.ask or providers.ask_claude)(b, question)
        except providers.ProviderError as exc:
            self.store.log_ai(row, error=str(exc))
            raise BadRequest(str(exc))
        self.store.log_ai(dict(row, model=r.get("model")), answer=r.get("answer"), refused=r.get("refused"),
                          usage=r.get("usage"))
        r["not_from_vigil"] = context.command_provenance(r.get("answer") or "", b["commands"])
        r["injection"] = b["injection"]
        return r

    def api_pivot(self, q):
        rows = correlate.pivot(self.store.findings(), q.get("kind", ""), q.get("value", ""))
        return {"kind": q.get("kind"), "value": q.get("value"),
                "findings": [{k: r[k] for k in ("key", "tool", "title", "severity", "summary", "first_seen")} for r in rows]}

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
                ("POST", "/api/note"): w(self.api_note), ("GET", "/api/export"): w(self.api_export),
                ("GET", "/api/stories"): w(self.api_stories), ("GET", "/api/story"): w(self.api_story),
                ("POST", "/api/story/case"): w(self.api_story_case), ("GET", "/api/pivot"): w(self.api_pivot),
                ("GET", "/api/ai"): w(self.api_ai_status), ("POST", "/api/ai/brief"): w(self.api_ai_brief),
                ("POST", "/api/ai/preview"): w(self.api_ai_preview), ("POST", "/api/ai/settings"): w(self.api_ai_settings),
                ("POST", "/api/ai/ask"): w(self.api_ai_ask)}


def make_server(app, port=8770, verbose=False):
    return web.make_server(app, port, verbose, max_body=IMPORT_MAX + 65536, static_dirs=[STATIC])


def serve(data_dir, port=8770, verbose=False, data_root=None):
    web.serve_tool(App(data_dir, data_root or default_data_dir()), "Vigil Cases", port, verbose,
                   static_dirs=[STATIC], max_body=IMPORT_MAX + 65536)
