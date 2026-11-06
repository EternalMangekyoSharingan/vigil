"""Read-only lookups an AI assistant may use while investigating: search the Cases
timeline, open a finding, pivot on a path, hash, address, package or unit, read a
storyline, look up an ATT&CK technique.

Rules (see docs/AI_PLATFORM.md):
- Every lookup only reads Vigil's own stores. None writes, runs a command, opens a file
  being inspected, reads /proc or reaches the network.
- Every result goes through the same treatment as the evidence bundle (ai/context.py):
  redaction and the injection scan, then a fence with this session's random boundary.
- Inputs are checked against the strict schemas here before anything runs, and every
  call is recorded (name, input, size, time, error).
"""

import json
import secrets
import time

from ..cases import correlate
from ..core import attack
from ..core.decisions import Decisions
from . import context

RESULT_MAX = 24_000           # characters per tool result
SEVERITIES = ["", "High", "Medium", "Low", "Info"]
TOOLS_ENUM = ["", "net", "pkg", "files", "persist", "tasks"]
KINDS = ["path", "sha256", "ip", "domain", "package", "unit"]


def _schema(props, required=None):
    return {"type": "object", "properties": props, "required": list(required if required is not None else props),
            "additionalProperties": False}


TOOLS = [
    {"name": "search_findings",
     "description": "Search Vigil's findings (from every tool, as imported into Cases) by words in the title, summary "
                    "or evidence. Empty strings mean 'any'. Returns up to `limit` short rows with their keys.",
     "input_schema": _schema({"query": {"type": "string", "description": "words to look for; empty for all"},
                              "severity": {"type": "string", "enum": SEVERITIES},
                              "tool": {"type": "string", "enum": TOOLS_ENUM},
                              "limit": {"type": "integer", "description": "1 to 30"}})},
    {"name": "get_finding",
     "description": "One finding in full (signals, evidence, indicators, ATT&CK, the commands Vigil generated for it, "
                    "the user's notes and decision) by its key, e.g. 'tasks:3f2a...'.",
     "input_schema": _schema({"key": {"type": "string"}})},
    {"name": "pivot",
     "description": "Every finding that mentions this path, sha256, public IP, domain, package or systemd unit.",
     "input_schema": _schema({"kind": {"type": "string", "enum": KINDS}, "value": {"type": "string"}})},
    {"name": "list_storylines",
     "description": "Vigil's storylines: findings from two or more tools joined by a shared program, file, address, "
                    "package or unit, most serious first.",
     "input_schema": _schema({})},
    {"name": "get_storyline",
     "description": "One storyline in time order, with what tied each step in.",
     "input_schema": _schema({"id": {"type": "string"}})},
    {"name": "attack_technique",
     "description": "What a MITRE ATT&CK technique id means (name, tactic) and which Vigil checks map to it.",
     "input_schema": _schema({"id": {"type": "string", "description": "e.g. T1543.002"}})},
]
BY_NAME = {t["name"]: t for t in TOOLS}


def definitions():
    """The tool list for the API, strict so inputs always match the schema."""
    return [dict(t, strict=True) for t in TOOLS]


class InputError(ValueError):
    pass


def validate(name, data):
    """Check an input against the strict schema (the API guarantees it; Vigil checks anyway)."""
    t = BY_NAME.get(name)
    if not t:
        raise InputError(f"no tool called {name!r}")
    s = t["input_schema"]
    if not isinstance(data, dict):
        raise InputError("input must be an object")
    extra = set(data) - set(s["properties"])
    missing = [k for k in s["required"] if k not in data]
    if extra or missing:
        raise InputError(f"unexpected {sorted(extra)} / missing {missing}")
    for k, p in s["properties"].items():
        v = data[k]
        if p["type"] == "string" and not isinstance(v, str):
            raise InputError(f"{k} must be a string")
        if p["type"] == "integer" and (not isinstance(v, int) or isinstance(v, bool)):
            raise InputError(f"{k} must be an integer")
        if "enum" in p and v not in p["enum"]:
            raise InputError(f"{k} must be one of {p['enum']}")
        if isinstance(v, str) and len(v) > 500:
            raise InputError(f"{k} is too long")
    return data


def _row(r):
    return {"key": r["key"], "tool": r["tool"], "severity": r["severity"], "title": r["title"], "summary": r["summary"],
            "first_seen": r["first_seen"], "last_seen": r.get("last_seen"), "times_seen": r.get("times")}


class Lookups:
    """One investigation's lookups over a Cases store. Not thread-safe; one per question."""

    def __init__(self, store, data_root=None, redact=True, home=None, user=None, host=None):
        self.store = store
        self.decisions = Decisions(data_root) if data_root else None
        self.redactor = context.Redactor(redact, home, user, host)
        self.boundary = f"vigil-evidence-{secrets.token_hex(6)}"
        self.injection, self.commands, self.calls, self.seen = [], set(), [], set()
        self._rows = None

    # ---- plumbing ---------------------------------------------------------------------------

    def rows(self):
        if self._rows is None:
            self._rows = self.store.findings()
        return self._rows

    def _clean(self, s, path):
        m = context.INJECTION.search(s)
        if m and len(self.injection) < 20:
            hit = {"where": path, "text": s[max(0, m.start() - 40): m.end() + 40]}
            if hit not in self.injection:
                self.injection.append(hit)
        return self.redactor(s)

    def fence(self, obj):
        text = json.dumps(context._walk(obj, self._clean), indent=1, ensure_ascii=False, default=str)
        if len(text) > RESULT_MAX:
            text = text[:RESULT_MAX] + "\n... (cut: ask for less)"
        return f"<{self.boundary}>\n{text}\n</{self.boundary}>"

    def call(self, name, data):
        """(text for the model, is_error). Never raises for a bad input or a missing key."""
        t0 = time.time()
        rec = {"name": name, "input": data, "ts": t0}
        try:
            validate(name, data)
            out = getattr(self, f"t_{name}")(**data)
            text, err = self.fence(out), False
        except (InputError, LookupError) as exc:
            text, err = f"Lookup failed: {exc}", True
            rec["error"] = str(exc)
        rec.update(bytes=len(text.encode()), ms=round((time.time() - t0) * 1000, 1))
        self.calls.append(rec)
        return text, err

    # ---- the tools (t_<name>) -------------------------------------------------------------------

    def t_search_findings(self, query, severity, tool, limit):
        words = [w for w in query.lower().split() if w]
        out = []
        for r in self.rows():
            if severity and r["severity"] != severity or tool and r["tool"] != tool:
                continue
            hay = " ".join([r["title"], r["summary"], r["check_name"]] +
                           [str(e.get("value") or "") for e in r["body"].get("evidence") or []]).lower()
            if all(w in hay for w in words):
                out.append(_row(r))
        n = max(1, min(int(limit), 30))
        self.seen.update(x["key"] for x in out[:n])
        return {"matches": len(out), "shown": out[:n]}

    def t_get_finding(self, key):
        r = self.store.finding(key)
        s = context.slim(r["body"])
        self.commands.update(s["vigil_commands"])
        self.seen.add(key)
        d = self.decisions.applies(key, r["severity"], None, r["last_seen"]) if self.decisions else None
        return dict(s, key=key, first_seen=r["first_seen"], last_seen=r["last_seen"], times_seen=r["times"],
                    notes=[n["text"] for n in r["notes"]], cases=[c["title"] for c in r["cases"]],
                    your_decision={"status": d["status"], "reason": d["reason"]} if d else None)

    def t_pivot(self, kind, value):
        hits = correlate.pivot(self.rows(), kind, value)
        self.seen.update(r["key"] for r in hits[:30])
        return {"entity": f"{kind}: {value}", "findings": [_row(r) for r in hits[:30]], "total": len(hits)}

    def t_list_storylines(self):
        return {"storylines": [{"id": s["id"], "title": s["title"], "severity": s["severity"], "summary": s["summary"],
                                "tools": s["tools"]} for s in correlate.stories(self.rows())[:10]]}

    def t_get_storyline(self, id):
        for s in correlate.stories(self.rows()):
            if s["id"] == id:
                self.seen.update(s["keys"])
                return {"id": s["id"], "title": s["title"], "severity": s["severity"], "summary": s["summary"],
                        "steps": [{"key": st["key"], "tool": st["tool_name"], "when": st["when"], "title": st["title"],
                                   "tied_by": st.get("linked_by")} for st in s["steps"]],
                        "shared": [f"{e['kind']}: {e['display']}" for e in s.get("shared") or []],
                        "attack": [f"{a['id']} {a['name']}" for a in s.get("attack") or []]}
        raise LookupError(f"no storyline {id}")

    def t_attack_technique(self, id):
        t = attack.TECHNIQUES.get(id.strip().upper())
        if not t:
            raise LookupError(f"{id} is not in Vigil's ATT&CK table")
        checks = sorted(f"{tool}:{check}" for (tool, check), ids in attack.BY_CHECK.items() if id in ids)
        groups = sorted(g for g, ids in attack.BY_PERSIST_GROUP.items() if id in ids)
        return {"id": id, "name": t[0], "tactic": t[1], "url": attack.URL.format(id.replace(".", "/")),
                "vigil_checks": checks, "persist_locations": groups}
