"""Cases: evidence, indicators, notes and status in one place, plus exports.

Evidence is copied into the case when it is added (a snapshot), so a case keeps
what was seen even after old connections are pruned, and records when it was added
and where it came from. Indicators are derived from the evidence and can be excluded
from exports individually. Exports: CSV, STIX 2.1 and a Markdown report.
"""

import csv
import hashlib
import io
import ipaddress
import json
import os
import re
import time
import uuid

from .. import __version__

STATUSES = ("open", "investigating", "closed")
IOC_TYPES = ("ipv4", "ipv6", "domain", "url", "email", "md5", "sha1", "sha256")
ITEM_KINDS = ("alert", "inspection", "program", "destination")
VIGIL_NS = uuid.UUID("9b8a3c5e-0d5f-4e0a-9a51-7a3c2f6b1e10")  # namespace for stable STIX ids
EXE_HASH_MAX = 256 * 1024 * 1024

SCHEMA = """
CREATE TABLE IF NOT EXISTS cases(
  id INTEGER PRIMARY KEY, title TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open',
  tags TEXT NOT NULL DEFAULT '[]', summary TEXT NOT NULL DEFAULT '',
  created_at REAL NOT NULL, updated_at REAL NOT NULL, closed_at REAL);
CREATE TABLE IF NOT EXISTS case_items(
  id INTEGER PRIMARY KEY, case_id INTEGER NOT NULL, kind TEXT NOT NULL, ref TEXT NOT NULL,
  title TEXT NOT NULL, snapshot TEXT NOT NULL, added_at REAL NOT NULL,
  UNIQUE(case_id, kind, ref));
CREATE TABLE IF NOT EXISTS case_iocs(
  id INTEGER PRIMARY KEY, case_id INTEGER NOT NULL, type TEXT NOT NULL, value TEXT NOT NULL,
  context TEXT NOT NULL, source TEXT NOT NULL, first_seen REAL, malicious INTEGER NOT NULL DEFAULT 0,
  excluded INTEGER NOT NULL DEFAULT 0, added_at REAL NOT NULL, UNIQUE(case_id, type, value));
CREATE TABLE IF NOT EXISTS case_log(
  id INTEGER PRIMARY KEY, case_id INTEGER NOT NULL, ts REAL NOT NULL, kind TEXT NOT NULL,
  text TEXT NOT NULL);
"""


class CaseError(ValueError):
    pass


def ioc_type(kind, value):
    """Normalise an indicator type; 'ip' becomes ipv4 or ipv6. Raises CaseError."""
    value = value.strip()
    if kind in ("ip", "ipv4", "ipv6"):
        try:
            a = ipaddress.ip_address(value)
        except ValueError:
            raise CaseError(f"{value!r} is not an IP address") from None
        return f"ipv{a.version}", str(a)
    if kind == "url" and not re.match(r"(?i)^(?:https?|ftps?)://\S+$", value):
        raise CaseError(f"{value!r} is not a URL")
    if kind == "domain" and not re.match(r"(?i)^(?:[a-z0-9-]{1,63}\.)+[a-z]{2,63}$", value):
        raise CaseError(f"{value!r} is not a domain name")
    if kind == "email" and not re.match(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$", value):
        raise CaseError(f"{value!r} is not an e-mail address")
    lengths = {"md5": 32, "sha1": 40, "sha256": 64}
    if kind in lengths:
        if not re.fullmatch(f"[0-9a-fA-F]{{{lengths[kind]}}}", value):
            raise CaseError(f"{value!r} is not a {kind} hash")
        value = value.lower()
    if kind not in IOC_TYPES:
        raise CaseError(f"indicator type must be one of {', '.join(IOC_TYPES + ('ip',))}")
    return kind, value.lower() if kind == "domain" else value


def iso(ts):
    """STIX/ISO 8601 UTC timestamp with millisecond precision."""
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(ts)) + f".{int(ts % 1 * 1000):03d}Z"


def local(ts):
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts)) if ts else "—"


def defang(value):
    """Make an indicator unclickable in documents: hxxp://, 198.51.100[.]20."""
    value = re.sub(r"(?i)^http", "hxxp", value)
    value = re.sub(r"(?i)^ftp", "fxp", value)
    return re.sub(r"\.(?=[^.]*$)", "[.]", value) if "://" not in value else \
        value.replace("://", "[://]", 1)


def hash_file(path, limit=EXE_HASH_MAX):
    """SHA-256/SHA-1/MD5 of a file, read in chunks (bytes only; nothing is run)."""
    h = [hashlib.sha256(), hashlib.sha1(), hashlib.md5()]
    size = 0
    with open(path, "rb") as fh:
        while chunk := fh.read(1 << 20):
            size += len(chunk)
            if size > limit:
                return None
            for x in h:
                x.update(chunk)
    return {"sha256": h[0].hexdigest(), "sha1": h[1].hexdigest(), "md5": h[2].hexdigest(),
            "size": size}


class Cases:
    def __init__(self, store, tracker=None, enricher=None, proc_root="/proc"):
        self.store, self.tracker, self.enricher = store, tracker, enricher
        self.proc_root = proc_root
        with store.lock:
            store.db.executescript(SCHEMA)

    # ---- helpers ------------------------------------------------------------------

    def _log(self, db, case_id, kind, text, now):
        db.execute("INSERT INTO case_log(case_id,ts,kind,text) VALUES(?,?,?,?)",
                   (case_id, now, kind, text))
        db.execute("UPDATE cases SET updated_at=? WHERE id=?", (now, case_id))

    def _case(self, case_id):
        row = self.store.one("SELECT * FROM cases WHERE id=?", (int(case_id),))
        if not row:
            raise LookupError(f"no case {case_id}")
        row["tags"] = json.loads(row["tags"])
        return row

    # ---- cases --------------------------------------------------------------------

    def create(self, title, tags=(), summary="", now=None):
        now = time.time() if now is None else now
        title = (title or "").strip()
        if not title:
            raise CaseError("a case needs a title")
        tags = clean_tags(tags)
        with self.store.lock, self.store.db as db:
            cur = db.execute("INSERT INTO cases(title,status,tags,summary,created_at,updated_at)"
                             " VALUES(?,?,?,?,?,?)", (title[:200], "open", json.dumps(tags),
                                                      summary[:20000], now, now))
            self._log(db, cur.lastrowid, "created", f"Case opened: {title[:200]}", now)
        return self.get(cur.lastrowid)

    def update(self, case_id, now=None, **fields):
        now = time.time() if now is None else now
        case = self._case(case_id)
        changes = []
        with self.store.lock, self.store.db as db:
            if fields.get("title") is not None and fields["title"].strip() != case["title"]:
                title = fields["title"].strip()[:200]
                if not title:
                    raise CaseError("a case needs a title")
                db.execute("UPDATE cases SET title=? WHERE id=?", (title, case["id"]))
                changes.append(f"Renamed to {title}")
            if fields.get("status") is not None and fields["status"] != case["status"]:
                if fields["status"] not in STATUSES:
                    raise CaseError(f"status must be one of {', '.join(STATUSES)}")
                db.execute("UPDATE cases SET status=?, closed_at=? WHERE id=?",
                           (fields["status"], now if fields["status"] == "closed" else None,
                            case["id"]))
                changes.append(f"Status {case['status']} → {fields['status']}")
            if fields.get("tags") is not None and clean_tags(fields["tags"]) != case["tags"]:
                tags = clean_tags(fields["tags"])
                db.execute("UPDATE cases SET tags=? WHERE id=?", (json.dumps(tags), case["id"]))
                changes.append(f"Tags: {', '.join(tags) or 'none'}")
            if fields.get("summary") is not None and fields["summary"] != case["summary"]:
                db.execute("UPDATE cases SET summary=? WHERE id=?",
                           (fields["summary"][:20000], case["id"]))
                changes.append("Summary edited")
            for c in changes:
                self._log(db, case["id"], "change", c, now)
        return self.get(case["id"])

    def list(self):
        rows = self.store.query(
            "SELECT c.*, (SELECT COUNT(*) FROM case_items i WHERE i.case_id=c.id) items,"
            " (SELECT COUNT(*) FROM case_iocs x WHERE x.case_id=c.id AND NOT x.excluded) iocs"
            " FROM cases c ORDER BY c.status='closed', c.updated_at DESC")
        for r in rows:
            r["tags"] = json.loads(r["tags"])
        return rows

    def get(self, case_id):
        case = self._case(case_id)
        case["items"] = self.store.query("SELECT * FROM case_items WHERE case_id=? ORDER BY added_at",
                                         (case["id"],))
        for i in case["items"]:
            i["snapshot"] = json.loads(i["snapshot"])
        case["iocs"] = self.store.query("SELECT * FROM case_iocs WHERE case_id=? ORDER BY type, value",
                                        (case["id"],))
        case["log"] = self.store.query("SELECT * FROM case_log WHERE case_id=? ORDER BY ts, id",
                                       (case["id"],))
        return case

    def note(self, case_id, text, now=None):
        now = time.time() if now is None else now
        text = (text or "").strip()
        if not text:
            raise CaseError("a note cannot be empty")
        case = self._case(case_id)
        with self.store.lock, self.store.db as db:
            self._log(db, case["id"], "note", text[:20000], now)
        return self.get(case["id"])

    # ---- evidence -----------------------------------------------------------------

    def add_item(self, case_id, kind, ref, now=None):
        """Copy evidence into the case and derive its indicators."""
        now = time.time() if now is None else now
        case = self._case(case_id)
        if kind not in ITEM_KINDS:
            raise CaseError(f"evidence kind must be one of {', '.join(ITEM_KINDS)}")
        title, snap, iocs = self._snapshot(kind, str(ref), now)
        with self.store.lock, self.store.db as db:
            cur = db.execute("INSERT OR IGNORE INTO case_items(case_id,kind,ref,title,snapshot,added_at)"
                             " VALUES(?,?,?,?,?,?)", (case["id"], kind, str(ref), title,
                                                       json.dumps(snap), now))
            if not cur.rowcount:
                raise CaseError(f"{title} is already in this case")
            item_id = cur.lastrowid
            self._log(db, case["id"], "evidence", f"Added {title}", now)
            for typ, value, context, first, malicious in iocs:
                self._add_ioc(db, case["id"], typ, value, context, f"item {item_id}", first,
                              malicious, now)
        return self.get(case["id"])

    def remove_item(self, case_id, item_id, now=None):
        now = time.time() if now is None else now
        case = self._case(case_id)
        item = self.store.one("SELECT * FROM case_items WHERE id=? AND case_id=?",
                              (int(item_id), case["id"]))
        if not item:
            raise LookupError("no such evidence in this case")
        with self.store.lock, self.store.db as db:
            db.execute("DELETE FROM case_items WHERE id=?", (item["id"],))
            db.execute("DELETE FROM case_iocs WHERE case_id=? AND source=?",
                       (case["id"], f"item {item['id']}"))
            self._log(db, case["id"], "evidence", f"Removed {item['title']}", now)
        return self.get(case["id"])

    def add_ioc(self, case_id, kind, value, context="", now=None):
        now = time.time() if now is None else now
        case = self._case(case_id)
        typ, value = ioc_type(kind, value)
        with self.store.lock, self.store.db as db:
            if not self._add_ioc(db, case["id"], typ, value, context.strip() or "added by hand",
                                 "manual", now, False, now):
                raise CaseError(f"{value} is already in this case")
            self._log(db, case["id"], "indicator", f"Added {typ} {value} by hand", now)
        return self.get(case["id"])

    def set_excluded(self, case_id, ioc_id, excluded, now=None):
        now = time.time() if now is None else now
        case = self._case(case_id)
        row = self.store.one("SELECT * FROM case_iocs WHERE id=? AND case_id=?",
                             (int(ioc_id), case["id"]))
        if not row:
            raise LookupError("no such indicator in this case")
        with self.store.lock, self.store.db as db:
            db.execute("UPDATE case_iocs SET excluded=? WHERE id=?", (int(bool(excluded)), row["id"]))
            self._log(db, case["id"], "indicator",
                      f"{'Excluded' if excluded else 'Included'} {row['type']} {row['value']} "
                      f"{'from' if excluded else 'in'} exports", now)
        return self.get(case["id"])

    def _add_ioc(self, db, case_id, typ, value, context, source, first, malicious, now):
        existing = db.execute("SELECT id, context FROM case_iocs WHERE case_id=? AND type=? AND"
                              " value=?", (case_id, typ, value)).fetchone()
        if existing:
            if context not in existing["context"]:
                db.execute("UPDATE case_iocs SET context=?, malicious=MAX(malicious, ?) WHERE id=?",
                           ((existing["context"] + "; " + context)[:2000], int(malicious),
                            existing["id"]))
            return False
        db.execute("INSERT INTO case_iocs(case_id,type,value,context,source,first_seen,malicious,"
                   "excluded,added_at) VALUES(?,?,?,?,?,?,?,0,?)",
                   (case_id, typ, value, context[:2000], source, first, int(malicious), now))
        return True

    def _snapshot(self, kind, ref, now):
        """(title, snapshot dict, [(type, value, context, first_seen, malicious)])."""
        st = self.store
        iocs = []
        if kind == "alert":
            a = st.one("SELECT a.*, p.name, p.info FROM alerts a LEFT JOIN programs p"
                       " ON p.key=a.program WHERE a.id=?", (int(ref),))
            if not a:
                raise LookupError(f"no alert {ref}")
            a["findings"] = json.loads(a["findings"])
            a["ports"] = json.loads(a["ports"] or "[]")
            a["info"] = json.loads(a["info"] or "{}")
            arrow = "←" if a["direction"] == "in" else "→"
            title = f"Alert #{a['id']}: {a['name'] or a['program']} {arrow} {a['ip']} (score {a['score']:.0f})"
            snap = {"alert": a, "enrichment": self._enrich(a["ip"])}
            intel = bool(snap["enrichment"] and snap["enrichment"]["intel"])
            iocs.append((*ioc_type("ip", a["ip"]), f"alert #{a['id']}: {a['name'] or a['program']} "
                         f"{arrow} {', '.join(a['ports']) or a['port']}; "
                         f"{max(a['findings'], key=lambda f: f['points'])['reason'] if a['findings'] else ''}",
                         a["first_raised"], intel))
        elif kind == "inspection":
            row = st.one("SELECT report FROM inspections WHERE id=?", (int(ref),))
            if not row:
                raise LookupError(f"no file report {ref}")
            r = json.loads(row["report"])
            title = f"File: {r['name']} ({r['verdict']}, score {r['score']:.0f})"
            keep = ("id", "name", "size", "hashes", "type", "verdict", "score", "findings", "iocs",
                    "limits", "inspected_at", "source", "engine")
            snap = {"report": {k: r.get(k) for k in keep}}
            bad = r["verdict"] != "No suspicious indicators found"
            for h in ("sha256", "sha1", "md5"):
                iocs.append((h, r["hashes"][h], f"file {r['name']} ({r['verdict']})",
                             r.get("inspected_at"), bad and r["score"] >= 70))
            for i in r["iocs"]:
                typ = i["type"]
                try:
                    typ, value = ioc_type("ip" if typ == "ip" else typ, i["value"])
                except CaseError:
                    continue
                iocs.append((typ, value, f"found in {r['name']}: {i['where']}", r.get("inspected_at"),
                             bool(i.get("intel"))))
        elif kind == "program":
            if not self.tracker:
                raise CaseError("program evidence needs the network tracker")
            p = self.tracker.program_detail(ref)
            if not p:
                raise LookupError(f"no program {ref}")
            p["timeline"] = p["timeline"][:100]
            title = f"Program: {p['name']}"
            snap = {"program": p, "executable": self._exe_hashes(p)}
            exe = snap["executable"]
            if exe.get("sha256"):
                for h in ("sha256", "sha1", "md5"):
                    iocs.append((h, exe[h], f"executable of {p['name']} ({exe['path']}, pid {exe['pid']})",
                                 p["first_seen"], False))
            for pair in p["pairs"][:50]:
                if pair["ip"] and not p["hidden"]:
                    try:
                        typ, value = ioc_type("ip", pair["ip"])
                    except CaseError:
                        continue
                    iocs.append((typ, value, f"contacted by {p['name']} on {pair['proto']}/{pair['port']}",
                                 pair["first_seen"], False))
        else:  # destination
            if not self.tracker:
                raise CaseError("destination evidence needs the network tracker")
            d = self.tracker.destination_detail(ref)
            if not d:
                raise LookupError(f"no destination {ref}")
            d["timeline"] = d["timeline"][:100]
            d["enrichment"] = self._enrich(ref)
            title = f"Destination: {ref}"
            snap = {"destination": d}
            names = ", ".join(sorted({x["name"] for x in d["pairs"]})[:5])
            iocs.append((*ioc_type("ip", ref), f"destination contacted by {names}", d["first_seen"],
                         bool(d["enrichment"] and d["enrichment"]["intel"])))
        snap["added_at"] = now
        return title, snap, iocs

    def _enrich(self, ip):
        return self.enricher.describe(ip) if self.enricher else None

    def _exe_hashes(self, p):
        """Hash the program's executable through /proc/<pid>/exe (works even if deleted)."""
        info = p.get("info") or {}
        pid, exe = info.get("pid"), info.get("exe")
        out = {"path": exe, "pid": pid}
        if p.get("hidden") or not pid:
            out["note"] = "No process is attributable, so there is no executable to hash."
            return out
        try:
            hashes = hash_file(f"{self.proc_root}/{pid}/exe")
        except OSError as exc:
            out["note"] = (f"Could not read /proc/{pid}/exe ({exc.strerror}): the process has "
                           f"exited or belongs to another user.")
            return out
        if hashes is None:
            out["note"] = "The executable is larger than 256 MB; not hashed."
            return out
        out.update(hashes)
        out["hashed_at"] = time.time()
        return out

    # ---- exports ------------------------------------------------------------------

    def export_csv(self, case_id):
        case = self.get(case_id)
        buf = io.StringIO()
        w = csv.writer(buf)
        # assessed_malicious: listed by a threat feed, or taken from a file whose static
        # verdict was "Likely malicious". The context column says which.
        w.writerow(["type", "value", "assessed_malicious", "first_seen_utc", "context", "case_id",
                    "case_title", "exported_utc"])
        now = iso(time.time())
        for i in case["iocs"]:
            if i["excluded"]:
                continue
            w.writerow([_cell(x) for x in (
                i["type"], i["value"], "yes" if i["malicious"] else "",
                iso(i["first_seen"]) if i["first_seen"] else "", i["context"], case["id"],
                case["title"], now)])
        return buf.getvalue()

    def export_stix(self, case_id, now=None):
        """A STIX 2.1 bundle: identity, one indicator per indicator, notes, a grouping."""
        now = time.time() if now is None else now
        case = self.get(case_id)
        sid = lambda kind, key: f"{kind}--{uuid.uuid5(VIGIL_NS, key)}"
        identity = {"type": "identity", "spec_version": "2.1", "id": sid("identity", "vigil-local"),
                    "created": iso(0), "modified": iso(0), "name": "Vigil (local blue-team lab)",
                    "identity_class": "system"}
        objects = [identity]
        refs = []
        for i in case["iocs"]:
            if i["excluded"]:
                continue
            ind = {
                "type": "indicator", "spec_version": "2.1",
                "id": sid("indicator", f"case:{case['id']}:{i['type']}:{i['value']}"),
                "created": iso(i["added_at"]), "modified": iso(i["added_at"]),
                "created_by_ref": identity["id"],
                "name": f"{i['type']} {i['value']}"[:250],
                "description": i["context"],
                "indicator_types": ["malicious-activity" if i["malicious"] else "anomalous-activity"],
                "pattern": stix_pattern(i["type"], i["value"]), "pattern_type": "stix",
                "valid_from": iso(i["first_seen"] or i["added_at"]),
                "labels": case["tags"] or None,
            }
            objects.append({k: v for k, v in ind.items() if v is not None})
            refs.append(ind["id"])
        group_id = sid("grouping", f"case:{case['id']}")
        notes = [e for e in case["log"] if e["kind"] == "note"]
        for n in notes:
            note = {"type": "note", "spec_version": "2.1", "id": sid("note", f"case:{case['id']}:note:{n['id']}"),
                    "created": iso(n["ts"]), "modified": iso(n["ts"]), "created_by_ref": identity["id"],
                    "content": n["text"], "object_refs": [group_id]}
            objects.append(note)
        objects.append({
            "type": "grouping", "spec_version": "2.1", "id": group_id,
            "created": iso(case["created_at"]), "modified": iso(case["updated_at"]),
            "created_by_ref": identity["id"], "name": case["title"],
            "description": (case["summary"] or f"Vigil case {case['id']}") + f" (status: {case['status']})",
            "context": "suspicious-activity",
            "object_refs": refs or [identity["id"]],
            **({"labels": case["tags"]} if case["tags"] else {}),
        })
        return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}

    def export_markdown(self, case_id, now=None):
        now = time.time() if now is None else now
        c = self.get(case_id)
        out = [f"# Case {c['id']}: {md(c['title'])}", "",
               f"**Status:** {c['status']} · **Tags:** {md(', '.join(c['tags'])) or 'none'} · "
               f"**Opened:** {local(c['created_at'])} · **Updated:** {local(c['updated_at'])}"
               + (f" · **Closed:** {local(c['closed_at'])}" if c["closed_at"] else ""), "",
               f"_Exported {iso(now)} by Vigil {__version__}. Network evidence was collected "
               f"read-only from /proc; files were triaged statically (read, never run). "
               f"Indicators are defanged._", ""]
        if c["summary"]:
            out += ["## Summary", "", c["summary"], ""]
        out += ["## Evidence", ""]
        if not c["items"]:
            out += ["None linked yet.", ""]
        for item in c["items"]:
            out += [f"### {md(item['title'])}", "", f"Added {local(item['added_at'])}.", ""]
            out += self._md_item(item)
        out += ["## Indicators", ""]
        kept = [i for i in c["iocs"] if not i["excluded"]]
        if kept:
            out += ["| Type | Indicator | Malicious | First seen | Context |", "| --- | --- | --- | --- | --- |"]
            out += [f"| {i['type']} | `{defang(i['value'])}` | {'yes' if i['malicious'] else ''} | "
                    f"{local(i['first_seen'])} | {md(i['context'])} |" for i in kept]
        else:
            out += ["None."]
        dropped = len(c["iocs"]) - len(kept)
        out += ["", "_Malicious = listed by a downloaded threat feed, or taken from a file whose "
                "static verdict was Likely malicious; the context says which._"]
        if dropped:
            out += ["", f"_{dropped} indicator(s) were excluded from exports by the analyst._"]
        out += ["", "## Timeline", ""]
        events = [(e["ts"], e["kind"], e["text"]) for e in c["log"]]
        for item in c["items"]:
            s = item["snapshot"]
            if "alert" in s:
                events.append((s["alert"]["first_raised"], "alert", f"Alert #{s['alert']['id']} raised"))
            if "report" in s and s["report"].get("inspected_at"):
                events.append((s["report"]["inspected_at"], "file", f"{s['report']['name']} inspected"))
        out += [f"- {local(ts)} · {kind} · {md(text)}" for ts, kind, text in sorted(events)]
        out += ["", "## Limits", "",
                "- Vigil runs without root: connections of other users' processes are listed "
                "without the program, and short connections between polls can be missed.",
                "- File verdicts come from static triage only; behaviour was not observed.",
                "- Scores and verdicts explain their reasons above; they are leads for an "
                "analyst, not proof.", ""]
        return "\n".join(out)

    def _md_item(self, item):
        s = item["snapshot"]
        out = []
        findings = []
        if "alert" in s:
            a = s["alert"]
            out += [f"- Program: `{md(a['program'])}`", f"- Address: `{defang(a['ip'])}` "
                    f"({a['direction']}, {', '.join(a['ports']) or a['port']})",
                    f"- Score {a['score']:.0f} (peak {a['peak_score']:.0f}), raised {local(a['first_raised'])}, "
                    f"status {a['status']}" + (f": {md(a['note'])}" if a.get("note") else "")]
            findings = a["findings"]
            out += self._md_enrichment(s.get("enrichment"))
        elif "report" in s:
            r = s["report"]
            out += [f"- Verdict: **{r['verdict']}** (score {r['score']:.0f})",
                    f"- Type: {md(r['type']['description'])}, {r['size']} bytes",
                    f"- SHA-256: `{r['hashes']['sha256']}`", f"- Inspected {local(r.get('inspected_at'))}"]
            findings = r["findings"]
            out += [f"- Limit: {md(x)}" for x in r["limits"]]
        elif "program" in s:
            p, exe = s["program"], s["executable"]
            info = p.get("info") or {}
            out += [f"- Executable: `{md(info.get('exe') or p['key'])}`",
                    f"- Command line: `{md(' '.join(info.get('cmdline') or []))}`",
                    f"- User: {md(str(info.get('user', '?')))}; parent chain: "
                    f"{md(' › '.join(a['name'] for a in reversed(info.get('ancestry') or [])))}",
                    f"- First seen {local(p['first_seen'])}; first outbound {local(p['first_outbound'])}"]
            out.append(f"- Executable SHA-256: `{exe['sha256']}`" if exe.get("sha256")
                       else f"- Executable not hashed: {md(exe.get('note', ''))}")
            for sc in p.get("findings", [])[:5]:
                findings += sc["findings"]
        elif "destination" in s:
            d = s["destination"]
            out += [f"- Address: `{defang(d['ip'])}` ({d['scope']}), first seen {local(d['first_seen'])}",
                    f"- Programs: {md(', '.join(sorted({p['name'] for p in d['pairs']})))}"]
            out += self._md_enrichment(d.get("enrichment"))
            for sc in d.get("findings", [])[:5]:
                findings += sc["findings"]
        if findings:
            out += ["", "Findings:", ""]
            out += [f"- +{f['points']:.0f} {md(f['reason'])} — _{md(f['check'])}: {md(f['data'])}_"
                    for f in sorted(findings, key=lambda f: -f["points"])]
        return out + [""]

    def _md_enrichment(self, en):
        if not en:
            return []
        out = []
        g = en.get("geo")
        if g:
            out.append(f"- Owner: AS{g['asn']} {md(g['owner'] or '')}, {md(g['country_name'] or '?')} "
                       f"(offline IPtoASN)")
        for h in en.get("intel") or []:
            out.append(f"- Listed by {md(h['title'])}: {md(h['label'] or '')}")
        return out


def stix_pattern(kind, value):
    v = value.replace("\\", "\\\\").replace("'", "\\'")
    return {
        "ipv4": f"[ipv4-addr:value = '{v}']", "ipv6": f"[ipv6-addr:value = '{v}']",
        "domain": f"[domain-name:value = '{v}']", "url": f"[url:value = '{v}']",
        "email": f"[email-addr:value = '{v}']", "md5": f"[file:hashes.MD5 = '{v}']",
        "sha1": f"[file:hashes.'SHA-1' = '{v}']", "sha256": f"[file:hashes.'SHA-256' = '{v}']",
    }[kind]


def clean_tags(tags):
    if isinstance(tags, str):
        tags = tags.split(",")
    out = []
    for t in tags:
        t = re.sub(r"\s+", "-", str(t).strip().lower())[:40]
        if t and t not in out:
            out.append(t)
    return out[:20]


def md(text):
    """Escape text for Markdown tables and prose, and defang any links inside it.

    Markdown viewers turn scheme URLs and www. names into live links; a report about
    malicious infrastructure should not.
    """
    text = re.sub(r"([\\`*_|<>\[\]])", r"\\\1", str(text or "")).replace("\n", " ")
    text = re.sub(r"(?i)\b(http|https|ftp|ftps)://",
                  lambda m: m.group(1).lower().replace("http", "hxxp").replace("ftp", "fxp") + "[://]", text)
    return re.sub(r"(?i)\bwww\.", "www[.]", text)


def _cell(value):
    """Neutralise spreadsheet formulas (CSV injection) without changing plain values."""
    s = str(value)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s
