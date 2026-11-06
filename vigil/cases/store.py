"""Vigil Cases' own store (data/cases/cases.db): every imported finding, cases, notes and a
case log. One timeline is built from all of it."""

import json
import sqlite3
import threading
import time
from pathlib import Path

from ..core import finding as fmt
from ..core.export import clean_tags

STATUSES = ("open", "investigating", "closed")
SCHEMA = """
CREATE TABLE IF NOT EXISTS findings(
  key TEXT PRIMARY KEY, tool TEXT NOT NULL, fid TEXT NOT NULL, check_name TEXT NOT NULL, title TEXT NOT NULL,
  severity TEXT NOT NULL, summary TEXT NOT NULL, first_seen REAL NOT NULL, last_seen REAL NOT NULL,
  imported_at REAL NOT NULL, source TEXT NOT NULL, times INTEGER NOT NULL DEFAULT 1, body TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS findings_when ON findings(first_seen);
CREATE TABLE IF NOT EXISTS cases(
  id INTEGER PRIMARY KEY, title TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open', tags TEXT NOT NULL DEFAULT '[]',
  summary TEXT NOT NULL DEFAULT '', created_at REAL NOT NULL, updated_at REAL NOT NULL, closed_at REAL);
CREATE TABLE IF NOT EXISTS case_findings(
  case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE, key TEXT NOT NULL, added_at REAL NOT NULL,
  PRIMARY KEY(case_id, key));
CREATE TABLE IF NOT EXISTS notes(
  id INTEGER PRIMARY KEY, case_id INTEGER REFERENCES cases(id) ON DELETE CASCADE, finding_key TEXT,
  ts REAL NOT NULL, text TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS case_log(
  id INTEGER PRIMARY KEY, case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE, ts REAL NOT NULL,
  text TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS ai_log(
  id INTEGER PRIMARY KEY, ts REAL NOT NULL, provider TEXT NOT NULL, model TEXT, scope TEXT NOT NULL,
  question TEXT NOT NULL, bytes_sent INTEGER NOT NULL, findings INTEGER NOT NULL, redactions INTEGER NOT NULL,
  answer TEXT, refused INTEGER NOT NULL DEFAULT 0, error TEXT, usage TEXT);
CREATE TABLE IF NOT EXISTS imports(
  id INTEGER PRIMARY KEY, ts REAL NOT NULL, source TEXT NOT NULL, added INTEGER NOT NULL, updated INTEGER NOT NULL,
  skipped INTEGER NOT NULL, notes TEXT NOT NULL DEFAULT '[]');
"""
NOTE_MAX = 20_000


class CaseError(ValueError):
    pass


class CaseStore:
    def __init__(self, data_dir):
        self.dir = Path(data_dir)
        self.dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.lock = threading.Lock()
        self.db = sqlite3.connect(str(self.dir / "cases.db"), check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys = ON")
        self.db.executescript(SCHEMA)
        self.db.commit()

    def close(self):
        with self.lock:
            self.db.close()

    def q(self, sql, args=()):
        with self.lock:
            return [dict(r) for r in self.db.execute(sql, args).fetchall()]

    def x(self, sql, args=()):
        with self.lock:
            cur = self.db.execute(sql, args)
            self.db.commit()
            return cur

    # ---- findings ----------------------------------------------------------------------------

    def add_findings(self, findings, source, now=None):
        """Insert or refresh findings. Returns (added, updated)."""
        now = now or time.time()
        added = updated = 0
        with self.lock:
            for f in findings:
                key = f"{f['tool']}:{f['id']}"
                when = f["source"]["when"]
                row = self.db.execute("SELECT first_seen, last_seen, body FROM findings WHERE key=?", (key,)).fetchone()
                if row is None:
                    self.db.execute("INSERT INTO findings(key, tool, fid, check_name, title, severity, summary, first_seen,"
                                    " last_seen, imported_at, source, body) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                                    (key, f["tool"], f["id"], f["check"], f["title"], f["severity"], f["summary"], when,
                                     when, now, source, json.dumps(f)))
                    added += 1
                elif when > row["last_seen"] or json.dumps(f) != row["body"]:
                    self.db.execute("UPDATE findings SET title=?, severity=?, summary=?, first_seen=MIN(first_seen, ?),"
                                    " last_seen=MAX(last_seen, ?), body=?, times=times+(? > last_seen) WHERE key=?",
                                    (f["title"], f["severity"], f["summary"], when, when, json.dumps(f), when, key))
                    updated += 1
            self.db.commit()
        return added, updated

    def finding(self, key):
        rows = self.q("SELECT * FROM findings WHERE key=?", (key,))
        if not rows:
            raise LookupError(f"no finding {key}")
        r = rows[0]
        r["body"] = json.loads(r["body"])
        r["notes"] = self.q("SELECT * FROM notes WHERE finding_key=? ORDER BY ts", (key,))
        r["cases"] = self.q("SELECT c.id, c.title FROM case_findings cf JOIN cases c ON c.id=cf.case_id WHERE cf.key=?", (key,))
        return r

    def findings(self, tool=None, severity=None, case_id=None, limit=2000):
        where, args = [], []
        if tool:
            where.append("f.tool=?")
            args.append(tool)
        if severity:
            where.append("f.severity=?")
            args.append(severity)
        join = ""
        if case_id:
            join = "JOIN case_findings cf ON cf.key=f.key"
            where.append("cf.case_id=?")
            args.append(int(case_id))
        sql = (f"SELECT f.key, f.tool, f.check_name, f.title, f.severity, f.summary, f.first_seen, f.last_seen, f.times,"
               f" f.body FROM findings f {join} {'WHERE ' + ' AND '.join(where) if where else ''}"
               f" ORDER BY f.first_seen DESC LIMIT ?")
        rows = self.q(sql, args + [limit])
        for r in rows:
            r["body"] = json.loads(r["body"])
        return rows

    # ---- cases and notes -------------------------------------------------------------------------

    def _log(self, case_id, text, now):
        self.db.execute("INSERT INTO case_log(case_id, ts, text) VALUES (?,?,?)", (case_id, now, text))

    def create(self, title, tags=(), summary="", now=None):
        title = (title or "").strip()
        if not title:
            raise CaseError("a case needs a title")
        now = now or time.time()
        with self.lock:
            cur = self.db.execute("INSERT INTO cases(title, tags, summary, created_at, updated_at) VALUES (?,?,?,?,?)",
                                  (title[:200], json.dumps(clean_tags(tags)), summary[:NOTE_MAX], now, now))
            self._log(cur.lastrowid, "Case opened", now)
            self.db.commit()
        return self.case(cur.lastrowid)

    def case(self, case_id):
        rows = self.q("SELECT * FROM cases WHERE id=?", (int(case_id),))
        if not rows:
            raise LookupError(f"no case {case_id}")
        c = rows[0]
        c["tags"] = json.loads(c["tags"])
        c["findings"] = self.findings(case_id=c["id"])
        c["notes"] = self.q("SELECT * FROM notes WHERE case_id=? ORDER BY ts", (c["id"],))
        c["log"] = self.q("SELECT * FROM case_log WHERE case_id=? ORDER BY ts", (c["id"],))
        c["counts"] = {s: sum(f["severity"] == s for f in c["findings"]) for s in fmt.SEVERITIES}
        return c

    def cases(self):
        rows = self.q("SELECT c.*, (SELECT COUNT(*) FROM case_findings cf WHERE cf.case_id=c.id) n FROM cases c"
                      " ORDER BY c.status='closed', c.updated_at DESC")
        for r in rows:
            r["tags"] = json.loads(r["tags"])
        return rows

    def update(self, case_id, now=None, **fields):
        now = now or time.time()
        c = self.case(case_id)
        sets, args, log = [], [], []
        if "title" in fields and fields["title"].strip() and fields["title"] != c["title"]:
            sets.append("title=?")
            args.append(fields["title"].strip()[:200])
            log.append(f"Renamed to {fields['title'].strip()[:200]}")
        if "status" in fields and fields["status"] != c["status"]:
            if fields["status"] not in STATUSES:
                raise CaseError(f"status must be one of {', '.join(STATUSES)}")
            sets += ["status=?", "closed_at=?"]
            args += [fields["status"], now if fields["status"] == "closed" else None]
            log.append(f"Status: {c['status']} → {fields['status']}")
        if "tags" in fields:
            sets.append("tags=?")
            args.append(json.dumps(clean_tags(fields["tags"])))
        if "summary" in fields:
            sets.append("summary=?")
            args.append(str(fields["summary"])[:NOTE_MAX])
        if not sets:
            return c
        with self.lock:
            self.db.execute(f"UPDATE cases SET {', '.join(sets)}, updated_at=? WHERE id=?", args + [now, int(case_id)])
            for line in log:
                self._log(int(case_id), line, now)
            self.db.commit()
        return self.case(case_id)

    def attach(self, case_id, key, now=None):
        now = now or time.time()
        self.case(case_id)
        f = self.finding(key)
        with self.lock:
            cur = self.db.execute("INSERT OR IGNORE INTO case_findings(case_id, key, added_at) VALUES (?,?,?)",
                                  (int(case_id), key, now))
            if cur.rowcount:
                self._log(int(case_id), f"Added finding: {f['title']}", now)
                self.db.execute("UPDATE cases SET updated_at=? WHERE id=?", (now, int(case_id)))
            self.db.commit()
        return self.case(case_id)

    def detach(self, case_id, key, now=None):
        now = now or time.time()
        with self.lock:
            cur = self.db.execute("DELETE FROM case_findings WHERE case_id=? AND key=?", (int(case_id), key))
            if cur.rowcount:
                self._log(int(case_id), f"Removed finding {key}", now)
            self.db.commit()
        return self.case(case_id)

    def note(self, text, case_id=None, finding_key=None, now=None):
        text = (text or "").strip()
        if not text:
            raise CaseError("a note needs text")
        if not case_id and not finding_key:
            raise CaseError("a note belongs to a case or a finding")
        if case_id:
            self.case(case_id)
        if finding_key:
            self.finding(finding_key)
        now = now or time.time()
        self.x("INSERT INTO notes(case_id, finding_key, ts, text) VALUES (?,?,?,?)",
               (int(case_id) if case_id else None, finding_key, now, text[:NOTE_MAX]))
        return {"ok": True}

    # ---- settings and the AI log -------------------------------------------------------------------

    def get_meta_ai(self):
        """AI settings: off until the user turns them on; redaction on by default."""
        rows = self.q("SELECT value FROM meta WHERE key='ai'")
        s = {"enabled": False, "redact": True}
        if rows:
            s.update(json.loads(rows[0]["value"]))
        return s

    def set_meta_ai(self, value):
        self.x("INSERT OR REPLACE INTO meta(key, value) VALUES ('ai', ?)", (json.dumps(value),))

    def log_ai(self, row, answer=None, refused=False, error=None, usage=None):
        self.x("INSERT INTO ai_log(ts, provider, model, scope, question, bytes_sent, findings, redactions, answer,"
               " refused, error, usage) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
               (time.time(), row["provider"], row.get("model"), row["scope"], row["question"], row["bytes_sent"],
                row["findings"], row["redactions"], answer, int(bool(refused)), error, json.dumps(usage or {})))

    # ---- the timeline ----------------------------------------------------------------------------

    def timeline(self, case_id=None, tool=None, severity=None, limit=1000):
        """Findings, notes and case events, newest first, as one list."""
        events = []
        for f in self.findings(tool, severity, case_id, limit):
            events.append({"ts": f["first_seen"], "kind": "finding", "key": f["key"], "tool": f["tool"],
                           "severity": f["severity"], "title": f["title"], "summary": f["summary"],
                           "seen": f["times"], "last_seen": f["last_seen"],
                           "attack": [a["id"] for a in f["body"].get("attack") or []]})
        if not tool and not severity:
            notes = self.q("SELECT * FROM notes WHERE case_id=? OR finding_key IN (SELECT key FROM case_findings "
                           "WHERE case_id=?)" if case_id else "SELECT * FROM notes", (case_id, case_id) if case_id else ())
            for n in notes:
                events.append({"ts": n["ts"], "kind": "note", "text": n["text"], "case_id": n["case_id"],
                               "key": n["finding_key"]})
            logs = self.q("SELECT l.*, c.title FROM case_log l JOIN cases c ON c.id=l.case_id"
                          + (" WHERE l.case_id=?" if case_id else ""), (case_id,) if case_id else ())
            for l in logs:
                events.append({"ts": l["ts"], "kind": "case", "text": l["text"], "case_id": l["case_id"],
                               "case": l["title"]})
        return sorted(events, key=lambda e: -e["ts"])[:limit]
