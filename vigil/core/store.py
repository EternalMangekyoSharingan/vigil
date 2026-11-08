"""Evidence store shared by the suite: one SQLite file per tool, plus a JSON-lines
export of its findings that Vigil Cases imports.

    data/<tool>/<tool>.db          runs, findings, baselines, settings (this module)
    data/<tool>/findings.jsonl     the latest findings, one per line (core.finding format)

The Network Map keeps its own, older store (vigil/net/store.py) in data/vigil.db.
"""

import json
import os
import sqlite3
import threading
import time
from pathlib import Path

from . import finding as fmt

ROOT = Path(__file__).resolve().parent.parent.parent
EXPORT_NAME = "findings.jsonl"

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY, tool TEXT NOT NULL, target TEXT, started REAL NOT NULL,
    finished REAL, summary TEXT
);
CREATE TABLE IF NOT EXISTS findings (
    rowid INTEGER PRIMARY KEY, run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    id TEXT NOT NULL, tool TEXT NOT NULL, severity TEXT NOT NULL, title TEXT NOT NULL,
    ts REAL NOT NULL, body TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS findings_run ON findings(run_id);
CREATE TABLE IF NOT EXISTS baselines (
    name TEXT PRIMARY KEY, ts REAL NOT NULL, body TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
"""


def default_data_dir():
    return Path(os.environ.get("VIGIL_DATA") or ROOT / "data")


def tool_dir(tool, base=None):
    """data/<tool>/, created private to this user."""
    d = Path(base) if base else default_data_dir() / tool
    d.mkdir(parents=True, exist_ok=True, mode=0o700)
    return d


class FindingStore:
    def __init__(self, tool, data_dir):
        self.tool = tool
        self.dir = Path(data_dir)
        self.dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.path = self.dir / f"{tool}.db"
        self.lock = threading.Lock()
        self.db = sqlite3.connect(str(self.path), check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys = ON")
        self.db.executescript(SCHEMA)
        self.db.commit()

    def close(self):
        with self.lock:
            self.db.close()

    # ---- runs and findings ----------------------------------------------------------

    def add_run(self, target, findings, summary=None, started=None):
        """Record one run (a scan, an inspection) and its findings; refresh the export."""
        now = time.time()
        with self.lock:
            cur = self.db.execute("INSERT INTO runs(tool, target, started, finished, summary) VALUES (?,?,?,?,?)",
                                  (self.tool, target, started or now, now, json.dumps(summary or {})))
            run_id = cur.lastrowid
            self.db.executemany(
                "INSERT INTO findings(run_id, id, tool, severity, title, ts, body) VALUES (?,?,?,?,?,?,?)",
                [(run_id, f["id"], f["tool"], f["severity"], f["title"], f["source"]["when"], json.dumps(f))
                 for f in findings])
            self.db.commit()
        self.export()
        return run_id

    def runs(self, limit=50):
        with self.lock:
            rows = self.db.execute("SELECT r.*, (SELECT COUNT(*) FROM findings f WHERE f.run_id = r.id) n "
                                   "FROM runs r ORDER BY r.id DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r, summary=json.loads(r["summary"] or "{}")) for r in rows]

    def run(self, run_id):
        with self.lock:
            r = self.db.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
            if not r:
                raise LookupError(f"no run {run_id}")
            fs = self.db.execute("SELECT body FROM findings WHERE run_id = ? ORDER BY rowid", (run_id,)).fetchall()
        return dict(r, summary=json.loads(r["summary"] or "{}"), findings=[json.loads(x["body"]) for x in fs])

    def finding(self, finding_id):
        """The most recent stored copy of one finding, by id, or None."""
        with self.lock:
            r = self.db.execute("SELECT body FROM findings WHERE id = ? ORDER BY rowid DESC LIMIT 1",
                                (str(finding_id),)).fetchone()
        return json.loads(r["body"]) if r else None

    def delete_run(self, run_id):
        with self.lock:
            self.db.execute("DELETE FROM runs WHERE id = ?", (run_id,))
            self.db.commit()
        self.export()

    def latest_findings(self):
        """Each target's most recent run's findings (what the export holds)."""
        with self.lock:
            rows = self.db.execute(
                "SELECT f.body FROM findings f JOIN runs r ON r.id = f.run_id WHERE r.id IN "
                "(SELECT MAX(id) FROM runs GROUP BY target) ORDER BY f.rowid").fetchall()
        return [json.loads(r["body"]) for r in rows]

    def export(self, path=None):
        """Write the latest findings as JSON lines (atomically). Returns the path."""
        path = Path(path) if path else self.dir / EXPORT_NAME
        tmp = path.with_suffix(".tmp")
        with open(tmp, "w", encoding="utf-8") as fh:
            os.chmod(tmp, 0o600)
            fh.write(fmt.to_jsonl(self.latest_findings()))
        os.replace(tmp, path)
        return path

    # ---- baselines and settings -------------------------------------------------------

    def save_baseline(self, name, body):
        with self.lock:
            self.db.execute("INSERT OR REPLACE INTO baselines(name, ts, body) VALUES (?,?,?)",
                            (name, time.time(), json.dumps(body)))
            self.db.commit()

    def baseline(self, name):
        with self.lock:
            r = self.db.execute("SELECT ts, body FROM baselines WHERE name = ?", (name,)).fetchone()
        return (r["ts"], json.loads(r["body"])) if r else (None, None)

    def get_meta(self, key, default=None):
        with self.lock:
            r = self.db.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return json.loads(r["value"]) if r else default

    def set_meta(self, key, value):
        with self.lock:
            self.db.execute("INSERT OR REPLACE INTO meta(key, value) VALUES (?,?)", (key, json.dumps(value)))
            self.db.commit()
