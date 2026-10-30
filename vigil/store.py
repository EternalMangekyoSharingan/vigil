"""SQLite evidence store and the tracker that turns snapshots into history.

Each poll of the collector is a snapshot. The tracker diffs consecutive snapshots
into connection lifetimes (first observed, last observed, gone), records first-seen
facts (new destination, new program-to-destination pair, a program's first
outbound connection) and keeps the evidence each fact came from.
"""

import json
import sqlite3
import threading
import time

from . import collector

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS programs(
  key TEXT PRIMARY KEY, name TEXT NOT NULL, hidden INTEGER NOT NULL DEFAULT 0,
  info TEXT, first_seen REAL NOT NULL, last_seen REAL NOT NULL, first_outbound REAL);
CREATE TABLE IF NOT EXISTS destinations(
  ip TEXT PRIMARY KEY, scope TEXT NOT NULL, first_seen REAL NOT NULL, last_seen REAL NOT NULL);
-- port is the service port: the remote port for outbound, our local port for inbound.
CREATE TABLE IF NOT EXISTS pairs(
  program TEXT NOT NULL, ip TEXT NOT NULL, port INTEGER NOT NULL, proto TEXT NOT NULL,
  direction TEXT NOT NULL, first_seen REAL NOT NULL, last_seen REAL NOT NULL,
  connections INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(program, ip, port, proto, direction));
CREATE TABLE IF NOT EXISTS connections(
  id INTEGER PRIMARY KEY, sock_key TEXT NOT NULL, kind TEXT NOT NULL, direction TEXT NOT NULL,
  program TEXT NOT NULL, pid INTEGER, uid INTEGER, proto TEXT NOT NULL, tbl TEXT NOT NULL,
  local_ip TEXT, local_port INTEGER, remote_ip TEXT, remote_port INTEGER,
  state TEXT, inode INTEGER, opened_at REAL NOT NULL, last_seen REAL NOT NULL,
  closed_at REAL, close_note TEXT);
CREATE INDEX IF NOT EXISTS conn_open ON connections(closed_at);
CREATE INDEX IF NOT EXISTS conn_prog ON connections(program, opened_at);
CREATE INDEX IF NOT EXISTS conn_ip ON connections(remote_ip, opened_at);
CREATE TABLE IF NOT EXISTS events(
  id INTEGER PRIMARY KEY, ts REAL NOT NULL, kind TEXT NOT NULL, program TEXT, ip TEXT,
  port INTEGER, proto TEXT, conn_id INTEGER, summary TEXT NOT NULL, source TEXT NOT NULL,
  detail TEXT);
CREATE INDEX IF NOT EXISTS ev_prog ON events(program, ts);
CREATE INDEX IF NOT EXISTS ev_ip ON events(ip, ts);
"""

TAIL_MEMORY = 300  # seconds a closed connection's 5-tuple is remembered


class Store:
    """One SQLite connection shared by the poller and the web server, behind a lock."""

    def __init__(self, path):
        self.path = path
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.lock = threading.RLock()
        with self.lock:
            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.executescript(SCHEMA)

    def close(self):
        with self.lock:
            self.db.close()

    def query(self, sql, args=()):
        with self.lock:
            return [dict(r) for r in self.db.execute(sql, args).fetchall()]

    def one(self, sql, args=()):
        rows = self.query(sql, args)
        return rows[0] if rows else None

    def get_meta(self, key, default=None):
        row = self.one("SELECT value FROM meta WHERE key=?", (key,))
        return json.loads(row["value"]) if row else default

    def set_meta(self, key, value):
        with self.lock, self.db:
            self.db.execute("INSERT OR REPLACE INTO meta VALUES(?,?)", (key, json.dumps(value)))

    def add_event(self, ts, kind, summary, source, program=None, ip=None, port=None,
                  proto=None, conn_id=None, detail=None):
        with self.lock, self.db:
            self._event(ts, kind, summary, source, program, ip, port, proto, conn_id, detail)

    def _event(self, ts, kind, summary, source, program=None, ip=None, port=None,
               proto=None, conn_id=None, detail=None):
        self.db.execute(
            "INSERT INTO events(ts,kind,program,ip,port,proto,conn_id,summary,source,detail)"
            " VALUES(?,?,?,?,?,?,?,?,?,?)",
            (ts, kind, program, ip, port, proto, conn_id, summary, source,
             json.dumps(detail) if detail is not None else None))

    def prune(self, now, keep_days=14):
        """Drop closed connection rows older than keep_days.

        Events and the first-seen tables are kept: they are the evidence trail, and
        they are what makes "new" meaningful.
        """
        cutoff = now - keep_days * 86400
        with self.lock, self.db:
            cur = self.db.execute("DELETE FROM connections WHERE closed_at IS NOT NULL"
                                  " AND closed_at < ?", (cutoff,))
            return cur.rowcount


def sock_key(s):
    return (f"{s['proto']}|{s['local_ip']}|{s['local_port']}|{s['remote_ip']}|"
            f"{s['remote_port']}|{s['inode']}")


def five_tuple(s):
    return (s["proto"], s["local_ip"], s["local_port"], s["remote_ip"], s["remote_port"])


def hidden_program(s):
    """Pseudo-program for sockets the kernel will not attribute."""
    reason = s["hidden"]["reason"]
    if reason == "other-user":
        user = collector.username(s["uid"])
        return f"hidden:other-user:{s['uid']}", f"Hidden: {user}"
    return f"hidden:{reason}", s["hidden"]["label"]


def fmt_endpoint(ip, port):
    return f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"


class Tracker:
    """Diffs successive snapshots into connection lifetimes and first-seen events."""

    source = "collector"

    def __init__(self, store):
        self.store = store
        self.open = {}      # sock_key -> connection id
        self.tuples = {}    # 5-tuple -> last time seen, to recognise TIME_WAIT tails
        self.latest = None  # last snapshot, for live process details
        self.resumed = False
        for row in store.query("SELECT id, sock_key FROM connections WHERE closed_at IS NULL"):
            self.open[row["sock_key"]] = row["id"]
            self.resumed = True

    def ingest(self, snap):
        """Record one snapshot. Returns counts of what changed."""
        now = snap["taken_at"]
        st = self.store
        baseline = st.get_meta("baseline_at")
        in_baseline = baseline is None
        if in_baseline:
            st.set_meta("baseline_at", now)
        stats = {"opened": 0, "closed": 0, "first_seen": 0}
        seen = set()
        with st.lock, st.db:
            db = st.db
            programs_done = set()
            for s in snap["sockets"]:
                if s["inode"] == 0 and five_tuple(s) in self.tuples:
                    # Tail of a connection we already tracked: same flow, now closing.
                    self.tuples[five_tuple(s)] = now
                    continue
                if s["program"]:
                    proc = snap["processes"][s["pid"]]
                    prog, name, hidden = s["program"], proc["name"], 0
                    info = {k: proc[k] for k in ("pid", "exe", "exe_deleted", "cmdline", "user",
                                                 "uid", "ppid", "parent", "ancestry", "started")}
                    info["pids"] = s["pids"]
                else:
                    prog, name = hidden_program(s)
                    hidden = 1
                    info = {"explanation": s["hidden"]["explanation"], "uid": s["uid"],
                            "reason": s["hidden"]["reason"]}
                if prog not in programs_done:
                    programs_done.add(prog)
                    db.execute(
                        "INSERT INTO programs(key,name,hidden,info,first_seen,last_seen)"
                        " VALUES(?,?,?,?,?,?) ON CONFLICT(key) DO UPDATE SET"
                        " name=excluded.name, info=excluded.info, last_seen=excluded.last_seen",
                        (prog, name, hidden, json.dumps(info), now, now))
                key = sock_key(s)
                seen.add(key)
                self.tuples[five_tuple(s)] = now
                if key in self.open:
                    db.execute("UPDATE connections SET last_seen=?, state=?, pid=? WHERE id=?",
                               (now, s["state"], s["pid"], self.open[key]))
                    continue
                cur = db.execute(
                    "INSERT INTO connections(sock_key,kind,direction,program,pid,uid,proto,tbl,"
                    "local_ip,local_port,remote_ip,remote_port,state,inode,opened_at,last_seen)"
                    " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (key, s["kind"], s["direction"], prog, s["pid"], s["uid"], s["proto"], s["table"],
                     s["local_ip"], s["local_port"], s["remote_ip"], s["remote_port"],
                     s["state"], s["inode"], now, now))
                cid = cur.lastrowid
                self.open[key] = cid
                stats["opened"] += 1
                if s["kind"] == "connection":
                    stats["first_seen"] += self._first_seen(db, s, prog, hidden, cid, now,
                                                            in_baseline)
                elif not in_baseline:
                    exposure = ("all interfaces" if collector.scope_of(s["local_ip"]) ==
                                "unspecified" else s["local_ip"])
                    self.store._event(
                        now, "listen",
                        f"{name} started listening on {s['proto']} port {s['local_port']}"
                        f" ({exposure})",
                        f"{self.source}: /proc/net/{s['table']} inode {s['inode']}",
                        program=prog, port=s["local_port"], proto=s["proto"], conn_id=cid,
                        detail={"local": fmt_endpoint(s["local_ip"], s["local_port"]),
                                "pid": s["pid"], "uid": s["uid"]})

            for key in [k for k in self.open if k not in seen]:
                cid = self.open.pop(key)
                if self.resumed:
                    # Gone while Vigil was not running: the last observation is the best bound.
                    db.execute("UPDATE connections SET closed_at=last_seen, close_note=?"
                               " WHERE id=?", ("closed while Vigil was stopped", cid))
                else:
                    db.execute("UPDATE connections SET closed_at=? WHERE id=?", (now, cid))
                stats["closed"] += 1
        self.resumed = False
        for t in [t for t, ts in self.tuples.items() if now - ts > TAIL_MEMORY]:
            del self.tuples[t]
        self.latest = snap
        return stats

    def _first_seen(self, db, s, prog, hidden, cid, now, in_baseline):
        """Record what is new about this connection as one event. Returns 1 if anything was."""
        ip, proto, inbound = s["remote_ip"], s["proto"], s["direction"] == "in"
        port = s["local_port"] if inbound else s["remote_port"]
        scope = collector.scope_of(ip)
        dest_new = db.execute("SELECT 1 FROM destinations WHERE ip=?", (ip,)).fetchone() is None
        db.execute("INSERT INTO destinations(ip,scope,first_seen,last_seen) VALUES(?,?,?,?)"
                   " ON CONFLICT(ip) DO UPDATE SET last_seen=excluded.last_seen",
                   (ip, scope, now, now))
        direction = s["direction"]
        pair_new = db.execute("SELECT 1 FROM pairs WHERE program=? AND ip=? AND port=? AND"
                              " proto=? AND direction=?",
                              (prog, ip, port, proto, direction)).fetchone() is None
        db.execute("INSERT INTO pairs(program,ip,port,proto,direction,first_seen,last_seen,"
                   "connections) VALUES(?,?,?,?,?,?,?,1)"
                   " ON CONFLICT(program,ip,port,proto,direction) DO UPDATE SET"
                   " last_seen=excluded.last_seen, connections=connections+1",
                   (prog, ip, port, proto, direction, now, now))
        first_out = False
        if not hidden and not inbound:
            row = db.execute("SELECT first_outbound FROM programs WHERE key=?", (prog,)).fetchone()
            if row["first_outbound"] is None:
                first_out = True
                db.execute("UPDATE programs SET first_outbound=? WHERE key=?", (now, prog))
        if not (dest_new or pair_new or first_out):
            return 0
        endpoint = fmt_endpoint(ip, port)
        if inbound and dest_new:
            what = f"new address for this PC: {ip} ({scope}) connected in to {proto} port {port}"
        elif inbound:
            what = f"first inbound connection from {ip} to this program's {proto} port {port}"
        elif first_out:
            what = f"first outbound connection seen for this program ({proto} {endpoint})"
        elif dest_new:
            what = f"new destination for this PC: {proto} {endpoint} ({scope})"
        else:
            what = f"first time this program used {proto} {endpoint}"
        if in_baseline:
            what = "baseline: " + what + " (already open when Vigil started)"
        self.store._event(
            now, "first_seen", what[0].upper() + what[1:],
            f"first-seen check on {self.source}: /proc/net/{s['table']} inode {s['inode']}",
            program=prog, ip=ip, port=port, proto=proto, conn_id=cid,
            detail={"direction": direction, "destination_new": dest_new, "pair_new": pair_new,
                    "program_first_outbound": first_out, "baseline": in_baseline,
                    "pid": s["pid"], "scope": scope})
        return 1

    # ---- read side ---------------------------------------------------------

    def graph(self, now=None, window=900, scopes=("internet", "lan", "link-local", "multicast",
                                                    "reserved")):
        """Programs -> destinations seen live or within `window` seconds."""
        now = time.time() if now is None else now
        since = now - window
        rows = self.store.query(
            "SELECT c.program, c.remote_ip ip, c.direction,"
            " CASE c.direction WHEN 'in' THEN c.local_port ELSE c.remote_port END port,"
            " c.proto, d.scope, COUNT(*) total, SUM(c.closed_at IS NULL) live,"
            " MIN(c.opened_at) first, MAX(COALESCE(c.closed_at, c.last_seen)) last"
            " FROM connections c JOIN destinations d ON d.ip = c.remote_ip"
            " WHERE c.kind='connection' AND (c.closed_at IS NULL OR c.closed_at >= ?)"
            " GROUP BY c.program, c.remote_ip, c.direction, 4, c.proto", (since,))
        edges, progs, dests = {}, {}, {}
        for r in rows:
            if r["scope"] not in scopes:
                continue
            e = edges.setdefault((r["program"], r["ip"]), {
                "program": r["program"], "ip": r["ip"], "ports": [], "live": 0, "total": 0,
                "first": r["first"], "last": r["last"]})
            e["ports"].append({"proto": r["proto"], "port": r["port"], "direction": r["direction"],
                               "live": r["live"], "total": r["total"], "first": r["first"],
                               "last": r["last"]})
            e["live"] += r["live"]
            e["total"] += r["total"]
            e["first"] = min(e["first"], r["first"])
            e["last"] = max(e["last"], r["last"])
            progs.setdefault(r["program"], set()).add(r["ip"])
            dests.setdefault(r["ip"], set()).add(r["program"])
        programs = []
        for key, ips in progs.items():
            p = self.store.one("SELECT * FROM programs WHERE key=?", (key,))
            mine = [e for e in edges.values() if e["program"] == key]
            programs.append({
                "key": key, "name": p["name"], "hidden": bool(p["hidden"]),
                "first_seen": p["first_seen"], "first_outbound": p["first_outbound"],
                "info": json.loads(p["info"] or "{}"), "destinations": len(ips),
                "live": sum(e["live"] for e in mine), "total": sum(e["total"] for e in mine)})
        destinations = []
        for ip, owners in dests.items():
            d = self.store.one("SELECT * FROM destinations WHERE ip=?", (ip,))
            mine = [e for e in edges.values() if e["ip"] == ip]
            ports = sorted({(p["proto"], p["port"], p["direction"]) for e in mine
                            for p in e["ports"]}, key=lambda x: (x[1], x[0]))
            destinations.append({
                "ip": ip, "scope": d["scope"], "first_seen": d["first_seen"],
                "programs": len(owners),
                "ports": [f"{p}/{n}" + (" in" if d == "in" else "") for p, n, d in ports],
                "live": sum(e["live"] for e in mine), "total": sum(e["total"] for e in mine)})
        return {"now": now, "window": window, "programs": programs,
                "destinations": destinations, "edges": list(edges.values())}

    def listeners(self):
        return self.store.query(
            "SELECT c.program, p.name, p.hidden, c.proto, c.local_ip, c.local_port, c.state,"
            " c.pid, c.opened_at FROM connections c JOIN programs p ON p.key=c.program"
            " WHERE c.kind='listen' AND c.closed_at IS NULL ORDER BY c.local_port")

    def timeline(self, program=None, ip=None, limit=200):
        """Events for one node: connection opens/closes merged with recorded events."""
        if program is not None:
            where, arg = "program=?", program
        else:
            where, arg = "remote_ip=?", ip
        conns = self.store.query(
            f"SELECT c.*, p.name FROM connections c JOIN programs p ON p.key=c.program"
            f" WHERE c.{where} AND c.kind='connection' ORDER BY c.opened_at DESC LIMIT ?",
            (arg, limit))
        items = []
        for c in conns:
            local = fmt_endpoint(c["local_ip"], c["local_port"])
            remote = fmt_endpoint(c["remote_ip"], c["remote_port"])
            if c["direction"] == "in":
                flow = f"{c['proto']} {remote} → {local} (inbound)"
            else:
                flow = f"{c['proto']} {local} → {remote}"
            who = c["name"] if ip is not None else (f"pid {c['pid']}" if c["pid"] else c["name"])
            src = f"{self.source}: /proc/net/{c['tbl']} inode {c['inode']}"
            if c["pid"]:
                src += f", owner from /proc/{c['pid']}/fd"
            items.append({"ts": c["opened_at"], "kind": "open", "summary": f"{who}: {flow}",
                          "state": c["state"], "source": src, "conn_id": c["id"]})
            if c["closed_at"] is not None:
                dur = c["closed_at"] - c["opened_at"]
                note = c["close_note"] or f"gone at this poll; open ≥ {fmt_duration(dur)}"
                items.append({"ts": c["closed_at"], "kind": "close",
                              "summary": f"{who}: {flow} closed ({note})", "source": src,
                              "conn_id": c["id"]})
        ev_where = "program=?" if program is not None else "ip=?"
        for e in self.store.query(f"SELECT * FROM events WHERE {ev_where} ORDER BY ts DESC"
                                  f" LIMIT ?", (arg, limit)):
            items.append({"ts": e["ts"], "kind": e["kind"], "summary": e["summary"],
                          "source": e["source"], "conn_id": e["conn_id"],
                          "detail": json.loads(e["detail"]) if e["detail"] else None})
        items.sort(key=lambda i: (i["ts"], i["kind"] != "open"), reverse=True)
        return items[:limit]

    def program_detail(self, key):
        p = self.store.one("SELECT * FROM programs WHERE key=?", (key,))
        if not p:
            return None
        p["info"] = json.loads(p["info"] or "{}")
        p["hidden"] = bool(p["hidden"])
        p["pairs"] = self.store.query("SELECT ip, port, proto, direction, first_seen, last_seen,"
                                      " connections"
                                      " FROM pairs WHERE program=? ORDER BY last_seen DESC"
                                      " LIMIT 100", (key,))
        p["timeline"] = self.timeline(program=key)
        return p

    def destination_detail(self, ip):
        d = self.store.one("SELECT * FROM destinations WHERE ip=?", (ip,))
        if not d:
            return None
        d["pairs"] = self.store.query(
            "SELECT pr.program, p.name, pr.port, pr.proto, pr.direction, pr.first_seen,"
            " pr.last_seen,"
            " pr.connections FROM pairs pr JOIN programs p ON p.key=pr.program WHERE pr.ip=?"
            " ORDER BY pr.last_seen DESC", (ip,))
        d["timeline"] = self.timeline(ip=ip)
        return d


def fmt_duration(seconds):
    seconds = int(max(0, seconds))
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m {seconds % 60}s"
    return f"{seconds // 3600}h {seconds % 3600 // 60}m"
