"""Explainable network scoring: beacons, long connections, rarity, allowlist, alerts.

A score belongs to a *pair*: one program talking to one address on one service port
in one direction. It is the sum of findings, and every finding states its points, a
plain-language reason, the check that produced it and the data it used. Only pairs
at or above the alert threshold that no allowlist rule covers become alerts.
"""

import fnmatch
import ipaddress
import json
import os
import statistics
import threading
import time

from . import collector
from .store import fmt_duration, fmt_endpoint

ALERT_THRESHOLD = 70
LOOKBACK = 24 * 3600   # history each scoring run looks at
RECENT = 24 * 3600     # how long something counts as "new"

# Points per check. A beacon alone (at most 65) stays below the alert threshold on
# purpose: plenty of legitimate software polls on a timer. A second signal (a new
# destination, an odd port, a binary in /tmp, a threat-intel hit) is needed to alert.
POINTS = {
    "beacon_regularity": 45, "beacon_persistence": 10, "beacon_size": 10,
    "long_connection": 30, "new_destination": 15, "new_program": 20,
    "rare_destination": 5, "uncommon_port": 10, "temp_executable": 25,
    "hidden_dir_executable": 10, "deleted_executable": 10, "rare_country": 10,
}
# Threat-intel points are per feed, in enrich.FEEDS: a listed botnet C2 alerts alone.
MIN_CHECKINS = 6           # fewer than this and regularity means nothing
MAX_MISSED_RUN = 5         # a longer silence is a pause (sleep, restart), not missed polls
CV_PERIODIC = 0.20         # the usual beacon threshold (RITA and others)
CV_CEILING = 0.35          # above this, no beacon points at all
LONG_MIN, LONG_MAX = 3600, 8 * 3600   # long-connection scoring starts at 1 h (as in RITA)

COMMON_PORTS = {20, 21, 22, 25, 53, 67, 68, 80, 110, 123, 143, 443, 465, 587, 853, 993, 995,
                1900, 3478, 5222, 5228, 5353, 8080, 8443, 19302}
TEMP_DIRS = ("/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/")
# Hidden directories where ordinary user-installed tools live.
HIDDEN_DIR_OK = {".local", ".cargo", ".rustup", ".nvm", ".npm", ".pyenv", ".sdkman", ".deno",
                 ".bun", ".var", ".vscode", ".vscode-server", ".vscode-oss", ".cursor",
                 ".cursor-server", ".steam", ".linuxbrew", ".dotnet", ".gem", ".rbenv",
                 ".juliaup", ".ghcup", ".opam", ".nix-profile", ".mozilla"}

BUILTIN_RULES = [
    {"id": "builtin-loopback", "ip": "loopback",
     "reason": "Traffic between programs on this machine never leaves it."},
    {"id": "builtin-ntp", "proto": "udp", "port": 123, "direction": "out",
     "reason": "Time sync (NTP) checks in on a timer by design."},
    {"id": "builtin-dns-lan", "port": 53, "ip": "lan", "direction": "out",
     "reason": "DNS lookups to a resolver on the local network."},
    {"id": "builtin-mdns", "port": 5353, "ip": "multicast",
     "reason": "Local service discovery (mDNS) is periodic by design."},
    {"id": "builtin-networkmanager", "program": "/usr/*bin/NetworkManager", "direction": "out",
     "reason": "NetworkManager's connectivity check polls on a timer."},
    {"id": "builtin-timesync",
     "program": "/usr/lib/systemd/systemd-timesyncd", "direction": "out",
     "reason": "systemd's time sync daemon."},
    {"id": "builtin-chrony", "program": "/usr/*bin/chronyd", "direction": "out",
     "reason": "chrony time sync daemon."},
    {"id": "builtin-packagekit", "program": "/usr/lib*/packagekit*", "direction": "out",
     "reason": "PackageKit checks for updates periodically."},
    {"id": "builtin-snapd", "program": "/usr/lib/snapd/snapd", "direction": "out",
     "reason": "snapd refreshes snaps periodically."},
    {"id": "builtin-fwupd", "program": "/usr/lib*/fwupd*", "direction": "out",
     "reason": "fwupd checks for firmware metadata periodically."},
    {"id": "builtin-apt", "program": "/usr/lib/apt/methods/*", "direction": "out",
     "reason": "APT package downloads."},
]
RULE_FIELDS = ("program", "ip", "port", "proto", "direction")
SCOPES = ("internet", "lan", "loopback", "link-local", "multicast", "reserved")


def alert_fingerprint(pair):
    return f"{pair['program']}|{pair['ip']}|{pair['direction']}"


def finding(check, points, reason, data, means=None, stats=None):
    """One explained finding. `means` says, in plain words, what it would do to you.
    `stats` holds the raw numbers behind it (and its `signal` kind), for wording.py."""
    f = {"check": check, "points": round(points, 1), "reason": reason, "data": data}
    if means:
        f["means"] = means
    if stats:
        f["stats"] = stats
    return f


def clamp(x, lo=0.0, hi=1.0):
    return max(lo, min(hi, x))


def fmt_bytes(n):
    for unit in ("B", "kB", "MB", "GB"):
        if n < 1000 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1000
    return f"{n} B"


def fmt_interval(seconds):
    return f"{seconds:.0f} s" if seconds < 120 else fmt_duration(seconds)


def clock(ts):
    return time.strftime("%H:%M:%S", time.localtime(ts))


# ---- individual checks ------------------------------------------------------------

def beacon_stats(times, poll):
    """Regularity of a pair's connection start times, or None if there is too little.

    Starts closer together than 1.5 poll intervals are one check-in (programs often
    open several connections at once). An interval close to a small whole multiple of
    the median is taken as check-ins the poller missed, not as irregularity. A much
    longer silence (laptop asleep, program restarted) is a pause: it is left out of
    the statistics and reported, not treated as hundreds of missed check-ins.
    """
    checkins = []
    for t in sorted(times):
        if not checkins or t - checkins[-1] > 1.5 * poll:
            checkins.append(t)
    if len(checkins) < MIN_CHECKINS:
        return None
    raw = [b - a for a, b in zip(checkins, checkins[1:])]
    med = statistics.median(raw)
    if med < 3 * poll:  # too frequent to tell apart from continuous traffic
        return None
    intervals, missed, pauses = [], 0, []
    for x in raw:
        k = round(x / med)
        if k > MAX_MISSED_RUN + 1:
            pauses.append(x)
        elif k >= 2 and abs(x / k - med) <= 0.15 * med:
            intervals.extend([x / k] * k)
            missed += k - 1
        else:
            intervals.append(x)
    if len(intervals) + 1 < MIN_CHECKINS:
        return None
    mean = statistics.fmean(intervals)
    return {"checkins": len(checkins), "missed": missed, "interval": mean,
            "cv": statistics.pstdev(intervals) / mean, "first": checkins[0],
            "last": checkins[-1], "samples": len(intervals) + 1 + len(pauses), "pauses": pauses}


def beacon_findings(conns, poll, endpoint):
    """Beacon findings for one outbound pair's connections."""
    b = beacon_stats([c["opened_at"] for c in conns], poll)
    if not b or b["cv"] >= CV_CEILING:
        return []
    out = []
    pct = round(b["cv"] * 100)
    kind = "Periodic" if b["cv"] < CV_PERIODIC else "Loosely periodic"
    missed = (f"; {b['missed']} probably missed between polls" if b["missed"] else "")
    if b["pauses"]:
        missed += (f"; {len(b['pauses'])} pause{'s' if len(b['pauses']) > 1 else ''} "
                   f"(longest {fmt_duration(max(b['pauses']))}) left out")
    data = (f"connections table: {len(conns)} connections to {endpoint} opened "
            f"{clock(b['first'])}–{clock(b['last'])}, start times measured to ±{poll:g} s")
    out.append(finding(
        "beacon", POINTS["beacon_regularity"] * clamp((CV_CEILING - b["cv"]) / (CV_CEILING - 0.05)),
        f"{kind}: every {fmt_interval(b['interval'])} ± {pct}% (coefficient of variation "
        f"{b['cv']:.2f} over {b['checkins']} check-ins{missed})", data,
        stats={"signal": "timer", "interval": round(b["interval"], 1), "cv": round(b["cv"], 3),
               "checkins": b["checkins"], "missed": b["missed"], "pauses": [round(x) for x in b["pauses"]],
               "first": b["first"], "last": b["last"], "connections": len(conns), "poll": poll}))
    span = b["last"] - b["first"]
    out.append(finding(
        "beacon", POINTS["beacon_persistence"] * clamp((b["samples"] - MIN_CHECKINS) / 24),
        f"Kept up for {fmt_duration(span)} ({b['samples']} check-ins counting missed ones)",
        data, stats={"signal": "duration", "span": round(span), "samples": b["samples"],
                     "first": b["first"], "last": b["last"]}))
    sizes = [c["bytes_sent"] + c["bytes_recv"] for c in conns
             if c["closed_at"] is not None and c["bytes_sent"] is not None]
    if len(sizes) >= 5 and statistics.fmean(sizes) > 0:
        mean = statistics.fmean(sizes)
        scv = statistics.pstdev(sizes) / mean
        if scv < CV_CEILING:
            out.append(finding(
                "beacon", POINTS["beacon_size"] * clamp((CV_CEILING - scv) / (CV_CEILING - 0.10)),
                f"Similar size each time: ≈ {fmt_bytes(mean)} ± {round(scv * 100)}%",
                f"sock_diag byte counts of {len(sizes)} closed connections (last poll before "
                f"close, so slightly low)",
                stats={"signal": "same_size", "mean": round(mean), "cv": round(scv, 3), "n": len(sizes)}))
    return [f for f in out if f["points"] > 0]


def long_connection_finding(conns, now, baseline):
    best = max(conns, key=lambda c: (c["closed_at"] or now) - c["opened_at"])
    dur = (best["closed_at"] or now) - best["opened_at"]
    if dur < LONG_MIN:
        return None
    points = POINTS["long_connection"] * (0.5 + 0.5 * clamp((dur - LONG_MIN) / (LONG_MAX - LONG_MIN)))
    at_least = "at least " if baseline is not None and best["opened_at"] <= baseline else ""
    state = "still open" if best["closed_at"] is None else f"closed {clock(best['closed_at'])}"
    return finding(
        "long_connection", points,
        f"One connection open {at_least}{fmt_duration(dur)} (since {clock(best['opened_at'])}, {state})",
        f"connections table: connection #{best['id']}, local port {best['local_port']}",
        stats={"signal": "long", "duration": round(dur), "opened_at": best["opened_at"],
               "closed_at": best["closed_at"], "at_least": bool(at_least)})


def location_findings(info, key):
    """Where the program runs from: temp directories, hidden directories, deleted files."""
    out = []
    paths = [(info.get("exe") or "").removesuffix(" (deleted)")]
    script = key.split(" ", 1)[1] if " " in key else ""
    if script.startswith("/"):
        paths.append(script)
    src = f"/proc/{info.get('pid')}/exe and cmdline at last poll"
    for path in paths:
        if path.startswith(TEMP_DIRS):
            out.append(finding("process_location", POINTS["temp_executable"],
                               f"Runs from {path}: a world-writable temporary directory, a common "
                               f"drop location for downloaded payloads", src,
                               stats={"signal": "temp_dir", "path": path}))
            break
        hidden = [part for part in path.split("/")[1:-1] if part.startswith(".")]
        if hidden and hidden[0] not in HIDDEN_DIR_OK:
            out.append(finding("process_location", POINTS["hidden_dir_executable"],
                               f"Runs from a hidden directory ({path})", src,
                               stats={"signal": "hidden_dir", "path": path}))
            break
    if info.get("exe_deleted"):
        out.append(finding("process_location", POINTS["deleted_executable"],
                           "Its executable was deleted or replaced while running. Normal right "
                           "after a package upgrade; otherwise a way to leave no file behind", src,
                           stats={"signal": "deleted_exe"}))
    return out


# ---- allowlist --------------------------------------------------------------------

class Allowlist:
    """Built-in rules plus user rules in <data>/allowlist.json (hand-editable).

    Program patterns match the real executable path from /proc/<pid>/exe, so a copy
    of an allowlisted program placed somewhere else does not match.
    """

    def __init__(self, path):
        self.path = path
        self.lock = threading.Lock()

    def _load(self):
        try:
            with open(self.path) as fh:
                data = json.load(fh)
        except FileNotFoundError:
            data = {}
        return {"rules": data.get("rules", []), "disabled_builtins": data.get("disabled_builtins", [])}

    def _save(self, data):
        tmp = self.path + ".tmp"
        with open(tmp, "w") as fh:
            json.dump(data, fh, indent=2)
        os.replace(tmp, self.path)

    def rules(self):
        data = self._load()
        builtin = [dict(r, source="built-in", enabled=r["id"] not in data["disabled_builtins"])
                   for r in BUILTIN_RULES]
        return builtin + [dict(r, source="user", enabled=True) for r in data["rules"]]

    def add(self, rule, now=None):
        rule = validate_rule(rule)
        with self.lock:
            data = self._load()
            n = max([int(r["id"].split("-")[1]) for r in data["rules"]] + [0]) + 1
            rule.update(id=f"user-{n}", added=now or time.time())
            data["rules"].append(rule)
            self._save(data)
        return rule

    def remove(self, rule_id):
        with self.lock:
            data = self._load()
            if rule_id.startswith("builtin-"):
                if rule_id not in {r["id"] for r in BUILTIN_RULES}:
                    return False
                if rule_id not in data["disabled_builtins"]:
                    data["disabled_builtins"].append(rule_id)
            else:
                before = len(data["rules"])
                data["rules"] = [r for r in data["rules"] if r["id"] != rule_id]
                if len(data["rules"]) == before:
                    return False
            self._save(data)
            return True

    def enable(self, rule_id):
        """Switch a built-in rule back on."""
        with self.lock:
            data = self._load()
            if rule_id not in data["disabled_builtins"]:
                return False
            data["disabled_builtins"].remove(rule_id)
            self._save(data)
            return True

    def match(self, pair, rules=None):
        for rule in rules if rules is not None else self.rules():
            if rule["enabled"] and rule_matches(rule, pair):
                return rule
        return None


def validate_rule(rule):
    """Check a user-supplied rule; raises ValueError with a readable message."""
    out = {}
    reason = str(rule.get("reason") or "").strip()
    if not reason:
        raise ValueError("an allowlist rule needs a reason")
    out["reason"] = reason[:500]
    program = str(rule.get("program") or "*").strip()
    out["program"] = program
    ip = str(rule.get("ip") or "*").strip()
    if ip != "*" and ip not in SCOPES:
        try:
            ipaddress.ip_network(ip, strict=False)
        except ValueError:
            raise ValueError(f"ip must be '*', an address, a CIDR range or one of {SCOPES}")
    out["ip"] = ip
    port = rule.get("port")
    if port not in (None, "", "*"):
        port = int(port)
        if not 0 < port < 65536:
            raise ValueError("port must be 1-65535")
        out["port"] = port
    if rule.get("proto") not in (None, "", "*"):
        if rule["proto"] not in ("tcp", "udp"):
            raise ValueError("proto must be tcp or udp")
        out["proto"] = rule["proto"]
    if rule.get("direction") not in (None, "", "*"):
        if rule["direction"] not in ("in", "out"):
            raise ValueError("direction must be in or out")
        out["direction"] = rule["direction"]
    if out["program"] == "*" and out["ip"] == "*" and "port" not in out:
        raise ValueError("a rule must name a program, an address or a port")
    return out


def rule_matches(rule, pair):
    if not fnmatch.fnmatchcase(pair["program"], rule.get("program") or "*"):
        return False
    ip = rule.get("ip") or "*"
    if ip in SCOPES:
        if collector.scope_of(pair["ip"]) != ip:
            return False
    elif ip != "*":
        try:
            if ipaddress.ip_address(pair["ip"]) not in ipaddress.ip_network(ip, strict=False):
                return False
        except (ValueError, TypeError):
            return False
    for field in ("port", "proto", "direction"):
        if rule.get(field) not in (None, "*") and rule[field] != pair[field]:
            return False
    return True


# ---- the scorer -------------------------------------------------------------------

class Scorer:
    """Scores every pair active in the last LOOKBACK seconds and raises alerts.

    `extra` holds further checks (threat intelligence, geography): objects with
    prepare(ctx), called once per run, and findings(pair, ctx) -> [finding].
    """

    def __init__(self, store, allowlist, poll_interval=2.0, threshold=ALERT_THRESHOLD):
        self.store, self.allowlist = store, allowlist
        self.poll, self.threshold = poll_interval, threshold
        self.extra = []
        self.last_run = None

    def pairs(self, now):
        rows = self.store.query(
            "SELECT id, program, remote_ip ip, direction, proto, local_port,"
            " CASE direction WHEN 'in' THEN local_port ELSE remote_port END port,"
            " opened_at, closed_at, last_seen, bytes_sent, bytes_recv"
            " FROM connections WHERE kind='connection'"
            " AND (closed_at IS NULL OR closed_at >= ?) ORDER BY opened_at", (now - LOOKBACK,))
        pairs = {}
        for r in rows:
            k = (r["program"], r["ip"], r["port"], r["proto"], r["direction"])
            pairs.setdefault(k, []).append(r)
        return pairs

    def score_pair(self, key, conns, ctx):
        program, ip, port, proto, direction = key
        prog = ctx["programs"].get(program) or {}
        dest = ctx["destinations"].get(ip) or {}
        now, baseline = ctx["now"], ctx["baseline"]
        endpoint = fmt_endpoint(ip, port)
        pair = {"program": program, "ip": ip, "port": port, "proto": proto,
                "direction": direction, "scope": dest.get("scope") or collector.scope_of(ip)}
        out = []
        if direction == "out":
            out += beacon_findings(conns, self.poll, f"{proto} {endpoint}")
        lf = long_connection_finding(conns, now, baseline)
        if lf:
            out.append(lf)
        if (baseline is not None and dest.get("first_seen", 0) > baseline
                and now - dest["first_seen"] < RECENT):
            out.append(finding(
                "first_seen", POINTS["new_destination"],
                f"New destination: first contacted at {clock(dest['first_seen'])}, after Vigil's "
                f"baseline of {time.strftime('%Y-%m-%d %H:%M', time.localtime(baseline))}",
                "destinations table (first-seen tracking)",
                stats={"signal": "new_destination", "at": dest["first_seen"], "baseline": baseline}))
        if (direction == "out" and not prog.get("hidden") and baseline is not None
                and (prog.get("first_outbound") or 0) > baseline
                and now - prog["first_outbound"] < RECENT):
            out.append(finding(
                "first_seen", POINTS["new_program"],
                f"This program made its first outbound connection at "
                f"{clock(prog['first_outbound'])}; it had not used the network since Vigil "
                f"started watching", "programs table (first outbound connection)",
                stats={"signal": "new_program", "at": prog["first_outbound"]}))
        prev = ctx["prevalence"].get(ip, (0, 0))
        if pair["scope"] == "internet" and prev[0] <= 1 and prev[1] <= 5:
            out.append(finding(
                "rarity", POINTS["rare_destination"],
                f"Rare: only this program has ever contacted this address ({prev[1]} "
                f"connection{'s' if prev[1] != 1 else ''} in Vigil's history)",
                "pairs table (all programs, all time)",
                stats={"signal": "rare", "programs": prev[0], "connections": prev[1]}))
        if port not in COMMON_PORTS and pair["scope"] != "loopback":
            out.append(finding(
                "uncommon_port", POINTS["uncommon_port"],
                f"{proto}/{port} is not a common service port",
                f"connections table: {'local' if direction == 'in' else 'remote'} port",
                stats={"signal": "odd_port", "port": port, "proto": proto}))
        if not prog.get("hidden"):
            out += location_findings(json.loads(prog.get("info") or "{}"), program)
        for check in self.extra:
            out += check.findings(pair, ctx)
        for f in out:
            f["at"] = now
        score = min(100.0, round(sum(f["points"] for f in out), 1))
        return pair, score, out

    def run(self, now=None):
        now = time.time() if now is None else now
        baseline = self.store.get_meta("baseline_at")
        ctx = {"now": now, "baseline": baseline,
               "programs": {p["key"]: p for p in self.store.query("SELECT * FROM programs")},
               "destinations": {d["ip"]: d for d in self.store.query("SELECT * FROM destinations")},
               "prevalence": {r["ip"]: (r["n"], r["c"]) for r in self.store.query(
                   "SELECT ip, COUNT(DISTINCT program) n, SUM(connections) c FROM pairs"
                   " GROUP BY ip")}}
        for check in self.extra:
            check.prepare(ctx)
        rules = self.allowlist.rules()
        results = []
        for key, conns in self.pairs(now).items():
            pair, score, findings = self.score_pair(key, conns, ctx)
            rule = self.allowlist.match(pair, rules)
            results.append((pair, score, findings, rule))
        # One alert per program, address and direction: a listed server reached on
        # several ports is one thing to investigate, not several.
        groups = {}
        for pair, score, findings, rule in results:
            if score >= self.threshold and not rule:
                key = alert_fingerprint(pair)
                if key not in groups or score > groups[key][1]:
                    groups[key] = (pair, score, findings, groups.get(key, (0, 0, 0, []))[3])
                groups[key][3].append(f"{pair['proto']}/{pair['port']}")
        new_alerts = 0
        st = self.store
        with st.lock, st.db:
            st.db.execute("DELETE FROM scores")
            for pair, score, findings, rule in results:
                allow = None
                if rule:
                    allow = json.dumps({"id": rule["id"], "reason": rule["reason"],
                                        "source": rule["source"]})
                st.db.execute(
                    "INSERT INTO scores VALUES(?,?,?,?,?,?,?,?,?)",
                    (pair["program"], pair["ip"], pair["port"], pair["proto"], pair["direction"],
                     score, json.dumps(findings), allow, now))
            for pair, score, findings, ports in groups.values():
                new_alerts += self._raise(pair, score, findings, sorted(set(ports)), now, ctx)
        self.store.set_meta("last_scored_at", now)
        self.last_run = now
        return {"pairs": len(results), "new_alerts": new_alerts, "alerting": len(groups)}

    def _raise(self, pair, score, findings, ports, now, ctx):
        db = self.store.db
        fp = alert_fingerprint(pair)
        row = db.execute("SELECT id, peak_score FROM alerts WHERE fingerprint=?", (fp,)).fetchone()
        if row:
            db.execute("UPDATE alerts SET score=?, peak_score=MAX(peak_score, ?), findings=?,"
                       " port=?, proto=?, ports=?, last_updated=? WHERE id=?",
                       (score, score, json.dumps(findings), pair["port"], pair["proto"],
                        json.dumps(ports), now, row["id"]))
            return 0
        cur = db.execute(
            "INSERT INTO alerts(fingerprint,program,ip,port,proto,direction,ports,score,peak_score,"
            "findings,status,first_raised,last_updated) VALUES(?,?,?,?,?,?,?,?,?,?,'open',?,?)",
            (fp, pair["program"], pair["ip"], pair["port"], pair["proto"], pair["direction"],
             json.dumps(ports), score, score, json.dumps(findings), now, now))
        name = (ctx["programs"].get(pair["program"]) or {}).get("name", pair["program"])
        arrow = "←" if pair["direction"] == "in" else "→"
        top = max(findings, key=lambda f: f["points"])["reason"]
        self.store._event(
            now, "alert",
            f"Alert, score {score:.0f}: {name} {arrow} {pair['proto']} "
            f"{fmt_endpoint(pair['ip'], pair['port'])}. {top}",
            f"scorer: {len(findings)} findings over the last {LOOKBACK // 3600} h of "
            f"connections (threshold {self.threshold})",
            program=pair["program"], ip=pair["ip"], port=pair["port"], proto=pair["proto"],
            detail={"alert_id": cur.lastrowid, "score": score})
        return 1
