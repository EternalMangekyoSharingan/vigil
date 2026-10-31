"""Offline enrichment: threat-intelligence feeds and a country/ASN database.

Nothing here uses the network unless update_feeds() or update_geo() is called, and
those run only when the user asks (the Intel tab's buttons, or the update-feeds /
update-geo commands). A download is a plain GET of a public list: it reveals the
machine's public address to the list's host, nothing about its traffic. Lookups
are local SQLite queries.
"""

import csv
import gzip
import hashlib
import io
import ipaddress
import json
import os
import sqlite3
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from . import __version__, collector
from .scoring import POINTS, RECENT, clock, finding

MAX_DOWNLOAD = 128 * 1024 * 1024
STALE_DAYS = 7

FEEDS = {
    "feodo": {
        "title": "abuse.ch Feodo Tracker: botnet C2 servers",
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
        "about": "https://feodotracker.abuse.ch/about/", "points": 80,
    },
    "sslbl": {
        "title": "abuse.ch SSLBL: botnet C2 servers seen over TLS",
        "url": "https://sslbl.abuse.ch/blacklist/sslipblacklist.csv",
        "about": "https://sslbl.abuse.ch/", "points": 80,
    },
    "urlhaus": {
        "title": "abuse.ch URLhaus: servers distributing malware",
        "url": "https://urlhaus.abuse.ch/downloads/csv_online/",
        "about": "https://urlhaus.abuse.ch/about/", "points": 60,
    },
}
GEO = {
    "title": "IPtoASN: country and network owner per address range",
    "url": "https://iptoasn.com/data/ip2asn-combined.tsv.gz",
    "about": "https://iptoasn.com/", "licence": "Public Domain (PDDL v1.0)",
}
ISO_3166 = "/usr/share/iso-codes/json/iso_3166-1.json"


# ---- downloading (only ever called on the user's request) ------------------------

def http(url, headers=None, data=None, limit=MAX_DOWNLOAD, timeout=60):
    """The one place Vigil opens a URL. Only reached from actions the user triggers:
    feed and geo updates, and hash lookups. Returns (status, body bytes); HTTP errors
    come back as their status, network failures raise RuntimeError."""
    req = urllib.request.Request(url, data=data, headers={
        "User-Agent": f"Vigil/{__version__} (personal blue-team lab)", **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as res:
            body = res.read(limit + 1)
            status = res.status
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(2**20)
    except urllib.error.URLError as exc:
        raise RuntimeError(f"could not reach {url}: {exc.reason}") from None
    if len(body) > limit:
        raise RuntimeError(f"download from {url} is larger than {limit} bytes; refused")
    return status, body


def fetch(url, headers=None, limit=MAX_DOWNLOAD, timeout=60):
    """GET a URL and return its bytes. Refuses anything larger than `limit`."""
    status, data = http(url, headers, limit=limit, timeout=timeout)
    if status >= 400:
        hint = ""
        if status in (401, 403) and "abuse.ch" in url:
            hint = (" (abuse.ch may require a free Auth-Key: get one at https://auth.abuse.ch/ "
                    "and set VIGIL_ABUSECH_KEY or abusech_auth_key in data/settings.json)")
        raise RuntimeError(f"HTTP {status} from {url}{hint}")
    return data


# ---- feed parsers: bytes -> list of indicator records -----------------------------

def _ip(value):
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


def _csv_rows(data):
    text = data.decode("utf-8", errors="replace")
    lines = [ln for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
    return csv.reader(lines)


def parse_feodo(data):
    """Feodo Tracker blocklist, JSON (preferred) or CSV."""
    out = []
    try:
        rows = json.loads(data)
    except ValueError:
        rows = None
    if isinstance(rows, list):
        for r in rows:
            ip = _ip(str(r.get("ip_address", "")))
            if ip:
                out.append({"kind": "ip", "indicator": ip, "host": ip, "port": _int(r.get("port")),
                            "label": r.get("malware") or "botnet C2",
                            "first_seen": r.get("first_seen"), "last_seen": r.get("last_online"),
                            "status": r.get("status"),
                            "reference": f"https://feodotracker.abuse.ch/browse/host/{ip}/"})
        return out
    # CSV: "first_seen_utc","dst_ip","dst_port","c2_status","last_online","malware"
    for r in _csv_rows(data):
        if len(r) >= 6 and _ip(r[1]):
            ip = _ip(r[1])
            out.append({"kind": "ip", "indicator": ip, "host": ip, "port": _int(r[2]),
                        "label": r[5] or "botnet C2", "first_seen": r[0], "last_seen": r[4],
                        "status": r[3],
                        "reference": f"https://feodotracker.abuse.ch/browse/host/{ip}/"})
    return out


def parse_sslbl(data):
    """SSLBL botnet C2 IP list: Firstseen,DstIP,DstPort."""
    out = []
    for r in _csv_rows(data):
        if len(r) >= 2 and _ip(r[1]):
            ip = _ip(r[1])
            out.append({"kind": "ip", "indicator": ip, "host": ip,
                        "port": _int(r[2]) if len(r) > 2 else None, "label": "botnet C2 (TLS)",
                        "first_seen": r[0], "last_seen": None, "status": None,
                        "reference": "https://sslbl.abuse.ch/blacklist/"})
    return out


def parse_urlhaus(data):
    """URLhaus CSV: id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter."""
    out = []
    for r in _csv_rows(data):
        if len(r) < 4 or not r[2].lower().startswith(("http://", "https://", "ftp://")):
            continue
        try:
            parts = urllib.parse.urlsplit(r[2])
            host = (parts.hostname or "").lower()
            port = parts.port
        except ValueError:
            continue
        if not host:
            continue
        out.append({"kind": "url", "indicator": r[2], "host": _ip(host) or host, "port": port,
                    "label": (r[5] if len(r) > 5 else "") or "malware_download",
                    "first_seen": r[1], "last_seen": r[4] if len(r) > 4 else None,
                    "status": r[3], "reference": r[7] if len(r) > 7 else None})
    return out


PARSERS = {"feodo": parse_feodo, "sslbl": parse_sslbl, "urlhaus": parse_urlhaus}


def _int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


# ---- country / ASN database --------------------------------------------------------

def ip_key(ip):
    """16-byte big-endian key; IPv4 maps into ::ffff:0:0/96 so one index serves both."""
    a = ipaddress.ip_address(ip)
    if a.version == 4:
        a = ipaddress.IPv6Address(b"\0" * 10 + b"\xff\xff" + a.packed)
    return a.packed


def import_ip2asn(fileobj, db_path):
    """Load an IPtoASN TSV (range_start, range_end, AS_number, country, AS_description).

    Builds a new database beside db_path and swaps it in, so readers never see a
    half-built table. Returns the number of ranges loaded.
    """
    tmp = db_path + ".tmp"
    if os.path.exists(tmp):
        os.remove(tmp)
    db = sqlite3.connect(tmp)
    db.execute("CREATE TABLE geo(start BLOB NOT NULL, end BLOB NOT NULL, asn INTEGER,"
               " country TEXT, owner TEXT)")
    rows, n = [], 0
    for line in io.TextIOWrapper(fileobj, encoding="utf-8", errors="replace"):
        f = line.rstrip("\n").split("\t")
        if len(f) < 5:
            continue
        try:
            asn = int(f[2])
            start, end = ip_key(f[0]), ip_key(f[1])
        except ValueError:
            continue
        if asn == 0:  # "Not routed": leave it out; a miss already means that
            continue
        rows.append((start, end, asn, f[3].upper() if f[3] != "None" else None, f[4]))
        if len(rows) >= 50000:
            db.executemany("INSERT INTO geo VALUES(?,?,?,?,?)", rows)
            n += len(rows)
            rows = []
    db.executemany("INSERT INTO geo VALUES(?,?,?,?,?)", rows)
    n += len(rows)
    db.execute("CREATE INDEX geo_start ON geo(start)")
    db.commit()
    db.close()
    if n == 0:
        os.remove(tmp)
        raise RuntimeError("no address ranges recognised; is this an IPtoASN TSV file?")
    os.replace(tmp, db_path)
    return n


def load_country_names(path=ISO_3166):
    """ISO 3166 names from the iso-codes package when installed; codes alone otherwise."""
    try:
        with open(path) as fh:
            return {c["alpha_2"]: c.get("common_name") or c["name"] for c in json.load(fh)["3166-1"]}
    except (OSError, ValueError, KeyError):
        return {}


# ---- the enricher ------------------------------------------------------------------

class Enricher:
    """Feed and geo lookups for the UI, plus the scorer's intel and country checks."""

    def __init__(self, store, data_dir):
        self.store = store
        self.data_dir = Path(data_dir)
        self.geo_path = str(self.data_dir / "geo.db")
        self.lock = threading.Lock()
        self.update_lock = threading.Lock()
        self._geo = None
        self.countries = load_country_names()

    # settings --------------------------------------------------------------------

    def settings(self):
        try:
            with open(self.data_dir / "settings.json") as fh:
                return json.load(fh)
        except (OSError, ValueError):
            return {}

    def auth_key(self):
        return os.environ.get("VIGIL_ABUSECH_KEY") or self.settings().get("abusech_auth_key")

    def source_url(self, name):
        """Default URL, unless data/settings.json names a mirror under "sources"."""
        default = GEO["url"] if name == "geo" else FEEDS[name]["url"]
        return self.settings().get("sources", {}).get(name, default)

    # updates (network, on request only) ------------------------------------------

    def update_feeds(self, names=None, fetcher=fetch):
        with self.update_lock:
            return [self._update_feed(n, fetcher) for n in (names or FEEDS)]

    def _update_feed(self, name, fetcher):
        url = self.source_url(name)
        now = time.time()
        headers = {}
        if self.auth_key() and "abuse.ch" in urllib.parse.urlsplit(url).netloc:
            headers["Auth-Key"] = self.auth_key()
        try:
            data = fetcher(url, headers=headers)
            result = self.import_feed(name, data, url, now)
        except Exception as exc:  # keep the previous data; report why
            st = self.store
            with st.lock, st.db:
                st.db.execute(
                    "INSERT INTO feeds(name,url,attempted_at,status,error) VALUES(?,?,?,'error',?)"
                    " ON CONFLICT(name) DO UPDATE SET url=excluded.url,"
                    " attempted_at=excluded.attempted_at, status='error', error=excluded.error",
                    (name, url, now, str(exc)))
            return {"name": name, "ok": False, "error": str(exc)}
        return result

    def import_feed(self, name, data, origin, now=None):
        """Parse and store one feed's bytes, replacing that feed's previous entries."""
        now = time.time() if now is None else now
        records = PARSERS[name](data)
        if not records:
            raise RuntimeError("no indicators recognised; the feed format may have changed "
                               "(previous data kept)")
        sha = hashlib.sha256(data).hexdigest()
        feed_dir = self.data_dir / "feeds"
        feed_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        path = feed_dir / f"{name}.dat"
        path.write_bytes(data)
        st = self.store
        with st.lock, st.db:
            st.db.execute("DELETE FROM intel WHERE feed=?", (name,))
            st.db.executemany(
                "INSERT INTO intel(feed,kind,indicator,host,port,label,first_seen,last_seen,"
                "status,reference) VALUES(?,?,?,?,?,?,?,?,?,?)",
                [(name, r["kind"], r["indicator"], r["host"], r["port"], r["label"],
                  r["first_seen"], r["last_seen"], r["status"], r["reference"]) for r in records])
            st.db.execute(
                "INSERT INTO feeds(name,url,fetched_at,attempted_at,entries,sha256,file,status,error)"
                " VALUES(?,?,?,?,?,?,?,'ok',NULL) ON CONFLICT(name) DO UPDATE SET"
                " url=excluded.url, fetched_at=excluded.fetched_at,"
                " attempted_at=excluded.attempted_at, entries=excluded.entries,"
                " sha256=excluded.sha256, file=excluded.file, status='ok', error=NULL",
                (name, origin, now, now, len(records), sha, str(path)))
        return {"name": name, "ok": True, "entries": len(records), "sha256": sha}

    def update_geo(self, fetcher=fetch, path=None):
        """Download (or, with `path`, load from disk) the IPtoASN database."""
        with self.update_lock:
            origin = path or self.source_url("geo")
            now = time.time()
            try:
                if path:
                    with open(path, "rb") as fh:
                        data = fh.read()
                else:
                    data = fetcher(origin)
                raw = gzip.decompress(data) if data[:2] == b"\x1f\x8b" else data
                with self.lock:
                    self._close_geo()
                    n = import_ip2asn(io.BytesIO(raw), self.geo_path)
            except Exception as exc:
                self.store.set_meta("geo", dict(self.store.get_meta("geo") or {},
                                                attempted_at=now, status="error", error=str(exc)))
                return {"name": "geo", "ok": False, "error": str(exc)}
            meta = {"source": origin, "fetched_at": now, "attempted_at": now, "ranges": n,
                    "sha256": hashlib.sha256(data).hexdigest(), "status": "ok", "error": None}
            self.store.set_meta("geo", meta)
            return {"name": "geo", "ok": True, "ranges": n}

    # lookups (offline) -------------------------------------------------------------

    def _close_geo(self):
        if self._geo is not None:
            self._geo.close()
            self._geo = None

    def geo(self, ip):
        try:
            key = ip_key(ip)
        except ValueError:
            return None
        with self.lock:
            if self._geo is None:
                if not os.path.exists(self.geo_path):
                    return None
                self._geo = sqlite3.connect(f"file:{self.geo_path}?mode=ro", uri=True,
                                            check_same_thread=False)
            row = self._geo.execute("SELECT start, end, asn, country, owner FROM geo"
                                    " WHERE start <= ? ORDER BY start DESC LIMIT 1",
                                    (key,)).fetchone()
        if not row or row[1] < key:
            return None
        country = row[3]
        return {"asn": row[2], "country": country,
                "country_name": self.countries.get(country, country) if country else None,
                "owner": row[4], "range": f"{_unkey(row[0])}–{_unkey(row[1])}"}

    def intel(self, host):
        rows = self.store.query("SELECT i.*, f.fetched_at FROM intel i LEFT JOIN feeds f"
                                " ON f.name = i.feed WHERE i.host=? LIMIT 50", (host,))
        for r in rows:
            r["title"] = FEEDS.get(r["feed"], {}).get("title", r["feed"])
        return rows

    def label(self, ip):
        """Short owner label for the map: 'AS15169 Google LLC · US'."""
        g = self.geo(ip)
        if not g:
            return None
        owner = g["owner"] or ""
        return f"AS{g['asn']} {owner}".strip() + (f" · {g['country']}" if g["country"] else "")

    def describe(self, ip):
        return {"geo": self.geo(ip), "intel": self.intel(ip)}

    def status(self):
        feeds = {r["name"]: r for r in self.store.query("SELECT * FROM feeds")}
        return {
            "feeds": [dict(FEEDS[n], name=n, url=self.source_url(n), **{
                k: feeds.get(n, {}).get(k) for k in ("fetched_at", "attempted_at", "entries",
                                                     "sha256", "status", "error")})
                      for n in FEEDS],
            "geo": dict(GEO, url=self.source_url("geo"), **(self.store.get_meta("geo") or {})),
            "auth_key_set": bool(self.auth_key()),
            "country_names": bool(self.countries),
        }

    # scoring hooks -------------------------------------------------------------------

    def prepare(self, ctx):
        """Per scoring run: feed freshness, and when each country was first contacted."""
        ctx["feeds"] = {r["name"]: r for r in self.store.query("SELECT * FROM feeds")}
        first = {}
        if os.path.exists(self.geo_path):
            for d in ctx["destinations"].values():
                if d["scope"] != "internet":
                    continue
                g = self.geo(d["ip"])
                if g and g["country"]:
                    c = g["country"]
                    if c not in first or d["first_seen"] < first[c]:
                        first[c] = d["first_seen"]
        ctx["country_first_seen"] = first

    def findings(self, pair, ctx):
        out = []
        best = {}
        for hit in self.intel(pair["ip"]):
            if hit["feed"] not in best:
                best[hit["feed"]] = hit
        for name, hit in best.items():
            feed = ctx["feeds"].get(name) or {}
            what = {"ip": f"{hit['label']}", "url": f"hosting malware ({hit['label']})"}[hit["kind"]]
            port = ""
            if hit["port"]:
                port = (f"; listed on port {hit['port']}, the port in use" if hit["port"] == pair["port"]
                        else f"; listed on port {hit['port']}")
            seen = f"; first seen {hit['first_seen']}" if hit["first_seen"] else ""
            if hit["kind"] == "url":
                n = self.store.one("SELECT COUNT(*) n FROM intel WHERE feed=? AND host=?",
                                   (name, pair["ip"]))["n"]
                what += f": {n} URL{'s' if n != 1 else ''}, e.g. {hit['indicator']}"
            age = ""
            if feed.get("fetched_at"):
                days = (ctx["now"] - feed["fetched_at"]) / 86400
                age = f", {days:.0f} days old" if days >= STALE_DAYS else ""
            out.append(finding(
                "threat_intel", FEEDS[name]["points"],
                f"Listed by {FEEDS[name]['title'].split(':')[0]} as {what}{port}{seen}",
                f"{name} feed downloaded {_date(feed.get('fetched_at'))} ({feed.get('entries')} "
                f"entries{age}, sha256 {str(feed.get('sha256'))[:12]}…); {hit['reference'] or ''}"))
        baseline = ctx["baseline"]
        if pair["scope"] == "internet" and baseline is not None:
            g = self.geo(pair["ip"])
            c = g and g["country"]
            first = ctx.get("country_first_seen", {}).get(c)
            if c and first and first > baseline and ctx["now"] - first < RECENT:
                out.append(finding(
                    "rare_country", POINTS["rare_country"],
                    f"First connection from this PC to a server in {g['country_name']} ({c}), "
                    f"at {clock(first)}",
                    f"offline IPtoASN database ({g['range']}, AS{g['asn']}) and the destinations "
                    f"table"))
        return out


def _unkey(raw):
    a = ipaddress.IPv6Address(raw)
    return str(a.ipv4_mapped or a)


def _date(ts):
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(ts)) if ts else "never"
