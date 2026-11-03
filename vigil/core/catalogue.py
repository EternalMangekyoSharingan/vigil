"""Known benign services: recognise common background traffic, so an alert can say
"probably NetworkManager's connectivity check" instead of leaving the user guessing.

A match only informs: it lowers the alert's severity and is stated plainly, but the
alert stays visible until the user decides to allowlist it.
"""

import functools
import json
import os
from pathlib import Path

CATALOGUE = Path(__file__).parent / "data" / "known_services.json"


@functools.lru_cache(maxsize=1)
def catalogue():
    """The known-services list. A missing or broken file must never take down a page:
    it only means "no 'probably X' match", so return an empty list and carry on."""
    try:
        with open(CATALOGUE, encoding="utf-8") as fh:
            return json.load(fh)["services"]
    except (OSError, ValueError, KeyError):
        return []


def by_id(sid):
    return next((s for s in catalogue() if s["id"] == sid), None)


def _domain_hit(hosts, domains):
    for h in hosts:
        h = h.lower().lstrip("*.")
        for d in domains:
            if h == d or h.endswith("." + d):
                return h
    return None


def match(process=None, port=None, proto=None, hosts=(), owner=None, interval=None):
    """Best catalogue match for one connection pattern, or None.

    process: executable basename or program name (None when unattributed)
    hosts:   names known for the destination (Identify, certificates)
    owner:   network owner from the offline ASN database
    interval: seconds between check-ins, if the traffic is on a timer
    Returns the service plus 'confidence' (Low/Medium/High) and 'matched' (what fitted).
    """
    best = None
    proc = (process or "").lower()
    for s in catalogue():
        m = s["match"]
        got, points = [], 0
        if proc and proc in [p.lower() for p in m.get("processes", [])]:
            got.append("process name")
            points += 3
        dom = _domain_hit(hosts or (), m.get("domains", []))
        if dom:
            got.append(f"destination {dom}")
            points += 3
        if port is not None and f"{proto}/{port}" in m.get("ports", []):
            got.append("port")
            points += 1
        lo_hi = m.get("interval")
        if interval and lo_hi and lo_hi[0] <= interval <= lo_hi[1]:
            got.append(f"{_interval_words(interval)} interval")
            points += 1
        if owner and any(o in owner.lower() for o in m.get("asn_owners", [])):
            got.append("network owner")
            points += 1
        strong = "process name" in got or dom
        weak_ok = m.get("port_and_interval_suffice") and "port" in got and any("interval" in g for g in got)
        if not (strong or weak_ok):
            continue
        conf = "High" if points >= 5 else "Medium" if points >= 4 else "Low"
        cand = dict(s, confidence=conf, matched=" + ".join(got), points=points)
        if best is None or points > best["points"]:
            best = cand
    return best


def _interval_words(seconds):
    if seconds < 90:
        return f"{round(seconds)} s"
    return f"{round(seconds / 60)} min"


def process_name(program_key, info=None):
    """The executable's basename, for matching."""
    exe = ((info or {}).get("exe") or program_key.split(" ", 1)[0]).removesuffix(" (deleted)")
    return os.path.basename(exe)
