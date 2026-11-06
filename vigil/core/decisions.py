"""Your decisions about findings, shared by every tool: "expected", "fixed" or "not a
problem", always with a reason.

A decided finding leaves Home's "needs a look", the posture counts and the analyst brief,
but stays on the timeline (dimmed) with your reason, so nothing disappears silently. If
the same finding comes back *worse* (a higher severity than when you decided), the
decision no longer applies and it shows again. A finding marked "fixed" that a later scan
sees again is back too: if it were fixed, the check would not match any more.

Stored in <data>/decisions.json (0600), written atomically under a file lock, because
several tools may run in different processes.
"""

import fcntl
import json
import os
import time
from pathlib import Path

from . import finding as fmt

STATUSES = {
    "expected": "Expected here (you know what it is)",
    "fixed": "Fixed (you dealt with it)",
    "not_a_problem": "Not a problem (a false alarm)",
}
FILE = "decisions.json"
REASON_MAX = 2000


class DecisionError(ValueError):
    pass


class Decisions:
    def __init__(self, data_root):
        self.root = Path(data_root)
        self.path = self.root / FILE

    def _load(self):
        try:
            with open(self.path, encoding="utf-8") as fh:
                data = json.load(fh)
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    def _locked(self, change):
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        with open(self.root / (FILE + ".lock"), "a+") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            data = self._load()
            result = change(data)
            tmp = self.path.with_suffix(".tmp")
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=1, sort_keys=True)
            os.replace(tmp, self.path)
            return result

    def all(self):
        return self._load()

    def get(self, key):
        return self._load().get(key)

    def set(self, key, status, reason, title="", severity="Info", now=None):
        if status not in STATUSES:
            raise DecisionError(f"status must be one of {', '.join(STATUSES)}")
        reason = (reason or "").strip()
        if not reason:
            raise DecisionError("say why: a decision needs a reason, so it can be checked later")
        if not key or ":" not in key:
            raise DecisionError("bad finding key")
        entry = {"status": status, "reason": reason[:REASON_MAX], "title": title[:200], "severity": severity,
                 "ts": now or time.time()}

        def change(d):
            d[key] = entry
            return entry
        return self._locked(change)

    def clear(self, key):
        return self._locked(lambda d: d.pop(key, None))

    def applies(self, key, severity, decided=None, seen=None):
        """The decision for this finding, if it still applies (None if it came back)."""
        return still_applies((decided if decided is not None else self._load()).get(key), severity, seen)


SEEN_SLACK = 5.0     # seconds: the scan that produced the finding may finish just after you decide


def still_applies(d, severity, seen=None):
    """A decision stops applying when the finding is worse than when you decided, or when
    something you marked fixed is seen again by a later scan."""
    if not d:
        return None
    if fmt.SEVERITY_RANK.get(severity, 0) > fmt.SEVERITY_RANK.get(d.get("severity"), 0):
        return None
    if d.get("status") == "fixed" and seen and seen > d.get("ts", 0) + SEEN_SLACK:
        return None
    return d


def split(findings, key_of, decided, seen_of=None):
    """(open findings, set-aside findings) given a decisions dict."""
    keep, aside = [], []
    for f in findings:
        d = still_applies(decided.get(key_of(f)), f["severity"], seen_of(f) if seen_of else None)
        (aside if d else keep).append(f)
    return keep, aside


def routes(decisions):
    """The decision API, shared by Home and Cases: decide, undo, list."""
    from .web import BadRequest, _json_body

    def decide(q, body, headers):
        d = _json_body(body)
        try:
            return {"key": d.get("key"), "decision": decisions.set(d.get("key", ""), d.get("status", ""),
                                                                   d.get("reason", ""), d.get("title", ""),
                                                                   d.get("severity", "Info"))}
        except DecisionError as exc:
            raise BadRequest(str(exc))

    def undecide(q, body, headers):
        d = _json_body(body)
        return {"key": d.get("key"), "removed": decisions.clear(d.get("key", ""))}

    def listing(q):
        return {"decisions": decisions.all(), "statuses": STATUSES}
    return {("POST", "/api/decide"): decide, ("POST", "/api/undecide"): undecide, ("GET", "/api/decisions"): listing}
