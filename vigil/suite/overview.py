"""What Home shows: every tool's latest state, read from its findings export, plus
what to do next. Read-only."""

import json
import os
import time
from pathlib import Path

from ..core import finding as fmt
from ..core.decisions import Decisions, split
from ..core.store import EXPORT_NAME
from ..core.suite import TOOLS, url

NEVER = {
    "net": "Start the Network Map to see which programs talk to whom.",
    "tasks": "Look at what is running right now.",
    "persist": "Scan once; that scan becomes your baseline, and later scans show what changed.",
    "files": "Check what is waiting in Downloads before you open it.",
    "pkg": "Review an AUR package before building it, or let Vigil find the ones your helper downloaded.",
    "cases": "Collect every tool's findings on one timeline.",
}


def _read(path):
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None, None
    fs, _ = fmt.from_jsonl(text)
    return fs, os.path.getmtime(path)


def tool_state(tid, root):
    fs, mtime = _read(Path(root) / tid / EXPORT_NAME)
    if fs is None:
        return {"last": None, "counts": {}, "top": [], "findings": []}
    counts = {s: sum(f["severity"] == s for f in fs) for s in fmt.SEVERITIES}
    top = [f for f in fmt.sort(fs) if f["severity"] in ("High", "Medium")][:3]
    return {"last": mtime, "counts": counts, "top": [{"title": f["title"], "severity": f["severity"]} for f in top],
            "findings": fs}


SEEN = "home-seen.json"


def current_keys(root):
    """Every finding key the tools hold now (Cases excluded: it re-shows the others)."""
    keys = []
    for t in TOOLS:
        if t["id"] in ("home", "cases"):
            continue
        keys += [f"{t['id']}:{f['id']}" for f in tool_state(t["id"], root)["findings"]]
    return keys


def remember_seen(root, now=None):
    """Called as a check-up starts: what was already there, so Home can say what is new."""
    p = Path(root) / SEEN
    tmp = p.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump({"ts": now or time.time(), "keys": current_keys(root)}, fh)
    os.replace(tmp, p)


def _seen(root):
    try:
        d = json.loads((Path(root) / SEEN).read_text(encoding="utf-8"))
        return d.get("ts"), set(d.get("keys") or [])
    except (OSError, ValueError, AttributeError):
        return None, None


def overview(root, running, job=None, stories=None):
    tools, needs, total = [], [], {s: 0 for s in fmt.SEVERITIES}
    decided = Decisions(root).all()
    aside = []
    seen_ts, seen = _seen(root)
    fresh = 0
    for t in TOOLS:
        if t["id"] == "home":
            continue
        st = tool_state(t["id"], root)
        if t["id"] == "cases":
            st["counts"], st["top"] = {}, []          # Cases re-shows other tools' findings
            db = Path(root) / "cases" / "cases.db"
            st["last"] = os.path.getmtime(db) if db.exists() else None
        else:
            keep, gone = split(st["findings"], lambda f, tid=t["id"]: f"{tid}:{f['id']}", decided,
                               lambda f: f["source"]["when"])
            aside += [{"key": f"{t['id']}:{f['id']}", "title": f["title"], "tool_name": t["name"],
                       "decision": decided[f"{t['id']}:{f['id']}"]} for f in gone]
            st["counts"] = {s: sum(f["severity"] == s for f in keep) for s in fmt.SEVERITIES}
            for s, n in st["counts"].items():
                total[s] += n
            for f in keep:
                is_new = seen is not None and bool(seen) and f"{t['id']}:{f['id']}" not in seen
                fresh += is_new
                if f["severity"] in ("High", "Medium"):
                    needs.append({"tool": t["id"], "tool_name": t["name"], "title": f["title"], "summary": f["summary"],
                                  "severity": f["severity"], "when": f["source"]["when"], "key": f"{t['id']}:{f['id']}",
                                  "url": url(t["id"]), "attack": f.get("attack") or [], "new": is_new})
        tools.append({"id": t["id"], "name": t["name"], "question": t["question"], "url": url(t["id"]),
                      "running": running.get(t["id"], False), "last": st["last"], "counts": st["counts"],
                      "top": st["top"], "hint": None if st["last"] else NEVER[t["id"]]})
    needs.sort(key=lambda n: (-fmt.SEVERITY_RANK[n["severity"]], -n["when"]))
    ran = [t for t in tools if t["last"]]
    return {"tools": tools, "posture": total, "needs_look": needs[:12], "needs_total": len(needs),
            "first_run": not ran, "last_activity": max((t["last"] for t in ran), default=None),
            "checkup": job.snapshot() if job else None, "stories": stories or [], "now": time.time(),
            "verdict": verdict(total, ran), "set_aside": aside[:50], "set_aside_total": len(aside),
            "new_since": {"ts": seen_ts, "count": fresh, "needs": sum(n["new"] for n in needs)} if seen else None}


def verdict(total, ran):
    if not ran:
        return {"word": "Not checked yet", "cls": "", "text": "Run a check-up: it reads what is running, what starts "
                "by itself and what is in Downloads. Nothing is changed, sent or deleted."}
    if total["High"]:
        return {"word": f"{total['High']} thing{'s' if total['High'] != 1 else ''} need a look", "cls": "danger",
                "text": "Start with the High items below; each one says why and what to check."}
    if total["Medium"]:
        return {"word": "Mostly normal", "cls": "warn", "text": "A few Medium items are worth reading when you have a minute."}
    return {"word": "Nothing stands out", "cls": "ok", "text": "No checks matched anything worth a look. That is not a "
            "promise the PC is clean; it means Vigil's checks found nothing."}


def dumps(o):
    return json.dumps(o, default=str)
