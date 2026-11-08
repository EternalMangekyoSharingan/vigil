"""Settings shared by every Vigil tool: data/settings.json (the file the Network Map has
always used), so switching Run mode on in one tool's Settings switches it on everywhere.

Keys this module owns (other keys in the file, such as feed mirrors, are kept as they are):

    sudo_mode   Run mode: Vigil may run its own generated commands when you press Run.
                Off by default. The key keeps its old name so existing files still work.
    density     "comfortable" (default) or "compact": spacing in every page.
    motion      "system" (default, follows the desktop's reduced-motion setting), "full"
                or "reduced".

Writes are atomic and the file is private to the user (0600).
"""

import json
import os
import threading
import time
from pathlib import Path

UI_KEYS = {"density": ("comfortable", "compact"), "motion": ("system", "full", "reduced")}
_lock = threading.Lock()


def path(root):
    return Path(root) / "settings.json"


def load(root):
    try:
        with open(path(root)) as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save(root, data):
    p = path(root)
    p.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = f"{p}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump(data, fh, indent=2)
    os.replace(tmp, p)


def run_mode(root):
    return bool(load(root).get("sudo_mode"))


def public(root):
    """What every page may read: Run mode and the interface preferences."""
    s = load(root)
    out = {"run_mode": bool(s.get("sudo_mode"))}
    for k, allowed in UI_KEYS.items():
        out[k] = s.get(k) if s.get(k) in allowed else allowed[0]
    return out


def update(root, req):
    """Apply a change from a page. Only known keys with valid values; returns public()."""
    with _lock:
        s = load(root)
        if "run_mode" in req:
            s["sudo_mode"] = bool(req["run_mode"])
        for k, allowed in UI_KEYS.items():
            if k in req:
                if req[k] not in allowed:
                    raise ValueError(f"{k} must be one of: {', '.join(allowed)}")
                s[k] = req[k]
        save(root, s)
    return public(root)


class RunLog:
    """The run log for tools without their own event store: data/run-log.jsonl.
    Has the same event() signature runner.run() uses on the Network Map's store."""

    def __init__(self, root, tool):
        self.file = Path(root) / "run-log.jsonl"
        self.tool = tool

    def event(self, ts, kind, summary, source, detail=None):
        line = json.dumps({"ts": ts or time.time(), "tool": self.tool, "kind": kind, "summary": summary,
                           "source": source, "detail": detail or {}})
        self.file.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(self.file, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a") as fh:
            fh.write(line + "\n")
