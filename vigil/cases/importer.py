"""Bring findings from every tool into Vigil Cases.

Sources: data/<tool>/findings.jsonl for each tool (Pkg, Files, Persist, Tasks), and the
Network Map's alerts (exported first, offline, by vigil.net.export). A JSON-lines file
from elsewhere (another PC) can be imported too. Every line is checked against the
finding format; lines that fail are skipped and counted, never half-imported.
"""

import json
import time
from pathlib import Path

from ..core import finding as fmt
from ..core.store import EXPORT_NAME

TOOLS = ("net", "pkg", "files", "persist", "tasks")
MAX_FILE = 64 * 1024 * 1024


def sources(data_root):
    root = Path(data_root)
    out = []
    for tool in TOOLS:
        p = root / tool / EXPORT_NAME
        out.append({"tool": tool, "path": str(p), "exists": p.exists(),
                    "mtime": p.stat().st_mtime if p.exists() else None,
                    "size": p.stat().st_size if p.exists() else 0})
    return out


def import_text(store, text, source, now=None):
    findings, skipped = fmt.from_jsonl(text)
    added, updated = store.add_findings(findings, source, now)
    store.x("INSERT INTO imports(ts, source, added, updated, skipped, notes) VALUES (?,?,?,?,?,?)",
            (now or time.time(), source, added, updated, len(skipped),
             json.dumps([f"line {n}: {why}" for n, why in skipped[:20]])))
    return {"source": source, "added": added, "updated": updated, "skipped": len(skipped),
            "skipped_lines": [{"line": n, "why": why} for n, why in skipped[:20]]}


def import_all(store, data_root, refresh_net=True, now=None):
    """Import every tool's export. The Network Map's is refreshed first (offline)."""
    results = []
    if refresh_net:
        try:
            from ..net import export as net_export
            r = net_export.export(data_root)
            if r:
                results.append({"source": "net (refreshed)", "exported": r[1], "skipped_alerts": r[2]})
        except Exception as exc:  # the Network Map's data must never stop the import
            results.append({"source": "net (refresh)", "error": f"{type(exc).__name__}: {exc}"})
    for s in sources(data_root):
        if not s["exists"]:
            continue
        if s["size"] > MAX_FILE:
            results.append({"source": s["path"], "error": "larger than 64 MB; not imported"})
            continue
        text = Path(s["path"]).read_text(encoding="utf-8", errors="replace")
        results.append(import_text(store, text, s["tool"], now))
    return results
