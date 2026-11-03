"""The Network Map's alerts in the suite's finding format, for Vigil Cases.

Reads the evidence store (data/vigil.db) without starting the monitor, builds each
alert's title, explanation and Fix panel exactly as the Alerts tab does, and writes
them to data/net/findings.jsonl. Nothing here touches the network: enrichment uses the
offline databases only, as everywhere in the Network Map.
"""

import ipaddress
import json
import os
from pathlib import Path

from ..core import finding as fmt
from ..core.store import EXPORT_NAME


def to_finding(a, ctx, view, fixpanel):
    x = view["explain"]
    summary = x["summary"]
    if not fmt.wording.one_sentence(summary):
        summary = summary.split(". ")[0].rstrip(".") + "."
    iocs = []
    try:
        ver = ipaddress.ip_address(a["ip"]).version
        if not ipaddress.ip_address(a["ip"]).is_private:
            iocs.append({"type": f"ipv{ver}", "value": a["ip"]})
    except ValueError:
        pass
    for h in ctx.get("hosts") or []:
        h = h.lstrip("*.").lower()
        if "." in h:
            iocs.append({"type": "domain", "value": h})
    likely = None
    if x.get("likely"):
        lk = x["likely"]
        likely = f"Probably {lk['name']} ({lk['matched']}): {lk['what']}"
    return fmt.make(
        "net", "alert", view["title"], summary, view["severity"],
        signals=[fmt.signal(s["text"], s["strength"], s.get("signal")) for s in x["signals"]],
        likely=likely, confidence=x["confidence"]["level"], confidence_reason=x["confidence"]["reason"],
        subject=a["fingerprint"], fixes=fixpanel,
        evidence=[{"kind": "program", "value": a["program"]},
                  {"kind": "destination", "value": f"{a['ip']}:{a['port']}/{a['proto']} ({a['direction']})"}],
        iocs=iocs[:10],
        technical=[{"label": t["label"], "value": t["value"]} for t in x["technical"]]
        + [{"label": "score", "value": str(a["score"])}, {"label": "status", "value": a["status"]}],
        data=f"alert #{a['id']} in vigil.db", when=a["first_raised"], tags=[a["status"]])


def export(data_dir):
    """Write data_dir/net/findings.jsonl. Returns (path, count, skipped) or None if the
    Network Map has never run with this data directory."""
    data_dir = Path(data_dir)
    if not (data_dir / "vigil.db").exists():
        return None
    from .server import App
    app = App(str(data_dir), start_monitor=False)
    out, skipped = [], 0
    try:
        for a in app.api_alerts({"status": "all"})["alerts"]:
            try:
                ctx = app.alert_context(a)
                out.append(to_finding(a, ctx, a["view"], app.api_alert_fix({"id": a["id"]})))
            except (fmt.FindingError, KeyError, ValueError):
                skipped += 1
    finally:
        app.store.close()
    d = data_dir / "net"
    d.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = d / EXPORT_NAME
    tmp = path.with_suffix(".tmp")
    tmp.write_text(fmt.to_jsonl(out))
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
    return path, len(out), skipped


if __name__ == "__main__":  # python -m vigil.net.export [DATA_DIR]
    import sys
    from ..core.store import default_data_dir
    r = export(sys.argv[1] if len(sys.argv) > 1 else default_data_dir())
    print(json.dumps({"path": str(r[0]), "findings": r[1], "skipped": r[2]} if r else {"path": None}))
