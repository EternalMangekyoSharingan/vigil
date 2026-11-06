"""Exports for a case (or everything): indicators and findings as CSV, a STIX 2.1 bundle,
and a Markdown report with the evidence chain. Text only."""

import csv
import io
import time

from .. import __version__
from ..core import finding as fmt
from ..core.export import _cell, defang, fence, iso, local, md, stix_id, stix_pattern

STIX_TYPES = {"ipv4", "ipv6", "domain", "url", "email", "md5", "sha1", "sha256", "file"}
TOOL_NAMES = {"net": "Vigil Net", "pkg": "Vigil Pkg", "files": "Vigil Files", "persist": "Vigil Persist",
              "tasks": "Vigil Tasks"}


def indicators(findings):
    """Unique indicators across findings: {(type, value): {first_seen, tools, findings}}."""
    out = {}
    for f in findings:
        body = f["body"]
        for i in body.get("iocs") or []:
            k = (i["type"], i["value"])
            e = out.setdefault(k, {"type": i["type"], "value": i["value"], "first_seen": f["first_seen"],
                                   "tools": set(), "findings": [], "worst": "Info"})
            e["first_seen"] = min(e["first_seen"], f["first_seen"])
            e["tools"].add(f["tool"])
            e["findings"].append(f["title"])
            if fmt.SEVERITY_RANK[f["severity"]] > fmt.SEVERITY_RANK[e["worst"]]:
                e["worst"] = f["severity"]
    return sorted(out.values(), key=lambda e: (-fmt.SEVERITY_RANK[e["worst"]], e["type"], e["value"]))


def csv_indicators(findings):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["type", "value", "first_seen_utc", "worst_severity", "tools", "findings"])
    for e in indicators(findings):
        w.writerow([_cell(e["type"]), _cell(e["value"]), iso(e["first_seen"]), e["worst"],
                    " ".join(sorted(e["tools"])), _cell(" | ".join(dict.fromkeys(e["findings"])))])
    return buf.getvalue()


def csv_findings(findings):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["first_seen_utc", "last_seen_utc", "tool", "severity", "confidence", "title", "summary", "subject",
                "evidence", "check", "id"])
    for f in findings:
        b = f["body"]
        w.writerow([iso(f["first_seen"]), iso(f["last_seen"]), f["tool"], f["severity"], b["confidence"]["level"],
                    _cell(f["title"]), _cell(f["summary"]), _cell(b.get("subject", "")),
                    _cell(" | ".join(e["value"] for e in b.get("evidence") or [])), b["check"], b["id"]])
    return buf.getvalue()


def stix(case, findings, now=None):
    """A STIX 2.1 bundle: Vigil's identity, one indicator per unique indicator, one note per
    finding and per analyst note, and a grouping that ties them together."""
    now = now or time.time()
    ident = stix_id("identity", "vigil")
    group_id = stix_id("grouping", "case", case["id"] if case else "all", case["created_at"] if case else 0)
    created = iso(case["created_at"] if case else now)
    objs = [{"type": "identity", "spec_version": "2.1", "id": ident, "created": iso(0), "modified": iso(0),
             "name": "Vigil", "identity_class": "system",
             "description": "Personal blue-team lab (suite of local tools); findings are local observations."}]
    ind_ids = {}
    for e in indicators(findings):
        if e["type"] not in STIX_TYPES:
            continue
        iid = stix_id("indicator", e["type"], e["value"])
        ind_ids[(e["type"], e["value"])] = iid
        objs.append({"type": "indicator", "spec_version": "2.1", "id": iid, "created_by_ref": ident,
                     "created": iso(e["first_seen"]), "modified": iso(e["first_seen"]),
                     "name": f"{e['type']} {e['value']}"[:250],
                     "description": "Seen in: " + "; ".join(dict.fromkeys(e["findings"]))[:900],
                     "indicator_types": ["malicious-activity" if e["worst"] == "High" else "anomalous-activity"],
                     "pattern": stix_pattern(e["type"], e["value"]), "pattern_type": "stix",
                     "valid_from": iso(e["first_seen"]),
                     "labels": sorted(f"vigil-{t}" for t in e["tools"])})
    note_ids = []
    for f in findings:
        b = f["body"]
        refs = [ind_ids[(i["type"], i["value"])] for i in b.get("iocs") or [] if (i["type"], i["value"]) in ind_ids]
        nid = stix_id("note", "finding", f["key"])
        note_ids.append(nid)
        lines = [b["summary"], ""] + [f"- {s['text']} (strength {s['strength']})" for s in b.get("signals") or []]
        if b.get("likely"):
            lines += ["", f"Likely explanation: {b['likely']}"]
        lines += ["", f"Confidence: {b['confidence']['level']}. {b['confidence'].get('reason', '')}",
                  f"Source: {TOOL_NAMES.get(f['tool'], f['tool'])}, check {b['check']}, {b['source'].get('data', '')}"]
        objs.append({"type": "note", "spec_version": "2.1", "id": nid, "created_by_ref": ident,
                     "created": iso(f["first_seen"]), "modified": iso(f["last_seen"]),
                     "abstract": f"[{f['severity']}] {f['title']}"[:250], "content": "\n".join(lines),
                     "object_refs": refs or [group_id], "labels": [f"vigil-{f['tool']}", f"severity-{f['severity'].lower()}"]})
    for n in (case or {}).get("notes") or []:
        nid = stix_id("note", "analyst", n["id"])
        note_ids.append(nid)
        objs.append({"type": "note", "spec_version": "2.1", "id": nid, "created_by_ref": ident,
                     "created": iso(n["ts"]), "modified": iso(n["ts"]), "abstract": "Analyst note",
                     "content": n["text"], "object_refs": [group_id], "authors": ["Vigil user"]})
    techniques = {}
    for f in findings:
        for a in f["body"].get("attack") or []:
            techniques[a["id"]] = a
    ap_ids = []
    for tid, a in sorted(techniques.items()):
        apid = stix_id("attack-pattern", "mitre", tid)
        ap_ids.append(apid)
        objs.append({"type": "attack-pattern", "spec_version": "2.1", "id": apid, "created": iso(0), "modified": iso(0),
                     "name": a["name"], "external_references": [{"source_name": "mitre-attack", "external_id": tid,
                                                                "url": a.get("url") or ""}],
                     "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": a["tactic"]}]
                     if a.get("tactic") else []})
    refs = list(ind_ids.values()) + note_ids + ap_ids
    objs.append({"type": "grouping", "spec_version": "2.1", "id": group_id, "created_by_ref": ident,
                 "created": created, "modified": iso(now), "name": (case or {}).get("title") or "All Vigil findings",
                 "description": (case or {}).get("summary") or f"Exported from Vigil {__version__}.",
                 "context": "suspicious-activity", "object_refs": refs or [ident],
                 "labels": ([f"status-{case['status']}"] + [f"tag-{t}" for t in case["tags"]]) if case else ["all-findings"]})
    return {"type": "bundle", "id": stix_id("bundle", group_id, iso(now)), "objects": objs}


def markdown(case, findings, timeline, now=None):
    now = now or time.time()
    title = (case or {}).get("title") or "All Vigil findings"
    counts = {s: sum(f["severity"] == s for f in findings) for s in fmt.SEVERITIES}
    out = [f"# {md(title)}", ""]
    if case:
        out += [f"- **Status:** {case['status']}", f"- **Opened:** {local(case['created_at'])}",
                f"- **Tags:** {', '.join(md(t) for t in case['tags']) or '—'}"]
    out += [f"- **Report generated:** {local(now)} by Vigil {__version__}",
            f"- **Findings:** {len(findings)} ({', '.join(f'{n} {s}' for s, n in counts.items() if n) or 'none'})", ""]
    if case and case.get("summary"):
        out += ["## Summary", "", md(case["summary"]), ""]
    out += ["## Timeline", "", "| When | What | Detail |", "| --- | --- | --- |"]
    for e in sorted(timeline, key=lambda e: e["ts"]):
        if e["kind"] == "finding":
            what, detail = f"{e['severity']} · {TOOL_NAMES.get(e['tool'], e['tool'])}", e["title"]
        elif e["kind"] == "note":
            what, detail = "Note", e["text"]
        else:
            what, detail = "Case", e["text"]
        out.append(f"| {local(e['ts'])} | {md(what)} | {md(detail)[:300]} |")
    out += ["", "## Findings", ""]
    for f in sorted(findings, key=lambda f: (-fmt.SEVERITY_RANK[f["severity"]], f["first_seen"])):
        b = f["body"]
        out += [f"### {md(f['title'])}", "",
                f"**{f['severity']}** · {TOOL_NAMES.get(f['tool'], f['tool'])} · first seen {local(f['first_seen'])}"
                + (f" · seen {f['times']} times, last {local(f['last_seen'])}" if f.get("times", 1) > 1 else ""), "",
                md(b["summary"]), ""]
        if b.get("signals"):
            out += ["What Vigil noticed:", ""] + [f"- {md(s['text'])}" for s in b["signals"]] + [""]
        if b.get("likely"):
            out += [f"Likely explanation: {md(b['likely'])}", ""]
        out += [f"How sure: **{b['confidence']['level']}**. {md(b['confidence'].get('reason', ''))}", ""]
        if b.get("attack"):
            out += ["Looks like (MITRE ATT&CK): " + ", ".join(f"**{a['id']}** {md(a['name'])}" for a in b["attack"]), ""]
        ev = [e for e in b.get("evidence") or [] if e.get("value")]
        if ev:
            out += ["Evidence:", ""] + [f"- {md(e['kind'])}: `{e['value'].replace('`', '')}`"
                                        + (f" — {md(e['note'])}" if e.get("note") else "") for e in ev] + [""]
        fx = b.get("fixes") or {}
        for label, key in (("Check (read-only)", "check"), ("Fix", "fix")):
            cmds = [(o["title"], c["text"]) for o in fx.get(key) or [] for c in o.get("commands") or []]
            if cmds:
                text = "\n".join(c for _, c in cmds)
                out += [f"{label} — commands to copy and run yourself:", "", fence(text) + "sh", text, fence(text), ""]
        out += [f"_Source: {md(b['source']['tool'])} / {md(b['check'])} / {md(b['source'].get('data', ''))}, "
                f"finding id {b['id']}._", ""]
    ind = indicators(findings)
    if ind:
        out += ["## Indicators (defanged)", "", "| Type | Value | First seen | Worst |", "| --- | --- | --- | --- |"]
        out += [f"| {e['type']} | {md(defang(e['value']))} | {local(e['first_seen'])} | {e['worst']} |" for e in ind]
        out.append("")
    if case and case.get("notes"):
        out += ["## Notes", ""] + [f"- {local(n['ts'])}: {md(n['text'])}" for n in case["notes"]] + [""]
    out += ["## Limits", "",
            "- Every finding comes from Vigil's read-only, static tools on one PC: nothing was run in a sandbox, "
            "so behaviour was not observed (Vigil Lab is not built yet).",
            "- \"No finding\" never means safe; it means nothing matched Vigil's checks.",
            "- Indicators are defanged here (hxxp, [.]) so the report cannot be clicked by accident.",
            "- ATT&CK ids name the technique a finding is evidence of (Vigil's mapping); look them up at "
            "attack.mitre.org/techniques/ followed by the id.", ""]
    return "\n".join(out)
