"""The offline analyst: a triage brief written from the evidence alone, with no model.

It is always available, costs nothing, sends nothing, and is the baseline any AI answer
is compared against. It answers the four questions an analyst asks first:

    What happened?        storylines in time order, by ATT&CK tactic
    How sure are we?      what is strong evidence, what has an innocent explanation
    What do I do first?   the read-only checks Vigil generated, worst finding first
    What can I ignore?    Low and Info findings, and what Vigil recognised as normal
"""

import time

from ..core import finding as fmt
from ..core.attack import TACTIC_NAMES

TOOL = {"net": "Net", "pkg": "Pkg", "files": "Files", "persist": "Persist", "tasks": "Tasks"}


def _when(ts):
    return time.strftime("%b %d %H:%M", time.localtime(ts))


def brief(findings, stories=(), injection=()):
    """Markdown-ish plain text brief plus structured parts for the page."""
    fs = fmt.sort(findings)
    serious = [f for f in fs if f["severity"] in ("High", "Medium")]
    quiet = [f for f in fs if f["severity"] in ("Low", "Info")]
    parts = {"headline": "", "happened": [], "sure": [], "first": [], "then": [], "ignore": [], "tamper": []}
    if not fs:
        parts["headline"] = "There is nothing to analyse yet: import findings from the tools first."
        return parts
    highs = [f for f in serious if f["severity"] == "High"]
    if stories:
        top = stories[0]
        parts["headline"] = (f"{len(stories)} storyline{'s' if len(stories) != 1 else ''} tie findings from several tools "
                             f"together; the most serious is “{top['title']}” ({top['severity']}).")
    elif highs:
        parts["headline"] = f"{len(highs)} High finding{'s' if len(highs) != 1 else ''}, none linked across tools yet."
    elif serious:
        parts["headline"] = f"{len(serious)} Medium finding{'s' if len(serious) != 1 else ''}; nothing High."
    else:
        parts["headline"] = "Only Low and Info findings: nothing stands out."
    for s in stories[:3]:
        steps = [f"{_when(st['when'])} {st['tool_name']}: {st['title']}" for st in s["steps"][:6]]
        tactic = " → ".join(TACTIC_NAMES.get(t, t) for t in s["tactics"][:5])
        parts["happened"].append({"title": s["title"], "severity": s["severity"], "tactics": tactic, "steps": steps,
                                  "why": s["summary"]})
    if not stories:
        for f in serious[:5]:
            parts["happened"].append({"title": f["title"], "severity": f["severity"], "tactics": ", ".join(
                a["tactic"] for a in f.get("attack") or [] if a.get("tactic")), "steps": [
                f"{_when(f['source']['when'])} {TOOL.get(f['tool'], f['tool'])}: {f['summary']}"], "why": f.get("likely") or ""})
    strong = [f for f in serious if f["confidence"]["level"] == "High"]
    weak = [f for f in serious if f["confidence"]["level"] != "High"]
    for f in strong[:5]:
        parts["sure"].append(f"Strong: {f['title']} — {f['confidence'].get('reason') or ''}".strip(" —"))
    for f in weak[:5]:
        parts["sure"].append(f"Could be innocent: {f['title']} — {f.get('likely') or f['confidence'].get('reason') or ''}"
                             .strip(" —"))
    seen = set()
    for f in serious:
        for o in (f.get("fixes") or {}).get("check") or []:
            for c in o.get("commands") or []:
                if c["text"] not in seen and len(parts["first"]) < 8:
                    seen.add(c["text"])
                    parts["first"].append({"command": c["text"], "tokens": c.get("tokens") or [], "why": o["title"],
                                           "for": f["title"]})
    for f in serious:          # fix advice with no command to copy ("assume it was copied: change ...")
        for o in (f.get("fixes") or {}).get("fix") or []:
            if not o.get("commands") and o.get("steps") and len(parts["then"]) < 4:
                parts["then"].append({"title": o["title"], "steps": o["steps"][:4], "for": f["title"]})
    for f in quiet[:8]:
        parts["ignore"].append(f"{f['title']} ({f['severity']}, {TOOL.get(f['tool'], f['tool'])})")
    for i in injection:
        parts["tamper"].append(f"Text addressed to an AI was found in the evidence ({i['where']}): “{i['text'].strip()}”. "
                               "Real system files and process names don't talk to assistants; treat its source as hostile.")
    return parts


def as_text(parts):
    out = [parts["headline"], ""]
    if parts["tamper"]:
        out += ["Possible tampering:"] + [f"- {t}" for t in parts["tamper"]] + [""]
    if parts["happened"]:
        out.append("What happened:")
        for h in parts["happened"]:
            out.append(f"- [{h['severity']}] {h['title']}" + (f" ({h['tactics']})" if h["tactics"] else ""))
            out += [f"    {s}" for s in h["steps"]]
        out.append("")
    if parts["sure"]:
        out += ["How sure:"] + [f"- {s}" for s in parts["sure"]] + [""]
    if parts["first"]:
        out += ["Check first (read-only, copy and run yourself):"] + [f"- {x['command']}   # {x['why']}" for x in parts["first"]] + [""]
    if parts.get("then"):
        out.append("Then:")
        for t in parts["then"]:
            out.append(f"- {t['title']} ({t['for']}):")
            out += [f"    {x}" for x in t["steps"]]
        out.append("")
    if parts["ignore"]:
        out += ["Probably fine to leave:"] + [f"- {s}" for s in parts["ignore"]]
    return "\n".join(out).strip() + "\n"
