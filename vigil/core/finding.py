"""The one finding format every Vigil tool produces and Vigil Cases imports.

A finding is a plain JSON-able dict:

    id          stable id: the same tool, check and subject give the same id
    tool        "pkg", "files", "persist", "tasks", "net", ...
    check       which check raised it (machine name)
    title       plain English, at most 60 characters (core.wording rules)
    summary     one sentence
    severity    High / Medium / Low / Info
    signals     [{"text", "strength" 0..1, "kind"}]: what was noticed, strongest first
    likely      the likely explanation (one or two sentences), or None
    confidence  {"level": High / Medium / Low, "reason": "..."}
    fixes       a core.fixes.panel(): Check / Fix / Undo commands (copy only), or None
    evidence    [{"kind", "value", "note"?}]: file and line, path, pid, hash ...
    iocs        [{"type", "value"}]: indicators worth exporting (urls, domains, ips, hashes)
    technical   [{"label", "value"}]: raw details, shown collapsed
    subject     what the finding is about (a path, package, pid ...)
    source      {"tool", "check", "data", "when"}: where it came from, as CLAUDE.md asks
    tags        free-form short labels
    format      FORMAT_VERSION

make() validates as it builds, so a tool cannot emit a finding that breaks the rules.
"""

import hashlib
import json
import time

from . import wording

FORMAT_VERSION = 1
SEVERITIES = ("High", "Medium", "Low", "Info")
CONFIDENCE = ("High", "Medium", "Low")
SEVERITY_RANK = {s: i for i, s in enumerate(reversed(SEVERITIES))}   # Info 0 .. High 3
IOC_TYPES = ("ipv4", "ipv6", "domain", "url", "email", "md5", "sha1", "sha256", "file")


class FindingError(ValueError):
    pass


def scored(check, points, reason, data, means=None, stats=None):
    """One raw scored observation (the Network Map's and File Inspector's building
    block). `means` says, in plain words, what it would do to you. `stats` holds the
    raw numbers behind it (and its `signal` kind), for the wording modules."""
    f = {"check": check, "points": round(points, 1), "reason": reason, "data": data}
    if means:
        f["means"] = means
    if stats:
        f["stats"] = stats
    return f


def signal(text, strength, kind=None):
    return {"text": text, "strength": round(max(0.0, min(1.0, float(strength))), 2), "kind": kind}


def finding_id(tool, check, subject):
    return hashlib.sha1(f"{tool}|{check}|{subject}".encode("utf-8", "replace")).hexdigest()[:16]


def make(tool, check, title, summary, severity, *, signals=(), likely=None, confidence="Medium",
         confidence_reason="", subject="", fixes=None, evidence=(), iocs=(), technical=(), data="",
         when=None, tags=()):
    """Build and validate one finding. Raises FindingError listing every rule it breaks."""
    when = time.time() if when is None else when
    f = {
        "format": FORMAT_VERSION, "id": finding_id(tool, check, subject), "tool": tool, "check": check,
        "title": title, "summary": summary, "severity": severity,
        "signals": sorted([s if isinstance(s, dict) else signal(*s) for s in signals],
                          key=lambda s: -s["strength"]),
        "likely": likely, "confidence": {"level": confidence, "reason": confidence_reason},
        "fixes": fixes, "evidence": [dict(e) for e in evidence], "iocs": [dict(i) for i in iocs],
        "technical": [dict(t) for t in technical], "subject": subject,
        "source": {"tool": tool, "check": check, "data": data, "when": when}, "tags": list(tags),
    }
    bad = problems(f)
    if bad:
        raise FindingError(f"{tool}/{check}: " + "; ".join(bad))
    return f


def problems(f):
    """Every way `f` breaks the suite's finding rules ([] when it is fine)."""
    out = []
    for key in ("id", "tool", "check", "title", "summary", "severity", "signals", "confidence", "source"):
        if key not in f:
            out.append(f"missing {key}")
    if out:
        return out
    out += [f"title {p}" for p in wording.title_problems(f["title"])]
    if not wording.one_sentence(f["summary"]):
        out.append("summary must be exactly one sentence")
    if f["severity"] not in SEVERITIES:
        out.append(f"severity must be one of {SEVERITIES}")
    if (f["confidence"] or {}).get("level") not in CONFIDENCE:
        out.append(f"confidence must be one of {CONFIDENCE}")
    for s in f["signals"]:
        if not s.get("text") or not 0 <= s.get("strength", -1) <= 1:
            out.append("every signal needs text and a strength between 0 and 1")
            break
    if f["severity"] in ("High", "Medium") and not f["signals"]:
        out.append("a High or Medium finding must say what was noticed (signals)")
    for i in f.get("iocs") or []:
        if i.get("type") not in IOC_TYPES or not i.get("value"):
            out.append(f"bad indicator {i!r}")
    for opt in ((f.get("fixes") or {}).get("fix") or []):
        if opt.get("commands") and not (opt.get("undo") or opt.get("undo_steps")):
            out.append(f"fix '{opt.get('title')}' has no undo")
    src = f["source"]
    if not (src.get("tool") and src.get("check") and src.get("when")):
        out.append("source must say which tool, which check and when")
    return out


def worst(findings):
    """The highest severity among `findings`, or None."""
    return max((f["severity"] for f in findings), key=SEVERITY_RANK.get, default=None)


def sort(findings):
    return sorted(findings, key=lambda f: (-SEVERITY_RANK[f["severity"]], f["title"]))


# ---- the shared export: JSON lines, one finding per line --------------------------------

def to_jsonl(findings):
    return "".join(json.dumps(f, sort_keys=True, ensure_ascii=False) + "\n" for f in findings)


def from_jsonl(text, strict=False):
    """Parse JSON lines. Lines that are not valid findings are skipped (or raise, if strict),
    and reported as (line number, reason) in the second return value."""
    out, skipped = [], []
    for n, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            f = json.loads(line)
        except ValueError:
            skipped.append((n, "not JSON"))
            continue
        bad = problems(f) if isinstance(f, dict) else ["not an object"]
        if bad:
            if strict:
                raise FindingError(f"line {n}: " + "; ".join(bad))
            skipped.append((n, "; ".join(bad)))
            continue
        out.append(f)
    return out, skipped
