"""Storylines: findings from different tools that point at the same thing, joined up.

Every finding is reduced to the entities it mentions: file paths, hashes, IP addresses,
domains, packages and systemd units. Findings that share an entity are linked; a group
that spans two or more tools becomes a storyline, ordered in time and by ATT&CK tactic.

    Tasks:   updater runs from a temporary folder          /tmp/.x/agent
    Persist: updater.service starts a program from /tmp   /tmp/.x/agent, updater.service
    Net:     agent checks in with 198.51.100.9 every ~60 s  /tmp/.x/agent, 198.51.100.9

This is plain set logic, explainable line by line: each step in a storyline names the
entity that tied it in. It is the deterministic core an AI assistant builds on.
"""

import hashlib
import ipaddress
import os
import re

from ..ai.context import is_lan
from ..core import attack as attack_map
from ..core import finding as fmt

TOOL_NAMES = {"net": "Net", "pkg": "Pkg", "files": "Files", "persist": "Persist", "tasks": "Tasks"}
PATH_RE = re.compile(r"(?<![\w:])(/(?:[\w.@+~-]+/)*[\w.@+~-]+)")
# Paths that would tie unrelated findings together: interpreters, shells, top folders.
NOISE_PATHS = {"/bin/sh", "/bin/bash", "/bin/dash", "/usr/bin/sh", "/usr/bin/bash", "/usr/bin/dash", "/usr/bin/env",
               "/usr/bin/python", "/usr/bin/python3", "/usr/bin/perl", "/usr/bin/node", "/usr/bin/zsh", "/bin/zsh",
               "/dev/null", "/dev/tcp", "/etc/passwd", "/etc/shadow", "/proc", "/tmp", "/var/tmp", "/dev/shm",
               "/usr/bin/curl", "/usr/bin/wget", "/bin/true", "/bin/false", "/usr/bin/sudo", "/usr/bin/systemctl"}
INTERP = re.compile(r"/(python[0-9.]*|perl|ruby|node|bash|sh|dash|zsh|java|php|lua)$")


def _path_ok(p):
    p = p.removesuffix(" (deleted)").rstrip(".,;:)")
    if p in NOISE_PATHS or INTERP.search(p) or p.count("/") < 2 or len(p) < 6:
        return None
    if p.startswith(("/proc/", "/sys/", "/dev/")):
        return None
    return p


def _ip_ok(v):
    try:
        a = ipaddress.ip_address(v)
    except ValueError:
        return None
    if a.is_loopback or a.is_link_local or a.is_unspecified or a.is_multicast or is_lan(str(a)):
        return None   # your own network: it would tie unrelated findings together
    return str(a)


def entities(f):
    """{(kind, value)} a finding mentions. Kinds: path, sha256, md5, sha1, ip, domain, package, unit."""
    out = set()
    for i in f.get("iocs") or []:
        t, v = i["type"], i["value"]
        if t in ("ipv4", "ipv6"):
            v = _ip_ok(v)
            if v:
                out.add(("ip", v))
        elif t in ("sha256", "sha1", "md5"):
            out.add((t, v.lower()))
        elif t == "domain":
            out.add(("domain", v.lower().lstrip("*.")))
        elif t == "url":
            m = re.match(r"(?i)^[a-z]+://([^/:?#]+)", v)
            if m:
                h = m.group(1).lower()
                out.add(("ip", h) if _ip_ok(h) else ("domain", h))
    for e in f.get("evidence") or []:
        k, v = e.get("kind"), str(e.get("value") or "")
        if k in ("path", "file", "program") or (k == "Exec"):
            for p in PATH_RE.findall(v):
                p = _path_ok(p)
                if p:
                    out.add(("path", p))
        elif k == "sha256" and re.fullmatch(r"[0-9a-f]{64}", v):
            out.add(("sha256", v))
        elif k == "destination":
            ip = _ip_ok(v.split("/")[0].split(" ")[0].rsplit(":", 1)[0].strip("[]"))
            if ip:
                out.add(("ip", ip))
        elif k == "package":
            out.add(("package", v.split()[0]))
        if k == "path" and v.endswith((".service", ".timer")):
            out.add(("unit", os.path.basename(v)))
    for t in f.get("technical") or []:
        label, v = t.get("label"), str(t.get("value") or "")
        if label == "package" and v not in ("none", "-", ""):
            out.add(("package", v.split()[0]))
        elif label == "systemd unit" and v not in ("-", ""):
            out.add(("unit", v))
        elif label == "command line":
            for p in PATH_RE.findall(v):
                p = _path_ok(p)
                if p:
                    out.add(("path", p))
    # Paths named in what was noticed ("starts a program from a temporary folder (/tmp/x)").
    for s in f.get("signals") or []:
        for p in PATH_RE.findall(s.get("text", "")):
            p = _path_ok(p)
            if p and not p.startswith(("/etc/", "/usr/lib/", "/usr/share/")):
                out.add(("path", p))
    return out


def display(entity):
    kind, v = entity
    if kind == "path":
        return os.path.basename(v)
    if kind in ("sha256", "sha1", "md5"):
        return f"file {v[:12]}…"
    return v


class _UF:
    def __init__(self):
        self.p = {}

    def find(self, x):
        self.p.setdefault(x, x)
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x

    def union(self, a, b):
        self.p[self.find(a)] = self.find(b)


def stories(rows, min_tools=2):
    """rows: Cases store findings ({key, tool, severity, title, first_seen, body}). Returns storylines."""
    ents = {r["key"]: entities(r["body"]) for r in rows}
    by_entity = {}
    for key, es in ents.items():
        for e in es:
            by_entity.setdefault(e, set()).add(key)
    uf = _UF()
    for keys in by_entity.values():
        keys = sorted(keys)
        for k in keys[1:]:
            uf.union(keys[0], k)
    groups = {}
    for r in rows:
        if ents[r["key"]]:
            groups.setdefault(uf.find(r["key"]), []).append(r)
    out = []
    for members in groups.values():
        tools = {m["tool"] for m in members}
        if len(tools) < min_tools:
            continue
        keys = {m["key"] for m in members}
        shared = sorted(((e, ks & keys) for e, ks in by_entity.items() if len(ks & keys) > 1),
                        key=lambda x: (-len({k.split(":")[0] for k in x[1]}), -len(x[1]), x[0]))
        anchor = shared[0][0] if shared else next(iter(ents[members[0]["key"]]))
        techniques = {}
        for m in members:
            for a in m["body"].get("attack") or []:
                techniques[a["id"]] = a
        chain = sorted(techniques.values(), key=lambda a: (attack_map.tactic_rank(a), a["id"]))
        tactics = list(dict.fromkeys(a["tactic"] for a in chain if a.get("tactic")))
        worst = fmt.worst(members) or "Info"
        escalated = worst != "High" and (len(tools) >= 3 or ({"persistence"} <= set(tactics) and
                                                             {"execution", "command-and-control"} & set(tactics)))
        sev = "High" if escalated or worst == "High" else worst
        steps = []
        for m in sorted(members, key=lambda m: m["first_seen"]):
            why = [display(e) for e in sorted(ents[m["key"]]) if any(e == s[0] for s in shared)]
            steps.append({"key": m["key"], "tool": m["tool"], "tool_name": TOOL_NAMES.get(m["tool"], m["tool"]),
                          "title": m["title"], "severity": m["severity"], "when": m["first_seen"], "linked_by": why[:3],
                          "attack": [a["id"] for a in m["body"].get("attack") or []]})
        names = " and ".join(sorted(TOOL_NAMES.get(t, t) for t in tools)) if len(tools) < 3 else \
            ", ".join(sorted(TOOL_NAMES.get(t, t) for t in tools)[:-1]) + f" and {sorted(TOOL_NAMES.get(t, t) for t in tools)[-1]}"
        summary = (f"{names} each saw something tied to {display(anchor)}"
                   + (f"; together they look like {', '.join(t.replace('-', ' ') for t in tactics[:4])}" if tactics else "")
                   + (". Seen together, this is more serious than any one finding." if escalated else "."))
        out.append({
            "id": hashlib.sha1(f"{anchor[0]}|{anchor[1]}".encode()).hexdigest()[:12],
            "title": f"What happened around {display(anchor)}"[:60], "anchor": {"kind": anchor[0], "value": anchor[1]},
            "severity": sev, "escalated": escalated, "summary": summary, "tools": sorted(tools),
            "first": min(m["first_seen"] for m in members), "last": max(m["first_seen"] for m in members),
            "steps": steps, "keys": sorted(keys), "attack": chain, "tactics": tactics,
            "shared": [{"kind": e[0], "value": e[1], "display": display(e), "findings": len(ks)} for e, ks in shared[:8]],
        })
    return sorted(out, key=lambda s: (-fmt.SEVERITY_RANK[s["severity"]], -len(s["tools"]), -s["last"]))


def pivot(rows, kind, value):
    """Findings that mention one entity."""
    return [r for r in rows if (kind, value) in entities(r["body"])]
