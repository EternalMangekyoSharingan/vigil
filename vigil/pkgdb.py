"""Installed packages, read from the package database files (no tools run).

Arch: /var/lib/pacman/local/<name>-<version>/desc. Other distros: not read here yet
(their databases are binary); callers then fall back to commands for the user.
"""

import glob
import os
import re


def pacman_installed(root="/"):
    """{name: {"version", "reason" (0 explicit, 1 dependency), "depends", "provides"}}."""
    out = {}
    for desc in glob.glob(os.path.join(root, "var/lib/pacman/local/*/desc")):
        fields, key = {}, None
        try:
            with open(desc, encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.rstrip("\n")
                    if line.startswith("%") and line.endswith("%"):
                        key = line.strip("%")
                        fields[key] = []
                    elif line and key:
                        fields[key].append(line)
        except OSError:
            continue
        name = (fields.get("NAME") or [None])[0]
        if not name:
            continue
        out[name] = {"version": (fields.get("VERSION") or [""])[0],
                     "reason": int((fields.get("REASON") or ["0"])[0] or 0),
                     "depends": [_bare(d) for d in fields.get("DEPENDS", [])],
                     "provides": [_bare(d) for d in fields.get("PROVIDES", [])],
                     "size": int((fields.get("SIZE") or ["0"])[0] or 0)}
    return out


def _bare(dep):
    return re.split(r"[<>=:]", dep, maxsplit=1)[0]


def orphans(pkgs):
    """Packages installed as dependencies that nothing installed needs any more."""
    needed = set()
    for p in pkgs.values():
        needed.update(p["depends"])
    provided_by = {}
    for name, p in pkgs.items():
        for prov in p["provides"]:
            provided_by.setdefault(prov, set()).add(name)
    needed_names = set()
    for dep in needed:
        needed_names.add(dep)
        needed_names.update(provided_by.get(dep, ()))
    return sorted(n for n, p in pkgs.items() if p["reason"] == 1 and n not in needed_names)


# ---- pacman's version comparison (alpm_pkg_vercmp / rpmvercmp), in Python ----------------

def _parse_evr(v):
    epoch, _, rest = v.rpartition(":") if ":" in v else ("0", "", v)
    ver, _, rel = rest.partition("-")
    return epoch or "0", ver, rel or None


def _rpmvercmp(a, b):
    if a == b:
        return 0
    ia = re.findall(r"[0-9]+|[a-zA-Z]+|[^0-9a-zA-Z]+", a)
    ib = re.findall(r"[0-9]+|[a-zA-Z]+|[^0-9a-zA-Z]+", b)
    ia = [x for x in ia if x.isalnum()]
    ib = [x for x in ib if x.isalnum()]
    for x, y in zip(ia, ib):
        if x.isdigit() and y.isdigit():
            x, y = int(x), int(y)
            if x != y:
                return 1 if x > y else -1
        elif x.isdigit() != y.isdigit():
            return 1 if x.isdigit() else -1  # numbers are newer than letters
        elif x != y:
            return 1 if x > y else -1
    if len(ia) == len(ib):
        return 0
    longer = ia if len(ia) > len(ib) else ib
    nxt = longer[min(len(ia), len(ib))]
    # an extra alpha segment means an older (pre-release) version; an extra number, newer
    result = 1 if nxt.isdigit() else -1
    return result if longer is ia else -result


def vercmp(a, b):
    """<0 if a is older than b, 0 if equal, >0 if newer (pacman's ordering)."""
    ea, va, ra = _parse_evr(a)
    eb, vb, rb = _parse_evr(b)
    c = _rpmvercmp(ea, eb) or _rpmvercmp(va, vb)
    if c == 0 and ra is not None and rb is not None:
        c = _rpmvercmp(ra, rb)
    return c
