"""Installed packages, read from the package database files (no tools run).

Arch: /var/lib/pacman/local/<name>-<version>/desc. Other distros: not read here yet
(their databases are binary); callers then fall back to commands for the user.
"""

import glob
import gzip
import hashlib
import os
import re
import stat
import tarfile


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
                     "size": int((fields.get("SIZE") or ["0"])[0] or 0),
                     "dir": os.path.dirname(desc),
                     "packager": (fields.get("PACKAGER") or [""])[0],
                     "builddate": int((fields.get("BUILDDATE") or ["0"])[0] or 0),
                     "installdate": int((fields.get("INSTALLDATE") or ["0"])[0] or 0),
                     "validation": (fields.get("VALIDATION") or [""])[0],
                     "backup": [b.split("\t")[0] for b in fields.get("BACKUP", [])]}
    return out


def sync_names(root="/"):
    """Package names in the sync databases (what the official/configured repos offer).
    Returns (names, unreadable db files). The databases are tar archives; only their
    member *names* are listed, nothing is extracted. zstd-compressed ones need a
    decoder the standard library doesn't have before Python 3.14: reported as unreadable."""
    names, bad = set(), []
    for db in sorted(glob.glob(os.path.join(root, "var/lib/pacman/sync/*.db"))):
        try:
            with tarfile.open(db, "r:*") as tf:
                for m in tf.getmembers():
                    top = m.name.split("/", 1)[0]
                    n = top.rsplit("-", 2)[0] if top.count("-") >= 2 else None
                    if n:
                        names.add(n)
        except (tarfile.TarError, OSError, EOFError):
            bad.append(db)
    return names, bad


def foreign(root="/"):
    """Installed packages that no sync database offers (`pacman -Qm`).
    Returns ({name: info}, how) where how is "sync" or the fallback used."""
    pkgs = pacman_installed(root)
    names, bad = sync_names(root)
    if names:
        return {n: p for n, p in pkgs.items() if n not in names}, "sync"
    # No readable sync database: fall back to the packager field. Official packages are
    # signed by Arch packagers (an @archlinux.org address); makepkg's default is
    # "Unknown Packager". A heuristic, and reported as one.
    return {n: p for n, p in pkgs.items() if "@archlinux.org" not in p["packager"]}, \
        "packager" + (" (sync databases unreadable)" if bad else " (no sync databases)")


# ---- pacman -Qkk, read-only: compare installed files with the package's mtree ------------

def _unescape(path):
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), path)


def mtree(pkg_dir):
    """{path: attrs} from <pkg_dir>/mtree (gzip, mtree format), relative to /."""
    out, defaults = {}, {}
    try:
        with gzip.open(os.path.join(pkg_dir, "mtree"), "rt", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                if parts[0] == "/set":
                    defaults.update(kv.split("=", 1) for kv in parts[1:] if "=" in kv)
                    continue
                if parts[0] == "/unset":
                    for k in parts[1:]:
                        defaults.pop(k, None)
                    continue
                path = _unescape(parts[0]).removeprefix("./")
                if path.startswith("."):
                    continue  # .PKGINFO, .BUILDINFO, .MTREE, .INSTALL
                attrs = dict(defaults)
                attrs.update(kv.split("=", 1) for kv in parts[1:] if "=" in kv)
                out[path] = attrs
    except (OSError, EOFError, gzip.BadGzipFile):
        return None
    return out


def verify(info, root="/", hash_limit=64 * 1024 * 1024):
    """Files of one installed package that differ from what it installed.

    Like `pacman -Qkk`: missing files, wrong type, link target, size, mode and SHA-256.
    Files the package marks as backup (config you are expected to edit) are skipped, as
    pacman does. Returns {"checked", "changed": [{path, problem, detail}], "unreadable", "error"}.
    """
    tree = mtree(info["dir"])
    if tree is None:
        return {"checked": 0, "changed": [], "unreadable": 0, "error": "no readable mtree file"}
    backup = set(info.get("backup") or [])
    changed, checked, unreadable = [], 0, 0
    for rel, a in sorted(tree.items()):
        if rel in backup:
            continue
        p = os.path.join(root, rel)
        checked += 1
        try:
            st = os.lstat(p)
        except FileNotFoundError:
            changed.append({"path": "/" + rel, "problem": "missing", "detail": "deleted since install"})
            continue
        except OSError:
            unreadable += 1
            continue
        want = a.get("type", "file")
        is_type = {"file": stat.S_ISREG, "dir": stat.S_ISDIR, "link": stat.S_ISLNK}.get(want, lambda m: True)
        if not is_type(st.st_mode):
            changed.append({"path": "/" + rel, "problem": "type", "detail": f"should be a {want}"})
            continue
        if want == "link":
            if "link" in a and os.readlink(p) != _unescape(a["link"]):
                changed.append({"path": "/" + rel, "problem": "link", "detail": f"points to {os.readlink(p)}"})
            continue
        if "mode" in a and (st.st_mode & 0o7777) != int(a["mode"], 8):
            changed.append({"path": "/" + rel, "problem": "mode",
                            "detail": f"permissions {oct(st.st_mode & 0o7777)[2:]}, installed as {a['mode']}"})
        if want != "file":
            continue
        if "size" in a and st.st_size != int(a["size"]):
            changed.append({"path": "/" + rel, "problem": "size",
                            "detail": f"{st.st_size} bytes, installed as {a['size']}"})
            continue
        digest = a.get("sha256digest")
        if digest and st.st_size <= hash_limit:
            try:
                h = hashlib.sha256()
                with open(p, "rb") as fh:
                    for chunk in iter(lambda: fh.read(1 << 20), b""):
                        h.update(chunk)
                if h.hexdigest() != digest:
                    changed.append({"path": "/" + rel, "problem": "content", "detail": "contents changed since install"})
            except OSError:
                unreadable += 1
    return {"checked": checked, "changed": changed, "unreadable": unreadable, "error": None}


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
