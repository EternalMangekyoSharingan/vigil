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


# ---- which package owns a path, and what the package says it should contain --------------

class PackageFiles:
    """Ownership and expected contents of installed files, read from the package database.

    pacman: local/<pkg>/files (ownership) and local/<pkg>/mtree (SHA-256, mode, size).
    dpkg:   info/<pkg>.list (ownership), info/<pkg>.md5sums (MD5), and the Conffiles
            section of /var/lib/dpkg/status (config files the admin may edit).
    rpm:    its database is binary; ownership and integrity are left to `rpm -qf` /
            `rpm -Vf`, which the user can run (Vigil never runs them here).
    Everything is loaded lazily, once.
    """

    def __init__(self, root="/"):
        self.root = root
        self._owners = None
        self._mtrees = {}
        self._md5 = {}
        self._conffiles = None
        self.kind = ("pacman" if os.path.isdir(os.path.join(root, "var/lib/pacman/local")) else
                     "dpkg" if os.path.isdir(os.path.join(root, "var/lib/dpkg/info")) else
                     "rpm" if os.path.isdir(os.path.join(root, "var/lib/rpm")) or
                     os.path.isdir(os.path.join(root, "usr/lib/sysimage/rpm")) else None)

    def _load(self):
        if self._owners is not None:
            return
        self._owners = {}
        if self.kind == "pacman":
            for files in glob.glob(os.path.join(self.root, "var/lib/pacman/local/*/files")):
                d = os.path.dirname(files)
                try:
                    with open(files, encoding="utf-8", errors="replace") as fh:
                        for line in fh:
                            line = line.rstrip("\n")
                            if line and not line.startswith("%") and not line.endswith("/"):
                                self._owners["/" + line] = d
                except OSError:
                    continue
        elif self.kind == "dpkg":
            for lst in glob.glob(os.path.join(self.root, "var/lib/dpkg/info/*.list")):
                pkg = os.path.basename(lst)[:-5]
                try:
                    with open(lst, encoding="utf-8", errors="replace") as fh:
                        for line in fh:
                            p = line.rstrip("\n")
                            if p and p != "/.":
                                self._owners.setdefault(p, pkg)
                except OSError:
                    continue

    def owner(self, path):
        """Package name owning `path` (absolute, as seen on the live system), or None."""
        self._load()
        v = self._owners.get(path)
        if v is None:
            return None
        if self.kind == "pacman":
            name_ver = os.path.basename(v)
            return name_ver.rsplit("-", 2)[0]
        return v.split(":")[0]

    def expected(self, path):
        """{"algo", "digest", "mode", "size", "conffile"} the package recorded, or None."""
        self._load()
        v = self._owners.get(path)
        if v is None:
            return None
        if self.kind == "pacman":
            if v not in self._mtrees:
                self._mtrees[v] = mtree(v) or {}
            a = self._mtrees[v].get(path.lstrip("/"))
            if not a:
                return None
            backup = set()
            try:
                with open(os.path.join(v, "desc"), encoding="utf-8", errors="replace") as fh:
                    text = fh.read()
                m = re.search(r"%BACKUP%\n(.*?)(?:\n\n|\Z)", text, re.S)
                if m:
                    backup = {b.split("\t")[0] for b in m.group(1).splitlines()}
            except OSError:
                pass
            return {"algo": "sha256", "digest": a.get("sha256digest"), "mode": a.get("mode"),
                    "size": int(a["size"]) if "size" in a else None, "conffile": path.lstrip("/") in backup,
                    "type": a.get("type", "file")}
        if self.kind == "dpkg":
            conf = self.conffiles()
            if path in conf:
                return {"algo": "md5", "digest": conf[path], "mode": None, "size": None, "conffile": True, "type": "file"}
            if v not in self._md5:
                sums = {}
                try:
                    with open(os.path.join(self.root, f"var/lib/dpkg/info/{v}.md5sums"), encoding="utf-8",
                              errors="replace") as fh:
                        for line in fh:
                            digest, _, rel = line.rstrip("\n").partition("  ")
                            sums["/" + rel] = digest
                except OSError:
                    pass
                self._md5[v] = sums
            d = self._md5[v].get(path)
            return {"algo": "md5", "digest": d, "mode": None, "size": None, "conffile": False, "type": "file"} if d else None
        return None

    def conffiles(self):
        if self._conffiles is None:
            self._conffiles = {}
            try:
                with open(os.path.join(self.root, "var/lib/dpkg/status"), encoding="utf-8", errors="replace") as fh:
                    inside = False
                    for line in fh:
                        if line.startswith("Conffiles:"):
                            inside = True
                            continue
                        if inside and line.startswith(" "):
                            parts = line.split()
                            if len(parts) >= 2:
                                self._conffiles[parts[0]] = parts[1]
                            continue
                        inside = False
            except OSError:
                pass
        return self._conffiles

    def verify(self, path, data=None):
        """"ok", "changed", "unknown" (no record) or "unreadable", for one file."""
        exp = self.expected(path)
        if not exp or not exp.get("digest"):
            return "unknown"
        if data is None:
            try:
                with open(os.path.join(self.root, path.lstrip("/")), "rb") as fh:
                    data = fh.read()
            except OSError:
                return "unreadable"
        h = hashlib.sha256(data) if exp["algo"] == "sha256" else hashlib.md5(data)
        return "ok" if h.hexdigest() == exp["digest"] else "changed"
