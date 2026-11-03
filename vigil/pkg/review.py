"""Read a PKGBUILD folder safely and review it; remember versions the user approved.

Reading rules: only regular files are read (links are reported, never followed), at
most FILE_MAX bytes each and FILES_MAX files, `.git` and `src`/`pkg` build folders are
skipped, and nothing in the folder is ever executed or written.
"""

import json
import os
import stat
import time
import urllib.parse

from ..core import netfetch
from ..core import system
from ..core.store import FindingStore
from . import checks, parse

FILE_MAX = 1024 * 1024
FILES_MAX = 300
SKIP_DIRS = {".git", "src", "pkg"}
TEXT_EXT = (".install", ".sh", ".patch", ".diff", ".hook", ".service", ".timer", ".desktop", ".conf", ".bash",
            ".zsh", ".py", ".txt", ".md", ".socket", ".rules", ".sysusers", ".tmpfiles", ".csh", ".fish")
AUR_RPC = "https://aur.archlinux.org/rpc/v5/"


def read_folder(folder):
    """({relative name: text}, [notes]) for a PKGBUILD folder."""
    folder = os.path.abspath(os.path.expanduser(folder))
    st = os.lstat(folder)
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise ValueError(f"{folder} is not a folder")
    files, notes = {}, []
    count = 0
    for root, dirs, names in os.walk(folder, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and not os.path.islink(os.path.join(root, d)))
        for d in os.listdir(root):
            p = os.path.join(root, d)
            if os.path.islink(p):
                rel = os.path.relpath(p, folder)
                target = os.readlink(p)
                notes.append({"check": "folder_link", "title": "The folder contains a link to another file",
                              "summary": f"{rel} points to {target}; Vigil did not follow it.",
                              "severity": "Medium" if target.startswith("/") or ".." in target else "Low",
                              "strength": 0.5, "signal": f"Symlink {rel} → {target}", "file": rel,
                              "reason": "AUR repositories rarely need links.",
                              "likely": "A link out of the folder could make the build read or overwrite your files."})
        for n in sorted(names):
            p = os.path.join(root, n)
            rel = os.path.relpath(p, folder)
            st = os.lstat(p)
            if not stat.S_ISREG(st.st_mode):
                continue
            count += 1
            if count > FILES_MAX:
                notes.append({"check": "folder_too_many", "title": "The folder has more files than Vigil reads",
                              "summary": f"Vigil stopped after {FILES_MAX} files; the rest were not reviewed.",
                              "severity": "Low", "strength": 0.3, "signal": "File limit reached", "file": rel})
                return files, notes
            with open(p, "rb") as fh:
                head = fh.read(min(st.st_size, FILE_MAX) + 1)
            if head[:4] == b"\x7fELF" or head[:2] == b"MZ":
                notes.append({"check": "folder_program", "title": "The folder contains a ready-made program",
                              "summary": f"{rel} is a compiled program, which an AUR repository should not carry.",
                              "severity": "Medium", "strength": 0.7, "signal": f"Executable file {rel}", "file": rel,
                              "reason": "Build files should be text; programs belong in source= downloads.",
                              "likely": "A compiled file here skips the source download and its checksum."})
                continue
            if len(head) > FILE_MAX:
                notes.append({"check": "folder_big_file", "title": "A file was too large to review",
                              "summary": f"{rel} is larger than {FILE_MAX // 1024} kB, so Vigil did not read it.",
                              "severity": "Low", "strength": 0.2, "signal": f"Large file {rel}", "file": rel})
                continue
            if b"\0" in head[:8192]:
                continue  # images and other binary assets: listed, not read
            if n in ("PKGBUILD", ".SRCINFO") or n.endswith(TEXT_EXT) or "." not in n:
                files[rel] = head.decode("utf-8", "replace")
    if "PKGBUILD" not in files:
        raise ValueError(f"no PKGBUILD in {folder}")
    return files, notes


class Trusted:
    """Versions the user approved, kept in the Pkg evidence store's baselines table."""

    def __init__(self, store):
        self.store = store

    def get(self, pkgbase):
        ts, body = self.store.baseline(f"trusted:{pkgbase}")
        return dict(body, ts=ts) if body else None

    def approve(self, pkgbase, files, version):
        self.store.save_baseline(f"trusted:{pkgbase}", {
            "files": files, "version": version,
            "maintainers": parse.maintainers(files.get("PKGBUILD", ""))})

    def all(self):
        with self.store.lock:
            rows = self.store.db.execute("SELECT name, ts, body FROM baselines WHERE name LIKE 'trusted:%' "
                                         "ORDER BY ts DESC").fetchall()
        return [{"pkgbase": r["name"].split(":", 1)[1], "ts": r["ts"], "version": json.loads(r["body"]).get("version")}
                for r in rows]

    def forget(self, pkgbase):
        with self.store.lock:
            self.store.db.execute("DELETE FROM baselines WHERE name = ?", (f"trusted:{pkgbase}",))
            self.store.db.commit()


def aur_info(pkgbase, fetcher=netfetch.fetch):
    """AUR metadata for one package. This is a NETWORK CALL to aur.archlinux.org, made
    only when the user presses "Check AUR details": it sends the package name, nothing else."""
    q = urllib.parse.urlencode({"arg[]": pkgbase})
    data = json.loads(fetcher(f"{AUR_RPC}info?{q}", limit=2 * 1024 * 1024))
    results = data.get("results") or []
    if not results:
        return {"found": False}
    info = dict(results[0], found=True)
    m = info.get("Maintainer")
    if m:
        q = urllib.parse.urlencode({"by": "maintainer"})
        other = json.loads(fetcher(f"{AUR_RPC}search/{urllib.parse.quote(m)}?{q}", limit=8 * 1024 * 1024))
        firsts = [r.get("FirstSubmitted") for r in other.get("results") or [] if r.get("FirstSubmitted")]
        info["_maintainer_packages"] = len(firsts)
        info["_maintainer_oldest"] = min(firsts) if firsts else None
    return info


def review_folder(folder, store=None, osr=None, aur=None, now=None, save=True):
    files, notes = read_folder(folder)
    return review_files(files, folder=os.path.abspath(os.path.expanduser(folder)), notes=notes, store=store,
                        osr=osr, aur=aur, now=now, save=save)


def review_files(files, folder=None, notes=(), store=None, osr=None, aur=None, now=None, save=True):
    osr = osr if osr is not None else system.os_release()
    pkgbase = parse.Script(files.get("PKGBUILD", "")).get("pkgbase") or \
        (lambda n: n[0] if isinstance(n, list) and n else n)(parse.Script(files.get("PKGBUILD", "")).get("pkgname"))
    trusted = Trusted(store).get(pkgbase) if store and pkgbase else None
    r = checks.Review(files, folder=folder, osr=osr, trusted=trusted, aur=aur, now=now or time.time())
    r.add_folder_notes(notes)
    rep = r.run()
    if store and save:
        rep["run_id"] = store.add_run(f"review:{rep['package']['pkgbase']}", rep["findings"],
                                      {"verdict": rep["verdict"], "package": rep["package"], "folder": folder,
                                       "counts": rep["counts"]})
    return rep


def open_store(data_dir):
    return FindingStore("pkg", data_dir)
