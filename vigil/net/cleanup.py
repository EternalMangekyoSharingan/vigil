"""Cleanup: find caches, leftovers and clutter, measure them, and say what removing them costs.

Read-only: this module only lists and measures. Each item carries one command per
action (exact paths, no wildcards) that the user copies, or runs with sudo mode.
Personal files (Downloads, large files, broken links) are listed, never given a delete
command: those are the user's to judge one by one.
"""

import os
import shlex
import time

from ..core import fixes, pkgdb

SCAN_SECONDS = 8.0
OLD_DAYS = 90
LARGE = 500 * 2**20

# What common ~/.cache folders hold, for the explanation.
CACHE_NOTES = {
    "thumbnails": "Picture previews for your file manager. Rebuilt when you browse again.",
    "mozilla": "Firefox's web cache. Pages load a little slower the first time afterwards.",
    "librewolf": "LibreWolf's web cache. Pages load a little slower the first time afterwards.",
    "chromium": "Chromium's web cache.", "google-chrome": "Chrome's web cache.",
    "BraveSoftware": "Brave's web cache.",
    "pip": "Downloaded Python packages; pip downloads them again if needed.",
    "yarn": "Yarn's package cache.", "npm": "npm's package cache.", "go-build": "Go build cache; rebuilt on the next build.",
    "mesa_shader_cache": "Compiled graphics shaders; games may stutter briefly while they rebuild.",
    "yay": "Packages yay built from the AUR; only needed to reinstall them without rebuilding.",
    "paru": "Packages paru built from the AUR; only needed to reinstall them without rebuilding.",
    "fontconfig": "Font lookup cache; rebuilt automatically.", "spotify": "Spotify's offline and streaming cache.",
    "electron": "Electron app runtime cache.", "JetBrains": "JetBrains IDE caches and indexes.",
}


def _size(path, deadline, follow=False):
    """Total bytes under path (stops at the deadline: then it is a lower bound)."""
    total, files, partial = 0, 0, False
    stack = [path]
    while stack:
        if time.monotonic() > deadline:
            partial = True
            break
        p = stack.pop()
        try:
            with os.scandir(p) as it:
                for e in it:
                    try:
                        if e.is_dir(follow_symlinks=follow):
                            stack.append(e.path)
                        elif e.is_file(follow_symlinks=False):
                            total += e.stat(follow_symlinks=False).st_size
                            files += 1
                    except OSError:
                        continue
        except OSError:
            continue
    return total, files, partial


def _item(**kw):
    kw.setdefault("commands", [])
    kw.setdefault("risk", "safe")
    kw["risk_label"] = fixes.RISK[kw["risk"]]
    return kw


def survey(home=None, root="/", osr=None, now=None, budget=SCAN_SECONDS):
    home = home or os.path.expanduser("~")
    now = now or time.time()
    deadline = time.monotonic() + budget
    osr = osr if osr is not None else fixes.os_release(os.path.join(root, "etc/os-release"))
    fam = fixes.family(osr)
    items = []

    # ~/.cache, one item per big folder
    cache = os.path.join(home, ".cache")
    rows = []
    try:
        names = os.listdir(cache)
    except OSError:
        names = []
    for name in names:
        path = os.path.join(cache, name)
        if os.path.islink(path) or not os.path.isdir(path):
            continue
        size, files, partial = _size(path, deadline)
        rows.append((size, name, path, files, partial))
    for size, name, path, files, partial in sorted(rows, reverse=True)[:15]:
        if size < 5 * 2**20:
            continue
        items.append(_item(id=f"cache:{name}", group="Caches", title=f"Cache: {name}", path=path, size=size,
                           files=files, partial=partial,
                           what=CACHE_NOTES.get(name, "Temporary data an app keeps to be faster. Apps recreate what they need."),
                           lose="Nothing permanent; the app may be slower once while it rebuilds.",
                           risk="deletes",
                           commands=[f"rm -r {shlex.quote(path)}"]))

    trash = os.path.join(home, ".local/share/Trash")
    if os.path.isdir(trash):
        size, files, partial = _size(trash, deadline)
        if size:
            items.append(_item(id="trash", group="Caches", title="Trash", path=trash, size=size, files=files, partial=partial,
                               what="Files you deleted in your file manager are kept here until you empty it.",
                               lose="Those files can no longer be restored.", risk="settings",
                               commands=["gio trash --empty"]))

    # package manager leftovers
    if fam == "arch":
        pkgcache = os.path.join(root, "var/cache/pacman/pkg")
        size, files, partial = _size(pkgcache, deadline)
        if size:
            items.append(_item(id="pacman-cache", group="Packages", title="pacman's package cache", path=pkgcache,
                               size=size, files=files, partial=partial,
                               what="Every package version you have downloaded. Older ones are only needed to downgrade.",
                               lose="Keeping the two newest versions (first command) still lets you roll back once. "
                                    "The second command keeps only installed versions.",
                               risk="admin", needs="paccache comes with the pacman-contrib package.",
                               commands=["sudo paccache -rk2", "sudo pacman -Sc"]))
        pk = pkgdb.pacman_installed(root)
        orph = pkgdb.orphans(pk)
        if orph:
            size = sum(pk[n]["size"] for n in orph)
            items.append(_item(id="orphans", group="Packages", title=f"{len(orph)} orphaned package{'s' if len(orph) != 1 else ''}",
                               size=size, list=orph[:200],
                               what="Installed as dependencies of something you since removed; nothing installed needs them now.",
                               lose="Nothing, unless you use one of them directly; check the list first.",
                               risk="admin", commands=[f"sudo pacman -Rns {' '.join(orph[:200])}"]))
    elif fam in ("fedora", "suse", "debian"):
        clean = {"fedora": ["sudo dnf clean packages", "sudo dnf autoremove"],
                 "suse": ["sudo zypper clean --all"],
                 "debian": ["sudo apt clean", "sudo apt autoremove"]}[fam]
        cdir = {"fedora": "var/cache/dnf", "suse": "var/cache/zypp", "debian": "var/cache/apt/archives"}[fam]
        size, files, partial = _size(os.path.join(root, cdir), deadline)
        if size >= 10 * 2**20:
            items.append(_item(id="pkg-cache", group="Packages", title="Package manager cache", path="/" + cdir, size=size,
                               files=files, partial=partial, risk="admin",
                               what="Downloaded packages and metadata. Only needed to reinstall without downloading again.",
                               lose="Nothing permanent.", commands=clean))

    for d, label in (("var/lib/flatpak", "system"), (".local/share/flatpak", "user")):
        base = os.path.join(root, d) if d.startswith("var") else os.path.join(home, d)
        if os.path.isdir(base):
            items.append(_item(id=f"flatpak-{label}", group="Packages", title=f"Unused Flatpak runtimes ({label})",
                               path=base, size=None, what="Runtimes no installed Flatpak app uses any more.",
                               lose="Nothing; apps that need a runtime keep it.",
                               risk="admin" if label == "system" else "settings",
                               commands=["flatpak uninstall --unused" if label == "user" else "sudo flatpak uninstall --unused"]))

    journal = os.path.join(root, "var/log/journal")
    if os.path.isdir(journal):
        size, files, partial = _size(journal, deadline)
        if size > 300 * 2**20:
            items.append(_item(id="journal", group="Logs", title="System log (journal)", path=journal, size=size,
                               files=files, partial=partial, risk="admin",
                               what="systemd's log of everything that happened. Old entries are rarely needed.",
                               lose="Log history older than what fits in 200 MB.",
                               commands=["sudo journalctl --vacuum-size=200M"]))
    coredump = os.path.join(root, "var/lib/systemd/coredump")
    if os.path.isdir(coredump):
        size, files, partial = _size(coredump, deadline)
        if size > 50 * 2**20:
            items.append(_item(id="coredumps", group="Logs", title="Crash dumps", path=coredump, size=size, files=files,
                               risk="admin", what="Memory snapshots of programs that crashed, kept for debugging.",
                               lose="The ability to debug those old crashes.",
                               commands=[f"sudo rm -r {shlex.quote(coredump)}"]))

    # personal files: listed only
    downloads = os.path.join(home, "Downloads")
    old = []
    try:
        for e in os.scandir(downloads):
            try:
                st = e.stat(follow_symlinks=False)
            except OSError:
                continue
            if now - st.st_mtime > OLD_DAYS * 86400:
                old.append({"path": e.path, "size": _size(e.path, deadline)[0] if e.is_dir(follow_symlinks=False) else st.st_size,
                            "age_days": int((now - st.st_mtime) / 86400)})
    except OSError:
        pass
    if old:
        old.sort(key=lambda x: -x["size"])
        items.append(_item(id="old-downloads", group="Your files", title=f"{len(old)} downloads older than {OLD_DAYS} days",
                           size=sum(x["size"] for x in old), files_list=old[:100], risk="settings",
                           what="Things you downloaded a while ago. Vigil lists them; you decide what goes.",
                           lose="Whatever you delete. Vigil gives no delete command for your own files."))
    large, dead = [], []
    for top in (os.path.join(home, d) for d in ("", "Downloads", "Videos", "Documents", "Desktop")):
        try:
            entries = list(os.scandir(top))
        except OSError:
            continue
        for e in entries:
            if time.monotonic() > deadline:
                break
            try:
                if e.is_symlink() and not os.path.exists(e.path):
                    dead.append({"path": e.path, "target": os.readlink(e.path)})
                elif e.is_file(follow_symlinks=False) and e.stat().st_size >= LARGE:
                    large.append({"path": e.path, "size": e.stat().st_size})
            except OSError:
                continue
    if large:
        items.append(_item(id="large-files", group="Your files", title=f"{len(large)} very large files",
                           size=sum(x["size"] for x in large), files_list=sorted(large, key=lambda x: -x["size"])[:50],
                           risk="settings", what=f"Single files over {LARGE // 2**20} MB in your main folders.",
                           lose="Whatever you delete. Listed only."))
    if dead:
        items.append(_item(id="dead-links", group="Your files", title=f"{len(dead)} broken shortcuts (symlinks)",
                           size=0, files_list=dead[:100], what="Links whose target no longer exists.",
                           lose="Nothing; they point nowhere. Listed only.", risk="settings"))
    total = sum(i["size"] or 0 for i in items if i["group"] != "Your files")
    return {"items": items, "reclaimable": total, "family": fam,
            "partial": time.monotonic() > deadline, "scanned_at": now}


def commands_for(items):
    """Every command text the survey offered (what sudo mode may run)."""
    return {c for i in items for c in i.get("commands", [])}
