"""Find the PKGBUILD folders your AUR helper downloaded, so there is nothing to type:
paru, yay, pikaur, trizen and pamac keep each package's AUR clone in a cache folder.
Read-only: folders are listed and their PKGBUILDs read as text, as everywhere in Pkg."""

import glob
import os

HELPERS = [  # (helper, glob relative to home or absolute)
    ("paru", "~/.cache/paru/clone/*"),
    ("yay", "~/.cache/yay/*"),
    ("pikaur", "~/.cache/pikaur/build/*"),
    ("pikaur", "~/.local/share/pikaur/aur_repos/*"),
    ("trizen", "~/.cache/trizen/*"),
    ("pamac", "/var/tmp/pamac-build-{user}/*"),
]
MAX = 200


def find(home=None, user=None):
    home = home or os.path.expanduser("~")
    user = user or os.environ.get("USER") or os.path.basename(home)
    out, helpers = [], set()
    for helper, pattern in HELPERS:
        pat = pattern.replace("{user}", user)
        pat = os.path.join(home, pat[2:]) if pat.startswith("~/") else pat
        for d in glob.glob(pat):
            pb = os.path.join(d, "PKGBUILD")
            if os.path.isfile(pb) and not os.path.islink(pb) and not os.path.islink(d):
                helpers.add(helper)
                out.append({"name": os.path.basename(d), "path": d, "helper": helper, "mtime": os.path.getmtime(pb)})
    out.sort(key=lambda x: -x["mtime"])
    return out[:MAX], sorted(helpers)
