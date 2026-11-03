"""Check / Fix / Undo options: commands for the user to read, copy and run themselves.

Vigil NEVER runs any of these. This module only builds text and has no way to start
a process; a test fails if it ever imports one. Every tool builds its Fix panel here,
so commands look and behave the same everywhere.

Rules every command follows: one action per command, no `curl | sh`, no `&&` chains,
no wildcards in rm, and every fix has an undo.
"""

import os

from . import commands
from .system import FAMILY_IDS, family, firewall, os_release  # noqa: F401  (re-exported)

# distro family -> package manager templates
PKG = {
    "arch": {"name": "Arch Linux", "install": "sudo pacman -S {pkg}", "remove": "sudo pacman -Rns {pkg}",
             "owner": "pacman -Qo {path}"},
    "fedora": {"name": "Fedora", "install": "sudo dnf install {pkg}", "remove": "sudo dnf remove {pkg}",
               "owner": "rpm -qf {path}"},
    "suse": {"name": "openSUSE", "install": "sudo zypper install {pkg}", "remove": "sudo zypper remove {pkg}",
             "owner": "rpm -qf {path}"},
    "debian": {"name": "Debian / Ubuntu", "install": "sudo apt install {pkg}", "remove": "sudo apt remove {pkg}",
               "owner": "dpkg -S {path}"},
    "void": {"name": "Void Linux", "install": "sudo xbps-install {pkg}", "remove": "sudo xbps-remove -R {pkg}",
             "owner": "xbps-query -o {path}"},
    "alpine": {"name": "Alpine Linux", "install": "doas apk add {pkg}", "remove": "doas apk del {pkg}",
               "owner": "apk info --who-owns {path}"},
    "gentoo": {"name": "Gentoo", "install": "sudo emerge --ask {pkg}", "remove": "sudo emerge --ask --depclean {pkg}",
               "owner": "equery belongs {path}"},
}
RISK = {"safe": "Safe (read-only)", "settings": "Changes settings", "admin": "Admin needed",
        "deletes": "Deletes files (rebuilt as needed)"}


def _fill(cmd, fam, pkg):
    t = PKG.get(fam)
    if "{pkg_remove}" in cmd:
        return t["remove"].format(pkg=pkg) if t and pkg else None
    if "{pkg_install}" in cmd:
        return t["install"].format(pkg=pkg) if t and pkg else None
    return cmd


def _render(opt, fam, pkg):
    """Fill templates, tokenise every command, and drop options that don't apply."""
    if opt.get("family") and opt["family"] != fam:
        return None
    out = {k: opt[k] for k in ("title", "what", "lose", "steps", "undo_steps", "file") if k in opt}
    out["risk"] = opt.get("risk", "safe")
    out["risk_label"] = RISK[out["risk"]]
    for key in ("commands", "undo"):
        cmds = [_fill(c, fam, pkg) for c in opt.get(key, [])]
        if any(c is None for c in cmds):
            return None  # needs a package manager we don't know
        out[key] = [{"text": c, "tokens": commands.tokenize(c)} for c in cmds]
    return out


INTERPRETER = ("python", "perl", "ruby", "node", "nodejs", "bash", "sh", "dash", "zsh", "java", "php", "lua", "deno", "bun")


def _script(program_key):
    """For 'python3 /path/script.py', the script: that is the program, not the interpreter."""
    parts = program_key.split(" ")
    base = os.path.basename(parts[0])
    if len(parts) > 1 and base.rstrip("0123456789.").startswith(INTERPRETER) and parts[1].startswith("/"):
        return parts[1]
    return None



def command(text):
    """One copyable command with its colour-coded tokens."""
    return {"text": text, "tokens": commands.tokenize(text)}


def option(title, what, risk="safe", commands_=(), undo=(), lose=None, steps=None, undo_steps=None, file=None):
    """One Check or Fix option. `commands_` and `undo` are plain command strings."""
    o = {"title": title, "what": what, "risk": risk, "risk_label": RISK[risk],
         "commands": [command(c) for c in commands_], "undo": [command(c) for c in undo]}
    for k, v in (("lose", lose), ("steps", steps), ("undo_steps", undo_steps), ("file", file)):
        if v:
            o[k] = v
    return o


def distro_info(osr):
    fam = family(osr)
    return {"id": osr.get("ID"), "name": osr.get("PRETTY_NAME") or osr.get("NAME"), "family": fam,
            "known": fam is not None}


def owner_check(path, fam):
    """'Which package installed this file?' for the distro in use (read-only)."""
    if fam:
        return option("Which package installed this file?",
                      f"Asks {PKG[fam]['name']}'s package database who owns {path}. "
                      "If nothing owns it, it was installed by hand or by something else.",
                      "safe", [PKG[fam]["owner"].format(path=path)])
    return option("Which package installed this file?",
                  "Vigil could not tell your distro from /etc/os-release, so it cannot show the "
                  f"right command. Ask your package manager which package owns {path}.", "safe")


def panel(osr, check=(), fix=(), fw=None):
    """The Fix panel every tool shows: distro, Check options, Fix options and their Undo."""
    fam = family(osr)
    fix = [o for o in fix if o]
    undo = [{"title": f"Undo: {o['title']}", "for": o["title"], "commands": o["undo"],
             "steps": o.get("undo_steps")} for o in fix if o.get("undo") or o.get("undo_steps")]
    return {"distro": distro_info(osr), "firewall": fw, "check": [c for c in check if c], "fix": fix,
            "undo": undo, "legend": commands.LEGEND,
            "note": None if fam else "Unknown distro: only generic, read-only checks are shown. "
                                     "Vigil read /etc/os-release and did not recognise ID or ID_LIKE."}
