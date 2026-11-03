"""Split a shell command into coloured, explained tokens for the Fix panel.

Only for display: nothing here runs anything. Each token gets a role (admin, pkgmgr,
install, remove, package, path, flag, service, command, arg) and a tooltip, so colour is
never the only signal.

    sudo pacman -S syncthing  ->  [admin][pkgmgr:arch][install][package]
"""

import re

ADMIN = {"sudo": "Runs the rest as administrator (root). Read the command before you type your password.",
         "doas": "Runs the rest as administrator (root).",
         "pkexec": "Asks for your password, then runs the rest as administrator (root).",
         "su": "Switches to another user, normally root.",
         "sudoedit": "Opens the file in your editor with administrator rights, then saves it as root."}

PKGMGR = {  # command -> (family, description)
    "pacman": ("arch", "pacman, Arch Linux's package manager"),
    "dnf": ("fedora", "dnf, Fedora's package manager"), "dnf5": ("fedora", "dnf5, Fedora's package manager"),
    "rpm": ("rpm", "rpm, the RPM package database (Fedora, openSUSE)"),
    "zypper": ("suse", "zypper, openSUSE's package manager"),
    "apt": ("debian", "apt, Debian/Ubuntu's package manager"), "apt-get": ("debian", "apt-get, Debian/Ubuntu's package manager"),
    "dpkg": ("debian", "dpkg, the Debian package database"),
    "xbps-install": ("void", "xbps-install, Void Linux's installer"), "xbps-remove": ("void", "xbps-remove, Void Linux's remover"),
    "xbps-query": ("void", "xbps-query, Void Linux's package database"),
    "apk": ("alpine", "apk, Alpine Linux's package manager"),
    "emerge": ("gentoo", "emerge, Gentoo's package manager"), "equery": ("gentoo", "equery, Gentoo's package query tool"),
    "flatpak": ("flatpak", "flatpak, the Flatpak app manager"),
}

# Words that install/turn something on, or remove/turn it off, per tool.
INSTALL = {"install", "add", "enable", "start", "unmask", "reload", "restart", "-S", "-U", "--now-enable"}
REMOVE = {"remove", "purge", "erase", "del", "autoremove", "disable", "stop", "mask", "-R", "-Rs", "-Rns",
          "-Rn", "--depclean", "--unmerge", "-C", "deny", "reject", "delete", "rm", "drop"}
QUERY = {"-Qo", "-Qi", "-Q", "-qf", "-qi", "-o", "--who-owns", "belongs", "info", "status", "show",
         "list-timers", "query", "-S"}  # dpkg -S is a search; see below

FLAG_TIPS = {"--now": "Also start/stop it right away, not only at next boot.",
             "--user": "Acts on your own user's services, not the system's: no admin rights needed.",
             "--all": "Include inactive items too.", "--permanent": "Keep the change after a reboot.",
             "-v": "Verbose: more detail."}
COMMAND_TIPS = {"systemctl": "systemctl, which starts, stops and enables services",
                "firewall-cmd": "firewall-cmd, the firewalld firewall's command line",
                "ufw": "ufw, the 'uncomplicated firewall'", "nft": "nft, the nftables firewall",
                "nmcli": "nmcli, NetworkManager's command line", "NetworkManager": "NetworkManager itself",
                "rm": "rm deletes a file. It names one exact file here.", "ss": "ss lists network connections",
                "timedatectl": "timedatectl shows and sets the system clock", "chronyc": "chronyc talks to the chrony time service",
                "gsettings": "gsettings changes a GNOME setting", "cat": "cat prints a file", "ls": "ls lists files",
                "journalctl": "journalctl reads the system log"}

TOKEN_RE = re.compile(r"""'[^']*'|"[^"]*"|\S+""")


def tokenize(command):
    """Return [{"text", "role", "tip", "family"?}] for one command line."""
    words = TOKEN_RE.findall(command)
    out = []
    tool = None          # the program being run (after sudo etc.)
    family = None
    seen_action = False
    for w in words:
        tok = {"text": w}
        bare = w.strip("'\"")
        if tool is None and w in ADMIN:
            tok.update(role="admin", tip=ADMIN[w])
            if w == "sudoedit":
                tool = "sudoedit"
        elif tool is None:
            tool = w
            if w in PKGMGR:
                family, desc = PKGMGR[w]
                tok.update(role="pkgmgr", family=family, tip=f"{desc}.")
                seen_action = w in ("xbps-install", "xbps-remove")  # the name says what it does
            elif w == "systemctl":
                tok.update(role="service", tip=COMMAND_TIPS[w])
            else:
                tok.update(role="command", tip=COMMAND_TIPS.get(w, f"The program {w}."))
        elif _is_path(bare):
            tok.update(role="path", tip="A file or folder path.")
        elif tool in PKGMGR and not seen_action and _pkg_action(tool, w):
            role, tip = _pkg_action(tool, w)
            tok.update(role=role, tip=tip)
            seen_action = True
        elif tool == "systemctl" and not seen_action and not w.startswith("-") and (w in INSTALL or w in REMOVE or w in QUERY):
            tok.update(role="install" if w in INSTALL else "remove" if w in REMOVE else "flag",
                       tip={"enable": "Turns it on at every boot.", "start": "Starts it now.", "unmask": "Allows it to start again.",
                            "reload": "Re-reads its configuration.", "restart": "Restarts it.",
                            "disable": "Stops it starting at boot.", "stop": "Stops it now.",
                            "mask": "Blocks it from being started at all.", "status": "Shows its state (read-only).",
                            "list-timers": "Lists scheduled jobs (read-only)."}.get(w, w))
            seen_action = True
        elif tool in ("ufw", "firewall-cmd", "nft", "timedatectl", "gsettings") and not w.startswith("-") and (w in REMOVE or w in INSTALL):
            tok.update(role="remove" if w in REMOVE else "install",
                       tip="Blocks or removes something." if w in REMOVE else "Adds or turns something on.")
        elif w.startswith("-"):
            tok.update(role="flag", tip=FLAG_TIPS.get(w.split("=")[0], "An option that changes how the command behaves."))
        elif (tool in PKGMGR or tool == "systemctl") and seen_action:
            tok.update(role="package", tip="The package, app or service this acts on."
                       if tool in PKGMGR else "The service (or timer) this acts on.")
        else:
            tok.update(role="arg", tip="An argument for the command.")
        out.append(tok)
    if tool == "rm":
        for t in out:
            if t["text"] == "rm":
                t.update(role="remove", tip="rm deletes a file. It names one exact file here.")
    return out


def _is_path(w):
    return w.startswith(("/", "~/", "./")) and len(w) > 1


def _pkg_action(tool, w):
    """(role, tip) for a package manager's action word, or None."""
    if tool == "pacman":
        if w.startswith("-S") and "s" not in w[2:] and "i" not in w[2:]:
            return "install", "-S installs (syncs) the packages named after it."
        if w.startswith("-R"):
            return "remove", "-R removes the package; n removes its config files, s unneeded dependencies."
        if w.startswith("-Q"):
            return "flag", "-Q queries the installed-package database (read-only); o asks who owns a file."
    if tool == "dpkg" and w in ("-S", "--search"):
        return "flag", "-S searches which package owns a file (read-only)."
    if tool == "rpm" and w.startswith("-q"):
        return "flag", "-q queries the package database (read-only); f asks who owns a file."
    if tool == "xbps-query" and w == "-o":
        return "flag", "-o asks which package owns a file (read-only)."
    if tool == "apk" and w == "info":
        return "flag", "Queries installed packages (read-only)."
    if tool == "equery" and w == "belongs":
        return "flag", "Asks which package owns a file (read-only)."
    if tool == "emerge" and w == "--depclean":
        return "remove", "--depclean removes the package if nothing else needs it."
    if w in ("install", "add"):
        return "install", f"{w} installs the packages named after it."
    if w in ("remove", "del", "erase", "purge", "autoremove", "uninstall"):
        return "remove", f"{w} removes the packages named after it."
    if w in ("info", "search", "list", "remotes", "query"):
        return "flag", f"{w} only reads information."
    return None


LEGEND = [
    ("admin", "Admin / root", "Runs with administrator rights (sudo, doas, pkexec, su)"),
    ("pkgmgr", "Package manager", "Installs or removes software; colour shows the distro family"),
    ("install", "Install / turn on", "Adds a package, or enables or starts something"),
    ("remove", "Remove / turn off", "Removes, disables, stops or blocks something"),
    ("package", "Package or app", "What the command acts on"),
    ("path", "File path", "A file or folder"),
    ("flag", "Option", "Changes how the command behaves; read-only queries too"),
    ("service", "Service manager", "systemctl, which controls services"),
]
