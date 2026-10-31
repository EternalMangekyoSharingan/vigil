"""The Fix panel: commands for the user to read, copy and run themselves.

Vigil NEVER runs any of these. This module only builds text: it reads two kinds of
files (/etc/os-release and firewall config) and has no way to start a process; a test
fails if it ever imports one.

Rules every command follows: one action per command, no `curl | sh`, no `&&` chains,
no wildcards in rm, firewall blocks name one destination, and every fix has an undo.
"""

import ipaddress
import os

from . import commands, services

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
FAMILY_IDS = [("arch", {"arch", "manjaro", "endeavouros", "garuda", "artix", "cachyos"}),
              ("fedora", {"fedora", "rhel", "centos", "rocky", "almalinux", "nobara"}),
              ("suse", {"opensuse", "suse", "opensuse-tumbleweed", "opensuse-leap", "sles"}),
              ("debian", {"debian", "ubuntu", "linuxmint", "pop", "elementary", "zorin", "kali", "raspbian"}),
              ("void", {"void"}), ("alpine", {"alpine"}), ("gentoo", {"gentoo"})]
RISK = {"safe": "Safe (read-only)", "settings": "Changes settings", "admin": "Admin needed"}


def os_release(path="/etc/os-release"):
    """Parse os-release (or /usr/lib/os-release) into a dict."""
    out = {}
    for p in (path, "/usr/lib/os-release") if path == "/etc/os-release" else (path,):
        try:
            with open(p, encoding="utf-8") as fh:
                for line in fh:
                    k, sep, v = line.strip().partition("=")
                    if sep and not k.startswith("#"):
                        out[k] = v.strip().strip('"').strip("'")
            break
        except OSError:
            continue
    return out


def family(osr):
    ids = [osr.get("ID", "").lower()] + osr.get("ID_LIKE", "").lower().split()
    for fam, names in FAMILY_IDS:
        if any(i in names for i in ids):
            return fam
    return None


def firewall(root="/"):
    """Which firewall is in use, judged from config files only (nothing is run)."""
    def exists(p):
        return os.path.exists(os.path.join(root, p.lstrip("/")))

    def enabled(unit):
        return any(exists(f"/etc/systemd/system/{t}.wants/{unit}") for t in ("multi-user.target", "sysinit.target", "network-pre.target"))
    if enabled("firewalld.service"):
        return "firewalld"
    try:
        with open(os.path.join(root, "etc/ufw/ufw.conf"), encoding="utf-8") as fh:
            if any(line.strip().upper() == "ENABLED=YES" for line in fh):
                return "ufw"
    except OSError:
        pass
    if enabled("nftables.service") or exists("/usr/bin/nft") or exists("/usr/sbin/nft"):
        return "nftables"
    return None


def block_option(fw, ip):
    """Block one destination with the firewall in use: reversible and specific."""
    v6 = ipaddress.ip_address(ip).version == 6
    if fw == "firewalld":
        fam = "ipv6" if v6 else "ipv4"
        cmd = [f"sudo firewall-cmd --direct --add-rule {fam} filter OUTPUT 0 -d {ip} -j REJECT"]
        undo = [f"sudo firewall-cmd --direct --remove-rule {fam} filter OUTPUT 0 -d {ip} -j REJECT"]
        note = "This lasts until reboot. Add --permanent to both commands to keep it."
    elif fw == "ufw":
        cmd = [f"sudo ufw deny out to {ip}"]
        undo = [f"sudo ufw delete deny out to {ip}"]
        note = "ufw keeps the rule across reboots."
    elif fw == "nftables":
        fam = "ip6" if v6 else "ip"
        cmd = ["sudo nft add table inet vigil",
               "sudo nft add chain inet vigil out '{ type filter hook output priority 0 ; }'",
               f"sudo nft add rule inet vigil out {fam} daddr {ip} reject"]
        undo = ["sudo nft delete table inet vigil"]
        note = "These rules last until reboot. The undo removes Vigil's own table and nothing else."
    else:
        return {"title": f"Block {ip}", "what": "No firewall was found (firewalld, ufw or nftables). "
                "Install and enable one first; Vigil then shows the matching command.",
                "risk": "admin", "commands": [], "undo": []}
    return {"title": f"Block this one address ({ip})", "what": f"Your {fw} firewall rejects all outgoing "
            f"traffic to {ip}. Nothing else is blocked. {note}",
            "lose": "Anything that legitimately uses this address stops working.",
            "risk": "admin", "commands": cmd, "undo": undo}


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


def options(alert, osr, fw, exe=None, service=None):
    """Check / Fix / Undo options for one alert.

    alert:   {"ip": ..., "program": ..., "hidden": bool}
    osr:     parsed os-release
    fw:      firewall() result
    exe:     the program's executable path, if known
    service: a services.match() result, if any
    """
    fam = family(osr)
    distro = {"id": osr.get("ID"), "name": osr.get("PRETTY_NAME") or osr.get("NAME"), "family": fam,
              "known": fam is not None}
    check, fix = [], []
    pkg = (service or {}).get("packages", {}).get(fam) if service else None
    script = _script(alert.get("program") or "")
    if script:
        # The interpreter (python, bash...) is not the program: never suggest removing it.
        exe = script
    if exe and fam:
        check.append(_render({"title": "Which package installed this program?",
                              "what": f"Asks {PKG[fam]['name']}'s package database who owns {exe}. "
                                      "If nothing owns it, it was installed by hand or by something else.",
                              "risk": "safe", "commands": [PKG[fam]["owner"].format(path=exe)]}, fam, pkg))
    elif exe:
        check.append({"title": "Which package installed this program?", "risk": "safe", "risk_label": RISK["safe"],
                      "what": f"Vigil could not tell your distro from /etc/os-release, so it cannot show the "
                              f"right command. Ask your package manager which package owns {exe}.",
                      "commands": [], "undo": []})
    check.append(_render({"title": "See this connection right now",
                          "what": "Lists current connections to this address (add sudo to see every program's name).",
                          "risk": "safe", "commands": [f"ss -tunp dst {alert['ip']}"]}, fam, pkg))
    if service:
        for o in service.get("check", []):
            r = _render(o, fam, pkg)
            if r:
                check.append(r)
        for o in service.get("fix", []):
            r = _render(o, fam, pkg)
            if r:
                fix.append(r)
    if alert.get("ip") and not ipaddress.ip_address(alert["ip"]).is_private:
        fix.append(block_option(fw, alert["ip"]))
    if not service and exe and fam and not alert.get("hidden") and not script:
        fix.append({"title": "Uninstall the program's package", "risk": "admin", "risk_label": RISK["admin"],
                    "what": "Run the 'Which package' check first, then replace PACKAGE with the name it printed.",
                    "lose": "The program is removed.",
                    "commands": [{"text": PKG[fam]["remove"].format(pkg="PACKAGE"),
                                  "tokens": commands.tokenize(PKG[fam]["remove"].format(pkg="PACKAGE"))}],
                    "undo": [{"text": PKG[fam]["install"].format(pkg="PACKAGE"),
                              "tokens": commands.tokenize(PKG[fam]["install"].format(pkg="PACKAGE"))}]})
    for o in fix:
        o.setdefault("risk_label", RISK[o.get("risk", "safe")])
        for k in ("commands", "undo"):
            o[k] = [c if isinstance(c, dict) else {"text": c, "tokens": commands.tokenize(c)} for c in o.get(k, [])]
    undo = [{"title": f"Undo: {o['title']}", "for": o["title"], "commands": o["undo"],
             "steps": o.get("undo_steps")} for o in fix if o.get("undo") or o.get("undo_steps")]
    return {"distro": distro, "firewall": fw, "check": [c for c in check if c], "fix": fix, "undo": undo,
            "legend": commands.LEGEND,
            "note": None if fam else "Unknown distro: only generic, read-only checks are shown. "
                                     "Vigil read /etc/os-release and did not recognise ID or ID_LIKE."}
