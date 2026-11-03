"""The Fix panel: commands for the user to read, copy and run themselves.

Vigil NEVER runs any of these. This module only builds text: it reads two kinds of
files (/etc/os-release and firewall config) and has no way to start a process; a test
fails if it ever imports one.

Rules every command follows: one action per command, no `curl | sh`, no `&&` chains,
no wildcards in rm, firewall blocks name one destination, and every fix has an undo.
"""

import ipaddress

from ..core import catalogue as services, commands  # noqa: F401
from ..core.fixes import PKG, RISK, INTERPRETER, _fill, _render, _script  # noqa: F401
from ..core.system import FAMILY_IDS, family, firewall, os_release  # noqa: F401


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
