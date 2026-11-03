"""System scans: what starts by itself, what is exposed, whether running programs are
intact, malware signatures in chosen folders, and known-vulnerable packages.

Read-only. Scanners (ClamAV, YARA) only read files. Network use happens only in the
explicit update functions (YARA rules, Arch security advisories), from a button.
Every result carries plain-language reasons and, where useful, a command to check or
fix it (copied, or run with sudo mode).
"""

import glob
import hashlib
import io
import ipaddress
import json
import os
import re
import shlex
import shutil
import subprocess
import time
import zipfile

from ..core import netfetch, pkgdb
from ..files import inspector
from . import collector, fixes, knowledge

TEMP = ("/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/")
YARA_URL = "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.zip"
ARCH_ADVISORIES_URL = "https://security.archlinux.org/all.json"
SCAN_TIMEOUT = 1800


def _r(severity, area, title, why, **kw):
    return dict(severity=severity, area=area, title=title, why=why, commands=kw.pop("commands", []),
                check=kw.pop("check", []), **kw)


def _read(path, limit=256 * 1024):
    try:
        with open(path, "rb") as fh:
            return fh.read(limit)
    except OSError:
        return None


# ---- persistence -------------------------------------------------------------------------

def persistence_sources(home, root):
    j = lambda *p: os.path.join(root, *p)
    srcs = []
    for pat in ("*.service", "*.timer", "*.path", "*.socket"):
        srcs += [("systemd user unit", p) for p in glob.glob(os.path.join(home, ".config/systemd/user", pat))]
        srcs += [("systemd user unit", p) for p in glob.glob(os.path.join(home, ".config/systemd/user/*.wants", pat))]
        srcs += [("systemd system unit", p) for p in glob.glob(j("etc/systemd/system", pat))]
        srcs += [("systemd system unit", p) for p in glob.glob(j("etc/systemd/system/*.wants", pat))]
    srcs += [("cron", p) for p in [j("etc/crontab")] + glob.glob(j("etc/cron.d/*")) + glob.glob(j("var/spool/cron/*"))]
    srcs += [("autostart", p) for p in glob.glob(os.path.join(home, ".config/autostart/*.desktop"))
             + glob.glob(j("etc/xdg/autostart/*.desktop"))]
    srcs += [("shell startup file", os.path.join(home, f)) for f in
             (".bashrc", ".bash_profile", ".profile", ".zshrc", ".zprofile", ".config/fish/config.fish", ".xprofile")]
    srcs += [("preload", j("etc/ld.so.preload")), ("ssh keys", os.path.join(home, ".ssh/authorized_keys"))]
    srcs += [("udev rule", p) for p in glob.glob(j("etc/udev/rules.d/*.rules"))]
    return [(k, p) for k, p in srcs if os.path.lexists(p)]


EXEC_RE = re.compile(rb"^\s*(?:ExecStart|ExecStartPre|ExecStartPost|Exec)\s*=\s*[-@+!:]*(\S+)", re.M)


def persistence(home, root="/", previous=None):
    """Everything that starts by itself, with flags; `previous` is the last scan's {path: sha256}."""
    previous = previous or {}
    out, state = [], {}
    for kind, path in persistence_sources(home, root):
        data = _read(path)
        if data is None:
            continue
        digest = hashlib.sha256(data).hexdigest()
        state[path] = digest
        reasons, sev = [], "info"
        target = os.readlink(path) if os.path.islink(path) else None
        for m in EXEC_RE.finditer(data):
            exe = m.group(1).decode("utf-8", "replace")
            if exe.startswith(TEMP):
                reasons.append(f"starts a program from a temporary folder ({exe})")
                sev = "high"
            elif "/." in exe and "/.local/" not in exe:
                reasons.append(f"starts a program from a hidden folder ({exe})")
                sev = max(sev, "medium", key=SEV_ORDER.index)
        for f in inspector.command_findings(data, os.path.basename(path)):
            if f["check"] == "persistence":
                continue  # everything listed here persists by definition
            reasons.append(f["reason"].rstrip(".").lower())
            sev = "high"
        if kind == "preload" and data.strip():
            reasons.append("libraries listed here are loaded into every program: a classic rootkit trick")
            sev = "high"
        if kind == "ssh keys":
            keys = [line for line in data.splitlines() if line.strip() and not line.startswith(b"#")]
            if path in previous and previous[path] != digest:
                reasons.append("the list of keys that can log in as you changed since the last scan")
                sev = "high"
            what = f"{len(keys)} key{'s' if len(keys) != 1 else ''} can log in to this account over SSH"
        else:
            what = None
        if kind == "udev rule" and b"RUN" in data:
            reasons.append("runs a command when a device is plugged in")
            sev = max(sev, "medium", key=SEV_ORDER.index)
        if kind == "systemd system unit" and not target and root == "/":
            owner = knowledge.package_owner(path)
            if owner is not None and not owner.get("package"):
                reasons.append("not installed by a package: added by hand or by an installer")
        new = path not in previous and bool(previous)
        changed = path in previous and previous[path] != digest
        if new:
            reasons.append("new since the last scan")
            sev = max(sev, "medium", key=SEV_ORDER.index)
        elif changed and kind != "shell startup file":
            reasons.append("changed since the last scan")
            sev = max(sev, "medium", key=SEV_ORDER.index)
        if reasons or kind in ("preload", "ssh keys"):
            out.append(_r(sev, "Starts by itself", f"{kind.capitalize()}: {os.path.basename(path)}",
                          "; ".join(reasons).capitalize() + "." if reasons else (what or "Present."),
                          path=path, kind=kind, sha256=digest, target=target, detail=what,
                          check=[f"cat {shlex.quote(path)}"]))
    return out, state


SEV_ORDER = ["info", "low", "medium", "high"]


# ---- exposure -----------------------------------------------------------------------------

def exposure(snapshot, root="/"):
    out = []
    procs = snapshot.get("processes") or {}
    seen = set()
    for s in snapshot.get("sockets", []):
        if s.get("kind") != "listen":
            continue
        ip = s["local_ip"]
        if (s["proto"], ip, s["local_port"]) in seen:
            continue
        seen.add((s["proto"], ip, s["local_port"]))
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if a.is_loopback:
            continue
        everywhere = a.is_unspecified
        prog = ((procs.get(s.get("pid")) or {}).get("name") or (s.get("program") or "").rsplit("/", 1)[-1]
                or "An unidentified program")
        pi = knowledge.port_info(s["proto"], s["local_port"])
        svc = f" ({pi['service']})" if pi else ""
        out.append(_r("medium" if everywhere else "low", "Open to the network",
                      f"{prog} accepts connections on {s['proto']}/{s['local_port']}{svc}",
                      ("It listens on every network this PC joins" if everywhere else f"It listens on {ip} only")
                      + ". Anything that can reach this PC can try to connect. Fine for services you use; "
                        "close the ones you don't.",
                      check=[f"ss -tulpn sport = :{s['local_port']}"]))
    cfg = _read(os.path.join(root, "etc/ssh/sshd_config"))
    if cfg is not None:
        text = cfg.decode("utf-8", "replace")
        def setting(name, default):
            m = re.search(rf"^\s*{name}\s+(\S+)", text, re.M | re.I)
            return (m.group(1) if m else default).lower()
        if setting("PermitRootLogin", "prohibit-password") == "yes":
            out.append(_r("high", "Open to the network", "SSH allows logging in as root with a password",
                          "Attackers try root passwords constantly. Log in as yourself and use sudo instead.",
                          check=["cat /etc/ssh/sshd_config"]))
        if setting("PasswordAuthentication", "yes") == "yes":
            out.append(_r("low", "Open to the network", "SSH accepts passwords (if the SSH server is running)",
                          "Keys are much harder to guess than passwords. Fine on a home network; risky if port 22 is reachable from the internet.",
                          check=["systemctl status sshd.service"]))
    fw = fixes.firewall(root)
    if not fw:
        out.append(_r("low", "Open to the network", "No firewall found",
                      "Vigil found no firewalld, ufw or nftables setup. A firewall blocks incoming connections you didn't ask for.",
                      check=["sudo nft list ruleset"]))
    return out


# ---- integrity ----------------------------------------------------------------------------

def integrity(snapshot, fam):
    out, seen = [], set()
    for p in (snapshot.get("processes") or {}).values():
        exe = p.get("exe") or ""
        if p.get("exe_deleted") and not exe.endswith(" (deleted)"):
            exe += " (deleted)"
        key = (p.get("name"), exe)
        if key in seen:
            continue
        seen.add(key)
        if exe.endswith(" (deleted)") and not exe.startswith("/memfd:"):
            out.append(_r("low", "Running programs", f"{p.get('name')} runs from a file that was deleted or replaced",
                          "Normal right after an update (restart it to use the new version). Malware also does this to leave no file behind.",
                          check=[f"ls -l /proc/{p.get('pid')}/exe"]))
        elif exe.startswith(TEMP):
            out.append(_r("high", "Running programs", f"{p.get('name')} runs from a temporary folder",
                          f"{exe} is in a folder anyone can write to, where downloaded payloads land.",
                          check=[f"ls -l {shlex.quote(exe)}"]))
        elif exe.startswith("/memfd:"):
            out.append(_r("high", "Running programs", f"{p.get('name')} runs from memory only",
                          "It has no file on disk at all (memfd). Some apps do this legitimately; fileless malware does too.",
                          check=[f"ls -l /proc/{p.get('pid')}/exe"]))
    verify = {"arch": "sudo pacman -Qkk", "fedora": "sudo rpm -Va", "suse": "sudo rpm -Va", "debian": "sudo dpkg --verify"}.get(fam)
    if verify:
        out.append(_r("info", "Running programs", "Deeper check: compare installed files with their packages",
                      "Lists files that differ from what your packages installed. Config files you edited show up too; "
                      "changed programs in /usr/bin would be serious.", commands=[verify]))
    return out


# ---- advisories (Arch) ----------------------------------------------------------------------

def update_advisories(data_dir, fetcher=netfetch.fetch):
    raw = fetcher(ARCH_ADVISORIES_URL, limit=64 * 2**20)
    groups = json.loads(raw)
    path = os.path.join(data_dir, "arch-advisories.json")
    with open(path + ".tmp", "wb") as fh:
        fh.write(raw)
    os.replace(path + ".tmp", path)
    return {"groups": len(groups), "fetched_at": time.time()}


def advisories(data_dir, installed):
    path = os.path.join(data_dir, "arch-advisories.json")
    try:
        with open(path, encoding="utf-8") as fh:
            groups = json.load(fh)
        fetched = os.path.getmtime(path)
    except (OSError, ValueError):
        return None, []
    out, upgradable = [], False
    for g in groups:
        for name in g.get("packages", []):
            p = installed.get(name)
            if not p:
                continue
            fixed, affected = g.get("fixed"), g.get("affected")
            if fixed and pkgdb.vercmp(p["version"], fixed) < 0:
                state = f"fixed in {fixed}: update to get the fix"
                upgradable = True
            elif not fixed and g.get("status") in ("Vulnerable", "Unknown") and affected and pkgdb.vercmp(p["version"], affected) >= 0:
                state = "no fixed version yet"
            else:
                continue
            sev = {"Critical": "high", "High": "high", "Medium": "medium", "Low": "low"}.get(g.get("severity"), "low")
            cves = ", ".join(g.get("issues", [])[:4]) + (" …" if len(g.get("issues", [])) > 4 else "")
            out.append(_r(sev, "Known vulnerabilities", f"{name} {p['version']}: {g.get('type', 'vulnerability')}",
                          f"Arch security advisory {g.get('name')} ({g.get('severity', '?')} severity): {state}. {cves}",
                          package=name, advisory=g.get("name")))
    if upgradable:
        out.append(_r("info", "Known vulnerabilities", "Install the available security fixes",
                      "Arch only supports full upgrades, so this updates everything.", commands=["sudo pacman -Syu"]))
    return fetched, out


# ---- malware scanners (ClamAV, YARA) ------------------------------------------------------------

def tools(data_dir):
    rules = glob.glob(os.path.join(data_dir, "yara", "*.yar"))
    return {"clamav": bool(shutil.which("clamdscan") or shutil.which("clamscan")),
            "yara": bool(shutil.which("yara")), "yara_rules": rules[0] if rules else None,
            "yara_rules_at": os.path.getmtime(rules[0]) if rules else None}


def update_yara(data_dir, fetcher=netfetch.fetch):
    """Download the YARA-Forge core rule set (a zip of one .yar file) and keep the rules."""
    raw = fetcher(YARA_URL, limit=64 * 2**20)
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        members = [i for i in z.infolist() if i.filename.endswith(".yar") and i.file_size < 64 * 2**20]
        if not members:
            raise RuntimeError("the download held no .yar rules")
        rules = z.read(members[0])
    d = os.path.join(data_dir, "yara")
    os.makedirs(d, exist_ok=True)
    path = os.path.join(d, "yara-forge-core.yar")
    with open(path + ".tmp", "wb") as fh:
        fh.write(rules)
    os.replace(path + ".tmp", path)
    return {"rules": path, "bytes": len(rules)}


def clamav_folders(folders, runner=subprocess.run, which=shutil.which):
    """ClamAV over folders (recursive). Returns (findings, note)."""
    tool = which("clamdscan")
    args = [tool, "--fdpass", "--multiscan", "--infected", "--no-summary"] if tool else None
    if not tool:
        tool = which("clamscan")
        if not tool:
            return [], "ClamAV is not installed."
        args = [tool, "-r", "--infected", "--no-summary", "--max-filesize=200M", "--max-scansize=400M",
                "--max-recursion=16", "--max-files=10000"]
    try:
        r = runner(args + folders, capture_output=True, timeout=SCAN_TIMEOUT)
    except subprocess.TimeoutExpired:
        return [], f"ClamAV stopped after {SCAN_TIMEOUT // 60} minutes."
    out = []
    for line in r.stdout.decode("utf-8", "replace").splitlines():
        m = re.match(r"^(.*): (.+) FOUND$", line)
        if m:
            out.append(_r("high", "Malware signatures", f"ClamAV: {m.group(2)} in {os.path.basename(m.group(1))}",
                          f"{m.group(1)} matches ClamAV's signature {m.group(2)}. Don't open it; delete it or send it to the Files tab first.",
                          path=m.group(1), check=[f"ls -l {shlex.quote(m.group(1))}"]))
    return out, None


def yara_folders(folders, rules, runner=subprocess.run, which=shutil.which):
    tool = which("yara")
    if not tool:
        return [], "YARA is not installed (sudo pacman -S yara)."
    if not rules:
        return [], "No YARA rules yet: press Update YARA rules."
    out = []
    for folder in folders:
        try:
            r = runner([tool, "-r", "-w", "-f", "-p", "4", rules, folder], capture_output=True, timeout=SCAN_TIMEOUT)
        except subprocess.TimeoutExpired:
            return out, f"YARA stopped after {SCAN_TIMEOUT // 60} minutes on {folder}."
        for line in r.stdout.decode("utf-8", "replace").splitlines():
            parts = line.split(" ", 1)
            if len(parts) == 2 and parts[1].startswith("/"):
                rule, path = parts
                out.append(_r("high", "Malware signatures", f"YARA: {rule} in {os.path.basename(path)}",
                              f"{path} matches the YARA rule {rule}. Rules name malware families and hacking tools; "
                              "some match legitimate security tools too.", path=path, rule=rule,
                              check=[f"ls -l {shlex.quote(path)}"]))
    return out, None


def default_folders(home):
    return [p for p in (os.path.join(home, "Downloads"), "/tmp", "/var/tmp", "/dev/shm") if os.path.isdir(p)]
