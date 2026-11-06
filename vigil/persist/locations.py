"""Every place on Linux where something can start by itself, and what to look for in each.

`collect(home, root)` returns one entry per file (or per loaded kernel module), read-only:
    {"path", "kind", "group", "scope" (user|system), "sha256", "size", "mode", "uid",
     "link", "readable", "text" (first 256 kB, for content checks), "lines" (flags)}

`flags(entry)` lists what is suspicious *inside* an entry, independent of any baseline.
"""

import glob
import hashlib
import os
import re
import stat

READ_MAX = 256 * 1024
TEMP = ("/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/", "/run/user/")

# (group, kind, scope, patterns relative to home ("~/...") or root ("/..."))
SOURCES = [
    ("systemd", "systemd user unit", "user", ["~/.config/systemd/user/*", "~/.config/systemd/user/*/*",
                                               "~/.local/share/systemd/user/*"]),
    ("systemd", "systemd unit", "system", ["/etc/systemd/system/*", "/etc/systemd/system/*/*",
                                           "/etc/systemd/user/*", "/etc/systemd/user/*/*",
                                           "/usr/lib/systemd/system/*.service", "/usr/lib/systemd/system/*.timer",
                                           "/usr/lib/systemd/user/*.service", "/usr/lib/systemd/user/*.timer"]),
    ("systemd", "systemd generator", "system", ["/etc/systemd/system-generators/*", "/etc/systemd/user-generators/*",
                                                "/usr/local/lib/systemd/system-generators/*"]),
    ("cron", "cron", "system", ["/etc/crontab", "/etc/anacrontab", "/etc/cron.d/*", "/etc/cron.hourly/*",
                                "/etc/cron.daily/*", "/etc/cron.weekly/*", "/etc/cron.monthly/*",
                                "/var/spool/cron/*", "/var/spool/cron/crontabs/*"]),
    ("autostart", "XDG autostart", "user", ["~/.config/autostart/*.desktop"]),
    ("autostart", "XDG autostart", "system", ["/etc/xdg/autostart/*.desktop"]),
    ("shell", "shell start-up file", "user", ["~/.bashrc", "~/.bash_profile", "~/.bash_login", "~/.bash_logout",
                                              "~/.profile", "~/.zshrc", "~/.zprofile", "~/.zshenv", "~/.zlogin",
                                              "~/.config/fish/config.fish", "~/.config/fish/conf.d/*.fish",
                                              "~/.xprofile", "~/.xinitrc", "~/.xsessionrc", "~/.pam_environment",
                                              "~/.config/environment.d/*.conf", "~/.config/plasma-workspace/env/*"]),
    ("shell", "shell start-up file", "system", ["/etc/profile", "/etc/profile.d/*", "/etc/bash.bashrc", "/etc/bashrc",
                                                "/etc/zsh/*", "/etc/zshrc", "/etc/environment", "/etc/environment.d/*"]),
    ("preload", "dynamic linker preload", "system", ["/etc/ld.so.preload"]),
    ("preload", "dynamic linker paths", "system", ["/etc/ld.so.conf", "/etc/ld.so.conf.d/*"]),
    ("pam", "PAM configuration", "system", ["/etc/pam.d/*", "/etc/security/pam_env.conf"]),
    ("sudoers", "sudo rules", "system", ["/etc/sudoers", "/etc/sudoers.d/*", "/etc/doas.conf"]),
    ("ssh", "SSH login keys", "user", ["~/.ssh/authorized_keys", "~/.ssh/authorized_keys2"]),
    ("ssh", "SSH client start-up", "user", ["~/.ssh/rc", "~/.ssh/config"]),
    ("ssh", "SSH server", "system", ["/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d/*", "/etc/ssh/sshrc",
                                     "/root/.ssh/authorized_keys"]),
    ("modules", "kernel modules at boot", "system", ["/etc/modules-load.d/*", "/etc/modules", "/etc/modprobe.d/*",
                                                     "/usr/lib/modules-load.d/*"]),
    ("udev", "udev rule", "system", ["/etc/udev/rules.d/*", "/usr/lib/udev/rules.d/*", "/run/udev/rules.d/*"]),
    ("other", "boot script", "system", ["/etc/rc.local", "/etc/init.d/*", "/etc/X11/xinit/xinitrc.d/*"]),
    ("other", "network hook", "system", ["/etc/NetworkManager/dispatcher.d/*", "/etc/NetworkManager/dispatcher.d/*/*"]),
    ("other", "package manager hook", "system", ["/etc/pacman.d/hooks/*", "/etc/apt/apt.conf.d/*"]),
    ("other", "login message script", "system", ["/etc/update-motd.d/*"]),
]
GROUP_NAMES = {"systemd": "systemd units and timers", "cron": "cron", "autostart": "XDG autostart",
               "shell": "shell start-up files", "preload": "/etc/ld.so.preload", "pam": "PAM", "sudoers": "sudoers",
               "ssh": "SSH", "modules": "kernel modules", "udev": "udev rules", "other": "other hooks"}

EXEC_RE = re.compile(r"^\s*(?:ExecStart|ExecStartPre|ExecStartPost|ExecStop|ExecReload|Exec|RUN\+?=|"
                     r"PROGRAM=)\s*=?\s*[-@+!:]*\"?(\S+)", re.M)
CRON_LINE = re.compile(r"^\s*(@\w+|[\d*/,\-]+\s+[\d*/,\-]+\s+[\d*/,\-]+\s+[\w*/,\-]+\s+[\w*/,\-]+)\s+(.*)$")


def _expand(pattern, home, root):
    if pattern.startswith("~/"):
        return glob.glob(os.path.join(home, pattern[2:]))
    return glob.glob(os.path.join(root, pattern.lstrip("/")))


def _live(path, home, root, home_real):
    """The path as it is on the live system (fixtures live under a fake root)."""
    if root != "/" and path.startswith(root.rstrip("/") + "/"):
        return "/" + path[len(root.rstrip("/")) + 1:]
    return path


def collect(home, root="/", proc="/proc"):
    entries, hidden, seen = [], [], set()
    for group, kind, scope, pats in SOURCES:
        for pat in pats:
            for p in sorted(_expand(pat, home, root)):
                if p in seen:
                    continue
                seen.add(p)
                e = read_entry(p, group, kind, scope, home, root)
                if e is None:
                    continue
                if not e["readable"]:
                    hidden.append({"path": e["path"], "kind": kind})
                entries.append(e)
    entries += kernel_modules(proc)
    return entries, hidden


def read_entry(p, group, kind, scope, home, root):
    try:
        st = os.lstat(p)
    except OSError:
        return None
    if stat.S_ISDIR(st.st_mode):
        return None
    live = _live(p, home, root, home)
    e = {"path": live, "fs_path": p, "kind": kind, "group": group, "scope": scope, "size": st.st_size,
         "mode": stat.S_IMODE(st.st_mode), "uid": st.st_uid, "mtime": st.st_mtime, "link": None,
         "readable": True, "sha256": None, "text": ""}
    if stat.S_ISLNK(st.st_mode):
        e["link"] = os.readlink(p)
        e["sha256"] = hashlib.sha256(("link:" + e["link"]).encode()).hexdigest()
        return e
    if not stat.S_ISREG(st.st_mode):
        return None
    try:
        with open(p, "rb") as fh:
            data = fh.read(READ_MAX)
            h = hashlib.sha256(data)
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        e["sha256"] = h.hexdigest()
        e["data"] = data
        e["text"] = data.decode("utf-8", "replace")
    except PermissionError:
        e["readable"] = False
    except OSError:
        e["readable"] = False
    return e


def kernel_modules(proc="/proc"):
    """Loaded kernel modules from /proc/modules, with their taint marks (O out-of-tree,
    E unsigned, P proprietary, F forced)."""
    out = []
    try:
        with open(os.path.join(proc, "modules"), encoding="utf-8", errors="replace") as fh:
            for line in fh:
                parts = line.split()
                if not parts:
                    continue
                taint = re.search(r"\(([A-Z]+)\)\s*$", line)
                out.append({"path": f"kernel module {parts[0]}", "fs_path": None, "kind": "loaded kernel module",
                            "group": "modules", "scope": "system", "size": int(parts[1]) if len(parts) > 1 and
                            parts[1].isdigit() else 0, "mode": None, "uid": 0, "mtime": None, "link": None,
                            "readable": True, "text": "", "taint": taint.group(1) if taint else "",
                            "sha256": hashlib.sha256(f"module:{parts[0]}:{taint.group(1) if taint else ''}".encode()).hexdigest()})
    except OSError:
        pass
    return out


# ---- what is suspicious inside an entry ------------------------------------------------------

DOWNLOAD = re.compile(r"\b(curl|wget|fetch|aria2c)\b[^\n|;]*(\|\s*(sudo\s+)?(ba|z|da)?sh\b|-o\s|-O\s|>)|"
                      r"\b(ba|z)?sh\s+-c\s+[\"']?\$\(\s*(curl|wget)|\bbase64\s+(-d|--decode)\b|/dev/tcp/|"
                      r"\b(nc|ncat)\b[^\n]*\s-e\s|\bpython[0-9.]*\s+-c\s+[\"'][^\n]*(socket|urllib|exec)")
HIDDEN_DIR = re.compile(r"/\.[^/\s]+/")


def program_of(cmd):
    cmd = cmd.strip().strip("\"'")
    return cmd.split()[0] if cmd else ""


# Autostart names used by known Linux malware (file or unit basename -> what it was).
KNOWN_BAD = {
    "rat-agent.service": "the service the July 2025 AUR browser packages installed (CHAOS RAT)",
    "rat-agent": "the service the July 2025 AUR browser packages installed (CHAOS RAT)",
}


def flags(e):
    """[(severity, strength, text, line number or None, title template)] for one entry.
    Title templates may use {name} (the file or module name)."""
    out = []
    text = e.get("text") or ""
    g = e["group"]
    lines = text.splitlines()

    def add(sev, st, msg, n=None, title=""):
        out.append((sev, st, msg, n, title))

    for n, line in enumerate(lines, 1):
        s = line.strip()
        if not s or s.startswith(("#", ";")):
            continue
        if DOWNLOAD.search(s):
            add("High", 0.9, f"downloads or decodes and runs code: {s[:120]}", n, "{name} downloads and runs code")
        progs = [m.group(1) for m in EXEC_RE.finditer(line)]
        if g == "cron":
            m = CRON_LINE.match(s)
            if m:
                rest = m.group(2)
                if e["path"] in ("/etc/crontab", "/etc/anacrontab") or e["path"].startswith("/etc/cron.d/"):
                    rest = rest.split(None, 1)[1] if len(rest.split(None, 1)) > 1 else rest
                progs.append(program_of(rest))
        for prog in progs:
            if prog.startswith(TEMP):
                add("High", 0.9, f"starts a program from a temporary folder ({prog})", n, "{name} starts a program from a temp folder")
            elif HIDDEN_DIR.search(prog) and "/.local/" not in prog and "/.nix-profile/" not in prog:
                add("Medium", 0.6, f"starts a program from a hidden folder ({prog})", n, "{name} starts a program from a hidden folder")
            elif "/Downloads/" in prog:
                add("Medium", 0.6, f"starts a program from Downloads ({prog})", n, "{name} starts a program from Downloads")
        if re.search(r"\bLD_PRELOAD\s*=|\bLD_AUDIT\s*=", s):
            add("High", 0.9, "forces a library into every program (LD_PRELOAD)", n, "{name} forces a library into every program")
        if g == "sudoers":
            if re.search(r"NOPASSWD\s*:\s*ALL\b", s) and not s.startswith("%wheel"):
                add("Medium", 0.6, f"lets someone run anything as root without a password: {s[:100]}", n, "A sudo rule skips the password for everything")
            if re.search(r"Defaults\s+.*(!authenticate|env_keep\s*\+?=\s*\"?[^\n]*LD_PRELOAD)", s):
                add("High", 0.9, f"switches off a sudo safety check: {s[:100]}", n, "A sudo rule switches off a safety check")
        if g == "pam":
            if "pam_exec.so" in s:
                add("Medium", 0.6, f"runs a program at every login (pam_exec): {s[:100]}", n, "Logging in runs an extra program")
            m = re.search(r"\s(/\S+\.so)\b", s)
            if m and not m.group(1).startswith(("/usr/lib", "/lib")):
                add("High", 0.9, f"loads a login module from an unusual place ({m.group(1)})", n, "Login loads a module from an unusual place")
            if re.search(r"\bauth\s+sufficient\s+pam_permit\.so", s):
                add("High", 1.0, "accepts any password (pam_permit as sufficient)", n, "Login accepts any password")
        if g == "modules" and e["kind"] != "loaded kernel module":
            m = re.match(r"^\s*install\s+(\S+)\s+(.+)$", s)
            if m and not re.match(r"^(/bin/|/usr/bin/)?(true|false)\b", m.group(2).strip()) \
                    and not re.match(r"^(/sbin/|/usr/sbin/)?modprobe\b", m.group(2).strip()):
                add("High", 0.8, f"runs a command whenever module {m.group(1)} loads: {m.group(2)[:80]}", n, "Loading a kernel module runs a command")
        if g == "udev" and re.search(r"RUN\+?=", s):
            if re.search(r"(ba|z)?sh\s+-c|curl|wget|/tmp/|/dev/shm|python[0-9.]*\s+-c", s):
                add("High", 0.8, f"runs a shell command when a device appears: {s[:100]}", n, "Plugging in a device runs a shell command")
        if g == "ssh" and e["kind"] == "SSH client start-up" and re.search(r"^\s*(ProxyCommand|LocalCommand|"
                                                                            r"KnownHostsCommand)\b", s, re.I):
            if DOWNLOAD.search(s) or re.search(r"/tmp/|base64", s):
                add("High", 0.8, f"SSH runs a suspicious command: {s[:100]}", n, "Your SSH settings run a suspicious command")
        if g == "ssh" and e["kind"] == "SSH server" and re.search(r"^\s*(PermitRootLogin\s+yes|"
                                                                  r"PermitEmptyPasswords\s+yes|AuthorizedKeysCommand\s)", s, re.I):
            add("Medium", 0.5, f"SSH server setting worth a look: {s[:80]}", n, "An SSH server setting is worth a look")
    base = os.path.basename(e["path"])
    if base in KNOWN_BAD:
        add("High", 1.0, f"has the name of {KNOWN_BAD[base]}", None, "{name} has the name of known malware")
    if g == "preload" and e["kind"] == "dynamic linker preload" and text.strip():
        add("High", 1.0, "lists libraries loaded into every program, a classic rootkit trick", 1, "/etc/ld.so.preload loads libraries into every program")
    if g == "ssh" and e["kind"] == "SSH login keys":
        keys = [ln for ln in lines if ln.strip() and not ln.lstrip().startswith("#")]
        forced = [ln for ln in keys if re.match(r'^\s*(command|environment)=', ln)]
        if forced:
            add("Low", 0.3, f"{len(forced)} key(s) run a forced command on login", None, "Some SSH keys run a fixed command on login")
    if e["kind"] == "loaded kernel module" and set(e.get("taint", "")) & set("OEF"):
        why = {"O": "built outside the kernel tree", "E": "not signed", "F": "force-loaded"}
        add("Low", 0.3, "kernel module " + ", ".join(why[c] for c in e["taint"] if c in why), None, "Kernel module {name} is unsigned or out of tree")
    if e.get("link") and e["link"].startswith(TEMP):
        add("High", 0.9, f"points into a temporary folder ({e['link']})", None, "{name} points into a temp folder")
    if e.get("link"):
        return out  # a link's own mode and owner mean nothing; its target is checked where it lives
    if e["scope"] == "system" and e.get("uid") not in (0, None) and e["kind"] != "loaded kernel module":
        add("Medium", 0.6, "a system start-up file owned by a normal user, so that user can change what root runs", None, "{name} is owned by a normal user")
    if e["scope"] == "system" and e.get("mode") is not None and e["mode"] & 0o002:
        add("High", 0.9, "anyone on this PC can change it (world-writable)", None, "Anyone on this PC can change {name}")
    return out
