"""Vigil Tasks: what is running, where did it come from, and should it be?

snapshot() walks /proc once (read-only) and returns every visible process with:
binary path, owning package, SHA-256 of the binary, parent, command line, user,
start time, systemd unit (from its cgroup), open sockets (via the Network Map's
collector), and a tree. flags() then marks the EDR-style signals from SUITE.md:
binaries deleted from disk while running, programs running from /tmp or ~/.cache,
LD_PRELOAD in the environment, and odd parents (a browser starting a shell).

Privacy: of a process's environment only the dynamic-linker variables (LD_PRELOAD,
LD_AUDIT, LD_LIBRARY_PATH) are kept; everything else in it (tokens, passwords) is
read only to find those names and is never stored or shown.
"""

import hashlib
import os
import re
import time

from ..core.pkgdb import PackageFiles
from ..net import collector
from . import secrets

HASH_MAX = 256 * 1024 * 1024
LD_VARS = (b"LD_PRELOAD=", b"LD_AUDIT=", b"LD_LIBRARY_PATH=")
TEMP = ("/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/")
SHELLS = {"sh", "bash", "dash", "zsh", "fish", "ksh", "csh", "tcsh", "busybox", "pwsh", "powershell"}
INTERPRETERS = {"python", "python3", "perl", "ruby", "node", "php", "lua", "osascript"}
NETTOOLS = {"nc", "ncat", "netcat", "socat", "curl", "wget", "telnet"}
APP_PARENTS = {   # programs that open untrusted content and should not start shells
    "firefox": "a web browser", "firefox-bin": "a web browser", "librewolf": "a web browser",
    "floorp": "a web browser", "zen": "a web browser", "chrome": "a web browser", "chromium": "a web browser",
    "brave": "a web browser", "vivaldi-bin": "a web browser", "opera": "a web browser", "msedge": "a web browser",
    "thunderbird": "the mail app", "evolution": "the mail app", "evince": "a document viewer",
    "okular": "a document viewer", "zathura": "a document viewer", "atril": "a document viewer",
    "soffice.bin": "LibreOffice", "libreoffice": "LibreOffice", "discord": "a chat app", "Discord": "a chat app",
    "slack": "a chat app", "telegram-desktop": "a chat app", "signal-desktop": "a chat app",
    "element-desktop": "a chat app", "teams": "a chat app",
}
SERVER_PARENTS = {"nginx": "the web server", "apache2": "the web server", "httpd": "the web server",
                  "php-fpm": "PHP", "lighttpd": "the web server", "mysqld": "the database",
                  "mariadbd": "the database", "postgres": "the database", "redis-server": "Redis"}
# Names malware borrows to blend in (the July 2026 AUR wave ran Tor as "dbus-daemon").
SYSTEM_NAMES = {"dbus-daemon", "dbus-broker", "systemd", "systemd-journald", "systemd-logind", "systemd-resolved",
                "systemd-timesyncd", "systemd-udevd", "systemd-networkd", "sshd", "cron", "crond", "atd", "rsyslogd",
                "NetworkManager", "wpa_supplicant", "polkitd", "udisksd", "upowerd", "accounts-daemon", "avahi-daemon",
                "cupsd", "pipewire", "wireplumber", "pulseaudio", "Xorg", "Xwayland", "gnome-shell", "kwin_wayland",
                "plasmashell", "gvfsd", "at-spi-bus-launcher", "xdg-desktop-portal", "agetty", "login", "bash", "sh"}
SYSTEM_DIRS = ("/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/", "/opt/", "/nix/store/", "/snap/", "/app/")
PAGE = os.sysconf("SC_PAGE_SIZE")
CLK = os.sysconf("SC_CLK_TCK")
HARMLESS_CHILD_CMD = re.compile(r"(^|[\s/])(xdg-open|xdg-mime|gio|kde-open\d*|exo-open)\b")


def _base(path):
    return os.path.basename((path or "").removesuffix(" (deleted)"))


def _environ_ld(proc_root, pid):
    """Only LD_* linker variables from a process's environment (None if unreadable)."""
    try:
        with open(f"{proc_root}/{pid}/environ", "rb") as fh:
            raw = fh.read(1 << 20)
    except OSError:
        return None
    out = {}
    for item in raw.split(b"\0"):
        if item.startswith(LD_VARS):
            k, _, v = item.partition(b"=")
            out[k.decode()] = v.decode("utf-8", "replace")[:500]
    return out


def _unit(proc_root, pid):
    """The systemd unit from /proc/<pid>/cgroup (the last *.service or *.scope part)."""
    try:
        with open(f"{proc_root}/{pid}/cgroup", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError:
        return None
    path = ""
    for line in text.splitlines():
        parts = line.split(":", 2)
        if len(parts) == 3 and (parts[0] == "0" or "name=systemd" in parts[1]):
            path = parts[2]
            break
    units = [p for p in path.split("/") if p.endswith((".service", ".scope"))]
    if not units:
        return None
    unit = units[-1]
    return {"unit": unit, "user": "/user@" in path or path.startswith("/user.slice/user-") and "user@" in path,
            "cgroup": path}


def _usage(proc_root, pid):
    """(cpu ticks used so far, resident memory in bytes), or (None, None)."""
    try:
        stat = collector._read(f"{proc_root}/{pid}/stat")
        rest = stat[stat.rfind(")") + 2:].split()
        ticks = int(rest[11]) + int(rest[12])            # utime + stime (fields 14 and 15)
    except (OSError, IndexError, ValueError):
        ticks = None
    try:
        rss = int(collector._read(f"{proc_root}/{pid}/statm").split()[1]) * PAGE
    except (OSError, IndexError, ValueError):
        rss = None
    return ticks, rss


def _threads_state(proc_root, pid):
    try:
        st = collector._status(proc_root, pid)
    except OSError:
        return None, None
    return st.get("Threads"), (st.get("State") or "").split(" ")[0]


class Hasher:
    """SHA-256 of each distinct binary, read through /proc/<pid>/exe (which works even
    when the file was deleted). Read, never run; cached per (device, inode, size, mtime)."""

    def __init__(self, limit=HASH_MAX):
        self.cache = {}
        self.limit = limit

    def __call__(self, proc_root, pid):
        p = f"{proc_root}/{pid}/exe"
        try:
            st = os.stat(p)
        except OSError:
            return None
        key = (st.st_dev, st.st_ino, st.st_size, int(st.st_mtime))
        if key in self.cache:
            return self.cache[key]
        if st.st_size > self.limit:
            self.cache[key] = None
            return None
        h = hashlib.sha256()
        try:
            with open(p, "rb") as fh:
                for chunk in iter(lambda: fh.read(1 << 20), b""):
                    h.update(chunk)
        except OSError:
            self.cache[key] = None
            return None
        self.cache[key] = h.hexdigest()
        return self.cache[key]


def sockets_by_pid(proc_root):
    """{pid: [sockets]} using the Network Map's collector (read-only)."""
    out = {}
    try:
        snap = collector.snapshot(proc_root)
    except Exception:  # a broken table must not take the process view down
        return out, None
    for s in snap["sockets"]:
        for pid in s.get("pids") or []:
            out.setdefault(pid, []).append({k: s.get(k) for k in ("proto", "state", "kind", "local_ip", "local_port",
                                                                  "remote_ip", "remote_port", "direction")})
    return out, snap


def snapshot(proc_root="/proc", pkgfiles=None, hasher=None, now=None, home=None, root="/"):
    now = time.time() if now is None else now
    pkg = pkgfiles or PackageFiles(root)
    hasher = hasher or Hasher()
    btime = collector._boot_time(proc_root)
    socks, _ = sockets_by_pid(proc_root)
    procs, unreadable, fd_hidden = {}, 0, 0
    for name in collector._listdir(proc_root):
        if not name.isdigit():
            continue
        pid = int(name)
        info = collector.read_process(proc_root, pid, btime, ancestry_depth=1)
        if not info:
            continue
        exe = info["exe"]
        if exe is None:
            unreadable += info["ppid"] != 2 and pid != 2   # kernel threads have no exe by design
        path = (exe or "").removesuffix(" (deleted)")
        threads, state = _threads_state(proc_root, pid)
        ticks, rss = _usage(proc_root, pid)
        held, readable = secrets.held(proc_root, pid) if exe else ([], True)
        fd_hidden += not readable
        info.update({
            "kernel": exe is None and (info["ppid"] == 2 or pid == 2) and not info["cmdline"],
            "path": path or None,
            "exists_now": bool(path) and os.path.exists(os.path.join(root, path.lstrip("/"))) if path and
            not path.startswith("/memfd:") else False,
            "package": pkg.owner(path) if path and not path.startswith("/memfd:") else None,
            "sha256": hasher(proc_root, pid) if exe else None,
            "ld": _environ_ld(proc_root, pid), "unit": _unit(proc_root, pid),
            "sockets": socks.get(pid, []), "threads": threads, "state": state, "ticks": ticks, "rss": rss,
            "cpu": None, "secrets": held, "fd_readable": readable,
            "children": [],
        })
        info.pop("ancestry", None)
        procs[pid] = info
    for pid, p in procs.items():
        parent = procs.get(p["ppid"])
        if parent:
            parent["children"].append(pid)
    for p in procs.values():
        p["children"].sort()
        p["package_db"] = pkg.kind
    roots = sorted(pid for pid, p in procs.items() if p["ppid"] not in procs)
    return {"taken_at": now, "proc_root": proc_root, "processes": procs, "roots": roots,
            "viewer_uid": os.getuid(), "unreadable_exe": unreadable, "package_db": pkg.kind,
            "unreadable_fds": fd_hidden}


# ---- flags ----------------------------------------------------------------------------------

def flags(p, procs, home=None):
    """[(check, severity, strength, text)] for one process."""
    out = []
    if p["kernel"]:
        return out
    path = p["path"] or ""
    home = (home or os.path.expanduser("~")).rstrip("/")
    parent = procs.get(p["ppid"])
    pbase = _base(parent["exe"] or parent["comm"]) if parent and parent.get("exe") else parent["comm"] if parent else ""
    base = _base(p["exe"] or "") or p["comm"]
    if path.startswith("/memfd:"):
        out.append(("memory_only", "High", 1.0, "runs from memory only (memfd): there is no file on disk"))
    elif p["exe_deleted"]:
        if p["exists_now"] and p["package"]:
            out.append(("replaced_binary", "Low", 0.2,
                        f"its program file was replaced while it ran (probably an update of {p['package']})"))
        else:
            out.append(("deleted_binary", "High", 0.9, f"its program file {path} was deleted while it kept running"))
    if path.startswith(TEMP):
        out.append(("temp_binary", "High", 0.9, f"runs from a temporary folder ({path})"))
    elif path.startswith(f"{home}/.cache/") or "/.cache/" in path:
        out.append(("cache_binary", "Medium", 0.7, f"runs from a cache folder ({path})"))
    elif "/Downloads/" in path:
        out.append(("downloads_binary", "Medium", 0.6, f"runs straight from Downloads ({path})"))
    elif re.search(r"/\.[^/]+/", path) and not re.search(r"/\.(local|nix-profile|cargo|rustup|npm|nvm|bun|deno|"
                                                          r"pyenv|sdkman|vscode|var/app|steam)/", path):
        out.append(("hidden_binary", "Medium", 0.5, f"runs from a hidden folder ({path})"))
    for var, val in (p["ld"] or {}).items():
        if var in ("LD_PRELOAD", "LD_AUDIT") and val.strip():
            out.append(("ld_preload", "High", 0.9, f"{var} forces {val[:120]} into it"))
    cmd = " ".join(p["cmdline"])
    if parent and (base in SHELLS or base.rstrip("0123456789.") in INTERPRETERS or base in NETTOOLS):
        kind = APP_PARENTS.get(pbase) or APP_PARENTS.get(parent["comm"])
        srv = SERVER_PARENTS.get(pbase) or SERVER_PARENTS.get(parent["comm"])
        if kind and not HARMLESS_CHILD_CMD.search(cmd):
            out.append(("odd_parent", "High", 0.9, f"{parent['name']} ({kind}) started {base}: {cmd[:120]}"))
        elif kind:
            out.append(("odd_parent", "Low", 0.2, f"{parent['name']} ({kind}) opened something with {cmd[:80]}"))
        elif srv:
            out.append(("odd_parent", "High", 0.9, f"{parent['name']} ({srv}) started {base}: {cmd[:120]}"))
    if (p["comm"] in SYSTEM_NAMES or base in SYSTEM_NAMES) and path and not path.startswith(SYSTEM_DIRS) \
            and not path.startswith("/memfd:"):
        out.append(("masquerade_name", "High", 0.9,
                    f"is named {p['comm']} like a system program, but runs from {path}"))
    elif (p["comm"] in SYSTEM_NAMES) and path and p.get("package") is None and p.get("package_db") \
            and base != p["comm"] and not base.startswith(p["comm"][:6]):
        out.append(("masquerade_name", "Medium", 0.6,
                    f"is named {p['comm']} like a system program, but its file {path} is a different program"))
    if p["cmdline"] and p["cmdline"][0].startswith("[") and p["exe"]:
        out.append(("fake_kernel_name", "High", 0.9, f"calls itself {p['cmdline'][0]} like a kernel thread, but runs {path}"))
    if base in NETTOOLS and re.search(r"\s-e\s|\bexec:|/bin/(ba)?sh", cmd):
        out.append(("reverse_shell", "High", 1.0, f"looks like a reverse shell: {cmd[:120]}"))
    odd = secrets.unexpected(p)
    if odd:
        names = {_base(path), p["comm"], *(os.path.basename(a) for a in p["cmdline"][:1])}
        risky = path.startswith(TEMP) or "/.cache/" in path or "/Downloads/" in path or path.startswith("/memfd:") \
            or bool(re.search(r"/\.[^/]+/", path)) or bool(names & (SHELLS | INTERPRETERS | NETTOOLS)) \
            or any(n.rstrip("0123456789.") in INTERPRETERS for n in names) \
            or (p.get("package") is None and bool(p.get("package_db")))
        more = f" and {len(odd) - 1} more" if len(odd) > 1 else ""
        out.append(("credential_access", "High" if risky else "Medium", 0.9 if risky else 0.6,
                    f"has {odd[0]['label']} open ({odd[0]['path']}){more}, which is not its own"))
    listening = [s for s in p["sockets"] if s["kind"] == "listen" and s["local_ip"] in ("0.0.0.0", "::")]
    if listening and (path.startswith(TEMP) or "/.cache/" in path or "/Downloads/" in path):
        out.append(("listens_from_odd_place", "High", 0.8,
                    f"listens on port {listening[0]['local_port']} for the whole network while running from {path}"))
    return out


def cpu_usage(snap, previous):
    """Fill in each process's CPU % from the ticks it used since the previous snapshot.
    previous: {(pid, started): (ticks, time)}; returns the new one to keep."""
    now, keep = snap["taken_at"], {}
    for pid, p in snap["processes"].items():
        if p.get("ticks") is None:
            continue
        k = (pid, p.get("started"))
        keep[k] = (p["ticks"], now)
        if k in previous:
            t0, w0 = previous[k]
            if now > w0:
                p["cpu"] = round(100.0 * (p["ticks"] - t0) / CLK / (now - w0), 1)
    return keep


def ancestry(procs, pid, depth=12):
    chain = []
    p = procs.get(pid)
    while p and len(chain) < depth:
        chain.append({"pid": p["pid"], "name": p["name"]})
        p = procs.get(p["ppid"])
    return chain
