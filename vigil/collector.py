"""Read-only network collector.

Reads the kernel's socket tables (/proc/net/tcp, tcp6, udp, udp6) and maps each
socket to the process holding it by scanning /proc/<pid>/fd. Needs no root: when
the kernel will not say who owns a socket, the socket is still reported, together
with the reason it could not be attributed.

Nothing here writes to /proc or changes any system setting.
"""

import ipaddress
import os
import pwd
import re
import sys
import time
from functools import lru_cache

TABLES = (("tcp", "tcp", 4), ("tcp6", "tcp", 6), ("udp", "udp", 4), ("udp6", "udp", 6))

TCP_STATES = {
    0x01: "ESTABLISHED", 0x02: "SYN_SENT", 0x03: "SYN_RECV", 0x04: "FIN_WAIT1",
    0x05: "FIN_WAIT2", 0x06: "TIME_WAIT", 0x07: "CLOSE", 0x08: "CLOSE_WAIT",
    0x09: "LAST_ACK", 0x0A: "LISTEN", 0x0B: "CLOSING", 0x0C: "NEW_SYN_RECV",
}
# UDP has no handshake; the kernel reuses two TCP codes for it.
UDP_STATES = {0x01: "ESTABLISHED", 0x07: "UNCONN"}

INTERPRETER = re.compile(
    r"^(python|perl|ruby|node|nodejs|java|php|lua|bash|sh|dash|zsh|ksh|fish|pwsh|deno|bun)[\d.]*$")
# "LAN" means ranges a home or office network actually uses. Python's is_private
# also covers documentation and benchmark ranges, which are better called reserved.
LAN_NETS = tuple(ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7"))

HIDDEN_LABELS = {
    "closed": "Closed before attribution",
    "other-user": "Hidden: other user",
    "protected": "Hidden: protected process",
    "unknown": "Unattributed",
}


def decode_address(field, byteorder=sys.byteorder):
    """Decode '0100007F:0277' into ('127.0.0.1', 631).

    The kernel prints the address as the in-memory 32-bit words in hex, so the
    byte order follows the CPU; the port is already in host order.
    """
    hexip, hexport = field.split(":")
    port = int(hexport, 16)
    if len(hexip) == 8:
        ip = ipaddress.IPv4Address(int(hexip, 16).to_bytes(4, byteorder))
    elif len(hexip) == 32:
        raw = b"".join(int(hexip[i:i + 8], 16).to_bytes(4, byteorder) for i in range(0, 32, 8))
        ip = ipaddress.IPv6Address(raw)
        if ip.ipv4_mapped:  # dual-stack socket talking IPv4
            ip = ip.ipv4_mapped
    else:
        raise ValueError(f"unexpected address field {field!r}")
    return str(ip), port


def scope_of(ip):
    """Where an address lives: loopback, lan, link-local, multicast, internet, unspecified."""
    a = ipaddress.ip_address(ip)
    if a.is_unspecified:
        return "unspecified"
    if a.is_loopback:
        return "loopback"
    if a.is_link_local:
        return "link-local"
    if a.is_multicast:
        return "multicast"
    if any(a in n for n in LAN_NETS if n.version == a.version):
        return "lan"
    if a.is_global:
        return "internet"
    return "reserved"


def parse_table(text, table, byteorder=sys.byteorder):
    """Parse one /proc/net/{tcp,tcp6,udp,udp6} file into socket dicts."""
    proto = "tcp" if table.startswith("tcp") else "udp"
    states = TCP_STATES if proto == "tcp" else UDP_STATES
    sockets = []
    for line in text.splitlines()[1:]:
        f = line.split()
        if len(f) < 10 or not f[0].endswith(":"):
            continue
        try:
            lip, lport = decode_address(f[1], byteorder)
            rip, rport = decode_address(f[2], byteorder)
            st = int(f[3], 16)
            uid = int(f[7])
            inode = int(f[9])
        except ValueError:
            continue
        state = states.get(st, f"0x{st:02X}")
        if (proto == "tcp" and state == "LISTEN") or (rport == 0 and scope_of(rip) == "unspecified"):
            kind = "listen"
        else:
            kind = "connection"
        sockets.append({
            "table": table, "proto": proto, "local_ip": lip, "local_port": lport,
            "remote_ip": rip, "remote_port": rport, "state": state, "uid": uid,
            "inode": inode, "kind": kind,
        })
    return sockets


@lru_cache(maxsize=256)
def username(uid):
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return f"uid {uid}"


def _read(path, mode="r"):
    with open(path, mode) as fh:
        return fh.read()


def _listdir(path):
    return os.listdir(path)


def _readlink(path):
    return os.readlink(path)


def _status(proc_root, pid):
    fields = {}
    for line in _read(f"{proc_root}/{pid}/status").splitlines():
        key, _, value = line.partition(":")
        fields[key] = value.strip()
    return fields


def scan_fds(proc_root="/proc"):
    """Map socket inodes to the pids holding them.

    Returns (pids, owners, unreadable): every visible pid, {inode: [pids]}, and the
    pids whose fd table the kernel would not show us (other users' processes, or
    setuid / non-dumpable ones of our own).
    """
    pids, owners, unreadable = [], {}, []
    for name in _listdir(proc_root):
        if not name.isdigit():
            continue
        pid = int(name)
        pids.append(pid)
        fd_dir = f"{proc_root}/{name}/fd"
        try:
            fds = _listdir(fd_dir)
        except PermissionError:
            unreadable.append(pid)
            continue
        except OSError:  # exited while we looked
            continue
        for fd in fds:
            try:
                target = _readlink(f"{fd_dir}/{fd}")
            except OSError:
                continue
            if target.startswith("socket:["):
                owners.setdefault(int(target[8:-1]), []).append(pid)
    return pids, owners, unreadable


def program_identity(exe, cmdline, comm):
    """A stable key for 'which program' plus a short display name.

    Interpreters are keyed by the script they run, so two Python scripts are two
    programs. A deleted executable (common right after a package upgrade) keeps
    its path; the deletion is reported separately.
    """
    path = (exe or "").removesuffix(" (deleted)") or (cmdline[0] if cmdline else "")
    if not path:  # kernel threads have neither; their names may contain '/'
        return f"[{comm}]", f"[{comm}]"
    base = os.path.basename(path)
    target = None
    if INTERPRETER.match(base):
        args = cmdline[1:]
        for i, arg in enumerate(args):
            if arg in ("-m", "-jar"):
                target = f"{arg} {args[i + 1]}" if i + 1 < len(args) else None
                break
            if arg == "-c":  # inline code: keep the interpreter as the program
                break
            if not arg.startswith("-"):
                target = arg
                break
    if target:
        name = target.split()[-1] if target.startswith("-") else os.path.basename(target)
        return f"{path} {target}", f"{name} ({base})"
    return path, base


def _boot_time(proc_root):
    try:
        for line in _read(f"{proc_root}/stat").splitlines():
            if line.startswith("btime "):
                return int(line.split()[1])
    except OSError:
        pass
    return None


def _start_time(proc_root, pid, btime):
    """Process start as epoch seconds, from field 22 of /proc/<pid>/stat."""
    if btime is None:
        return None
    try:
        stat = _read(f"{proc_root}/{pid}/stat")
    except OSError:
        return None
    rest = stat[stat.rfind(")") + 2:].split()  # comm may contain spaces and ')'
    try:
        return btime + int(rest[19]) / os.sysconf("SC_CLK_TCK")
    except (IndexError, ValueError):
        return None


def read_process(proc_root, pid, btime=None, ancestry_depth=12):
    """Identity and context for one process, or None if it has exited."""
    base = f"{proc_root}/{pid}"
    try:
        status = _status(proc_root, pid)
        comm = _read(f"{base}/comm").strip()
    except OSError:
        return None
    try:
        cmdline = [a for a in _read(f"{base}/cmdline", "rb").decode(errors="replace").split("\0")]
        while cmdline and cmdline[-1] == "":
            cmdline.pop()
    except OSError:
        cmdline = []
    try:
        exe = _readlink(f"{base}/exe")
    except OSError:
        exe = None
    uid = int(status.get("Uid", "-1").split()[0])
    ppid = int(status.get("PPid", "0") or 0)
    key, name = program_identity(exe, cmdline, comm)
    ancestry = []
    p = ppid
    while p > 0 and len(ancestry) < ancestry_depth:
        try:
            pst = _status(proc_root, p)
        except OSError:
            break
        ancestry.append({"pid": p, "name": pst.get("Name", "?")})
        p = int(pst.get("PPid", "0") or 0)
    return {
        "pid": pid, "key": key, "name": name, "comm": comm, "exe": exe,
        "exe_deleted": bool(exe and exe.endswith(" (deleted)")),
        "cmdline": cmdline, "uid": uid, "user": username(uid), "ppid": ppid,
        "parent": ancestry[0]["name"] if ancestry else None, "ancestry": ancestry,
        "started": _start_time(proc_root, pid, btime),
    }


def hidepid_option(mountinfo="/proc/self/mountinfo"):
    """The hidepid= mount option of /proc, if set (hardened distros use it)."""
    try:
        for line in _read(mountinfo).splitlines():
            parts = line.split(" - ")
            if len(parts) == 2 and parts[1].split()[0] == "proc" and line.split()[4] == "/proc":
                for opt in parts[1].split()[-1].split(","):
                    if opt.startswith("hidepid="):
                        return opt.split("=", 1)[1]
    except OSError:
        pass
    return None


def explain_hidden(reason, sock, viewer_uid, protected_count=0):
    """Plain-language reason a socket has no process attached."""
    if reason == "closed":
        return (f"The program already closed this connection; the kernel keeps it in "
                f"{sock['state']} to finish the shutdown, and no process owns it any more.")
    if reason == "other-user":
        return (f"Owned by {username(sock['uid'])} (uid {sock['uid']}). The kernel shows a "
                f"process's open sockets only to its owner and to root, so Vigil, running as "
                f"{username(viewer_uid)}, cannot see which program this is.")
    if reason == "protected":
        return (f"Owned by your user, but {protected_count} of your processes do not allow "
                f"inspection (setuid or non-dumpable programs such as ssh-agent or keyring "
                f"daemons). One of them probably holds it.")
    return ("No visible process holds this socket. The process may have exited between reads, "
            "or live in another PID namespace (a container).")


def snapshot(proc_root="/proc", now=None, viewer_uid=None):
    """One read-only pass over /proc: sockets, their processes, and what is hidden."""
    now = time.time() if now is None else now
    viewer_uid = os.getuid() if viewer_uid is None else viewer_uid
    sockets, missing = [], []
    for table, _proto, _family in TABLES:
        try:
            text = _read(f"{proc_root}/net/{table}")
        except FileNotFoundError:  # e.g. tcp6 on a kernel with IPv6 disabled
            missing.append(table)
            continue
        sockets.extend(parse_table(text, table))

    # A connection whose local port is one we listen on was accepted from outside:
    # direction "in". Everything else was opened by a program here: "out".
    listening = {(x["proto"], x["local_port"]) for x in sockets
                 if x["kind"] == "listen" and x["state"] == "LISTEN"}
    for x in sockets:
        x["direction"] = ("in" if x["kind"] == "connection" and
                          (x["proto"], x["local_port"]) in listening else "out")

    pids, owners, unreadable = scan_fds(proc_root)
    unreadable_by_uid = {}
    for pid in unreadable:
        try:
            uid = int(_status(proc_root, pid).get("Uid", "-1").split()[0])
        except OSError:
            continue
        unreadable_by_uid[uid] = unreadable_by_uid.get(uid, 0) + 1
    protected = unreadable_by_uid.get(viewer_uid, 0) if viewer_uid != 0 else 0

    btime = _boot_time(proc_root)
    processes, hidden_counts = {}, {}
    for s in sockets:
        holders = sorted(owners.get(s["inode"], [])) if s["inode"] else []
        for pid in holders:
            if pid not in processes:
                processes[pid] = read_process(proc_root, pid, btime)
        live = [pid for pid in holders if processes.get(pid)]
        if live:
            s["pid"], s["pids"], s["program"] = live[0], live, processes[live[0]]["key"]
            s["hidden"] = None
            continue
        if s["inode"] == 0:
            reason = "closed"
        elif viewer_uid != 0 and s["uid"] != viewer_uid:
            reason = "other-user"
        elif protected:
            reason = "protected"
        else:
            reason = "unknown"
        s["pid"], s["pids"], s["program"] = None, [], None
        s["hidden"] = {"reason": reason, "label": HIDDEN_LABELS[reason],
                       "explanation": explain_hidden(reason, s, viewer_uid, protected)}
        hidden_counts[reason] = hidden_counts.get(reason, 0) + 1

    return {
        "taken_at": now,
        "proc_root": proc_root,
        "viewer": {"uid": viewer_uid, "user": username(viewer_uid), "root": viewer_uid == 0},
        "sockets": sockets,
        "processes": {pid: info for pid, info in processes.items() if info},
        "pids_visible": len(pids),
        "unreadable_by_uid": unreadable_by_uid,
        "hidden_counts": hidden_counts,
        "missing_tables": missing,
        "hidepid": hidepid_option() if proc_root == "/proc" else None,
    }
