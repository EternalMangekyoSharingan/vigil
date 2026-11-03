"""System facts every tool needs: which distro this is, which package owns a file,
which firewall is in use, and the commands that ask the package manager.

All distro differences live here, each behind one small function with a fallback, so
the rest of the suite stays distro-neutral. Everything is read from files; the one
exception is the RPM database, which has no stable on-disk format, so `rpm -qf` (a
read-only query) is asked instead.
"""

import functools
import glob
import os
import shutil
import subprocess

FAMILY_IDS = [("arch", {"arch", "manjaro", "endeavouros", "garuda", "artix", "cachyos"}),
              ("fedora", {"fedora", "rhel", "centos", "rocky", "almalinux", "nobara"}),
              ("suse", {"opensuse", "suse", "opensuse-tumbleweed", "opensuse-leap", "sles"}),
              ("debian", {"debian", "ubuntu", "linuxmint", "pop", "elementary", "zorin", "kali", "raspbian"}),
              ("void", {"void"}), ("alpine", {"alpine"}), ("gentoo", {"gentoo"})]

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


def package_owner(path, root="/"):
    """Which installed package ships this file, or how it was installed, or None.

    Reads the package databases directly (dpkg, pacman), falling back to `rpm -qf`.
    One small function so distro differences stay in one place.
    """
    if not path:
        return None
    path = path.removesuffix(" (deleted)")
    for prefix, how in (("/snap/", "a Snap package"), ("/var/lib/flatpak/", "a Flatpak (system)"),
                        ("/app/", "a Flatpak"), ("/tmp/.mount_", "an AppImage (mounted from a file)"),
                        ("/nix/store/", "the Nix store")):
        if path.startswith(prefix):
            return {"how": how, "package": None}
    if "/.local/share/flatpak/" in path:
        return {"how": "a Flatpak (user)", "package": None}
    return _owner_cached(path, root)


@functools.lru_cache(maxsize=512)
def _owner_cached(path, root="/"):
    for info in glob.glob(os.path.join(root, "var/lib/dpkg/info/*.list")):  # Debian, Ubuntu, Mint, …
        try:
            with open(info, "rb") as fh:
                if f"\n{path}\n".encode() in b"\n" + fh.read() + b"\n":
                    return {"how": "a Debian package (dpkg)", "package": os.path.basename(info)[:-5].split(":")[0]}
        except OSError:
            continue
    rel = path.lstrip("/")
    for files in glob.glob(os.path.join(root, "var/lib/pacman/local/*/files")):  # Arch, Manjaro, …
        try:
            with open(files, encoding="utf-8", errors="replace") as fh:
                if f"\n{rel}\n" in "\n" + fh.read() + "\n":
                    return {"how": "an Arch package (pacman)", "package": os.path.basename(os.path.dirname(files))}
        except OSError:
            continue
    if root == "/" and shutil.which("rpm"):  # Fedora, openSUSE, … (live system only)
        try:
            r = subprocess.run(["rpm", "-qf", "--queryformat", "%{NAME}-%{VERSION}", path],
                               capture_output=True, text=True, timeout=3)
            if r.returncode == 0 and r.stdout.strip():
                return {"how": "an RPM package", "package": r.stdout.strip()}
        except (OSError, subprocess.TimeoutExpired):
            pass
    if glob.glob(os.path.join(root, "var/lib/dpkg/info/*.list")) or glob.glob(os.path.join(root, "var/lib/pacman/local/*")) or (root == "/" and shutil.which("rpm")):
        return {"how": None, "package": None}  # a package database exists and does not list it
    return None  # no package database we can read
