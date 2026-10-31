"""Offline explanations: what a program does, what a port is for, where a binary came from.

Everything here is local: a hand-written catalog of common Linux programs and network
services, plus a lookup of which installed package owns an executable. Nothing is
fetched. The catalog says what is *normal*; findings elsewhere say what is not.
"""

import functools
import glob
import math
import os
import re
import shutil
import subprocess
import time

# Executable basename (lower case, version digits stripped) -> knowledge.
# what: what the program is and does. net: why it uses the network and what that looks
# like. normal: what is expected. watch: what would be worth a second look.
PROGRAMS = {
    "firefox": {"title": "Firefox web browser",
                "what": "Mozilla's web browser. Each tab and helper runs as its own process.",
                "net": "Talks to every site you visit over HTTPS (TCP 443, or UDP 443 for HTTP/3), plus "
                       "Mozilla services for updates, sync, safe-browsing lists and telemetry.",
                "normal": "Many short connections to many addresses, mostly 443; lots of CDNs.",
                "watch": "Listening sockets, unusual ports, or a 'firefox' binary outside /usr, /opt or a Flatpak/Snap."},
    "chrome": {"title": "Google Chrome / Chromium web browser",
               "what": "A Chromium-based web browser. Tabs, GPU and network work run in separate processes.",
               "net": "HTTPS to the sites you visit (TCP and UDP 443/QUIC), Google update and sync services, "
                      "and local-network discovery (mDNS 5353, SSDP 1900) for casting.",
               "normal": "Many connections on 443 to many addresses.",
               "watch": "A browser process running from /tmp or a hidden folder; connections on unusual ports."},
    "discord": {"title": "Discord",
                "what": "Chat, voice and video app built on Electron (a bundled Chromium).",
                "net": "Keeps a WebSocket open to Discord's gateway over HTTPS (443) for messages and presence, "
                       "fetches images and updates from its CDN (usually Cloudflare or Google Cloud), and sends "
                       "voice/video over UDP to Discord's voice servers on ports 50000–65535 while you are in a call.",
                "normal": "One or two long-lived 443 connections plus short CDN fetches; UDP voice only during calls.",
                "watch": "Voice-port traffic when you are not in a call, or a Discord binary outside the usual "
                         "install paths (/usr/share/discord, /opt/discord, Flatpak, Snap)."},
    "slack": {"title": "Slack", "what": "Slack's desktop app: a web page in its own Chromium (Electron) runtime that keeps your workspaces' messages, calls and notifications in sync.",
              "net": "Long-lived WebSocket to Slack over 443, plus CDN and file traffic.",
              "normal": "443 to Slack and AWS/Cloudflare addresses.", "watch": "Unusual ports."},
    "spotify": {"title": "Spotify", "what": "Spotify's desktop player. Streams music from Spotify's servers, caches tracks on disk and can control or be controlled by other Spotify devices on your network.",
                "net": "Streams audio and fetches metadata over 443 and 4070; discovers speakers on the LAN "
                       "(mDNS 5353, SSDP 1900, port 57621).",
                "normal": "Steady 443 traffic while playing.", "watch": "Listening on all interfaces beyond Connect."},
    "steam": {"title": "Steam", "what": "Valve's game store and launcher.",
              "net": "Talks to Steam servers on 443 and 27015–27050, downloads from CDNs, and finds other "
                     "Steam devices on the LAN (27036).",
              "normal": "Bursty downloads; game traffic on UDP during play.", "watch": "Traffic while Steam is closed."},
    "code": {"title": "Visual Studio Code", "what": "Microsoft's code editor, built on Electron. Its extensions run as separate Node.js processes and can do anything a program you run can do.",
             "net": "Extension marketplace, updates, telemetry and any language servers or extensions "
                    "that reach out (443). Remote/SSH sessions use 22.",
             "normal": "443 to Microsoft/GitHub addresses.",
             "watch": "Extensions opening listeners or contacting unknown addresses."},
    "telegram-desktop": {"title": "Telegram", "what": "Telegram's desktop messenger. Keeps a permanent encrypted connection to Telegram's data centres to send and receive messages, files and calls.",
                         "net": "Persistent connections to Telegram data centres (443, sometimes 80/5222).",
                         "normal": "A few long-lived connections.", "watch": "-"},
    "signal-desktop": {"title": "Signal", "what": "End-to-end encrypted messenger (Electron).",
                       "net": "WebSocket to Signal's servers over 443; calls use UDP relays.",
                       "normal": "One long-lived 443 connection.", "watch": "-"},
    "thunderbird": {"title": "Thunderbird", "what": "Mozilla's email and calendar client. Fetches and sends your mail from the mail servers you configured and keeps calendars and contacts in sync.",
                    "net": "IMAP (993/143), SMTP (465/587), POP (995/110) to your mail servers, plus updates.",
                    "normal": "Long IMAP IDLE connections that stay open for hours.", "watch": "-"},
    "zoom": {"title": "Zoom", "what": "Zoom's video-meeting client. Joins meetings by streaming audio, video and screen shares through Zoom's servers, or peer to peer.",
             "net": "443 for control; UDP 8801–8810 for media during meetings.",
             "normal": "Heavy UDP during calls only.", "watch": "Media traffic outside meetings."},
    "systemd-resolved": {"title": "systemd-resolved (DNS resolver)",
                         "what": "The system's DNS resolver: turns names like example.com into addresses for "
                                 "every program.",
                         "net": "Sends DNS queries to the servers your network gave you (UDP/TCP 53, or 853 for "
                                "DNS-over-TLS) and answers local programs on 127.0.0.53.",
                         "normal": "Frequent short DNS lookups to one or two resolvers.",
                         "watch": "DNS to unexpected servers, or very regular lookups (DNS tunnelling)."},
    "systemd-timesyncd": {"title": "systemd-timesyncd (clock sync)",
                          "what": "Keeps the system clock correct.",
                          "net": "Asks NTP servers for the time over UDP 123 every few minutes to hours.",
                          "normal": "Small periodic UDP 123 packets: periodic by design.", "watch": "-"},
    "chronyd": {"title": "chrony (clock sync)", "what": "Keeps the system clock correct.",
                "net": "NTP over UDP 123 to a pool of time servers.", "normal": "Periodic by design.", "watch": "-"},
    "networkmanager": {"title": "NetworkManager", "what": "Manages Wi-Fi, Ethernet and VPN connections.",
                       "net": "DHCP (67/68), and a periodic connectivity check over HTTP (80) to a vendor URL to "
                              "detect captive portals.",
                       "normal": "Small periodic HTTP checks.", "watch": "-"},
    "avahi-daemon": {"title": "Avahi (mDNS / local discovery)",
                     "what": "Announces and discovers devices and services on your local network (printers, "
                             "speakers, other PCs).",
                     "net": "Multicast DNS on UDP 5353 to 224.0.0.251 / ff02::fb.",
                     "normal": "Constant small multicast chatter.", "watch": "-"},
    "cupsd": {"title": "CUPS (printing)", "what": "The print server (CUPS). Queues documents you print, converts them for the printer and sends them over USB or the network.",
              "net": "Listens on 127.0.0.1:631; may talk IPP (631) to network printers.",
              "normal": "Loopback only, unless you share printers.", "watch": "Listening on all interfaces."},
    "cups-browsed": {"title": "cups-browsed", "what": "Part of CUPS that listens for printers announced on your local network and adds them as print queues automatically.",
                     "net": "mDNS and IPP (631) on the LAN.", "normal": "LAN only.", "watch": "-"},
    "sshd": {"title": "OpenSSH server", "what": "Lets other machines log in to this one.",
             "net": "Listens on TCP 22; each login is an inbound connection.",
             "normal": "Nothing, unless you log in remotely.",
             "watch": "Inbound connections from addresses you don't know: someone is trying to log in."},
    "ssh": {"title": "OpenSSH client", "what": "Remote login / file copy from this machine.",
            "net": "Outbound TCP 22 (or a custom port) to the server you connect to; sessions can last hours.",
            "normal": "Long-lived connections you started.", "watch": "ssh started by something other than you."},
    "packagekitd": {"title": "PackageKit", "what": "Backend that checks for and installs software updates.",
                    "net": "Downloads package lists and packages from your distribution's mirrors (443/80).",
                    "normal": "Periodic update checks.", "watch": "-"},
    "snapd": {"title": "snapd", "what": "Installs and refreshes Snap packages.",
              "net": "Talks to the Snap Store (443) a few times a day.", "normal": "Periodic.", "watch": "-"},
    "fwupd": {"title": "fwupd", "what": "The firmware updater. Checks the LVFS service for firmware updates for your laptop, disks, docks and other devices, and installs them when you agree.",
              "net": "Fetches firmware metadata from LVFS (443).", "normal": "Rare.", "watch": "-"},
    "flatpak": {"title": "Flatpak", "what": "Installs and updates Flatpak apps.",
                "net": "Flathub and other remotes over 443.", "normal": "During updates.", "watch": "-"},
    "http": {"title": "APT download method", "what": "APT's helper that downloads packages.",
             "net": "HTTP/HTTPS to your distribution's mirrors.", "normal": "During updates.", "watch": "-"},
    "https": {"title": "APT download method", "what": "APT's helper that downloads packages.",
              "net": "HTTPS to your distribution's mirrors.", "normal": "During updates.", "watch": "-"},
    "dnf": {"title": "DNF", "what": "Fedora's package manager. Downloads software and updates from Fedora's mirrors and installs them, checking signatures as it goes.", "net": "Mirrors over 443/80.",
            "normal": "During updates.", "watch": "-"},
    "pacman": {"title": "pacman", "what": "Arch Linux's package manager. Downloads packages from the mirrors listed in /etc/pacman.d/mirrorlist and installs them, checking signatures.", "net": "Mirrors over 443/80.",
               "normal": "During updates.", "watch": "-"},
    "gnome-shell": {"title": "GNOME Shell", "what": "The GNOME desktop itself: draws the top bar, the overview and window switching, and runs GNOME extensions inside its own process.",
                    "net": "Weather, calendar and extension services over 443.", "normal": "Occasional.", "watch": "-"},
    "gnome-software": {"title": "GNOME Software", "what": "GNOME's app store and update tool. Looks up apps, Flatpaks and firmware, downloads updates and shows you what can be installed.",
                       "net": "App metadata and updates over 443.", "normal": "Periodic.", "watch": "-"},
    "evolution-source-registry": {"title": "Evolution data server", "what": "Calendar/contacts sync for GNOME.",
                                  "net": "Your online accounts' servers over 443.", "normal": "Periodic sync.", "watch": "-"},
    "geoclue": {"title": "GeoClue", "what": "Location service for apps that ask where you are.",
                "net": "May send nearby Wi-Fi networks to a location service over 443.",
                "normal": "Only when an app asks for location.", "watch": "-"},
    "kdeconnectd": {"title": "KDE Connect", "what": "KDE Connect's background service. Pairs your phone and PC over the local network to share notifications, files, the clipboard and media controls.",
                    "net": "LAN discovery and connections on 1714–1764.", "normal": "LAN only.", "watch": "-"},
    "syncthing": {"title": "Syncthing", "what": "A peer-to-peer file synchroniser. Copies folders directly between your own devices, encrypted, with no cloud storage in between.",
                  "net": "22000 (TCP/UDP) to your devices, 21027 for discovery, relays over 443.",
                  "normal": "Long-lived connections to your own devices.", "watch": "-"},
    "dropbox": {"title": "Dropbox", "what": "Dropbox's sync client. Watches your Dropbox folder and uploads and downloads changes to and from Dropbox's cloud storage.", "net": "443 to Dropbox; LAN sync on 17500.",
                "normal": "Long-lived 443.", "watch": "-"},
    "dockerd": {"title": "Docker daemon", "what": "The Docker daemon. Starts and manages containers, pulls images from registries and sets up the virtual networks containers use.",
                "net": "Pulls images from registries (443); containers' own traffic appears from their namespaces.",
                "normal": "During pulls.", "watch": "Published ports on all interfaces."},
    "containerd": {"title": "containerd", "what": "Container runtime used by Docker/Kubernetes.",
                   "net": "Image pulls over 443.", "normal": "During pulls.", "watch": "-"},
    "tailscaled": {"title": "Tailscale", "what": "Tailscale's VPN service. Builds an encrypted WireGuard mesh between your own devices and coordinates it through Tailscale's servers.",
                   "net": "Control plane over 443, WireGuard traffic on UDP 41641, DERP relays over 443.",
                   "normal": "Steady, small.", "watch": "-"},
    "openvpn": {"title": "OpenVPN", "what": "The OpenVPN client. Tunnels some or all of your traffic, encrypted, to a VPN server you configured.", "net": "UDP/TCP 1194 or 443 to your VPN server.",
                "normal": "One long-lived connection.", "watch": "-"},
    "curl": {"title": "curl", "what": "A command-line tool that downloads or uploads data from a URL. Scripts, installers and package hooks use it all the time; so does malware.",
             "net": "Whatever URL it was given.", "normal": "Short, started by you or a script.",
             "watch": "curl started by something you didn't run, especially piped into a shell."},
    "wget": {"title": "wget", "what": "A command-line downloader that fetches files from web or FTP servers. Common in scripts and installers, and in malware droppers.", "net": "Whatever URL it was given.",
             "normal": "Short, started by you or a script.", "watch": "Started by something you didn't run."},
    "git-remote-https": {"title": "git (HTTPS transport)", "what": "Git fetching or pushing a repository.",
                         "net": "443 to your Git host.", "normal": "Short.", "watch": "-"},
    "qbittorrent": {"title": "qBittorrent", "what": "A BitTorrent client. Downloads files in pieces from many other people and uploads the pieces you already have back to them.",
                    "net": "Many peers on many ports, DHT on UDP.", "normal": "Hundreds of connections.", "watch": "-"},
    "transmission-gtk": {"title": "Transmission", "what": "A BitTorrent client (GTK interface). Downloads files from many peers at once and uploads pieces to them in return.",
                         "net": "Many peers on many ports.", "normal": "Hundreds of connections.", "watch": "-"},
    "obs": {"title": "OBS Studio", "what": "OBS Studio: records your screen and camera and can stream them live to services such as Twitch or YouTube.", "net": "RTMP (1935) or 443 to your stream service.",
            "normal": "Only while streaming.", "watch": "-"},
    "ollama": {"title": "Ollama", "what": "Runs large language models on your own machine. Serves a local API on port 11434 and downloads models from ollama.com when asked.",
               "net": "Listens on 127.0.0.1:11434; downloads models over 443.", "normal": "Loopback.",
               "watch": "Listening on all interfaces."},
    "systemd": {"title": "systemd", "what": "The service manager that starts and supervises everything else.",
                "net": "Socket activation: it may hold listening sockets for services until they start.",
                "normal": "Listeners on behalf of other services.", "watch": "-"},
    "python": {"title": "Python interpreter", "what": "Runs a Python script; the script decides what it does.",
               "net": "Depends entirely on the script (shown in the name).",
               "normal": "Depends on the script.", "watch": "Scripts in /tmp, hidden folders, or that you don't recognise."},
    "node": {"title": "Node.js", "what": "Runs a JavaScript program; the program decides what it does.",
             "net": "Depends on the program.", "normal": "Depends on the program.",
             "watch": "Programs you don't recognise."},
    "java": {"title": "Java runtime", "what": "The Java runtime. It does nothing by itself: it runs whatever Java program (a .jar file) it was started with, so look at its command line.", "net": "Depends on the program.",
             "normal": "Depends on the program.", "watch": "-"},
    "bash": {"title": "Shell", "what": "A command shell. It runs commands typed by you or listed in a script; a shell that talks to the network directly is unusual.", "net": "Shells rarely open sockets themselves.",
             "normal": "No network.", "watch": "A shell holding a network socket can be a reverse shell."},
    "sh": {"title": "Shell", "what": "A minimal command shell, mostly used to run scripts; a shell that talks to the network directly is unusual.", "net": "Shells rarely open sockets themselves.",
           "normal": "No network.", "watch": "A shell holding a network socket can be a reverse shell."},
    "nc": {"title": "netcat", "what": "netcat: a raw networking tool that sends and receives bytes over any TCP or UDP port. Handy for testing, and a classic way to open a backdoor or reverse shell.", "net": "Arbitrary TCP/UDP.",
           "normal": "Only when you run it.", "watch": "netcat you didn't start is a classic backdoor."},
    "socat": {"title": "socat", "what": "A raw network relay that joins two data streams (sockets, files, programs). Useful for admins, and also used to build tunnels and reverse shells.", "net": "Arbitrary.", "normal": "Only when you run it.",
              "watch": "Started by something else."},
}
ALIASES = {"chromium": "chrome", "chromium-browser": "chrome", "google-chrome": "chrome", "brave": "chrome",
           "brave-browser": "chrome", "msedge": "chrome", "vivaldi-bin": "chrome", "chrome-headless-shell": "chrome",
           "discordcanary": "discord", "discordptb": "discord", "spotify-launcher": "spotify",
           "steamwebhelper": "steam", "code-oss": "code", "codium": "code", "telegram": "telegram-desktop",
           "zoom.real": "zoom", "ntpd": "chronyd", "nm-dispatcher": "networkmanager", "geoclue-2.0": "geoclue",
           "snap": "snapd", "fwupdmgr": "fwupd", "pip": "python", "ncat": "nc", "netcat": "nc", "zsh": "bash",
           "dash": "sh", "fish": "bash", "nodejs": "node", "deno": "node", "bun": "node",
           "transmission-daemon": "transmission-gtk", "systemd-resolve": "systemd-resolved"}

# (protocol or "*", port) -> (service, what it is for). Ranges are listed at the end.
PORTS = {
    ("tcp", 20): ("FTP data", "file transfer (unencrypted)"),
    ("tcp", 21): ("FTP", "file transfer control (unencrypted)"),
    ("tcp", 22): ("SSH", "encrypted remote login and file copy"),
    ("tcp", 23): ("Telnet", "unencrypted remote login: rarely legitimate today"),
    ("tcp", 25): ("SMTP", "mail delivery between servers"),
    ("*", 53): ("DNS", "turning names into addresses"),
    ("udp", 67): ("DHCP", "getting an address from your router"),
    ("udp", 68): ("DHCP", "getting an address from your router"),
    ("tcp", 80): ("HTTP", "unencrypted web traffic"),
    ("tcp", 110): ("POP3", "fetching mail (unencrypted)"),
    ("udp", 123): ("NTP", "clock synchronisation"),
    ("tcp", 143): ("IMAP", "reading mail (unencrypted)"),
    ("tcp", 443): ("HTTPS", "encrypted web and app traffic; most of the internet"),
    ("udp", 443): ("HTTP/3 (QUIC)", "encrypted web traffic over UDP"),
    ("tcp", 445): ("SMB", "Windows file sharing"),
    ("tcp", 465): ("SMTPS", "sending mail (encrypted)"),
    ("tcp", 587): ("Submission", "sending mail"),
    ("tcp", 631): ("IPP", "printing"),
    ("tcp", 853): ("DNS over TLS", "encrypted DNS"),
    ("tcp", 993): ("IMAPS", "reading mail (encrypted)"),
    ("tcp", 995): ("POP3S", "fetching mail (encrypted)"),
    ("*", 1194): ("OpenVPN", "VPN tunnel"),
    ("udp", 1900): ("SSDP", "local device discovery (UPnP)"),
    ("tcp", 1935): ("RTMP", "live-stream upload"),
    ("tcp", 3306): ("MySQL", "database"),
    ("tcp", 3389): ("RDP", "Windows remote desktop"),
    ("*", 3478): ("STUN/TURN", "helping calls get through NAT"),
    ("tcp", 4444): ("4444", "no standard service; the default port of several hacking tools "
                            "(e.g. Metasploit listeners)"),
    ("tcp", 5222): ("XMPP", "chat"),
    ("tcp", 5228): ("Google push", "Android/Chrome notifications"),
    ("udp", 5353): ("mDNS", "local network discovery"),
    ("udp", 5355): ("LLMNR", "local name lookup"),
    ("tcp", 5432): ("PostgreSQL", "database"),
    ("tcp", 5900): ("VNC", "remote desktop"),
    ("tcp", 8080): ("HTTP alt", "web traffic on an alternate port (proxies, dev servers)"),
    ("tcp", 8443): ("HTTPS alt", "encrypted web traffic on an alternate port"),
    ("tcp", 9001): ("Tor", "Tor relay traffic"),
    ("tcp", 9050): ("Tor SOCKS", "local Tor proxy"),
    ("udp", 19302): ("Google STUN", "call connectivity (Meet, WebRTC)"),
    ("tcp", 22000): ("Syncthing", "file sync"),
    ("udp", 41641): ("Tailscale", "WireGuard mesh VPN"),
    ("udp", 51820): ("WireGuard", "VPN tunnel"),
}
PORT_RANGES = [
    ("tcp", 6881, 6999, "BitTorrent", "peer-to-peer file sharing"),
    ("*", 27015, 27050, "Steam", "games and Steam services"),
    ("udp", 50000, 65535, "Discord voice / dynamic", "Discord voice and video, or a temporary port"),
    ("tcp", 32768, 60999, "ephemeral", "a temporary port picked by the operating system"),
]


def _norm(name):
    name = os.path.basename(name or "").lower()
    name = re.sub(r"\.(bin|real|exe|appimage)$", "", name)
    return re.sub(r"[-_]?\d+(\.\d+)*$", "", name)


def lookup_program(exe=None, name=None, key=None):
    """Catalog entry for a program, by executable path, display name or program key."""
    candidates = []
    if key and " " in key:  # interpreters: "python3 /path/script.py"
        candidates.append(key.split(" ", 1)[0])
    candidates += [exe or "", name or "", (key or "").split(" ", 1)[0]]
    for c in candidates:
        n = _norm(c)
        n = ALIASES.get(n, n)
        if n in PROGRAMS:
            return dict(PROGRAMS[n], id=n)
    return None


def port_info(proto, port):
    for k in ((proto, port), ("*", port)):
        if k in PORTS:
            return {"service": PORTS[k][0], "what": PORTS[k][1]}
    for p, lo, hi, svc, what in PORT_RANGES:
        if p in (proto, "*") and lo <= port <= hi:
            return {"service": svc, "what": what}
    return None


# ---- where did the executable come from? ------------------------------------------------

def package_owner(path):
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
    return _owner_cached(path)


@functools.lru_cache(maxsize=512)
def _owner_cached(path):
    for info in glob.glob("/var/lib/dpkg/info/*.list"):  # Debian, Ubuntu, Mint, …
        try:
            with open(info, "rb") as fh:
                if f"\n{path}\n".encode() in b"\n" + fh.read() + b"\n":
                    return {"how": "a Debian package (dpkg)", "package": os.path.basename(info)[:-5].split(":")[0]}
        except OSError:
            continue
    rel = path.lstrip("/")
    for files in glob.glob("/var/lib/pacman/local/*/files"):  # Arch, Manjaro, …
        try:
            with open(files, encoding="utf-8", errors="replace") as fh:
                if f"\n{rel}\n" in "\n" + fh.read() + "\n":
                    return {"how": "an Arch package (pacman)", "package": os.path.basename(os.path.dirname(files))}
        except OSError:
            continue
    if shutil.which("rpm"):  # Fedora, openSUSE, …
        try:
            r = subprocess.run(["rpm", "-qf", "--queryformat", "%{NAME}-%{VERSION}", path],
                               capture_output=True, text=True, timeout=3)
            if r.returncode == 0 and r.stdout.strip():
                return {"how": "an RPM package", "package": r.stdout.strip()}
        except (OSError, subprocess.TimeoutExpired):
            pass
    if glob.glob("/var/lib/dpkg/info/*.list") or glob.glob("/var/lib/pacman/local/*") or shutil.which("rpm"):
        return {"how": None, "package": None}  # a package database exists and does not list it
    return None  # no package database we can read


# ---- plain-language summaries ----------------------------------------------------------------

def ago(seconds):
    seconds = max(0, int(seconds))
    for unit, n in (("day", 86400), ("hour", 3600), ("minute", 60)):
        if seconds >= n:
            v = seconds // n
            return f"{v} {unit}{'s' if v != 1 else ''}"
    return f"{seconds} second{'s' if seconds != 1 else ''}"


def about_program(d, enricher=None, now=None):
    """Sentences that say what this program is, where it came from and what it is doing."""
    now = now or time.time()
    info = d.get("info") or {}
    out = {"facts": [], "knowledge": None, "provenance": None, "ports": []}
    if d.get("hidden"):
        out["facts"].append(info.get("explanation", ""))
        return out
    k = lookup_program(info.get("exe"), d.get("name"), d.get("key"))
    out["knowledge"] = k
    chain = [a["name"] for a in reversed(info.get("ancestry") or [])]
    who = f"{d['name']} (pid {info.get('pid')}) runs as {info.get('user', '?')}"
    if info.get("started"):
        who += f", started {ago(now - info['started'])} ago"
    if chain:
        who += f" by {chain[-1]}" + (f" (under {' › '.join(chain[:-1][-3:])})" if len(chain) > 1 else "")
    out["facts"].append(who + ".")
    exe = info.get("exe")
    if exe:
        owner = package_owner(exe)
        if owner and owner["package"]:
            out["provenance"] = f"Its executable {exe.removesuffix(' (deleted)')} is part of {owner['how']} " \
                                f"“{owner['package']}”: installed through your package manager."
        elif owner and owner["how"]:
            out["provenance"] = f"Its executable {exe} comes from {owner['how']}."
        elif owner:
            out["provenance"] = (f"Its executable {exe} is not part of any installed package: it was installed "
                                 f"by hand, by an app's own installer, or dropped there by something else.")
        if info.get("exe_deleted"):
            out["facts"].append("Its executable file has been deleted or replaced since it started "
                                "(normal right after an update; restart it to run the new version).")
    pairs = d.get("pairs") or []
    if pairs:
        ips = {p["ip"] for p in pairs}
        by_port = {}
        for p in pairs:
            by_port[(p["proto"], p["port"], p["direction"])] = by_port.get((p["proto"], p["port"], p["direction"]), 0) + p["connections"]
        top = sorted(by_port.items(), key=lambda kv: -kv[1])[:4]
        words = []
        for (proto, port, direction), n in top:
            pi = port_info(proto, port)
            label = f"{pi['service']} ({proto}/{port})" if pi else f"{proto}/{port}"
            words.append(f"{label}{' inbound' if direction == 'in' else ''}: {n} connection{'s' if n != 1 else ''}")
            if pi:
                out["ports"].append({"proto": proto, "port": port, **pi})
        owners = []
        if enricher:
            seen = set()
            for p in pairs[:40]:
                lab = enricher.label(p["ip"])
                if lab and lab not in seen:
                    seen.add(lab)
                    owners.append(lab)
        out["facts"].append(f"Vigil has seen it talk to {len(ips)} address{'es' if len(ips) != 1 else ''}: "
                            + "; ".join(words) + "."
                            + (f" Mostly to {', '.join(owners[:3])}." if owners else ""))
    else:
        out["facts"].append("It holds a socket but Vigil has not seen it connect anywhere yet.")
    top_findings = [f for sc in (d.get("findings") or []) if not sc.get("allowlisted")
                    for f in sc["findings"]]
    if top_findings:
        best = max(d["findings"], key=lambda s: s["score"])
        reasons = sorted(best["findings"], key=lambda f: -f["points"])[:3]
        out["facts"].append(f"Why its score is {math.floor(best['score'] + 0.5)}: "
                            + "; ".join(r["reason"].rstrip(".") for r in reasons) + ".")
    return out


def about_destination(d, enricher=None):
    out = {"facts": [], "ports": []}
    scope = d.get("scope")
    where = {"internet": "on the public internet", "lan": "on your local network",
             "loopback": "this machine itself", "link-local": "a link-local address on your network",
             "multicast": "a multicast group (one-to-many local traffic)",
             "reserved": "in a reserved range that should not appear on the internet"}.get(scope, scope)
    s = f"{d['ip']} is {where}"
    en = d.get("enrichment") or {}
    g = en.get("geo")
    if g:
        s += f", in AS{g['asn']} ({g['owner']})" + (f", {g['country_name']}" if g.get("country") else "")
    out["facts"].append(s + ".")
    pairs = d.get("pairs") or []
    if pairs:
        progs = {}
        for p in pairs:
            progs.setdefault(p["name"], set()).add((p["proto"], p["port"]))
        parts = []
        for name, ports in list(progs.items())[:4]:
            labels = []
            for proto, port in sorted(ports)[:3]:
                pi = port_info(proto, port)
                labels.append(f"{pi['service']} {port}" if pi else f"{proto}/{port}")
                if pi and {"proto": proto, "port": port, **pi} not in out["ports"]:
                    out["ports"].append({"proto": proto, "port": port, **pi})
            parts.append(f"{name} over {', '.join(labels)}")
        out["facts"].append("Used by " + "; ".join(parts) + ".")
    for h in en.get("intel") or []:
        out["facts"].append(f"{h['title']} lists it: {h['label']}.")
    return out
