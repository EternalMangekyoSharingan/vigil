"""Look-alike package names, and names known to have carried malware.

The July 2025 AUR malware (librewolf-fix-bin, firefox-patch-bin, zen-browser-patched-bin)
copied popular names and added "fix" or "patched". This module flags that pattern and
plain typos of popular names. It is a static list on purpose: no network needed.
"""

import re

# Popular desktop packages (official repos and the most-used AUR names), the ones a
# squatter would copy. Base names without -bin/-git suffixes.
POPULAR = sorted(set("""
firefox librewolf zen-browser floorp waterfox chromium ungoogled-chromium google-chrome brave vivaldi
opera microsoft-edge tor-browser mullvad-browser thunderbird betterbird discord vesktop webcord
spotify spotify-launcher steam lutris heroic-games-launcher bottles wine proton protonup-qt
visual-studio-code code vscodium cursor zed sublime-text jetbrains-toolbox intellij-idea pycharm
android-studio telegram-desktop signal-desktop slack-desktop zoom teams element-desktop whatsapp
obs-studio vlc mpv kdenlive gimp inkscape krita blender darktable audacity handbrake libreoffice
onlyoffice obsidian notion logseq joplin keepassxc bitwarden 1password protonvpn mullvad-vpn
nordvpn expressvpn tailscale syncthing nextcloud-client dropbox megasync timeshift yay paru
pamac pikaur octopi nvidia nvidia-dkms nvidia-utils linux linux-zen linux-lts mesa ventoy
balena-etcher virtualbox vmware-workstation docker docker-desktop podman-desktop github-desktop
github-cli postman insomnia anydesk teamviewer rustdesk parsec minecraft-launcher prismlauncher
osu-lazer qbittorrent transmission deluge ttf-ms-fonts noto-fonts google-earth-pro davinci-resolve
""".split()))

SUFFIXES = ("-bin", "-git", "-appimage", "-nightly", "-beta", "-stable", "-wayland", "-dev", "-latest", "-esr")
# Words squatters add, with how strongly each one suggests a trick (0..1).
BAIT = {"fix": 0.9, "fixed": 0.9, "patch": 0.85, "patched": 0.9, "cracked": 1.0, "crack": 1.0,
        "keygen": 1.0, "hack": 0.9, "hacked": 0.9, "unlocked": 0.9, "premium": 0.8, "pro": 0.5,
        "full": 0.4, "free": 0.6, "all": 0.4, "plus": 0.4, "mod": 0.5, "modded": 0.7, "updated": 0.6,
        "new": 0.4, "working": 0.8, "nocheck": 0.6, "official": 0.7, "secure": 0.5}

# Package names removed from the AUR for carrying malware, with what is known.
KNOWN_MALICIOUS = {
    "librewolf-fix-bin": "removed from the AUR in July 2025: it installed the CHAOS remote access trojan",
    "firefox-patch-bin": "removed from the AUR in July 2025: it installed the CHAOS remote access trojan",
    "zen-browser-patched-bin": "removed from the AUR in July 2025: it installed the CHAOS remote access trojan",
    "acroread": "an orphaned package adopted by an attacker in June 2018 and made malicious",
    "balz": "an orphaned package adopted by an attacker in June 2018 and made malicious",
    "minergate": "an orphaned package adopted by an attacker in June 2018 and made malicious",
}

# Packages named in reporting on the July 2026 takeover wave: real projects whose AUR
# packages were adopted or taken over and pushed a malicious commit for a few days. The
# name is not bad in itself; installing or updating it during the window is the risk.
# (Reported by BleepingComputer, SC Media and others; Arch had not published a full list.)
HIJACKED = {
    "openconnect-sso": "2026-07", "boringssl-git": "2026-07", "icloudpd": "2026-07",
    "windscribe-cli-v2-bin": "2026-07", "stirling-pdf-desktop-bin": "2026-07",
    "arduino-language-server-noclang-bin": "2026-07", "pgadmin4-server": "2026-07",
}
# Known AUR malware windows (UTC dates, inclusive). Approximate where reporting differs.
INCIDENTS = [
    {"id": "2025-07", "start": "2025-07-16", "end": "2025-07-18",
     "what": "browser packages carrying the CHAOS remote access trojan (librewolf-fix-bin and others)"},
    {"id": "2026-06", "start": "2026-06-08", "end": "2026-06-20",
     "what": "the June 2026 AUR malware wave (hundreds of packages; dates approximate)"},
    {"id": "2026-07", "start": "2026-07-29", "end": "2026-08-02",
     "what": "the July 2026 package-takeover wave (adopted packages pushing an infostealer)"},
]


def base(name):
    n = name.lower()
    changed = True
    while changed:
        changed = False
        for s in SUFFIXES:
            if n.endswith(s) and len(n) > len(s):
                n = n[: -len(s)]
                changed = True
    return n


def distance(a, b, cap=3):
    """Damerau-Levenshtein (optimal string alignment) distance, stopping early past `cap`."""
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    prev2, prev = None, list(range(len(b) + 1))
    for i in range(1, len(a) + 1):
        cur = [i] + [0] * len(b)
        for j in range(1, len(b) + 1):
            cost = a[i - 1] != b[j - 1]
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if prev2 is not None and i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        prev2, prev = prev, cur
    return prev[-1]


def check(name):
    """What is suspicious about a package name: a dict, or None.

    {"kind": "known"|"bait"|"typo", "like": popular name, "word": bait word, "strength"}
    """
    low = name.lower()
    if low in KNOWN_MALICIOUS:
        return {"kind": "known", "like": None, "word": None, "strength": 1.0, "why": KNOWN_MALICIOUS[low]}
    b = base(low)
    if b in POPULAR:
        return None
    parts = re.split(r"[-_.]", b)
    for pop in sorted(POPULAR, key=len, reverse=True):
        pp = pop.split("-")
        for i in range(len(parts) - len(pp) + 1):
            if parts[i:i + len(pp)] == pp:
                extra = parts[:i] + parts[i + len(pp):]
                hits = [w for w in extra if w in BAIT]
                if hits:
                    w = max(hits, key=BAIT.get)
                    return {"kind": "bait", "like": pop, "word": w, "strength": BAIT[w]}
                break
    if len(b) >= 5:
        for pop in POPULAR:
            if len(pop) >= 5 and pop[0] == b[0] or (len(pop) >= 5 and pop[-1] == b[-1]):
                if distance(b, pop, 1) == 1:
                    return {"kind": "typo", "like": pop, "word": None, "strength": 0.7}
    return None
