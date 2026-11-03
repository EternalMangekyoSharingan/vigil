"""Suite-wide wording rules: how every Vigil tool talks to the user.

Titles are plain English, at most 60 characters, with no statistics or jargon. The
numbers behind them belong in a finding's collapsed technical details. Every tool builds
its titles with fit_title() and is held to these rules by tests (tests/core).

Only text is built here; nothing is run.
"""

import ipaddress
import re
import time

TITLE_MAX = 60
BANNED = ("coefficient", "variation", "cv", "±", "poll", "polls", "check-ins", "stdev", "%")

# Everyday names for common programs (by executable basename).
FRIENDLY = {
    "librewolf": "LibreWolf", "firefox": "Firefox", "firefox-bin": "Firefox", "firefox-esr": "Firefox",
    "chromium": "Chromium", "chrome": "Chrome", "google-chrome": "Chrome", "brave": "Brave",
    "floorp": "Floorp", "zen": "Zen", "zen-bin": "Zen", "vivaldi-bin": "Vivaldi", "msedge": "Edge",
    "syncthing": "Syncthing", "networkmanager": "NetworkManager", "systemd-resolved": "systemd-resolved",
    "systemd-timesyncd": "Time sync", "chronyd": "chrony", "discord": "Discord", "steam": "Steam",
    "spotify": "Spotify", "code": "VS Code", "codium": "VSCodium", "slack": "Slack", "signal-desktop": "Signal",
    "telegram-desktop": "Telegram", "thunderbird": "Thunderbird", "dropbox": "Dropbox", "ssh": "SSH",
    "sshd": "SSH server", "packagekitd": "PackageKit", "flatpak": "Flatpak", "pacman": "pacman",
    "dnf": "dnf", "zypper": "zypper", "apt": "apt", "gnome-software": "GNOME Software",
    "plasma-discover": "Discover", "fwupd": "fwupd", "tailscaled": "Tailscale", "ollama": "Ollama",
    "qbittorrent": "qBittorrent", "transmission-gtk": "Transmission", "obs": "OBS",
}
OWNERS = [("amazon", "Amazon AWS"), ("google", "Google"), ("cloudflare", "Cloudflare"), ("fastly", "Fastly"),
          ("microsoft", "Microsoft"), ("akamai", "Akamai"), ("hetzner", "Hetzner"), ("digitalocean", "DigitalOcean"),
          ("ovh", "OVH"), ("linode", "Linode"), ("facebook", "Meta"), ("apple", "Apple"), ("valve", "Valve"),
          ("github", "GitHub"), ("oracle", "Oracle"), ("mozilla", "Mozilla"), ("anthropic", "Anthropic"),
          ("vultr", "Vultr"), ("scaleway", "Scaleway"), ("contabo", "Contabo")]

# Words that make a title harder to read for a non-specialist. A title is the one line
# everybody reads, so the rule is strict there; the explanation can say more.
JARGON = ("ioc", "ttp", "heuristic", "entropy", "regex", "payload", "exfil", "c2 ", "edr", "stdout")
SENTENCE_WORDS = 20      # longest sentence in an explanation line


def fit_title(candidates, limit=TITLE_MAX):
    """The first candidate that fits in `limit` characters and breaks no title rule; else
    the first that fits; else the last one, cut with '…'.

    Candidates often carry names an attacker controls (a process called "payload", a
    file called "50%"), so a rule-breaking candidate is skipped rather than shown, and
    callers end their list with a generic candidate that has no name in it."""
    candidates = [c for c in candidates if c]
    for c in candidates:
        if len(c) <= limit and not title_problems(c):
            return c
    for c in candidates:
        if len(c) <= limit:
            return c
    c = candidates[-1]
    return c[:limit - 1].rstrip() + "…"


def title_problems(title):
    """Why a title breaks the suite's rules ([] when it is fine)."""
    out = []
    if not title or not title.strip():
        return ["empty"]
    if len(title) > TITLE_MAX:
        out.append(f"longer than {TITLE_MAX} characters")
    low = f" {title.lower()} "
    for w in BANNED:
        if (w in low) if not w.isalpha() else re.search(rf"\b{re.escape(w)}\b", low):
            out.append(f"uses '{w}'")
    for w in JARGON:
        if w.strip() and re.search(rf"\b{re.escape(w.strip())}\b", low):
            out.append(f"jargon '{w.strip()}'")
    for tok in re.findall(r"[0-9A-Fa-f:]*:[0-9A-Fa-f:]*:[0-9A-Fa-f:.]*", title):
        try:
            ipaddress.IPv6Address(tok.strip(".:") if not tok.startswith("::") else tok.rstrip("."))
            out.append("contains a raw IPv6 address")
            break
        except ValueError:
            continue
    if title.rstrip().endswith("."):
        out.append("ends with a full stop")
    return out


def one_sentence(text):
    """True when `text` is a single sentence that ends with a full stop (or ? or !)."""
    t = (text or "").strip()
    if not t or t[-1] not in ".?!":
        return False
    inner = re.sub(r"\b(e\.g|i\.e|etc|vs|approx|no)\.", "", t[:-1])
    inner = re.sub(r"\d\.\d", "", inner)                      # 1.5 GB
    inner = re.sub(r"[\w./-]+\.[A-Za-z0-9]{1,5}\b", "", inner)  # file names, domains
    return not re.search(r"[.?!]\s+[A-Z]", inner)


def word_count(text):
    return len((text or "").split())


# ---- small helpers ----------------------------------------------------------------------

def every(seconds):
    """'every ~7 min' — rounded the way a person would say it."""
    if seconds < 55:
        return f"every ~{max(5, round(seconds / 5) * 5)} s"
    if seconds < 90:
        return "every ~1 min"
    if seconds < 3300:
        return f"every ~{round(seconds / 60)} min"
    h = seconds / 3600
    return f"every ~{round(h)} h" if h >= 1.5 else "every hour"


def span(seconds, short=False):
    """'7 h 42 min', '11 hours', '40 min'."""
    seconds = int(seconds)
    if seconds < 90:
        return f"{seconds} s"
    if seconds < 3600:
        return f"{round(seconds / 60)} min"
    h, m = divmod(seconds // 60, 60)
    if short or h >= 10:
        return f"{h + (1 if m >= 30 and short else 0)} hours" if h != 1 else "1 hour"
    return f"{h} h {m} min" if m else f"{h} h"


def clock(ts, now=None):
    """'03:34' today, 'Oct 30, 21:42' otherwise."""
    now = now or time.time()
    lt = time.localtime(ts)
    if time.strftime("%Y-%m-%d", lt) == time.strftime("%Y-%m-%d", time.localtime(now)):
        return time.strftime("%H:%M", lt)
    return time.strftime("%b %d, %H:%M", lt).replace(" 0", " ")


def kb(n):
    if n >= 1e6:
        return f"~{n / 1e6:.1f} MB"
    if n >= 1e3:
        return f"~{round(n / 1e3)} kB"
    return f"~{round(n)} bytes"


def friendly_program(exe=None, key=None, name=None):
    """A program's everyday name: 'LibreWolf', a script's own name, else its basename."""
    key = key or ""
    exe = (exe or key.split(" ", 1)[0]).removesuffix(" (deleted)")
    base = exe.rsplit("/", 1)[-1]
    if " " in key and re.match(r"^(python|perl|ruby|node|bash|sh|java)", base):
        script = key.split(" ", 1)[1].split(" ")[0].rsplit("/", 1)[-1]
        if script:
            return script
    return FRIENDLY.get(base.lower(), name or base or "A program")


def owner_name(owner):
    if not owner:
        return None
    low = owner.lower()
    for k, v in OWNERS:
        if k in low:
            return v
    word = re.split(r"[\s,]", owner.strip())[0]
    word = re.sub(r"(-?AS\d*|-?ASN|-NET|NET|-\d+)$", "", word, flags=re.I).strip("-_ ")
    return word.title() if word.isupper() or word.islower() else word or None


def short_host(host):
    host = host.lstrip("*.").lower()
    if host.startswith("www."):
        host = host[4:]
    parts = host.split(".")
    if len(host) > 26 and len(parts) > 2:
        host = ".".join(parts[-2:])
    return host
