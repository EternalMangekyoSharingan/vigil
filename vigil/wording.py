"""Everything an alert says to the user: its title, subtitle and explanation.

Titles follow one pattern: [who] [does what] [to whom] [how often], plain English, at
most 60 characters, with no statistics or jargon. The numbers behind them are kept, in
the explanation's collapsed "Technical details".

Input is a context dict built by the server:
  program, name, hidden (reason or None), info, ip, port, proto, direction, score,
  findings, first_raised, hosts (names from Identify), geo, scope, service (catalogue
  match or None), poll (seconds between polls).
"""

import ipaddress
import re
import time

from . import commands

TITLE_MAX = 60
BANNED = ("coefficient", "variation", "cv", "±", "poll", "polls", "check-ins", "stdev", "%")

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
UNKNOWN_WHO = "An unidentified program"
HIDDEN_WHY = {
    "closed": "the connection closed before Vigil could see which program owned it",
    "other-user": "it runs as another user (often root), whose programs a normal user cannot see",
    "protected": "the system protects that process from being inspected",
    "unknown": "no visible process held the connection",
}
# Points each signal can reach (scoring.POINTS), for the strength bars.
MAX_POINTS = {"timer": 45, "duration": 10, "same_size": 10, "long": 30, "new_destination": 15,
              "new_program": 20, "rare": 5, "odd_port": 10, "temp_dir": 25, "hidden_dir": 10,
              "deleted_exe": 10, "threat": 100, "new_country": 10}


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


def friendly_name(ctx):
    """The program's everyday name, or None when Vigil cannot tell which program it is."""
    if ctx.get("hidden"):
        return None
    key = ctx.get("program") or ""
    exe = ((ctx.get("info") or {}).get("exe") or key.split(" ", 1)[0]).removesuffix(" (deleted)")
    base = exe.rsplit("/", 1)[-1]
    if " " in key and re.match(r"^(python|perl|ruby|node|bash|sh|java)", base):
        script = key.split(" ", 1)[1].split(" ")[0].rsplit("/", 1)[-1]
        if script:
            return script
    return FRIENDLY.get(base.lower(), ctx.get("name") or base or "A program")


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


def destination(ctx, with_country=True):
    """To whom: a domain, else network owner and country, else a short address; never a raw IPv6."""
    hosts = [h for h in ctx.get("hosts") or [] if not h.startswith("*") or len(h) > 2]
    if hosts:
        return short_host(sorted(hosts, key=lambda h: (h.startswith("*"), len(h)))[0])
    geo = ctx.get("geo") or {}
    own = owner_name(geo.get("owner"))
    if own:
        return f"{own} ({geo['country']})" if with_country and geo.get("country") else own
    ip = ctx.get("ip") or ""
    scope = ctx.get("scope")
    if scope == "loopback":
        return "this PC"
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return "a server"
    if scope == "lan" or a.is_private:
        return "a device on your network" if a.version == 6 else f"{ip} on your network"
    return ip if a.version == 4 else "an IPv6 server"


def _signals(ctx):
    return {(f.get("stats") or {}).get("signal"): f for f in ctx.get("findings") or []
            if (f.get("stats") or {}).get("signal")}


def plain_http(ctx):
    return ctx.get("proto") == "tcp" and ctx.get("port") in (80, 8080) and ctx.get("direction") == "out"


# ---- titles --------------------------------------------------------------------------------

def title(ctx):
    who = friendly_name(ctx)
    sig = _signals(ctx)
    interval = (sig.get("timer") or {}).get("stats", {}).get("interval")
    freq = every(interval) if interval else None
    candidates = []
    for w in ([who] if who else [UNKNOWN_WHO, "Unidentified program"]):
        for to in (destination(ctx), destination(ctx, with_country=False)):
            candidates += _phrasings(w, to, freq, sig, ctx)
    for c in candidates:
        if len(c) <= TITLE_MAX:
            return c
    c = candidates[-1]
    return c[:TITLE_MAX - 1].rstrip() + "…"


def _phrasings(who, to, freq, sig, ctx):
    out = []
    if "threat" in sig:
        out += [f"{who} contacts a known malicious server, {to}", f"{who} contacts a listed server, {to}",
                f"{who} contacts a known malicious server"]
    if ctx.get("direction") == "in":
        out += [f"{to} connects in to {who}" + (f" {freq}" if freq else ""), f"{who} accepts connections from {to}"]
    if freq and plain_http(ctx):
        out += [f"{who} sends plain HTTP to {to} {freq}", f"{who} sends plain HTTP {freq}"]
    if freq:
        out += [f"{who} checks in with {to} {freq}", f"{who} checks in {freq}"]
    if "long" in sig:
        d = span(sig["long"]["stats"]["duration"], short=True)
        out += [f"{who} keeps a connection to {to} open for {d}", f"{who} keeps a connection open for {d}"]
    if "temp_dir" in sig:
        out += [f"A program in a temp folder contacts {to}", f"{who} runs from a temp folder"]
    if "new_program" in sig:
        out += [f"{who} went online for the first time, to {to}", f"{who} went online for the first time"]
    if "new_destination" in sig:
        out += [f"{who} contacted {to} for the first time", f"{who} contacted a new server"]
    out += [f"{who} talks to {to}", f"{who} talks to a server"]
    return out


def severity(ctx):
    sig = _signals(ctx)
    svc = ctx.get("service")
    if "threat" in sig:
        return "High"
    if svc and svc["confidence"] in ("High", "Medium"):
        return "Low"
    return "High" if ctx.get("score", 0) >= 90 else "Medium"


def adjusted_score(ctx):
    """The score after a known-service match: lowered, never hidden."""
    svc = ctx.get("service")
    cut = {"High": 40, "Medium": 25, "Low": 10}.get((svc or {}).get("confidence"), 0)
    if "threat" in _signals(ctx):
        cut = 0
    return max(0.0, round(ctx.get("score", 0) - cut, 1))


def subtitle(ctx, now=None):
    parts = [severity(ctx), f"first seen {clock(ctx['first_raised'], now)}"]
    svc = ctx.get("service")
    if svc:
        parts.append(f"probably {svc['name']}")
    return " · ".join(parts)


# ---- the explanation -----------------------------------------------------------------------

WHY = {
    "timer": "Updaters, sync tools and chat apps do this. So does malware checking in with its owner. "
             "A timer alone is never enough to raise an alert.",
    "long": "Chat apps, sync tools and VPNs keep connections open for hours. So do remote-control tools.",
    "new": "Most new things are harmless: a new app or a new website. But almost everything bad is new too.",
    "rare": "Popular servers are shared by many programs. One only this program uses is worth a look.",
    "odd_port": "Most software uses a few well-known ports. Odd ones are often games or file sharing, sometimes backdoors.",
    "location": "Installed software lives in /usr or /opt. Temporary and hidden folders are where downloaded payloads hide.",
    "threat": "A public blocklist has seen this server used for malware. This is the strongest signal Vigil has.",
    "plain_http": "Anyone between you and the server can read or change unencrypted traffic. "
                  "Some background checks still use it on purpose, because they carry nothing private.",
    "unattributed": "Vigil reads the system every couple of seconds as your user. Very short connections, "
                    "or ones owned by root, can come and go before Vigil sees their owner.",
    "country": "A first connection to a new country is usually a new website or CDN. Rarely, it is the first sign of trouble.",
}
WHY_GROUP = {"timer": "timer", "duration": "timer", "same_size": "timer", "long": "long",
             "new_destination": "new", "new_program": "new", "rare": "rare", "odd_port": "odd_port",
             "temp_dir": "location", "hidden_dir": "location", "deleted_exe": "location",
             "threat": "threat", "new_country": "country"}


def signal_line(sig, st, ctx):
    if sig == "timer":
        reg = "very regular" if st["cv"] < 0.1 else "regular" if st["cv"] < 0.2 else "fairly regular"
        return f"Contacts it on a steady timer ({every(st['interval']).replace('every ~', 'about every ')}, {reg})"
    if sig == "duration":
        return f"Has kept this up for {span(st['span'])}"
    if sig == "same_size":
        return f"Sends about the same amount each time ({kb(st['mean'])})"
    if sig == "long":
        return f"Has kept one connection open for {span(st['duration'])}" + (" or more" if st.get("at_least") else "")
    if sig == "new_destination":
        return "First time this PC has talked to this server since Vigil started watching"
    if sig == "new_program":
        return "First time this program used the network since Vigil started watching"
    if sig == "rare":
        return "No other program on this PC talks to this server"
    if sig == "odd_port":
        return f"Uses port {st['port']}, which no common service uses"
    if sig == "temp_dir":
        return f"Runs from a temporary folder ({st['path']}), where downloads land"
    if sig == "hidden_dir":
        return f"Runs from a hidden folder ({st['path']})"
    if sig == "deleted_exe":
        return "Its program file was deleted or replaced while it ran"
    if sig == "threat":
        return f"{st['feed']} lists this server as {st['label']}"
    if sig == "new_country":
        return f"First connection from this PC to a server in {st['name']}"
    return None


def summary(ctx, now=None):
    who = friendly_name(ctx) or "A program Vigil could not identify"
    to = destination(ctx)
    sig = _signals(ctx)
    if "threat" in sig:
        st = sig["threat"]["stats"]
        return f"{who} connected to {to}, which {st['feed']} lists as {st['label']}."
    if "timer" in sig:
        st = sig["timer"]["stats"]
        how = "over plain HTTP " if plain_http(ctx) else ""
        return (f"{who} has contacted {to} {how}about "
                f"{every(st['interval']).replace('every ~', 'every ')} since {clock(st['first'], now)}.")
    if "long" in sig:
        return f"{who} has kept one connection to {to} open for {span(sig['long']['stats']['duration'])}."
    if "temp_dir" in sig:
        return f"{who} runs from a temporary folder and talks to {to}."
    return f"{who} talks to {to} in a way Vigil found unusual."


def explain(ctx, now=None):
    sig = _signals(ctx)
    lines, groups, technical = [], [], []
    for f in sorted(ctx.get("findings") or [], key=lambda f: -f["points"]):
        st = f.get("stats") or {}
        kind = st.get("signal")
        text = signal_line(kind, st, ctx) if kind else None
        strength = min(1.0, f["points"] / MAX_POINTS.get(kind, 50)) if f["points"] > 0 else 0
        if text:
            lines.append({"signal": kind, "text": text, "strength": round(strength, 2)})
            g = WHY_GROUP.get(kind)
            if g and g not in groups:
                groups.append(g)
        elif f["points"] > 0:  # an older finding without stats: keep its own words
            lines.append({"signal": f["check"], "text": f["reason"].split(" (")[0], "strength": round(min(1, f["points"] / 50), 2)})
        technical.append({"label": f["reason"], "value": f.get("data", ""), "stats": st, "points": f["points"]})
    if plain_http(ctx):
        lines.append({"signal": "plain_http", "text": "Uses unencrypted HTTP, so anyone on the network path can read it",
                      "strength": 0.5})
        groups.append("plain_http")
    if ctx.get("hidden"):
        lines.append({"signal": "unattributed",
                      "text": "Vigil could not see which program this is: " + HIDDEN_WHY.get(ctx["hidden"], HIDDEN_WHY["unknown"]),
                      "strength": 0.3})
        groups.append("unattributed")
    svc = ctx.get("service")
    likely = None
    if svc:
        likely = {"id": svc["id"], "name": svc["name"], "confidence": svc["confidence"], "matched": svc["matched"],
                  "what": svc["what"], "why_fine": svc["why_fine"], "privacy": svc["privacy"]}
    if "threat" in sig:
        sure = ("High", "A threat feed lists this server; that is strong evidence on its own.")
    elif svc and svc["confidence"] in ("High", "Medium"):
        sure = ("Low", f"It matches {svc['name']} ({svc['matched']}), which is normal background traffic.")
    elif "temp_dir" in sig and ("timer" in sig or "new_program" in sig):
        sure = ("High", "A program running from a temporary folder that phones home is a classic malware pattern.")
    elif len([s for s in sig if s not in ("duration", "same_size")]) >= 3:
        sure = ("Medium", "Several separate signals point the same way, but none of them is conclusive.")
    else:
        sure = ("Low", "Only common patterns, each with innocent explanations.")
    if "threat" in sig:
        nxt = ["Block the address first: Fix tab → Block this one address.", "Then use Check it to find which program and package this is."]
    elif svc:
        nxt = ["If the likely explanation fits, press Allowlist and write why.", "Prefer it gone? The Fix tab shows how to turn it off."]
    else:
        nxt = ["Open the Fix tab and run the Check it commands to see what this program is.",
               "If you don't recognise it, block the address (Fix tab) while you find out."]
    return {"summary": summary(ctx, now), "signals": lines,
            "why": [{"group": g, "text": WHY[g]} for g in groups],
            "likely": likely, "confidence": {"level": sure[0], "reason": sure[1]},
            "next": nxt, "technical": technical,
            "attribution": attribution(ctx) if ctx.get("hidden") else None}


def attribution(ctx):
    """Why the program is unknown, and the safe ways to find out."""
    reason = ctx["hidden"]
    poll = ctx.get("poll") or 2
    if reason == "closed":
        why = (f"Vigil looks every {poll:g} s. This connection opened and closed in between, so the kernel "
               "had already forgotten which program owned it.")
    elif reason == "other-user":
        why = ("The connection belongs to a program running as another user, usually root (system services). "
               "Linux hides other users' programs from a normal user, and Vigil runs as you.")
    else:
        why = "No visible program held this connection when Vigil looked."
    return {"reason": reason, "why": why, "options": [
        {"id": "fast-poll", "title": "Look more often for a while",
         "what": "Vigil checks every 0.5 s for 10 minutes, so short connections are caught with their owner. "
                 "Uses a little more CPU; changes nothing on your system."},
        {"id": "root-helper", "title": "Run Vigil with admin rights (off by default)",
         "what": "As root, Vigil can see every program's connections. It still only reads /proc and changes "
                 "nothing, but any bug in Vigil would run with full rights. Only do this if you need it.",
         "command": "sudo python3 -m vigil serve", "tokens": commands.tokenize("sudo python3 -m vigil serve")},
    ]}


def present(ctx, now=None):
    """Everything the Alerts view shows for one alert."""
    return {"title": title(ctx), "subtitle": subtitle(ctx, now), "severity": severity(ctx),
            "adjusted_score": adjusted_score(ctx), "explain": explain(ctx, now), "who": friendly_name(ctx),
            "to": destination(ctx)}


# ---- "Why is this red?" for a map node ---------------------------------------------------------
# A node on the Network Map turns red when its score reaches the alert threshold, or when a
# threat feed lists it. This answers that in plain words, right in the panel: which program is
# doing it, and why it counts. It directly answers "why is GitHub red when I don't have it open?"
# — because a background program (git, an editor, an updater) is talking to it on a timer.

_WHY_SEV = ["Info", "Low", "Medium", "High"]


def why_node(detail, threshold, is_program, now=None, base_ctx=None):
    """Plain-language 'why flagged' for a program or destination detail, or None if not flagged."""
    now = now or time.time()
    base = base_ctx or {}
    pairs = [p for p in (detail.get("findings") or []) if not p.get("allowlisted")]
    listed = [h for h in ((detail.get("enrichment") or {}).get("intel") or [])]
    scored = [p for p in pairs if (p.get("score") or 0) >= threshold]
    if not scored and not listed:
        return None

    lines, seen, sev = [], set(), "Info"
    programs, dests = {}, {}
    for p in sorted(scored, key=lambda x: -(x.get("score") or 0)):
        ctx = dict(base, program=p.get("program") or detail.get("key"),
                   name=p.get("name"), ip=p.get("ip") or detail.get("ip"),
                   port=p.get("port"), proto=p.get("proto"), direction=p.get("direction"),
                   findings=p.get("findings") or [], hidden=_hidden_reason(p.get("program")),
                   scope=detail.get("scope"), poll=base.get("poll", 2))
        if is_program:
            ctx["info"] = detail.get("info") or {}
        who = friendly_name(ctx) or "An unidentified program"
        programs[who] = programs.get(who, 0) + 1
        dests[destination(ctx)] = dests.get(destination(ctx), 0) + 1
        sev = max(sev, severity(ctx), key=_WHY_SEV.index)
        for f in sorted(ctx["findings"], key=lambda f: -f["points"]):
            st = f.get("stats") or {}
            text = signal_line(st.get("signal"), st, ctx) if st.get("signal") else None
            if text and text not in seen:
                seen.add(text)
                lines.append({"signal": st.get("signal"), "text": text,
                              "strength": round(min(1.0, f["points"] / MAX_POINTS.get(st.get("signal"), 50)), 2)})
        if plain_http(ctx):
            t = "Uses unencrypted HTTP, so anyone on the network path can read it"
            if t not in seen:
                seen.add(t)
                lines.append({"signal": "plain_http", "text": t, "strength": 0.5})

    feed_lines = []
    for h in listed:
        sev = "High"
        feed_lines.append(f"{h.get('title', h.get('feed', 'A threat feed'))}: {h.get('label', 'listed')}")

    # The headline: the thing a confused user needs most — who is doing this.
    if listed:
        head = f"This address is on a threat-intelligence blocklist ({len(listed)} feed{'s' if len(listed) != 1 else ''})."
    elif is_program:
        where = ", ".join(list(dests)[:2])
        head = f"This program is flagged for how it talks to {where}."
    else:
        names = [n for n in programs if n != "An unidentified program"]
        if len(programs) == 1 and names:
            head = f"{names[0]} is contacting this address in the background — you don't need it open."
        elif names:
            head = f"{len(programs)} programs contact this address, including {', '.join(names[:2])}."
        else:
            head = "A program Vigil can't identify is contacting this address."

    return {"flagged": True, "severity": sev, "headline": head, "reasons": lines,
            "listed": feed_lines, "programs": list(programs), "destinations": list(dests),
            "score": round(max([p.get("score") or 0 for p in scored] + [0]), 0),
            "what_now": _what_now(sev, bool(listed), is_program)}


def _hidden_reason(program_key):
    if program_key and program_key.startswith("hidden:"):
        return program_key.split(":")[1]
    return None


def _what_now(sev, listed, is_program):
    if listed:
        return ["This is the strongest signal Vigil has. Don't dismiss it.",
                "Find which program uses it (Scores tab), then block the address or remove that program."]
    if sev == "High":
        return ["Check which program is responsible in the Scores tab below.",
                "If you don't recognise it, treat it as suspicious until you do."]
    return ["Open the Scores tab for the exact reasons.",
            "If it's an app you trust doing normal background work, use Allowlist to stop the alert."]
