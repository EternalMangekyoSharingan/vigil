"""Who is behind an address: browser tabs, host names, and the security of the connection.

Two halves:

- Local, passive, no network: the open tabs of Firefox-family browsers (LibreWolf,
  Firefox, Floorp, Waterfox, Zen), read from their session file; recent history of
  Chromium-family browsers; HSTS hosts the browser has recorded; and, for every
  connection, what its port says about encryption (HTTPS, QUIC, plain HTTP, ...).
- Active, only when the user presses "Identify": the host names of open tabs are looked
  up with the system resolver (the same lookups the browser already made), and HTTPS
  destinations get one TLS handshake each, to read their certificate. Vigil sends no
  HTTP request, nothing about the user, and never contacts an address listed by a
  threat feed.

Browser data stays in memory: Vigil keeps host names and tab titles, never full URLs.
"""

import concurrent.futures
import datetime
import glob
import json
import os
import socket
import sqlite3
import ssl
import struct
import time
import urllib.parse

# ---- Firefox session files (mozLz4) ----------------------------------------------------------

def lz4_block(src, size):
    """Decompress one raw LZ4 block (the format inside Firefox's .jsonlz4 files)."""
    out = bytearray()
    i, n = 0, len(src)
    while i < n:
        token = src[i]
        i += 1
        lit = token >> 4
        if lit == 15:
            while True:
                b = src[i]
                i += 1
                lit += b
                if b != 255:
                    break
        out += src[i:i + lit]
        i += lit
        if i >= n:
            break
        off = src[i] | (src[i + 1] << 8)
        i += 2
        if off == 0 or off > len(out):
            raise ValueError("corrupt LZ4 block")
        mlen = token & 15
        if mlen == 15:
            while True:
                b = src[i]
                i += 1
                mlen += b
                if b != 255:
                    break
        mlen += 4
        start = len(out) - off
        if mlen <= off:
            out += out[start:start + mlen]
        else:  # overlapping copy: repeat byte by byte
            for k in range(mlen):
                out.append(out[start + k])
        if len(out) > size:
            raise ValueError("LZ4 block larger than declared")
    return bytes(out)


def read_mozlz4(path, limit=64 * 2**20):
    with open(path, "rb") as fh:
        raw = fh.read(limit + 12)
    if raw[:8] != b"mozLz40\0":
        raise ValueError("not a mozLz4 file")
    size = struct.unpack_from("<I", raw, 8)[0]
    if size > limit:
        raise ValueError("session file too large")
    return lz4_block(raw[12:], size)


# ---- browser profiles --------------------------------------------------------------------

FIREFOX_FAMILY = [  # (browser name, profile directory globs under $HOME)
    ("LibreWolf", [".librewolf/*", ".var/app/io.gitlab.librewolf-community/.librewolf/*"]),
    ("Firefox", [".mozilla/firefox/*", "snap/firefox/common/.mozilla/firefox/*",
                 ".var/app/org.mozilla.firefox/.mozilla/firefox/*"]),
    ("Floorp", [".floorp/*", ".var/app/one.ablaze.floorp/.floorp/*"]),
    ("Waterfox", [".waterfox/*"]),
    ("Zen", [".zen/*", ".var/app/app.zen_browser.zen/.zen/*"]),
]
CHROMIUM_FAMILY = [
    ("Chromium", ".config/chromium"), ("Chrome", ".config/google-chrome"),
    ("Brave", ".config/BraveSoftware/Brave-Browser"), ("Vivaldi", ".config/vivaldi"),
    ("Edge", ".config/microsoft-edge"),
]


def firefox_profiles(home):
    for browser, patterns in FIREFOX_FAMILY:
        for pat in patterns:
            for d in glob.glob(os.path.join(home, pat)):
                if os.path.isdir(d) and (os.path.exists(os.path.join(d, "prefs.js"))
                                         or os.path.isdir(os.path.join(d, "sessionstore-backups"))):
                    yield browser, d


def _host(url):
    try:
        u = urllib.parse.urlsplit(url)
    except ValueError:
        return None, None
    if u.scheme not in ("http", "https") or not u.hostname:
        return None, None
    return u.hostname.lower(), u.scheme


def open_tabs(home=None, now=None):
    """Open tabs of Firefox-family browsers, plus the last two hours of Chromium-family
    history (Chromium's session format is not worth parsing). Host and title only."""
    home = home or os.path.expanduser("~")
    now = now or time.time()
    tabs = []
    for browser, prof in firefox_profiles(home):
        for name in ("sessionstore-backups/recovery.jsonlz4", "sessionstore.jsonlz4"):
            path = os.path.join(prof, name)
            if not os.path.exists(path):
                continue
            try:
                session = json.loads(read_mozlz4(path))
            except (OSError, ValueError):
                continue
            for w in session.get("windows", []):
                for t in w.get("tabs", []):
                    entries = t.get("entries") or []
                    if not entries:
                        continue
                    e = entries[min(max(t.get("index", len(entries)) - 1, 0), len(entries) - 1)]
                    host, scheme = _host(e.get("url", ""))
                    if host:
                        tabs.append({"browser": browser, "profile": os.path.basename(prof), "host": host,
                                     "scheme": scheme, "title": (e.get("title") or host)[:200],
                                     "last_accessed": (t.get("lastAccessed") or 0) / 1000 or None, "kind": "tab"})
            break  # recovery.jsonlz4 is the live one; sessionstore.jsonlz4 only after a clean exit
    for browser, base in CHROMIUM_FAMILY:
        for hist in glob.glob(os.path.join(home, base, "*", "History")):
            try:  # immutable: read without taking the browser's lock or writing anything
                db = sqlite3.connect(f"file:{hist}?immutable=1", uri=True, timeout=1)
                # Chromium time: microseconds since 1601-01-01
                since = int((now - 7200 + 11644473600) * 1e6)
                rows = db.execute("SELECT url, title, last_visit_time FROM urls WHERE last_visit_time > ? "
                                  "ORDER BY last_visit_time DESC LIMIT 100", (since,)).fetchall()
                db.close()
            except sqlite3.Error:
                continue
            for url, title, lv in rows:
                host, scheme = _host(url)
                if host:
                    tabs.append({"browser": browser, "profile": os.path.basename(os.path.dirname(hist)),
                                 "host": host, "scheme": scheme, "title": (title or host)[:200],
                                 "last_accessed": lv / 1e6 - 11644473600, "kind": "recent"})
    return tabs


def hsts_hosts(home=None):
    """Hosts the browser has recorded as HSTS (Strict-Transport-Security), from Firefox's
    SiteSecurityServiceState.txt. Local only."""
    home = home or os.path.expanduser("~")
    hosts = set()
    for _, prof in firefox_profiles(home):
        try:
            with open(os.path.join(prof, "SiteSecurityServiceState.txt"), encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    key = line.split("\t", 1)[0]
                    if key.endswith(":HSTS"):
                        hosts.add(key[:-5].split("^", 1)[0].lower())
        except OSError:
            continue
    return hosts


# ---- passive: what the port says about encryption ---------------------------------------

TRANSPORT = {
    ("tcp", 443): ("HTTPS", "good", "Encrypted web traffic (TLS). Identify checks the certificate and TLS version."),
    ("udp", 443): ("QUIC", "good", "HTTP/3 over QUIC: always encrypted, TLS 1.3 built in."),
    ("tcp", 8443): ("HTTPS (8443)", "good", "Encrypted web traffic on an alternative port."),
    ("tcp", 80): ("Plain HTTP", "warn", "Unencrypted web traffic: anyone on the path can read or change it. Often just a redirect to HTTPS."),
    ("tcp", 8080): ("Plain HTTP (8080)", "warn", "Unencrypted web traffic on an alternative port."),
    ("udp", 53): ("Plain DNS", "info", "Name lookups in the clear: your network and resolver see which sites you look up."),
    ("tcp", 53): ("Plain DNS", "info", "Name lookups in the clear."),
    ("tcp", 853): ("DNS over TLS", "good", "Encrypted name lookups."),
    ("udp", 853): ("DNS over QUIC", "good", "Encrypted name lookups."),
    ("tcp", 22): ("SSH", "good", "Encrypted remote shell or file transfer."),
    ("tcp", 21): ("FTP (plaintext)", "bad", "File transfer with passwords in the clear."),
    ("tcp", 23): ("Telnet (plaintext)", "bad", "Remote login with everything, passwords included, in the clear."),
    ("tcp", 25): ("SMTP", "info", "Mail between servers; may or may not upgrade to TLS."),
    ("tcp", 110): ("POP3 (plaintext)", "warn", "Mail download without TLS."),
    ("tcp", 143): ("IMAP (plaintext)", "warn", "Mail access without TLS."),
    ("tcp", 465): ("SMTPS", "good", "Mail sending over TLS."),
    ("tcp", 587): ("SMTP submission", "info", "Mail sending; normally upgraded to TLS (STARTTLS)."),
    ("tcp", 993): ("IMAPS", "good", "Mail access over TLS."),
    ("tcp", 995): ("POP3S", "good", "Mail download over TLS."),
    ("udp", 123): ("NTP", "info", "Time sync; unauthenticated unless NTS is used."),
    ("tcp", 4460): ("NTS", "good", "Authenticated time sync (Network Time Security)."),
    ("udp", 51820): ("WireGuard", "good", "Encrypted VPN tunnel."),
    ("udp", 1194): ("OpenVPN", "good", "Encrypted VPN tunnel."),
    ("tcp", 1194): ("OpenVPN", "good", "Encrypted VPN tunnel."),
    ("udp", 3478): ("STUN/TURN", "info", "WebRTC connection setup (calls, video)."),
    ("udp", 19302): ("STUN", "info", "WebRTC connection setup (Google)."),
    ("tcp", 5228): ("Google push (TLS)", "good", "Push notifications for Chrome and Android services."),
    ("tcp", 5222): ("XMPP", "info", "Chat; normally upgraded to TLS."),
    ("tcp", 6667): ("IRC (plaintext)", "warn", "Chat in the clear; also a classic botnet channel."),
    ("tcp", 3389): ("RDP", "warn", "Remote desktop; encrypted, but a frequent attack target."),
    ("tcp", 445): ("SMB", "warn", "Windows file sharing; should not cross the internet."),
}


def transport(proto, port):
    t = TRANSPORT.get((proto, port))
    if t:
        return {"label": t[0], "level": t[1], "why": t[2]}
    if proto == "udp" and 49152 <= port <= 65535:
        return {"label": "UDP (unknown)", "level": "info", "why": "UDP to a high port: often games, calls or WebRTC media."}
    return None


# ---- active: resolve tab hosts, TLS handshake ------------------------------------------------

def resolve(hosts, timeout=6.0):
    """host -> set of addresses, via the system resolver (as the browser did)."""
    out = {}

    def one(h):
        try:
            return h, {ai[4][0] for ai in socket.getaddrinfo(h, 443, type=socket.SOCK_STREAM)}
        except (OSError, UnicodeError):
            return h, set()
    with concurrent.futures.ThreadPoolExecutor(8) as ex:
        futs = [ex.submit(one, h) for h in sorted(hosts)[:200]]
        for f in concurrent.futures.as_completed(futs, timeout=timeout + 2):
            try:
                h, ips = f.result()
                out[h] = ips
            except Exception:
                pass
    return out


def tls_probe(ip, port=443, sni=None, timeout=4.0):
    """One TLS handshake to ip:port to read the certificate. No HTTP is sent.

    Two handshakes at most: one that accepts any certificate (to read it), then one
    that verifies the chain and host name against the system's trusted CAs.
    """
    def handshake(ctx, name):
        with socket.create_connection((ip, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=name) as s:
                return s.version(), s.cipher(), s.selected_alpn_protocol(), s.getpeercert(binary_form=True)

    loose = ssl.create_default_context()
    loose.check_hostname = False
    loose.verify_mode = ssl.CERT_NONE
    loose.set_alpn_protocols(["h2", "http/1.1"])
    out = {"ip": ip, "port": port, "sni": sni, "at": time.time()}
    try:
        version, cipher, alpn, der = handshake(loose, sni)
    except (OSError, ssl.SSLError) as exc:
        out["error"] = f"{type(exc).__name__}: {exc}"[:200]
        return out
    out.update(version=version, cipher=cipher[0] if cipher else None, bits=cipher[2] if cipher else None, alpn=alpn)
    try:
        out["cert"] = parse_cert(der)
    except (ValueError, IndexError) as exc:
        out["cert"] = None
        out["cert_error"] = f"could not parse the certificate: {exc}"
    name = sni or _pick_name((out.get("cert") or {}).get("san") or [])
    out["verified_as"] = name
    if name:
        strict = ssl.create_default_context()
        try:
            handshake(strict, name)
            out["trusted"] = True
        except ssl.SSLCertVerificationError as exc:
            out["trusted"] = False
            out["trust_error"] = exc.verify_message or str(exc)
        except (OSError, ssl.SSLError) as exc:
            out["trusted"] = None
            out["trust_error"] = f"{type(exc).__name__}: {exc}"[:200]
    return out


def _pick_name(sans):
    for s in sans:
        if not s.startswith("*."):
            return s
    for s in sans:
        return "www" + s[1:]
    return None


# ---- minimal X.509 (DER) parser: enough for badges ---------------------------------------

OIDS = {
    "2.5.4.3": "CN", "2.5.4.10": "O", "2.5.4.6": "C",
    "1.2.840.113549.1.1.1": "RSA", "1.2.840.10045.2.1": "EC", "1.3.101.112": "Ed25519", "1.3.101.113": "Ed448",
    "1.2.840.10045.3.1.7": "P-256", "1.3.132.0.34": "P-384", "1.3.132.0.35": "P-521",
    "1.2.840.113549.1.1.11": "SHA-256 with RSA", "1.2.840.113549.1.1.12": "SHA-384 with RSA",
    "1.2.840.113549.1.1.13": "SHA-512 with RSA", "1.2.840.113549.1.1.5": "SHA-1 with RSA",
    "1.2.840.113549.1.1.4": "MD5 with RSA", "1.2.840.10045.4.3.2": "ECDSA with SHA-256",
    "1.2.840.10045.4.3.3": "ECDSA with SHA-384", "1.2.840.113549.1.1.10": "RSA-PSS",
}
EXT_SAN, EXT_POLICIES, EXT_SCT, EXT_MUST_STAPLE, EXT_BASIC = (
    "2.5.29.17", "2.5.29.32", "1.3.6.1.4.1.11129.2.4.2", "1.3.6.1.5.5.7.1.24", "2.5.29.19")
POLICY_LEVEL = {"2.23.140.1.2.1": "DV", "2.23.140.1.2.2": "OV", "2.23.140.1.2.3": "IV", "2.23.140.1.1": "EV"}


def _tlv(b, i):
    tag = b[i]
    ln = b[i + 1]
    i += 2
    if ln & 0x80:
        k = ln & 0x7F
        ln = int.from_bytes(b[i:i + k], "big")
        i += k
    return tag, i, i + ln  # tag, content start, content end


def _children(b, start, end):
    out = []
    i = start
    while i < end:
        tag, s, e = _tlv(b, i)
        out.append((tag, s, e))
        i = e
    return out


def _oid(raw):
    first = raw[0]
    parts = [first // 40, first % 40]
    v = 0
    for c in raw[1:]:
        v = (v << 7) | (c & 0x7F)
        if not c & 0x80:
            parts.append(v)
            v = 0
    return ".".join(map(str, parts))


def _name(b, s, e):
    out = {}
    for _, rs, re_ in _children(b, s, e):           # SET
        for _, as_, ae in _children(b, rs, re_):   # SEQUENCE {oid, value}
            kids = _children(b, as_, ae)
            if len(kids) == 2:
                key = OIDS.get(_oid(b[kids[0][1]:kids[0][2]]))
                if key and key not in out:
                    out[key] = b[kids[1][1]:kids[1][2]].decode("utf-8", "replace")
    return out


def _time(b, tag, s, e):
    t = b[s:e].decode("ascii")
    fmt = "%y%m%d%H%M%SZ" if tag == 0x17 else "%Y%m%d%H%M%SZ"
    return datetime.datetime.strptime(t, fmt).replace(tzinfo=datetime.timezone.utc).timestamp()


def parse_cert(der):
    _, cs, ce = _tlv(der, 0)
    cert = _children(der, cs, ce)
    _, ts, te = cert[0]
    tbs = _children(der, ts, te)
    k = 1 if tbs[0][0] == 0xA0 else 0              # optional [0] version
    _, ss, se = tbs[k + 1]                          # signature algorithm
    sig_alg = _oid(der[_children(der, ss, se)[0][1]:_children(der, ss, se)[0][2]])
    issuer = _name(der, tbs[k + 2][1], tbs[k + 2][2])
    validity = _children(der, tbs[k + 3][1], tbs[k + 3][2])
    subject = _name(der, tbs[k + 4][1], tbs[k + 4][2])
    spki = _children(der, tbs[k + 5][1], tbs[k + 5][2])
    alg = _children(der, spki[0][1], spki[0][2])
    key_type = OIDS.get(_oid(der[alg[0][1]:alg[0][2]]), "other")
    key_detail = None
    if key_type == "EC" and len(alg) > 1 and alg[1][0] == 0x06:
        key_detail = OIDS.get(_oid(der[alg[1][1]:alg[1][2]]))
    elif key_type == "RSA":
        bits = der[spki[1][1] + 1:spki[1][2]]       # BIT STRING: skip the unused-bits byte
        rsa = _children(bits, 0, len(bits))
        _, ms, me = _children(bits, rsa[0][1], rsa[0][2])[0]
        modulus = bits[ms:me].lstrip(b"\0")
        key_detail = f"{len(modulus) * 8} bit"
    out = {"subject": subject, "issuer": issuer, "sig_alg": OIDS.get(sig_alg, sig_alg),
           "not_before": _time(der, *validity[0]), "not_after": _time(der, *validity[1]),
           "key": key_type, "key_detail": key_detail, "san": [], "san_ips": [], "level": None,
           "sct": False, "must_staple": False, "ca": False}
    out["self_signed"] = issuer == subject
    for tag, s, e in tbs[k + 6:]:
        if tag != 0xA3:
            continue
        _, xs, xe = _tlv(der, s)
        for _, es, ee in _children(der, xs, xe):
            parts = _children(der, es, ee)
            oid = _oid(der[parts[0][1]:parts[0][2]])
            val = parts[-1]
            if oid == EXT_SAN:
                _, gs, ge = _tlv(der, val[1])
                for gtag, a, z in _children(der, gs, ge):
                    if gtag == 0x82:
                        out["san"].append(der[a:z].decode("ascii", "replace").lower())
                    elif gtag == 0x87:
                        out["san_ips"].append(socket.inet_ntop(socket.AF_INET if z - a == 4 else socket.AF_INET6, der[a:z]))
            elif oid == EXT_POLICIES:
                _, ps, pe = _tlv(der, val[1])
                for _, qs, qe in _children(der, ps, pe):
                    pid = _children(der, qs, qe)[0]
                    lvl = POLICY_LEVEL.get(_oid(der[pid[1]:pid[2]]))
                    if lvl:
                        out["level"] = lvl
            elif oid == EXT_SCT:
                out["sct"] = True
            elif oid == EXT_MUST_STAPLE:
                out["must_staple"] = True
            elif oid == EXT_BASIC:
                _, bs, be = _tlv(der, val[1])
                kids = _children(der, bs, be)
                out["ca"] = bool(kids and kids[0][0] == 0x01 and der[kids[0][1]] != 0)
    return out


def name_matches(host, pattern):
    host, pattern = host.lower().rstrip("."), pattern.lower().rstrip(".")
    if pattern.startswith("*."):
        return host.count(".") == pattern.count(".") and host.endswith(pattern[1:])
    return host == pattern


# ---- badges ---------------------------------------------------------------------------------

STRONG_CIPHERS = ("AES_256_GCM", "AES_128_GCM", "CHACHA20_POLY1305", "AES256-GCM", "AES128-GCM", "CHACHA20")


def tls_badges(t, hsts=None, now=None):
    """Plain-language security badges for one TLS probe. Each has a level and a reason."""
    now = now or time.time()
    b = []

    def add(label, level, why):
        b.append({"label": label, "level": level, "why": why})
    if t.get("error"):
        add("TLS handshake failed", "warn", f"Vigil could not complete a TLS handshake: {t['error']}. "
            "Some servers only answer when they know the site name (SNI).")
        return b
    v = t.get("version")
    if v == "TLSv1.3":
        add("TLS 1.3", "good", "The current TLS version: modern ciphers only, forward secrecy always.")
    elif v == "TLSv1.2":
        add("TLS 1.2", "good", "Still secure with modern ciphers; TLS 1.3 is newer.")
    elif v:
        add(v.replace("TLSv", "TLS "), "bad", "Outdated TLS version with known weaknesses; browsers no longer accept it.")
    c = t.get("cipher") or ""
    if c:
        strong = any(s in c for s in STRONG_CIPHERS)
        bits = f" ({t['bits']}-bit)" if t.get("bits") else ""
        add("Strong cipher" if strong else "Weak cipher", "good" if strong else "warn",
            f"{c}{bits}: " + ("authenticated encryption (AEAD)." if strong else "not an AEAD cipher; older and weaker."))
        if v == "TLSv1.3" or "ECDHE" in c or "DHE" in c:
            add("Forward secrecy", "good", "Each session has its own key: recorded traffic cannot be decrypted later, "
                "even if the server's key leaks.")
        else:
            add("No forward secrecy", "warn", "If the server's key leaks, recorded traffic could be decrypted.")
    if t.get("alpn") == "h2":
        add("HTTP/2", "info", "The server speaks HTTP/2 (negotiated with ALPN).")
    trusted = t.get("trusted")
    if trusted is True:
        add("Trusted certificate", "good", f"The certificate chain is valid for {t.get('verified_as')} and leads to a "
            "certificate authority your system trusts.")
    elif trusted is False:
        add("Untrusted certificate", "bad", f"Verification failed for {t.get('verified_as')}: {t.get('trust_error')}. "
            "A browser would show a warning page.")
    cert = t.get("cert")
    if cert:
        if cert["self_signed"]:
            add("Self-signed", "bad", "The certificate vouches for itself: no certificate authority checked it.")
        days = (cert["not_after"] - now) / 86400
        if days < 0:
            add("Expired", "bad", f"The certificate expired {int(-days)} days ago.")
        elif days < 14:
            add(f"Expires in {int(days)} d", "warn", "The certificate is about to expire.")
        else:
            add(f"Valid {int(days)} more days", "info", f"Valid until {time.strftime('%Y-%m-%d', time.gmtime(cert['not_after']))}.")
        if cert["not_before"] > now:
            add("Not yet valid", "bad", "The certificate's start date is in the future.")
        lvl = cert.get("level")
        if lvl:
            add({"DV": "Domain validated", "OV": "Organisation validated", "EV": "Extended validation",
                 "IV": "Individual validated"}[lvl], "info",
                {"DV": "The authority only checked control of the domain, not who runs it. Most sites use this.",
                 "OV": f"The authority also checked the organisation: {cert['subject'].get('O', '?')}.",
                 "EV": f"The strictest identity check: {cert['subject'].get('O', '?')}.",
                 "IV": "The authority checked an individual's identity."}[lvl])
        if cert.get("sct"):
            add("Certificate Transparency", "good", "The certificate is recorded in public CT logs, so mis-issued "
                "certificates for this site can be spotted.")
        else:
            add("No CT proof in certificate", "info", "No embedded CT timestamps (they may be sent in the handshake instead).")
        if cert.get("must_staple"):
            add("OCSP must-staple", "good", "Browsers must receive fresh revocation status with every connection.")
        key = cert.get("key")
        kd = cert.get("key_detail") or ""
        if key == "RSA" and kd:
            bits = int(kd.split()[0])
            add(f"RSA {bits}", "good" if bits >= 2048 else "bad",
                "Key size is fine." if bits >= 2048 else "RSA keys under 2048 bits are breakable.")
        elif key in ("EC", "Ed25519", "Ed448"):
            add(f"{'ECDSA ' + kd if key == 'EC' else key}".strip(), "good", "Elliptic-curve key: small and strong.")
        if "SHA-1" in cert.get("sig_alg", "") or "MD5" in cert.get("sig_alg", ""):
            add("Weak signature", "bad", f"Signed with {cert['sig_alg']}, which can be forged.")
        if t.get("sni") and cert.get("san") and not any(name_matches(t["sni"], p) for p in cert["san"]):
            add("Name mismatch", "bad", f"The certificate does not cover {t['sni']}.")
    if hsts:
        add("HSTS", "good", "Your browser has recorded this site as HTTPS-only (Strict-Transport-Security): "
            "it will refuse to connect without valid encryption.")
    return b


def summary_level(badges):
    levels = {x["level"] for x in badges}
    return "bad" if "bad" in levels else "warn" if "warn" in levels else "good" if "good" in levels else "info"
