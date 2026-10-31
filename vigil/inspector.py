"""File Inspector: static triage of a file's bytes.

Safety: the file is never executed, opened in another program, rendered, imported
or written to disk. Every check reads bytes in memory. Archives and compressed
streams are expanded in memory only, with size caps, and parse failures become
stated limits rather than errors.

A report leads with a verdict and a score built from findings, exactly like the
network scores: each finding has points, a reason, and where in the file it was
found. The verdict is never "safe": the best it says is "no suspicious indicators
found", followed by what this kind of check cannot see.
"""

import bisect
import bz2
import hashlib
import io
import ipaddress
import json
import lzma
import re
import struct
import time
import urllib.parse
import zipfile
import zlib

from . import __version__, archives, engines, ole
from .enrich import FEEDS
from .scoring import finding

MEMBER_MAX = 32 * 1024 * 1024    # largest archive member read into memory
EXPAND_MAX = 64 * 1024 * 1024    # total bytes decompressed per file
SCAN_MAX = 64 * 1024 * 1024      # bytes searched for strings and IOCs
IOC_MAX = 300
SNIPPET = 160

# Expanded sizes that make an archive a bomb (bytes): severe, large, worth a note.
BOMB_SEVERE, BOMB_LARGE, BOMB_NOTE = 10 * 1000 ** 3, 1000 ** 3, 100 * 1000 ** 2

VERDICTS = ((70, "Likely malicious"), (30, "Suspicious"), (0, "No suspicious indicators found"))

EXEC_EXTS = {"exe", "scr", "com", "pif", "bat", "cmd", "vbs", "vbe", "js", "jse", "wsf", "wsh",
             "hta", "lnk", "ps1", "psm1", "msi", "msp", "jar", "cpl", "reg", "dll", "iso", "img",
             "vhd", "vhdx", "appref-ms", "sh", "run", "desktop", "appimage", "elf", "bin", "apk"}
DECOY_EXTS = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "rtf", "txt", "csv", "jpg",
              "jpeg", "png", "gif", "mp3", "mp4", "mov", "zip", "rar", "odt", "html", "htm", "eml"}
EXT_FAMILY = {
    "pdf": {"pdf"}, "doc": {"ole2"}, "xls": {"ole2"}, "ppt": {"ole2"}, "msg": {"ole2"},
    "msi": {"ole2"}, "rtf": {"rtf"}, "zip": {"zip", "ooxml", "jar", "odf", "apk"},
    "jar": {"zip", "jar"}, "apk": {"zip", "apk"}, "odt": {"odf"}, "ods": {"odf"}, "odp": {"odf"},
    "exe": {"pe"}, "dll": {"pe"}, "scr": {"pe"}, "sys": {"pe"}, "cpl": {"pe"}, "ocx": {"pe"},
    "png": {"image"}, "jpg": {"image"}, "jpeg": {"image"}, "gif": {"image"},
    "txt": {"text"}, "csv": {"text"}, "log": {"text"}, "md": {"text"},
    "html": {"html", "text"}, "htm": {"html", "text"}, "lnk": {"lnk"}, "iso": {"iso"},
    "img": {"iso", "binary"}, "gz": {"gzip"}, "tgz": {"gzip"}, "bz2": {"bzip2"}, "xz": {"xz"},
    "7z": {"7z"}, "rar": {"rar"},
}
for _e in ("docx", "docm", "dotx", "dotm", "xlsx", "xlsm", "xltx", "xltm", "xlam", "pptx",
           "pptm", "potx", "potm", "ppsx", "ppsm"):
    EXT_FAMILY[_e] = {"ooxml"}
EXECUTABLE_FAMILIES = {"pe", "elf", "macho", "lnk"}
TEXT_FAMILIES = {"text", "script", "html"}
TYPE_NAMES = {
    "pdf": "PDF document", "ole2": "OLE2 compound file (legacy Office, MSI or Outlook)",
    "ooxml": "Office Open XML document (zip)", "zip": "ZIP archive", "jar": "Java archive",
    "apk": "Android package", "odf": "OpenDocument file", "rtf": "Rich Text Format",
    "pe": "Windows executable (PE)", "elf": "Linux executable (ELF)",
    "macho": "macOS executable (Mach-O)", "lnk": "Windows shortcut (.lnk)",
    "iso": "ISO disc image", "gzip": "gzip data", "bzip2": "bzip2 data", "xz": "xz data",
    "7z": "7-Zip archive", "rar": "RAR archive",
    "image": "image", "html": "HTML", "script": "script (#!)", "text": "text",
    "binary": "unrecognised binary data", "empty": "empty file",
}
BIDI = "\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069\u200e\u200f"
# Hosts of XML namespaces and format metadata: present in every Office file.
FORMAT_HOSTS = {"schemas.openxmlformats.org", "schemas.microsoft.com", "www.w3.org", "purl.org",
                "ns.adobe.com", "schemas.xmlsoap.org", "openoffice.org", "www.openoffice.org",
                "docs.oasis-open.org", "www.libreoffice.org", "schemas.libreoffice.org", "xml.org"}
GENERIC_TLDS = {"com", "net", "org", "info", "biz", "io", "co", "me", "xyz", "top", "online",
                "site", "club", "app", "dev", "shop", "store", "live", "icu", "vip", "work",
                "click", "link", "buzz", "cloud", "tech", "space", "website", "fun", "life",
                "world", "today", "pro", "mobi", "name", "gov", "edu", "mil", "int", "onion",
                "su", "cc", "tk", "ml", "ga", "cf", "gq", "pw", "ws", "tv", "ly", "to", "gg"}
NOT_TLDS = {"sh", "py", "pl", "rs", "md", "so", "ps", "cs", "js", "db", "go", "ts", "ai", "gz",
            "vb", "mk", "am", "in", "is", "it", "at", "as", "be", "do", "id", "no", "ms"}
FILE_EXT_TLDS = {"zip", "mov", "app", "doc"}

URL_RE = re.compile(rb"\b(?:https?|ftps?)://[\x21\x23-\x26\x28-\x3b\x3d\x3f-\x5a\x5f\x61-\x7a\x7e]{3,2048}",
                    re.I)
# Not glued to a word or a slash: "LibreOffice/24.2.7.2" and "v1.2.3.4" are versions.
IPV4_RE = re.compile(rb"(?<![\w/.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)"
                     rb"(?![\w.])")
DOMAIN_RE = re.compile(rb"(?<![\w.@/-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}"
                       rb"(?![\w-])", re.I)
EMAIL_RE = re.compile(rb"(?<![\w.%+-])[A-Za-z0-9._%+-]{1,64}@(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,24}"
                      rb"(?![\w-])")
HASH_RE = re.compile(rb"(?<![0-9a-fA-F])(?:[0-9a-fA-F]{64}|[0-9a-fA-F]{40}|[0-9a-fA-F]{32})"
                     rb"(?![0-9a-fA-F])")
UTF16_RE = re.compile(rb"(?:[\x20-\x7e]\x00){6,}")

COMMANDS = [
    ("download_cradle", 40, "PowerShell download-and-run (IEX with a web download)",
     r"(?is)(?:\bIEX\b|Invoke-Expression).{0,300}(?:DownloadString|Net\.WebClient|Invoke-WebRequest|\biwr\b)"
     r"|(?:DownloadString|DownloadFile)\s*\(\s*['\"]?https?://"),
    ("hidden_powershell", 35, "PowerShell started hidden, encoded or with policy bypass",
     r"(?i)powershell(?:\.exe)?\b[^\n]{0,200}?\s[-/](?:e|enc|encodedcommand|w\s+hidden|windowstyle\s+hidden|nop|noprofile|ep\s+bypass|executionpolicy\s+bypass)\b"),
    ("pipe_to_shell", 40, "Downloads a script and pipes it straight into a shell",
     r"(?i)\b(?:curl|wget)\b[^\n|;]{0,300}\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b"),
    ("reverse_shell", 40, "Reverse-shell pattern",
     r"/dev/tcp/\d|\bnc(?:at)?\b[^\n]{0,80}\s-e\s|bash\s+-i\s+>&|socat\b[^\n]{0,80}exec:"),
    ("lolbin", 20, "Uses a Windows system tool often abused to run payloads",
     # the tool itself (mshta, mshta.exe), not a COM name such as WScript.Shell
     r"(?i)\b(?:mshta|rundll32|regsvr32|certutil|bitsadmin|cscript|wscript|installutil|msbuild|forfiles)"
     r"(?:\.exe\b|(?![.\w]))"),
    ("temp_exec", 20, "Makes a file in a temporary directory executable",
     r"chmod\s+(?:\+x|[0-7]*7[0-7]{2})\s+/(?:tmp|var/tmp|dev/shm)/"),
    ("persistence", 20, "Sets up something to run again later (persistence)",
     r"(?i)\bcrontab\s+-|/etc/cron|>>\s*~?/?\S*\.bashrc|systemctl\s+(?:--user\s+)?enable|"
     r"\\CurrentVersion\\Run\b|\bschtasks\b[^\n]{0,80}/create"),
]
VBA_AUTOEXEC = re.compile(
    r"^[ \t]*(?:Private[ \t]+|Public[ \t]+)?(?:Sub|Function)[ \t]+"
    r"(Auto_?Open|AutoExec|AutoNew|Auto_?Close|Document_Open|Document_New|Document_Close|"
    r"DocumentOpen|DocumentBeforeClose|Workbook_Open|Workbook_Activate|Workbook_Close|"
    r"Workbook_BeforeClose|App_DocumentOpen|\w+_(?:Painted|GotFocus|LostFocus|Layout|"
    r"Resize|Initialize|Activate))\b", re.I | re.M)
VBA_SUSPICIOUS = [
    ("runs a command", 15, r"\bShell\b|WScript\.Shell|ShellExecute|\.Run\b|\.Exec\b"),
    ("downloads from the internet", 15, r"URLDownloadToFile|XMLHTTP|WinHttp|Net\.WebClient|"
                                        r"DownloadString|DownloadFile|InternetOpen"),
    ("creates COM objects", 10, r"\bCreateObject\b|\bGetObject\b"),
    ("mentions PowerShell", 10, r"powershell"),
    ("writes files", 10, r"ADODB\.Stream|SaveToFile|\bOpen\b[^\n]+\bFor\s+(?:Binary|Output)\b"),
    ("calls the Windows API directly", 10, r"\bDeclare\s+(?:PtrSafe\s+)?(?:Function|Sub)\b[^\n]*\bLib\b"),
    ("touches process memory (shellcode loaders)", 15, r"VirtualAlloc|RtlMoveMemory|CreateThread|"
                                                       r"WriteProcessMemory|EnumSystemCodePages"),
    ("hides itself or deletes files", 5, r"vbHide|\.Visible\s*=\s*False|\bKill\b"),
    ("obfuscates strings", 10, r"StrReverse|\bCallByName\b|FromBase64|Base64Decode"),
    ("runs AppleScript", 10, r"MacScript|AppleScriptTask"),
]
PDF_KEYS = ("/JS", "/JavaScript", "/AA", "/OpenAction", "/Launch", "/EmbeddedFile", "/EmbeddedFiles",
            "/XFA", "/AcroForm", "/RichMedia", "/ObjStm", "/URI", "/SubmitForm", "/GoToR", "/GoToE",
            "/JBIG2Decode", "/Encrypt", "/Page")


class Budget:
    """Caps how much a single inspection may decompress, across all its parts."""

    def __init__(self):
        self.left = EXPAND_MAX
        self.exhausted = False

    def take(self, n):
        self.left -= n
        if self.left < 0:
            self.exhausted = True
        return not self.exhausted


def verdict_for(score):
    return next(label for floor, label in VERDICTS if score >= floor)


def ext_of(name):
    base = name.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    return base.rsplit(".", 1)[1].lower().strip() if "." in base else ""


def snippet(text, start, end):
    s = text[max(0, start - 40):min(len(text), end + 80)]
    s = re.sub(r"\s+", " ", s if isinstance(s, str) else s.decode("latin-1"))
    return s[:SNIPPET] + ("…" if len(s) > SNIPPET else "")


# ---- identification ------------------------------------------------------------------

def detect_type(data):
    if not data:
        return "empty"
    if data.startswith(ole.MAGIC):
        return "ole2"
    if data.startswith((b"PK\x03\x04", b"PK\x05\x06")):
        return "zip"
    if b"%PDF-" in data[:1024]:
        return "pdf"
    if data.startswith(b"{\\rt"):
        return "rtf"
    if data.startswith(b"MZ") and len(data) > 0x40:
        off = struct.unpack_from("<I", data, 0x3C)[0]
        return "pe" if data[off:off + 4] == b"PE\0\0" else "binary"
    if data.startswith(b"\x7fELF"):
        return "elf"
    if data[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        return "macho"
    if data.startswith(b"L\x00\x00\x00\x01\x14\x02\x00"):
        return "lnk"
    if data[0x8001:0x8006] == b"CD001":
        return "iso"
    for magic, kind in ((b"\x1f\x8b", "gzip"), (b"BZh", "bzip2"), (b"\xfd7zXZ\x00", "xz"),
                        (b"7z\xbc\xaf\x27\x1c", "7z"), (b"Rar!\x1a\x07", "rar"),
                        (b"\x89PNG\r\n\x1a\n", "image"), (b"\xff\xd8\xff", "image"),
                        (b"GIF87a", "image"), (b"GIF89a", "image")):
        if data.startswith(magic):
            return kind
    if data.startswith(b"#!"):
        return "script"
    head = data[:4096]
    printable = sum(1 for b in head if b in b"\t\r\n" or 32 <= b < 127 or b >= 0xC2)
    if printable / len(head) > 0.95:
        low = head.lower()
        if b"<html" in low or b"<!doctype html" in low or b"<script" in low:
            return "html"
        return "text"
    return "binary"


def refine_zip(names):
    if "[Content_Types].xml" in names:
        return "ooxml"
    if "AndroidManifest.xml" in names:
        return "apk"
    if "META-INF/MANIFEST.MF" in names:
        return "jar"
    if "mimetype" in names:
        return "odf"
    return "zip"


def disguise_findings(name, family):
    out = []
    hidden = [c for c in name if c in BIDI]
    if hidden:
        shown = "".join(f"<U+{ord(c):04X}>" if c in BIDI else c for c in name)
        out.append(finding("disguise", 60,
                           "The file name contains invisible text-direction characters that make "
                           "its end display backwards, hiding the real extension",
                           f"file name: {shown}"))
    clean = "".join(c for c in name if c not in BIDI)
    parts = clean.lower().rsplit(".", 2)
    ext = ext_of(clean)
    if len(parts) == 3 and parts[1].strip() in DECOY_EXTS and ext in EXEC_EXTS:
        out.append(finding("disguise", 60,
                           f"Double extension: it looks like a .{parts[1].strip()} but is a .{ext}",
                           f"file name: {clean}"))
    if re.search(r"[ \u00a0_]{4,}\.[A-Za-z0-9]{1,5}$", clean):
        out.append(finding("disguise", 30,
                           "A long run of spaces before the extension pushes it out of view",
                           f"file name: {clean!r}"))
    if ext in EXEC_EXTS and family not in EXECUTABLE_FAMILIES and not any(f["points"] >= 50 for f in out):
        out.append(finding("file_type", 10,
                           f"A .{ext} file runs code when opened (on Windows, or when made "
                           f"executable on Linux)", f"file name extension .{ext}"))
    expected = EXT_FAMILY.get(ext)
    if family is not None and expected and family not in expected and family != "empty":
        if family in EXECUTABLE_FAMILIES:
            pts, why = 60, f"It is really a {TYPE_NAMES[family]} named like a .{ext}"
        elif ext == "doc" and family == "rtf":
            pts, why = 20, "It is RTF renamed .doc: Word opens it anyway, a common hiding place for RTF exploits"
        else:
            pts, why = 15, f"Its content is {TYPE_NAMES.get(family, family)}, not what .{ext} suggests"
        out.append(finding("type_mismatch", pts, why,
                           f"magic bytes say {family}; extension says .{ext}"))
    return out


# ---- IOC extraction --------------------------------------------------------------------


PRINTABLE_RE = re.compile(rb"[\x20-\x7e\t\r\n]{4,}")


def _printable_runs(blob):
    """Like `strings`: the runs of printable text in `blob`, joined by NUL, plus a function
    mapping an offset in the joined text back to the offset in `blob`. Every indicator
    is printable ASCII, so nothing is lost, and binaries shrink about tenfold."""
    runs = list(PRINTABLE_RE.finditer(blob))
    if len(runs) == 1 and runs[0].span() == (0, len(blob)):
        return blob, lambda pos: pos
    joined, starts, origins = bytearray(), [], []
    for m in runs:
        starts.append(len(joined))
        origins.append(m.start())
        joined += m.group() + b"\0"

    def at(pos):
        i = bisect.bisect_right(starts, pos) - 1
        return origins[i] + pos - starts[i] if i >= 0 else pos
    return bytes(joined), at


def _shift(base):
    return lambda pos: base + 2 * pos  # UTF-16: two bytes per character


class Iocs:
    def __init__(self):
        self.items = {}
        self.ignored_format_urls = 0
        self.truncated = False

    def add(self, kind, value, where):
        key = (kind, value.lower() if kind in ("domain", "email") else value)
        if key in self.items:
            return
        if len(self.items) >= IOC_MAX:
            self.truncated = True
            return
        self.items[key] = {"type": kind, "value": value, "where": where}

    def scan(self, blob, where, hashes=False):
        """Find URLs, IPs, domains, emails (and optionally hashes) in bytes or text."""
        if isinstance(blob, str):
            blob = blob.encode("utf-8", "replace")
        blob = blob[:SCAN_MAX]
        strings, at = _printable_runs(blob)
        for text, label, at in ((strings, where, at),
                                *[(m.group().replace(b"\0", b""), f"{where} (UTF-16 text)", _shift(m.start()))
                                  for m in UTF16_RE.finditer(blob)]):
            url_spans = []
            for m in URL_RE.finditer(text):
                url = m.group().decode("ascii", "replace")
                again = re.search(r"(?i)(?:https?|ftps?)://", url[8:])
                if again:  # two strings run together (common in font tables)
                    url = url[:8 + again.start()]
                url = url.rstrip(".,;:!?)'\"")
                host = (urllib.parse.urlsplit(url).hostname or "").lower()
                url_spans.append(m.span())
                if host in FORMAT_HOSTS:
                    self.ignored_format_urls += 1
                    continue
                self.add("url", url, f"{label} at offset {at(m.start()):#x}")
            in_url = lambda s: any(a <= s < b for a, b in url_spans)
            for m in IPV4_RE.finditer(text):
                ip = m.group().decode()
                if not in_url(m.start()) and ip not in ("0.0.0.0", "255.255.255.255"):
                    self.add("ip", ip, f"{label} at offset {at(m.start()):#x}")
            for m in EMAIL_RE.finditer(text):
                self.add("email", m.group().decode("ascii", "replace"), f"{label} at offset {at(m.start()):#x}")
            for m in DOMAIN_RE.finditer(text):
                if in_url(m.start()):
                    continue
                dom = m.group().decode("ascii").lower()
                labels = dom.split(".")
                tld = labels[-1]
                if dom in FORMAT_HOSTS or tld in NOT_TLDS:
                    continue
                if not (tld in GENERIC_TLDS or len(tld) == 2):
                    continue
                if tld in FILE_EXT_TLDS and len(labels) < 3:
                    continue
                if any(lbl.isdigit() for lbl in labels):
                    continue
                self.add("domain", dom, f"{label} at offset {at(m.start()):#x}")
            if hashes:
                for m in HASH_RE.finditer(text):
                    h = m.group().decode().lower()
                    if len(set(h)) > 4:
                        kind = {32: "md5", 40: "sha1", 64: "sha256"}[len(h)]
                        self.add(kind, h, f"{label} at offset {at(m.start()):#x}")

    def hosts(self):
        """Hosts referenced by URLs, plus bare domains and IPs, for intel matching."""
        out = {}
        for item in self.items.values():
            if item["type"] == "url":
                host = (urllib.parse.urlsplit(item["value"]).hostname or "").lower()
                if host:
                    out.setdefault(host, item)
            elif item["type"] in ("domain", "ip"):
                out.setdefault(item["value"].lower(), item)
        return out


def command_findings(text, where):
    """Shell, PowerShell and LOLBin patterns in script-like text."""
    out = []
    if isinstance(text, bytes):
        text = text[:SCAN_MAX].decode("latin-1")
    for check, pts, reason, pattern in COMMANDS:
        m = re.search(pattern, text)
        if m:
            out.append(finding(check, pts, reason,
                               f"{where} at offset {m.start():#x}: {snippet(text, m.start(), m.end())}"))
    return out


# ---- PDF -------------------------------------------------------------------------------

def _unescape_name(raw):
    return re.sub(rb"#([0-9A-Fa-f]{2})", lambda m: bytes([int(m.group(1), 16)]), raw)


def pdf_streams(data, budget):
    """Yield (offset, decompressed bytes) for every stream that inflates."""
    for m in re.finditer(rb"stream\r?\n", data):
        start = m.end()
        end = data.find(b"endstream", start)
        if end < 0:
            break
        raw = data[start:end]
        if not raw[:1] or raw[0] & 0x0F != 8:  # zlib header: deflate method
            continue
        try:
            d = zlib.decompressobj()
            out = d.decompress(raw, min(budget.left, 16 * 1024 * 1024) or 1)
        except zlib.error:
            continue
        if out and budget.take(len(out)):
            yield start, out
        elif budget.exhausted:
            return


def analyze_pdf(data, name, report, iocs, budget):
    findings = []
    header = data.find(b"%PDF-")
    version = data[header + 5:header + 8].decode("latin-1", "replace")
    counts = {k: 0 for k in PDF_KEYS}
    body_js = 0
    obfuscated = set()
    sources = [(data, "PDF body")]
    decompressed = 0
    for off, chunk in pdf_streams(data, budget):
        sources.append((chunk, f"PDF stream at offset {off:#x}"))
        decompressed += 1
    for blob, _ in sources:
        for m in re.finditer(rb"/[A-Za-z0-9#]{1,64}", blob):
            raw = m.group()
            name_ = _unescape_name(raw).decode("latin-1")
            if name_ in counts:
                counts[name_] += 1
                if blob is data and name_ in ("/JS", "/JavaScript"):
                    body_js += 1
                if b"#" in raw:
                    obfuscated.add(raw.decode("latin-1"))
    objects = len(re.findall(rb"\d+\s+\d+\s+obj\b", data))
    report["details"]["pdf"] = {"version": version, "header_offset": header, "objects": objects,
                                "streams_inflated": decompressed,
                                "keywords": {k: v for k, v in counts.items() if v}}
    js = counts["/JS"] + counts["/JavaScript"]
    auto = [k for k in ("/OpenAction", "/AA") if counts[k]]
    where = f"PDF keyword counts over the body and {decompressed} inflated streams"
    if js:
        findings.append(finding("pdf_javascript", 30,
                                f"Contains JavaScript (/JavaScript ×{counts['/JavaScript']}, "
                                f"/JS ×{counts['/JS']})", where))
        if not body_js:
            findings.append(finding("pdf_obfuscation", 10,
                                    "The JavaScript only appears inside compressed streams, out of "
                                    "sight of simple scanners", where))
    runs = [w for w, present in (("JavaScript", js), ("a /Launch action", counts["/Launch"])) if present]
    if auto and runs:
        findings.append(finding("pdf_autorun", 40,
                                f"Has an automatic action ({', '.join(auto)}) that can run "
                                f"{' and '.join(runs)} as soon as the PDF is opened", where))
    elif auto:
        findings.append(finding("pdf_autorun", 0,
                                f"Has an automatic action ({', '.join(auto)}); common (zoom, first "
                                f"page) and harmless without JavaScript or /Launch", where))
    # File names are read per object: embedded ones from file specs with /EF, launch
    # targets from /Launch actions.
    names, targets = [], []
    for blob, _ in sources:
        for m in re.finditer(rb"\d+\s+\d+\s+obj\b(.*?)endobj", blob, re.S):
            body = m.group(1)
            found = [x.decode("latin-1", "replace")
                     for x in re.findall(rb"/(?:F|UF)\s*\(([^)\r\n]{1,200})\)", body)]
            if b"/EF" in body:
                names += found
            if b"/Launch" in body:
                targets += found
    if counts["/Launch"]:
        what = f" → {', '.join(sorted(set(targets)))}" if targets else ""
        findings.append(finding("pdf_launch", 50, f"Can launch a program or open a file on this "
                                                  f"computer (/Launch{what})", where))
    if counts["/EmbeddedFile"] or counts["/EmbeddedFiles"]:
        risky = [n for n in names if ext_of(n) in EXEC_EXTS]
        findings.append(finding("pdf_embedded", 20, "Carries embedded files"
                                + (f": {', '.join(sorted(set(names))[:5])}" if names else ""), where))
        if risky:
            findings.append(finding("pdf_embedded", 30, f"An embedded file is executable: {risky[0]}",
                                    where))
    for key, pts, why in (("/XFA", 15, "Uses XFA forms, which can carry scripts"),
                          ("/RichMedia", 15, "Embeds rich media (Flash), a past exploit route"),
                          ("/JBIG2Decode", 10, "Uses the JBIG2 image codec, a past exploit route"),
                          ("/SubmitForm", 10, "Can send form contents to a web address"),
                          ("/GoToR", 5, "Links to another document (/GoToR)"),
                          ("/GoToE", 5, "Links to an embedded document (/GoToE)")):
        if counts[key]:
            findings.append(finding("pdf_feature", pts, why, where))
    if counts["/Encrypt"]:
        findings.append(finding("pdf_encrypted", 10, "The PDF is encrypted, so its streams could "
                                                     "not be inspected", where))
        report["limits"].append("The PDF is encrypted: compressed streams (where scripts usually "
                                "live) could not be read.")
    if obfuscated:
        findings.append(finding("pdf_obfuscation", 25,
                                f"Keywords are hex-escaped ({', '.join(sorted(obfuscated)[:3])}), a "
                                f"trick to slip past simple scanners", where))
    if header > 0:
        findings.append(finding("pdf_structure", 10, f"{header} bytes of other data come before "
                                                     f"the %PDF header", "start of file"))
    eof = data.rfind(b"%%EOF")
    tail = data[eof + 5:].strip() if eof >= 0 else b""
    if tail:
        inner = detect_type(tail)
        if inner in EXECUTABLE_FAMILIES or tail.find(b"MZ") >= 0 and b"This program" in tail:
            findings.append(finding("pdf_structure", 50, "An executable is appended after the end "
                                                         "of the PDF", f"offset {eof + 5:#x}"))
        else:
            findings.append(finding("pdf_structure", 5, f"{len(tail)} bytes follow the final %%EOF",
                                    f"offset {eof + 5:#x}"))
    js_text = []
    for blob, label in sources:
        for m in re.finditer(rb"/JS\s*\(", blob):
            js_text.append(_pdf_literal(blob, m.end() - 1)[:2000])
        iocs.scan(blob, label)
    if js_text:
        report["details"]["pdf"]["javascript"] = js_text[:5]
        for t in js_text:
            findings += command_findings(t, "PDF JavaScript")
    return findings


def _pdf_literal(blob, start):
    """A PDF literal string starting at '(' (balanced parentheses, escapes kept)."""
    depth, i, out = 0, start, bytearray()
    while i < len(blob) and len(out) < 4096:
        c = blob[i]
        if c == 0x5C and i + 1 < len(blob):
            out += blob[i:i + 2]
            i += 2
            continue
        if c == 0x28:
            depth += 1
            if depth == 1:
                i += 1
                continue
        elif c == 0x29:
            depth -= 1
            if depth == 0:
                break
        out.append(c)
        i += 1
    return out.decode("latin-1")


# ---- Office ------------------------------------------------------------------------------

def analyze_vba(modules, where, report):
    findings = []
    if not modules:
        return findings
    names = [m["name"] for m in modules]
    findings.append(finding("macros", 25, f"Contains VBA macros ({len(modules)} module"
                                          f"{'s' if len(modules) != 1 else ''}: {', '.join(names[:6])})",
                            where))
    seen = set()
    shown = []
    for m in modules:
        src = m["source"]
        hits = []
        for match in VBA_AUTOEXEC.finditer(src):
            line = src.count("\n", 0, match.start()) + 1
            hits.append(f"auto-runs: {match.group(1)} (line {line})")
            if "autoexec" not in seen:
                seen.add("autoexec")
                findings.append(finding("macro_autoexec", 30,
                                        f"A macro runs automatically when the document opens or "
                                        f"closes: {match.group(1)}", f"VBA module {m['name']}, line {line}"))
        for label, pts, pattern in VBA_SUSPICIOUS:
            match = re.search(pattern, src, re.I)
            if match:
                line = src.count("\n", 0, match.start()) + 1
                hits.append(f"{label}: {match.group()} (line {line})")
                if label not in seen:
                    seen.add(label)
                    findings.append(finding("macro_behaviour", pts, f"Macro code {label}",
                                            f"VBA module {m['name']}, line {line}: "
                                            f"{snippet(src, match.start(), match.end())}"))
        chr_calls = len(re.findall(r"\bChr[BW]?\$?\s*\(", src, re.I))
        if chr_calls > 20 and "chr" not in seen:
            seen.add("chr")
            findings.append(finding("macro_behaviour", 10, f"Builds strings from {chr_calls} Chr() "
                                                           f"calls, a common obfuscation",
                                    f"VBA module {m['name']}"))
        shown.append({"name": m["name"], "stream": m["stream"], "lines": src.count("\n") + 1,
                      "hits": hits, "source": src[:20000],
                      "truncated": len(src) > 20000})
    report["details"]["macros"] = report["details"].get("macros", []) + shown
    return findings


def _ole_findings(data, where, report, iocs, budget):
    findings = []
    try:
        f = ole.OleFile(data)
    except ole.OleError as exc:
        report["limits"].append(f"Could not parse the compound file in {where}: {exc}.")
        return findings, None
    streams = ["/".join(p) for p in f.streams()]
    lower = {s.lower() for s in streams}
    kind = ("Word document" if "worddocument" in lower else
            "Excel workbook" if lower & {"workbook", "book"} else
            "PowerPoint presentation" if "powerpoint document" in lower else
            "encrypted Office document" if {"encryptioninfo", "encryptedpackage"} <= lower else
            "Outlook message" if any(s.startswith("__substg1.0_") for s in lower) else
            "VBA project" if any(s.endswith("/dir") for s in lower) and
            any(s.endswith("_vba_project") for s in lower) else
            "compound file")
    report["details"].setdefault("ole", []).append({"where": where, "kind": kind,
                                                     "streams": streams[:200]})
    if kind == "encrypted Office document":
        findings.append(finding("encrypted", 20, "Password-protected Office document: its content "
                                                 "cannot be inspected, which is also why attackers "
                                                 "use it", where))
        report["limits"].append("The Office document is encrypted; its content was not inspected.")
    try:
        modules = ole.vba_modules(f)
    except (ole.OleError, struct.error, IndexError) as exc:
        modules = []
        report["limits"].append(f"VBA project in {where} could not be decoded: {exc}.")
    findings += analyze_vba(modules, f"{where}: VBA project", report)
    for m in modules:
        iocs.scan(m["source"], f"VBA module {m['name']}", hashes=True)
        findings += command_findings(m["source"], f"VBA module {m['name']}")
    for path in f.streams():
        if path[-1].lower() == "workbook":
            findings += _xls_findings(f.read(path), where)
        elif path[-1] == "\x01Ole10Native":
            raw = f.read(path)
            label = _ole10_name(raw)
            if label and ext_of(label) in EXEC_EXTS:
                findings.append(finding("embedded_object", 50, f"Embeds a packaged executable: {label}",
                                        f"{where}: {'/'.join(path)}"))
            elif label:
                findings.append(finding("embedded_object", 15, f"Embeds a packaged file: {label}",
                                        f"{where}: {'/'.join(path)}"))
    return findings, f


def _ole10_name(raw):
    """File name in an Ole10Native (Packager) stream: size, flags, label, path, …"""
    try:
        parts = raw[6:6 + 1024].split(b"\0")
        return parts[0].decode("latin-1") or parts[1].decode("latin-1")
    except IndexError:
        return None


def _xls_findings(stream, where):
    """Excel 4.0 (XLM) macro sheets and Auto_Open names in a BIFF8 Workbook stream."""
    findings, pos, macro_sheets, auto_open = [], 0, [], False
    while pos + 4 <= len(stream):
        rtype, size = struct.unpack_from("<HH", stream, pos)
        rec = stream[pos + 4:pos + 4 + size]
        pos += 4 + size
        if rtype == 0x0085 and len(rec) >= 8:  # BOUNDSHEET8
            state, dt, cch = rec[4], rec[5], rec[6]
            name = rec[8:8 + cch * (2 if rec[7] & 1 else 1)].decode(
                "utf-16-le" if rec[7] & 1 else "latin-1", "replace")
            if dt == 1:
                macro_sheets.append((name, {0: "visible", 1: "hidden", 2: "very hidden"}.get(state & 3)))
        elif rtype == 0x0018 and len(rec) >= 16:  # NAME
            builtin = struct.unpack_from("<H", rec, 0)[0] & 0x20
            if builtin and rec[15] == 0x01:
                auto_open = True
    for name, state in macro_sheets:
        findings.append(finding("xlm_macro", 40, f"Excel 4.0 (XLM) macro sheet '{name}' ({state})",
                                f"{where}: Workbook BOUNDSHEET record"))
        if state == "very hidden":
            findings.append(finding("xlm_macro", 10, "The macro sheet is 'very hidden': it cannot be "
                                                     "unhidden from Excel's menus", where))
    if auto_open:
        findings.append(finding("macro_autoexec", 30, "Defines Auto_Open: macros run when the "
                                                      "workbook opens", f"{where}: NAME record"))
    return findings


def bomb_findings(rep, total, size, report):
    """Findings from archives.check_zip: what extracting this would do."""
    out = []
    lower = " about" if rep.extrapolated or rep.inferred else " at least" if rep.unfinished else ""
    exp = archives.human(total)
    report["details"]["expansion"] = {
        "file_size": size, "estimated": total, "lower_bound": bool(rep.unfinished),
        "ratio": round(total / max(size, 1)), "depth": rep.depth, "entries": rep.entries,
        "shared": [{"name": n, "entries": k, "each": e} for n, k, e in rep.shared[:5]],
        "max_member_ratio": round(rep.max_ratio, 1),
        "extrapolated": [{"name": n, "counted": c, "estimate": e} for n, c, e in rep.extrapolated[:5]],
        "inferred_members": rep.inferred}
    if total >= BOMB_SEVERE or (rep.unfinished and total >= BOMB_LARGE):
        out.append(finding(
            "decompression_bomb", 90,
            f"Decompression bomb: this {archives.human(size)} file would expand to{lower} {exp} "
            f"({total / max(size, 1):,.0f} times its size)",
            "measured by expanding the archive as a stream and counting, never keeping the output"
            + ("; streams cut off at the counting limit were extrapolated from the compressed input "
               "they had used" if rep.extrapolated else "")
            + (f"; {rep.inferred} unmeasured member(s) sized from identical measured siblings"
               if rep.inferred else ""),
            means="Extracting it (double-clicking it, letting a file manager preview it, or an "
                  "antivirus unpacking it) would fill your disk or memory until the program, or "
                  "the whole desktop, freezes or crashes. Do not extract it; delete it."))
    elif total >= BOMB_LARGE:
        out.append(finding("decompression_bomb", 50, f"Would expand to {exp} when extracted "
                           f"({total / max(size, 1):,.0f} times its size)", "streamed expansion",
                           means="Extracting it needs that much free disk space and time; far more "
                                 "than anything this size normally holds."))
    elif total >= BOMB_NOTE and total / max(size, 1) > 100:
        out.append(finding("decompression_bomb", 20, f"Expands {total / max(size, 1):,.0f}-fold "
                           f"(to {exp})", "streamed expansion",
                           means="Unusually compressible content; check what it is before extracting."))
    if rep.overlaps:
        names = rep.shared[0][1] if rep.shared else rep.overlaps + 1
        out.append(finding(
            "overlapping_entries", 60,
            f"{names} file names point at the same compressed data (overlapping entries)",
            f"zip directory: {rep.overlaps} entries start inside or at another entry's data",
            means="No archiving tool produces this. It is how 'non-recursive' zip bombs multiply "
                  "one small block of data into many huge files on extraction."))
    for name, declared, actual in rep.lies[:3]:
        out.append(finding("size_lie", 40,
                           f"{name} claims to be {archives.human(declared)} but produces"
                           f"{' over' if actual > declared else ''} {archives.human(actual)}",
                           "declared size in the zip directory vs. bytes counted while streaming",
                           means="False sizes defeat tools that check the size before extracting."))
    if rep.forged:
        out.append(finding("forged_directory", 30, "The archive's directory has been falsified: "
                           + rep.forged[0], "zip end-of-directory record vs. the records found",
                           means="Done deliberately, to make tools miscount or skip what is inside."))
    if rep.max_ratio > archives.MAX_DEFLATE_RATIO:
        out.append(finding("impossible_ratio", 40, f"A member claims a {rep.max_ratio:,.0f}:1 "
                           f"compression ratio, beyond what deflate can reach (~1,032:1)",
                           "zip directory sizes", means="Either the sizes are forged or the data "
                           "is built to explode when extracted."))
    if rep.slip:
        out.append(finding("path_traversal", 50, f"{len(rep.slip)} member name(s) would be written "
                           f"outside the folder you extract into: {rep.slip[0]}", "member names",
                           means="'Zip slip': extracting could overwrite files elsewhere, for "
                                 "example your shell startup files, to run code later."))
    if rep.symlinks:
        out.append(finding("symlink_member", 25, f"Contains symbolic links: {rep.symlinks[0]}",
                           "member file modes", means="A link can make a later member land "
                           "somewhere else on your system when extracted."))
    if rep.entries > 10000:
        out.append(finding("entry_flood", 25, f"{rep.entries:,} entries", "zip directory",
                           means="Huge entry counts exhaust tools that list or extract archives."))
    if rep.unfinished:
        report["limits"].append(
            f"Expansion was measured by streaming and counting, never stored, and stopped at "
            f"{archives.human(archives.COUNT_LIMIT)} per member or {archives.TIME_LIMIT:.0f} s: "
            f"the real size is larger than reported.")
    return out


def analyze_stream(data, name, family, report, iocs, budget, depth):
    """gzip, bzip2 or xz: measure the expansion, then inspect the content if it is sane."""
    size, complete = archives.check_stream(data, family)
    rep = archives.Report()
    if size > archives.COUNT_LIMIT or (not complete and size > MEMBER_MAX):
        rep.unfinished.append((name, size))
        if size > archives.COUNT_LIMIT:
            rep.extrapolated.append((name, archives.COUNT_LIMIT, size))
    findings = bomb_findings(rep, size, len(data), report)
    if findings or not complete or size > MEMBER_MAX or depth >= 2:
        if not findings:
            report["limits"].append(f"The {TYPE_NAMES[family]} content was measured "
                                    f"({archives.human(size)}) but not inspected.")
        return findings
    d = {"gzip": lambda: zlib.decompressobj(31), "bzip2": bz2.BZ2Decompressor,
         "xz": lzma.LZMADecompressor}[family]()
    inner = d.decompress(data, MEMBER_MAX)
    inner_name = name.rsplit(".", 1)[0] if "." in name else f"{name}.out"
    sub = inspect_bytes(inner, inner_name, depth=depth + 1, budget=budget)
    report["details"].setdefault("nested", []).append(
        {"name": inner_name, "verdict": sub["verdict"], "score": sub["score"], "type": sub["type"]["detected"]})
    for f in sub["findings"]:
        f["reason"] = f"Inside ({inner_name}): {f['reason']}"
        findings.append(f)
    for item in sub["iocs"]:
        iocs.add(item["type"], item["value"], f"in {inner_name}: {item['where']}")
    return findings


def analyze_zip(data, name, family, report, iocs, budget, depth):
    findings = []
    checked = archives.check_zip(data) if depth == 0 else None
    bomb = False
    if checked:
        findings += bomb_findings(*checked, len(data), report)
        bomb = any(f["check"] in ("decompression_bomb", "overlapping_entries") and f["points"] >= 50
                   for f in findings)
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
        infos = zf.infolist()
    except (zipfile.BadZipFile, ValueError, OSError) as exc:
        report["limits"].append(f"The ZIP structure could not be read: {exc}.")
        return findings
    members = [{"name": i.filename, "size": i.file_size, "compressed": i.compress_size,
                "encrypted": bool(i.flag_bits & 1)} for i in infos]
    report["details"]["members"] = members[:500]

    skipped = []

    def read(info):
        if info.flag_bits & 1:
            return None
        if info.file_size > MEMBER_MAX or not budget.take(info.file_size):
            skipped.append(info.filename)
            return None
        try:
            with zf.open(info) as fh:
                return fh.read(MEMBER_MAX + 1)[:MEMBER_MAX]
        except (zipfile.BadZipFile, RuntimeError, NotImplementedError, OSError, zlib.error):
            return None

    encrypted = [m["name"] for m in members if m["encrypted"]]
    if encrypted:
        findings.append(finding("encrypted", 20, f"{len(encrypted)} password-protected member(s) "
                                                 f"cannot be inspected, a common way to slip malware "
                                                 f"past scanners", f"archive: {encrypted[0]}"))
        report["limits"].append("Password-protected archive members were not inspected.")
    def note_skipped():
        if skipped:
            report["limits"].append(
                f"{len(skipped)} archive member(s) were too large to expand in memory (over "
                f"{MEMBER_MAX // 2**20} MB each, or {EXPAND_MAX // 2**20} MB in total) and were not "
                f"inspected: {', '.join(skipped[:5])}.")

    if bomb:  # never unpack a bomb's members, not even into memory
        report["limits"].append("Members were not unpacked for inspection because the archive is "
                                "built to explode when extracted.")
        return findings
    if family != "ooxml":
        # Each member is inspected in full when it can be read; otherwise its name alone.
        for info in infos:
            if info.is_dir():
                continue
            base = info.filename.rsplit("/", 1)[-1]
            inner = read(info) if depth < 2 else None
            if inner is None:
                for f in disguise_findings(base, None):
                    f["reason"] = f"Archive member {info.filename}: {f['reason']}"
                    findings.append(f)
                continue
            sub = inspect_bytes(inner, base, depth=depth + 1, budget=budget)
            report["details"].setdefault("nested", []).append(
                {"name": info.filename, "verdict": sub["verdict"], "score": sub["score"],
                 "type": sub["type"]["detected"]})
            for f in sub["findings"]:
                f["reason"] = f"Archive member {info.filename}: {f['reason']}"
                findings.append(f)
            for item in sub["iocs"]:
                iocs.add(item["type"], item["value"], f"in {info.filename}: {item['where']}")
            report["limits"].extend(l for l in sub["limits"] if l not in report["limits"])
        note_skipped()
        return findings

    # Office Open XML: macros, external relationships, embedded objects, DDE.
    ext = ext_of(name)
    parts = {i.filename: i for i in infos}
    vba = [n for n in parts if n.lower().endswith("vbaproject.bin")]
    for n in vba:
        blob = read(parts[n])
        if blob:
            fs, _ = _ole_findings(blob, n, report, iocs, budget)
            findings += fs
        if ext in ("docx", "xlsx", "pptx", "dotx", "xltx", "potx", "ppsx"):
            findings.append(finding("type_mismatch", 20, f"Has a VBA project although .{ext} files "
                                                         f"cannot run macros; renamed or tampered",
                                    n))
    sheets = [n for n in parts if "/macrosheets/" in n.lower()]
    if sheets:
        findings.append(finding("xlm_macro", 40, f"Excel 4.0 (XLM) macro sheet: {sheets[0]}", sheets[0]))
    for n, info in parts.items():
        low = n.lower()
        if low.endswith(".rels") or low.endswith(".xml"):
            blob = read(info)
            if blob is None:
                continue
            iocs.scan(blob, n)
            if low.endswith(".rels"):
                findings += _rels_findings(blob, n)
            if low.endswith("workbook.xml") and re.search(rb"_xlnm\.Auto_Open|name=\"Auto_Open", blob, re.I):
                findings.append(finding("macro_autoexec", 30, "Defines Auto_Open: macros run when the "
                                                              "workbook opens", n))
            dde = re.search(rb"(?:instrText[^>]*>|instr=\")\s*(DDEAUTO|DDE)\b([^<\"]{0,200})", blob)
            if dde:
                auto = dde.group(1) == b"DDEAUTO"
                command = dde.group(2).decode("latin-1")
                findings.append(finding("dde", 50 if auto else 35,
                                        f"A {dde.group(1).decode()} field can run a command"
                                        + (" when the document opens" if auto else ""),
                                        f"{n}: {command[:SNIPPET]}"))
                if re.search(r"(?i)cmd(?:\.exe)?|powershell|mshta|wscript|cscript", command):
                    findings.append(finding("dde", 20, "The DDE command starts a shell or script host",
                                            f"{n}: {command[:SNIPPET]}"))
        elif "/embeddings/" in low:
            blob = read(info) or b""
            inner = detect_type(blob)
            if inner in EXECUTABLE_FAMILIES:
                findings.append(finding("embedded_object", 50, f"Embeds an executable ({TYPE_NAMES[inner]})", n))
            elif inner == "ole2":
                fs, _ = _ole_findings(blob, n, report, iocs, budget)
                findings += fs or [finding("embedded_object", 15, f"Embeds an OLE object ({n.rsplit('/', 1)[-1]})", n)]
            else:
                findings.append(finding("embedded_object", 5, f"Embeds a {TYPE_NAMES.get(inner, inner)} "
                                                              f"({n.rsplit('/', 1)[-1]}, {info.file_size} bytes)", n))
        elif "/activex/" in low and low.endswith(".xml"):
            findings.append(finding("activex", 20, "Contains ActiveX controls, whose event handlers "
                                                   "can run macros on open", n))
    note_skipped()
    return _dedupe(findings)


REL_RE = re.compile(rb"<Relationship\b[^>]*>", re.I)


def _rels_findings(blob, where):
    findings = []
    for m in REL_RE.finditer(blob):
        tag = m.group().decode("utf-8", "replace")
        attrs = dict(re.findall(r'(\w+)="([^"]*)"', tag))
        if attrs.get("TargetMode", "").lower() != "external":
            continue
        rtype = attrs.get("Type", "").rsplit("/", 1)[-1]
        target = attrs.get("Target", "")
        scheme = target.split(":", 1)[0].lower() if ":" in target else ""
        if rtype == "attachedTemplate" and (scheme in ("http", "https", "ftp") or target.startswith("\\\\")):
            host = urllib.parse.urlsplit(target).hostname or target.lstrip("\\").split("\\")[0]
            f = finding("remote_template", 60 if _is_ip(host) else 50,
                        "Loads a template from a remote server when opened (template injection, "
                        "ATT&CK T1221)" + (", addressed by bare IP" if _is_ip(host) else ""),
                        f"{where}: {target[:SNIPPET]}")
        elif rtype == "attachedTemplate":
            f = finding("remote_template", 5, "Uses a template stored elsewhere on disk "
                                              "(normal for corporate templates)", f"{where}: {target[:SNIPPET]}")
        elif rtype == "oleObject" and scheme in ("mhtml", "ms-msdt", "search-ms", "ms-officecmd"):
            f = finding("remote_object", 70, f"Remote OLE object using the {scheme}: handler, the "
                                             f"pattern of the Follina exploit (CVE-2022-30190)",
                        f"{where}: {target[:SNIPPET]}")
        elif rtype == "oleObject":
            f = finding("remote_object", 40, "Loads an OLE object from outside the file",
                        f"{where}: {target[:SNIPPET]}")
        elif rtype in ("frame", "subDocument"):
            f = finding("remote_object", 30, f"Pulls in a remote {rtype}", f"{where}: {target[:SNIPPET]}")
        elif rtype == "hyperlink":
            continue  # links are listed as IOCs, not scored
        else:
            f = finding("remote_object", 5, f"Refers to an external {rtype}", f"{where}: {target[:SNIPPET]}")
        findings.append(f)
    return findings


def analyze_rtf(data, report, iocs, budget):
    findings = []
    text = data[:SCAN_MAX].decode("latin-1")
    if not text.startswith("{\\rtf1"):
        findings.append(finding("rtf_structure", 15, "Malformed RTF header: Word tolerates it, many "
                                                      "scanners do not", f"start: {text[:12]!r}"))
    classes = re.findall(r"\\objclass\s+([^\\}\s]{1,64})", text)
    if "\\objdata" in text or "\\object" in text:
        findings.append(finding("rtf_object", 25, "Embeds an OLE object"
                                + (f" ({', '.join(sorted(set(classes)))})" if classes else ""),
                                "\\object / \\objdata control words"))
    if "\\objupdate" in text:
        findings.append(finding("rtf_object", 30, "The embedded object updates itself on open "
                                                  "(\\objupdate), used to trigger exploits without a click",
                                "\\objupdate control word"))
    for cls in set(c.lower() for c in classes):
        if cls.startswith("equation"):
            findings.append(finding("rtf_object", 40, "Equation Editor object: the route of "
                                                      "CVE-2017-11882 and CVE-2018-0802", f"\\objclass {cls}"))
        elif cls.startswith("package"):
            findings.append(finding("rtf_object", 25, "Packaged file object: can carry any file",
                                    f"\\objclass {cls}"))
        elif "ole2link" in cls or cls.startswith("htmlfile"):
            findings.append(finding("rtf_object", 40, "Linked object that fetches remote content "
                                                      "(CVE-2017-0199 pattern)", f"\\objclass {cls}"))
    for m in list(re.finditer(r"\\objdata\b", text))[:3]:
        hexes = re.sub(r"[^0-9a-fA-F]", "", text[m.end():m.end() + 16 * 1024 * 1024].split("}", 1)[0])
        blob = bytes.fromhex(hexes[:len(hexes) // 2 * 2])
        if not budget.take(len(blob)):
            break
        iocs.scan(blob, "RTF embedded object")
        if b"MZ" in blob and b"This program cannot be run in DOS mode" in blob:
            findings.append(finding("embedded_object", 50, "The embedded object contains a Windows "
                                                           "executable", "RTF \\objdata"))
    iocs.scan(data, "RTF body")
    return _dedupe(findings)


def _dedupe(findings):
    seen, out = set(), []
    for f in findings:
        key = (f["check"], f["reason"])
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


# ---- the inspection --------------------------------------------------------------------

# ---- analyzers: the report's "detection" grid ---------------------------------------------
# Each row is one of Vigil's own analyzers, named for what it looks at. A row says whether
# it ran on this kind of file and which of its checks fired. No third-party engines are
# implied: rows only ever describe checks this file actually went through.

ARCHIVE_FAMILIES = {"zip", "ooxml", "jar", "apk", "odf", "gzip", "bzip2", "xz"}
ANALYZERS = [
    ("identity", "Name and file type",
     "Disguised names, extensions that lie about the content, programs.",
     {"disguise", "type_mismatch", "file_type"}, lambda f: True),
    ("archive", "Archive and bomb analysis",
     "Measures what unpacking would write, without unpacking; size lies, overlapping and "
     "forged entries, paths that escape the folder.",
     {"decompression_bomb", "overlapping_entries", "size_lie", "forged_directory", "impossible_ratio",
      "path_traversal", "symlink_member", "entry_flood"}, lambda f: f in ARCHIVE_FAMILIES),
    ("macro", "Office macros",
     "VBA source (decompressed), auto-run entry points, what the code calls; Excel 4.0 macros; ActiveX.",
     {"macros", "macro_autoexec", "macro_behaviour", "xlm_macro", "activex"},
     lambda f: f in ("ooxml", "ole2", "odf")),
    ("office", "Office structure",
     "Remote templates and objects (Follina), DDE fields, embedded files and programs, encryption.",
     {"remote_template", "remote_object", "dde", "embedded_object", "encrypted"},
     lambda f: f in ("ooxml", "ole2", "odf", "rtf")),
    ("rtf", "RTF exploits",
     "Embedded objects, Equation Editor and OLE2Link exploits, malformed headers.",
     {"rtf_object", "rtf_structure"}, lambda f: f == "rtf"),
    ("pdf", "PDF actions and scripts",
     "JavaScript, auto-actions, launch actions, embedded files, obfuscated names, hidden streams.",
     {"pdf_javascript", "pdf_autorun", "pdf_launch", "pdf_embedded", "pdf_obfuscation",
      "pdf_feature", "pdf_structure", "pdf_encrypted"}, lambda f: f == "pdf"),
    ("commands", "Scripts and command lines",
     "Download-and-run commands, hidden PowerShell, reverse shells, persistence, HTML smuggling.",
     {"download_cradle", "hidden_powershell", "lolbin", "persistence", "pipe_to_shell", "reverse_shell",
      "temp_exec", "html_smuggling"}, lambda f: f in TEXT_FAMILIES or f == "lnk"),
    ("clamav", "ClamAV (local antivirus)",
     "ClamAV's signature database, run on this PC from memory. Optional: install ClamAV to enable.",
     {"antivirus"}, None),
    ("intel", "Threat feeds (offline)",
     "Indicators matched against the abuse.ch lists you downloaded.",
     {"threat_intel"}, None),
    ("history", "This PC's network history",
     "Addresses in the file that this PC has really connected to.",
     {"seen_on_network"}, None),
]


def summarize_analyzers(report, context=None):
    """Fill report["analyzers"]: one row per analyzer, with its status and the checks that fired.

    `context` says whether the offline sources were available: {"feeds": n, "history": bool}.
    Without it (the command line, or before link_context), those two rows read "not run".
    """
    if "type" not in report:
        return report
    if context is not None:
        report["context"] = context
    context = report.get("context") or {}
    family = report["type"]["detected"]
    families = {family} | {n["type"] for n in report["details"].get("nested", [])}  # members were inspected too
    rows = []
    for key, title, about, checks, applies in ANALYZERS:
        hits = [f for f in report["findings"] if f["check"] in checks and f["points"] > 0]
        if key == "clamav":
            clam = (report.get("engines") or {}).get("clamav") or {}
            ran = clam.get("status") in ("flagged", "nothing")
            why_not = {"unavailable": "Not run: ClamAV is not installed",
                       "skipped": f"Not run: {clam.get('reason')}",
                       "error": f"Not run: {clam.get('reason', 'ClamAV failed')}"}.get(clam.get("status"),
                                                                                    "Not run: inside the Vigil app only")
        elif key == "intel":
            ran = bool(context.get("feeds"))
            why_not = "Not run: no feeds downloaded (Intel tab)"
        elif key == "history":
            ran = bool(context.get("history"))
            why_not = "Not run: only inside the Vigil app"
        else:
            ran = any(applies(f) for f in families) or bool(hits)
            why_not = "Not run: not for this file type"
        if key == "clamav" and ((report.get("engines") or {}).get("clamav") or {}).get("status") == "pending":
            status, label = ("pending", "Scanning…")
        elif hits:
            top = max(hits, key=lambda f: f["points"])
            status, label = ("flagged", _short(top["reason"]))
        elif ran:
            status, label = ("nothing", "Nothing found")
        else:
            status, label = ("skipped", why_not)
        rows.append({"id": key, "title": title, "about": about, "status": status, "label": label,
                     "checks": sorted({f["check"] for f in hits}),
                     "points": round(sum(f["points"] for f in hits), 1)})
    report["analyzers"] = rows
    return report


def _short(reason, limit=64):
    reason = reason.split(":", 1)[0] if len(reason) > limit and ":" in reason[:limit] else reason
    return reason if len(reason) <= limit else reason[:limit - 1].rstrip() + "…"


def inspect_bytes(data, name, depth=0, budget=None):
    """Static triage of one file. Returns a report dict; never raises on bad input."""
    budget = budget or Budget()
    family = detect_type(data)
    report = {"name": name, "size": len(data), "engine": f"Vigil {__version__} static triage",
              "hashes": {"md5": hashlib.md5(data).hexdigest(), "sha1": hashlib.sha1(data).hexdigest(),
                         "sha256": hashlib.sha256(data).hexdigest()},
              "details": {}, "limits": []}
    iocs = Iocs()
    findings = []
    try:
        if family == "zip":
            try:
                family = refine_zip(zipfile.ZipFile(io.BytesIO(data)).namelist())
            except (zipfile.BadZipFile, ValueError, OSError):
                pass
        findings += disguise_findings(name, family)
        if family in EXECUTABLE_FAMILIES:
            findings.append(finding("file_type", 15, f"This is a program ({TYPE_NAMES[family]})",
                                    "magic bytes"))
            report["limits"].append("Programs get identity, string and IOC checks only; their code "
                                    "is not analysed. Run it only inside the detonation VM.")
        if family == "pdf":
            findings += analyze_pdf(data, name, report, iocs, budget)
        elif family in ("zip", "ooxml", "jar", "apk", "odf"):
            findings += analyze_zip(data, name, family, report, iocs, budget, depth)
        elif family in ("gzip", "bzip2", "xz"):
            findings += analyze_stream(data, name, family, report, iocs, budget, depth)
        elif family == "ole2":
            fs, _ = _ole_findings(data, "compound file", report, iocs, budget)
            findings += fs
            iocs.scan(data, "raw bytes")
        elif family == "rtf":
            findings += analyze_rtf(data, report, iocs, budget)
        else:
            iocs.scan(data, "raw bytes", hashes=family in TEXT_FAMILIES)
        if family in TEXT_FAMILIES:
            findings += command_findings(data, "file text")
        elif family == "lnk":  # shortcut targets and arguments are stored as UTF-16
            text = b"\n".join(m.group().replace(b"\0", b"") for m in UTF16_RE.finditer(data))
            findings += command_findings(text, "shortcut strings")
        if family == "html" and re.search(rb"(?i)msSaveOrOpenBlob|\bdownload\s*=|new\s+Blob\s*\(", data) \
                and re.search(rb"[A-Za-z0-9+/]{2000,}={0,2}", data):
            findings.append(finding("html_smuggling", 40, "HTML that assembles a file from a large "
                                                          "embedded blob and saves it (HTML smuggling)",
                                    "script in the HTML"))
    except Exception as exc:  # a parser bug must never take the inspector down
        report["limits"].append(f"Analysis stopped early ({type(exc).__name__}: {exc}); findings "
                                f"before that point are kept.")
    if family in ("binary", "7z", "rar", "iso"):
        report["limits"].append(f"{TYPE_NAMES[family].capitalize()} is not unpacked or parsed; only "
                                f"identity, name and string checks ran.")
    if budget.exhausted:
        report["limits"].append(f"Stopped expanding compressed content after {EXPAND_MAX // 2**20} MB.")
    if len(data) > SCAN_MAX:
        report["limits"].append(f"Only the first {SCAN_MAX // 2**20} MB were searched for strings.")
    if iocs.truncated:
        report["limits"].append(f"Only the first {IOC_MAX} indicators are listed.")
    findings = _dedupe(findings)
    score = min(100.0, round(sum(f["points"] for f in findings), 1))
    report.update({
        "type": {"detected": family, "description": TYPE_NAMES.get(family, family),
                 "extension": ext_of(name)},
        "findings": sorted(findings, key=lambda f: -f["points"]),
        "iocs": list(iocs.items.values()),
        "ignored_format_urls": iocs.ignored_format_urls,
        "score": score, "verdict": verdict_for(score),
    })
    report["limits"] = list(dict.fromkeys(report["limits"] + [
        "Static triage only: the file was read as bytes and never opened, run or rendered.",
        "Code can behave differently when it runs, and obfuscated or encrypted content can hide "
        "what it does. Behaviour analysis needs the detonation VM (build step 6).",
    ]))
    return summarize_analyzers(report)


def _local_only(ip):
    a = ipaddress.ip_address(ip)
    return a.is_loopback or a.is_unspecified or a.is_link_local or a.is_multicast


def link_context(report, store, enricher=None):
    """Attach threat-feed hits and this PC's own history to the report's IOCs.

    Runs only against local data (the downloaded feeds and the evidence store).
    """
    findings = []
    for item in report["iocs"]:
        host = None
        if item["type"] == "url":
            host = (urllib.parse.urlsplit(item["value"]).hostname or "").lower()
        elif item["type"] in ("ip", "domain"):
            host = item["value"].lower()
        hits = []
        if enricher is not None:
            if item["type"] == "url":
                hits += store.query("SELECT feed, label, indicator, reference FROM intel"
                                    " WHERE indicator=? LIMIT 5", (item["value"],))
            if host:
                hits += store.query("SELECT feed, label, indicator, reference FROM intel"
                                    " WHERE host=? LIMIT 5", (host,))
        if hits:
            item["intel"] = hits
            best = max(hits, key=lambda h: FEEDS.get(h["feed"], {}).get("points", 0))
            pts = 70 if best["feed"] in ("feodo", "sslbl") else 60
            findings.append(finding("threat_intel", pts,
                                    f"Contains {item['value']}, which {FEEDS[best['feed']]['title'].split(':')[0]} "
                                    f"lists ({best['label']})", f"{item['where']}; local {best['feed']} feed"))
        ip = host if host and _is_ip(host) else None
        if ip and _local_only(ip):
            ip = None  # every PC talks to its own loopback; matching it says nothing about the file
        if ip:
            dest = store.one("SELECT first_seen, last_seen FROM destinations WHERE ip=?", (ip,))
            if dest:
                item["seen"] = dest
                findings.append(finding("seen_on_network", 15,
                                        f"This PC has connected to {ip}, which this file mentions "
                                        f"(first {time.strftime('%Y-%m-%d %H:%M', time.localtime(dest['first_seen']))})",
                                        f"{item['where']}; Vigil's destinations table"))
    if findings:
        report["findings"] = sorted(_dedupe(report["findings"] + findings), key=lambda f: -f["points"])
        report["score"] = min(100.0, round(sum(f["points"] for f in report["findings"]), 1))
        report["verdict"] = verdict_for(report["score"])
    feeds = store.one("SELECT COUNT(*) AS n FROM feeds WHERE entries > 0") if enricher is not None else None
    return summarize_analyzers(report, {"feeds": (feeds or {}).get("n", 0), "history": True})


def _is_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


# ---- second opinions: ClamAV and hash lookups ------------------------------------------------

def _rescore(report):
    report["findings"] = sorted(_dedupe(report["findings"]), key=lambda f: -f["points"])
    report["score"] = min(100.0, round(sum(f["points"] for f in report["findings"]), 1))
    report["verdict"] = verdict_for(report["score"])
    return summarize_analyzers(report)


# ClamAV unpacks archives to scan inside them (and writes temporary files while it does),
# so it must never be handed something Vigil has measured as a bomb.
BOMB_CHECKS = {"decompression_bomb", "overlapping_entries", "size_lie", "forged_directory",
               "impossible_ratio", "entry_flood"}
CLAM_EXPANSION_MAX = 1 << 30


def clamav_unsafe(report):
    """Why ClamAV must not scan this file, or None."""
    if any(f["check"] in BOMB_CHECKS and f["points"] > 0 for f in report["findings"]):
        return "Vigil found an archive bomb, and ClamAV would try to unpack it"
    exp = report.get("details", {}).get("expansion") or {}
    if exp.get("lower_bound") or (exp.get("estimated") or 0) > CLAM_EXPANSION_MAX:
        return "it would expand to over 1 GB, and ClamAV unpacks archives to scan them"
    return None


def clamav_plan(report, available=None):
    """Decide whether ClamAV scans this file. Marks the report "pending" (scan to follow),
    "skipped" (with the reason) or "unavailable". Returns True when a scan should run."""
    available = available or engines.clamav_available
    why = clamav_unsafe(report)
    if why:
        report.setdefault("engines", {})["clamav"] = {"status": "skipped", "reason": why}
        report["limits"].append(f"ClamAV was not run: {why}.")
    elif not available():
        report.setdefault("engines", {})["clamav"] = {"status": "unavailable", "reason": "ClamAV is not installed"}
        report["limits"].append("ClamAV is not installed, so no antivirus signatures were checked.")
    else:
        report.setdefault("engines", {})["clamav"] = {"status": "pending", "started": time.time()}
        summarize_analyzers(report)
        return True
    summarize_analyzers(report)
    return False


def clamav_apply(report, result, version=None):
    """Put a finished ClamAV scan into the report and rescore it."""
    if result["status"] in ("flagged", "nothing"):
        result.update((version or engines.clamav_version)() or {})
    report.setdefault("engines", {})["clamav"] = result
    report["findings"] = [f for f in report["findings"] if f["check"] != "antivirus"]
    if result["status"] == "flagged":
        where = (f"ClamAV {result.get('engine', '?')} via {result['tool']}, signatures "
                 f"{result.get('db_version') or '?'} ({result.get('db_date') or 'date unknown'}); bytes passed on stdin")
        for sig in result["signatures"][:5]:
            pts, kind = engines.clamav_points(sig)
            report["findings"].append(finding("antivirus", pts, f"ClamAV identifies it as {sig} ({kind})", where))
    elif result["status"] == "unavailable":
        report["limits"].append("ClamAV is not installed, so no antivirus signatures were checked.")
    elif result["status"] == "error":
        report["limits"].append(f"ClamAV could not scan it: {result['reason']}.")
    return _rescore(report)


def run_clamav(report, data, scan=None, version=None, available=None):
    """Plan and run ClamAV in one go (command line and tests; the app runs it in the background)."""
    if clamav_plan(report, available or (lambda: True)):
        clamav_apply(report, (scan or engines.clamav_scan)(data), version)
    return report


def apply_lookup(report, service, result):
    """Attach a hash-lookup result to a saved report and rescore it."""
    result = dict(result, at=time.time())
    report.setdefault("lookups", {})[service] = result
    report["findings"] = [f for f in report["findings"] if f["check"] != service]
    report["findings"] += engines.lookup_findings(service, result, finding)
    return _rescore(report)


def save(store, report, source):
    """Record an inspection in the evidence store (the report, never the file)."""
    now = time.time()
    report["inspected_at"] = now
    report["source"] = source
    with store.lock, store.db:
        cur = store.db.execute(
            "INSERT INTO inspections(name,size,sha256,md5,sha1,type,verdict,score,report,"
            "inspected_at,source) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (report["name"], report["size"], report["hashes"]["sha256"], report["hashes"]["md5"],
             report["hashes"]["sha1"], report["type"]["detected"], report["verdict"],
             report["score"], "", now, source))
        report["id"] = cur.lastrowid
        store.db.execute("UPDATE inspections SET report=? WHERE id=?",
                         (json.dumps(report), report["id"]))
    return report


def resave(store, report):
    """Store an updated report (after a hash lookup) under its existing id."""
    with store.lock, store.db:
        store.db.execute("UPDATE inspections SET report=?, verdict=?, score=? WHERE id=?",
                         (json.dumps(report), report["verdict"], report["score"], report["id"]))
    return report
