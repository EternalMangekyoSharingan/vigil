"""Vigil Files triage: is this file or archive safe to open?

One entry point, inspect_path(). It never opens a file with its default app, never
extracts an archive and never runs anything. It reads bytes, and:

1. lists an archive from its index (listing.py) and checks every entry: compression
   ratio, total declared size, entry count, depth, overlapping entries, path traversal,
   absolute paths, links, device files, setuid/setgid, duplicate names;
2. runs the File Inspector engine (inspector.py: zip-bomb measurement by streamed
   counting, PDF and Office triage, disguise checks, indicators);
3. adds disguise checks the inspector doesn't do: a program sitting in Downloads, a
   runnable file, and .desktop files that run commands.

Everything comes back in the suite's finding format with a verdict that is never "safe".
"""

import hashlib
import os
import posixpath
import re
import shlex
import stat
import time

from ..core import finding as fmt
from ..core import fixes as fx
from ..core.wording import fit_title
from . import inspector, listing
from .archives import human

TOOL = "files"
READ_MAX = 512 * 1024 * 1024          # bytes read into memory for content checks
VERDICTS = {"High": "Likely malicious", "Medium": "Suspicious"}
NOTHING = "No suspicious indicators found"
RATIO_HIGH, RATIO_MEDIUM = 1000, 100  # normal files compress about 2–10×
TOTAL_HIGH, TOTAL_MEDIUM = 100 * 2**30, 10 * 2**30
ENTRIES_HIGH, ENTRIES_MEDIUM = 100_000, 10_000
DEPTH_MEDIUM = 40
EXEC_NAMES = re.compile(r"\.(exe|scr|com|pif|bat|cmd|vbs|vbe|js|jse|wsf|ps1|msi|jar|sh|run|bin|appimage|desktop|lnk|hta)$", re.I)

# Inspector check -> plain title (≤ 60 characters).
TITLES = {
    "macro_autoexec": "Office macro runs by itself when the file opens",
    "macros": "Document contains macros",
    "macro_behaviour": "Macro code downloads or starts programs",
    "xlm_macro": "Spreadsheet contains old Excel 4 macros",
    "embedded_object": "Document has another file embedded in it",
    "remote_template": "Document loads a template from the internet",
    "remote_object": "Document loads content from the internet",
    "dde": "Document can run a command through DDE",
    "activex": "Document contains ActiveX controls",
    "rtf_object": "RTF document carries an embedded object",
    "rtf_structure": "RTF document has an unusual structure",
    "encrypted": "File is encrypted, so its contents can't be checked",
    "disguise": "File name hides what the file really is",
    "type_mismatch": "File content doesn't match its extension",
    "file_type": "This file is a program",
    "pdf_javascript": "PDF contains JavaScript",
    "pdf_autorun": "PDF does something as soon as it opens",
    "pdf_launch": "PDF can start a program",
    "pdf_embedded": "PDF has another file embedded in it",
    "pdf_obfuscation": "PDF hides parts of its structure",
    "pdf_structure": "PDF structure is unusual",
    "pdf_encrypted": "PDF is encrypted",
    "pdf_feature": "PDF uses an interactive feature",
    "decompression_bomb": "Archive expands to an enormous size (zip bomb)",
    "overlapping_entries": "Archive entries reuse the same data (zip bomb)",
    "impossible_ratio": "Archive claims an impossible compression ratio",
    "size_lie": "Archive lies about the size of its contents",
    "forged_directory": "Archive's table of contents is forged",
    "entry_flood": "Archive holds an enormous number of entries",
    "path_traversal": "Archive entry would land outside its folder",
    "symlink_member": "Archive contains a link to a file outside it",
    "html_smuggling": "Web page builds and saves a hidden file",
    "threat_intel": "File contains an address on a threat list",
    "seen_on_network": "File mentions an address this PC talked to",
    "antivirus": "ClamAV recognises this file as malware",
    "download_cradle": "Contains a PowerShell download-and-run command",
    "hidden_powershell": "Starts PowerShell hidden or with checks off",
    "pipe_to_shell": "Downloads a script and runs it straight away",
    "reverse_shell": "Contains a reverse-shell command",
    "lolbin": "Uses a Windows tool often abused by malware",
    "temp_exec": "Makes a file in a temp folder runnable",
    "persistence": "Sets something up to run again later",
}


def severity_of(points):
    return "High" if points >= 50 else "Medium" if points >= 25 else "Low" if points >= 10 else "Info"


class Triage:
    def __init__(self, path, osr=None, now=None, downloads=None):
        self.path = os.path.abspath(path)
        self.name = os.path.basename(self.path)
        self.osr = osr or {}
        self.now = now or time.time()
        self.downloads = downloads
        self.findings = []

    # ---- finding helpers ------------------------------------------------------------------

    def fixes(self, severity, archive=False):
        q = shlex.quote(self.path)
        check = [fx.option("What the file really is", "Reads the first bytes to name the type; opens nothing.",
                           "safe", [f"file -- {q}"]),
                 fx.option("Its fingerprint (SHA-256)", "Compare with a vendor's published hash, or search for it.",
                           "safe", [f"sha256sum -- {q}"])]
        if archive:
            check.append(fx.option("List the archive yourself", "bsdtar lists an archive's index without extracting.",
                                   "safe", [f"bsdtar -tvf {q}"]))
        if self.path.startswith(("/usr/", "/opt/", "/etc/")):
            check.append(fx.owner_check(self.path, fx.family(self.osr)))
        fix = []
        if severity in ("High", "Medium"):
            fix.append(fx.option("Quarantine it", "Vigil Files moves it into its quarantine folder and removes every "
                                 "permission, and remembers where it came from. Use the Quarantine button.",
                                 "settings", steps=["Press Quarantine on this file's report."],
                                 undo_steps=["Open the Quarantine tab and press Restore."]))
            fix.append(fx.option("Move it to the Trash", "Out of the way, and recoverable from the Trash.",
                                 "settings", [f"gio trash -- {q}"],
                                 undo_steps=["Open the Trash in your file manager and restore it."],
                                 lose="Nothing: the Trash keeps it until you empty it."))
        return fx.panel(self.osr, check=check, fix=fix)

    def add(self, check, title, summary, severity, strength, signal_text, *, likely=None, confidence="Medium",
            reason="", evidence=(), iocs=(), technical=(), subject=None, archive=False, extra_signals=()):
        self.findings.append(fmt.make(
            TOOL, check, fit_title([title]), summary, severity,
            signals=[fmt.signal(signal_text, strength, check)] + [fmt.signal(*s) for s in extra_signals],
            likely=likely, confidence=confidence, confidence_reason=reason,
            subject=subject or f"{self.path}:{check}:{signal_text[:80]}",
            fixes=self.fixes(severity, archive), evidence=[{"kind": "file", "value": self.path}] + list(evidence),
            iocs=iocs, technical=technical, data=self.path, when=self.now))

    # ---- 1. archive index ---------------------------------------------------------------------

    def archive(self, lst, size):
        entries = lst["entries"]
        a = dict(archive=True)
        names = [e["name"] for e in entries]
        if lst["encrypted_names"]:
            self.add("archive_encrypted", "Archive is password-protected, so it can't be checked",
                     "The archive hides even its file names behind a password, so Vigil cannot see what is inside.",
                     "Medium", 0.5, "Encrypted archive headers", reason="Common for privacy, and for slipping past scanners.",
                     likely="Malware is often sent in password-protected archives with the password in the message.", **a)
        total = lst["declared_total"]
        if lst["format"].startswith("tar.") and lst["unpacked_read"]:
            total = max(total, lst["unpacked_read"])
        ratio = total / size if size else 0
        if ratio >= RATIO_MEDIUM and total >= 2**20:
            sev = "High" if ratio >= RATIO_HIGH else "Medium"
            self.add("archive_ratio", "Archive expands far more than normal files do",
                     f"Its {human(size)} would unpack to {human(total)}, {ratio:,.0f} times its size.", sev,
                     min(1.0, ratio / (RATIO_HIGH * 10)), f"Compression ratio {ratio:,.0f}× (normal files: about 2–10×)",
                     likely="Archive bombs fill the disk or freeze the computer when unpacked; very repetitive data "
                            "(empty disk images, logs) can also compress this well.",
                     confidence="High" if sev == "High" else "Medium", reason="The ratio is measured from the index.",
                     technical=[{"label": "declared total", "value": str(lst["declared_total"])},
                                {"label": "decompressed to list", "value": str(lst["unpacked_read"])}], **a)
        if total >= TOTAL_MEDIUM:
            self.add("archive_total", f"Archive would unpack to {human(total)}",
                     f"The entries add up to {human(total)}, more than most disks have free.",
                     "High" if total >= TOTAL_HIGH else "Medium", 0.8, f"Declared total size {human(total)}",
                     likely="Either a disk image or backup, or a bomb.", reason="Sizes come from the archive's own index.", **a)
        if len(entries) >= ENTRIES_MEDIUM:
            self.add("archive_entries", f"Archive holds {len(entries):,} entries" + ("" if lst["complete"] else " or more"),
                     "Unpacking this many files can take a very long time and exhaust the file system.",
                     "High" if len(entries) >= ENTRIES_HIGH else "Medium", 0.6, f"{len(entries):,} entries",
                     likely="Large source trees do this; so do entry-flood bombs.", reason="Counted from the index.", **a)
        deepest = max((n.strip("/").count("/") + 1 for n in names), default=0)
        if deepest >= DEPTH_MEDIUM:
            self.add("archive_depth", f"Folders inside nest {deepest} levels deep",
                     f"One entry sits {deepest} folders deep, which breaks or slows many tools that unpack it.", "Medium", 0.5,
                     f"Path depth {deepest}", reason="Real projects rarely nest this deep.", **a)
        for x, y in lst["overlaps"][:1]:
            self.add("archive_overlap", "Archive entries reuse the same data (zip bomb)",
                     f"{len(lst['overlaps'])} entries point into data that belongs to another entry, a trick of "
                     "overlapping zip bombs.", "High", 1.0, f"{x} and {y} share data",
                     likely="Normal zip tools never write overlapping entries.", confidence="High",
                     reason="Overlap is measured from the offsets in the index.",
                     technical=[{"label": "overlapping pairs", "value": str(len(lst["overlaps"]))}], **a)
        seen, dups = set(), []
        for n in names:
            k = n.rstrip("/").lower()
            if k in seen:
                dups.append(n)
            seen.add(k)
        if dups:
            self.add("archive_duplicates", "Archive has several entries with the same name",
                     f"{len(dups)} names appear more than once, so a later entry silently replaces an earlier one.",
                     "Medium", 0.5, f"Duplicate names: {', '.join(dups[:3])}",
                     likely="Used to show one file to a scanner and unpack another.", reason="Rare in honest archives.", **a)
        self._entries(entries, a)

    def _entries(self, entries, a):
        groups = {}
        for e in entries:
            n = e["name"]
            p = n.replace("\\", "/")
            norm = posixpath.normpath(p)
            if p.startswith("/") or re.match(r"^[A-Za-z]:/", p):
                groups.setdefault("abs", []).append(n)
            elif norm == ".." or norm.startswith("../"):
                groups.setdefault("trav", []).append(n)
            t, mode = e["type"], e["mode"] or 0
            if t in ("symlink", "hardlink") and e.get("link") is not None:
                target = e["link"].replace("\\", "/")
                inside = posixpath.normpath(posixpath.join(posixpath.dirname(norm), target))
                if target.startswith("/") or inside == ".." or inside.startswith("../"):
                    groups.setdefault("escape", []).append(f"{n} → {e['link']}")
                else:
                    groups.setdefault("link", []).append(n)
            elif t in ("symlink", "hardlink"):
                groups.setdefault("link", []).append(n)
            if t in ("chardev", "blockdev"):
                groups.setdefault("dev", []).append(n)
            if t == "fifo":
                groups.setdefault("fifo", []).append(n)
            if t == "file" and mode & (stat.S_ISUID | stat.S_ISGID):
                groups.setdefault("suid", []).append(f"{n} ({oct(mode & 0o7777)[2:]})")
            if t == "file" and (mode & 0o111 or EXEC_NAMES.search(n)):
                groups.setdefault("exec", []).append(n)
        rules = {  # (check, title, severity, strength, (one, many))
            "abs": ("archive_absolute", "Archive entry has an absolute path", "High", 0.9,
                    ("{x} has an absolute path, so unpacking it could overwrite a system or home file.",
                     "{n} entries, such as {x}, have absolute paths, so unpacking could overwrite system or home files.")),
            "trav": ("archive_traversal", "Archive entry would land outside its folder", "High", 1.0,
                     ("{x} uses a ../ path, which climbs out of the folder you unpack into.",
                      "{n} entries, such as {x}, use ../ paths, which climb out of the folder you unpack into.")),
            "escape": ("archive_link_escape", "Archive contains a link out of its folder", "High", 0.9,
                       ("The link {x} points outside the archive, so a file written through it lands elsewhere.",
                        "{n} links, such as {x}, point outside the archive, so files written through them land elsewhere.")),
            "dev": ("archive_device", "Archive contains device files", "High", 0.9,
                    ("{x} is a device file, which ordinary archives never contain.",
                     "{n} entries, such as {x}, are device files, which ordinary archives never contain.")),
            "suid": ("archive_setuid", "Archive contains a program set to run as its owner", "High", 0.8,
                     ("{x} has the setuid or setgid bit, which makes it run with its owner's rights.",
                      "{n} files, such as {x}, have the setuid or setgid bit, which makes them run with their owner's rights.")),
            "fifo": ("archive_fifo", "Archive contains a named pipe", "Medium", 0.5,
                     ("{x} is a named pipe, which can hang tools that unpack it.",
                      "{n} entries, such as {x}, are named pipes, which can hang tools that unpack them.")),
            "link": ("archive_link", "Archive contains links", "Low", 0.2,
                     ("{x} is a link that stays inside the archive.",
                      "{n} entries, such as {x}, are links that stay inside the archive.")),
            "exec": ("archive_programs", "Archive contains programs or scripts", "Low", 0.3,
                     ("{x} is a program or script.", "{n} entries, such as {x}, are programs or scripts.")),
        }
        for key, (check, title, sev, st, summary) in rules.items():
            items = groups.get(key)
            if not items:
                continue
            self.add(check, title, summary[len(items) > 1].format(n=len(items), x=items[0]), sev, st,
                     f"{len(items)} × {check.removeprefix('archive_')}: {items[0]}",
                     likely={"abs": "A path-traversal ('zip slip') trick, or a careless backup.",
                             "trav": "A path-traversal ('zip slip') trick: honest archives use relative paths.",
                             "escape": "Links out of an archive are a classic way to overwrite files on unpack.",
                             "dev": "Device files let an archive reach hardware or kernel interfaces when unpacked as root.",
                             "suid": "A setuid program unpacked as root gives anyone who runs it root rights.",
                             "fifo": "Rare outside system backups.", "link": "Normal in source archives.",
                             "exec": "Normal for software downloads; check that you expected a program."}[key],
                     confidence="High" if sev == "High" else "Low", reason="Read from the archive's own index.",
                     evidence=[{"kind": "entry", "value": x} for x in items[:10]], **a)

    # ---- 2. the File Inspector engine ---------------------------------------------------------------

    def inspector(self, rep):
        iocs = [{"type": {"ip": "ipv4"}.get(i["type"], i["type"]), "value": i["value"]} for i in rep.get("iocs", [])
                if i["type"] in ("ip", "ipv4", "ipv6", "domain", "url", "email", "md5", "sha1", "sha256")]
        # The same minor note about many archive members reads as one finding, not fifteen.
        groups = {}
        for f in rep["findings"]:
            if severity_of(f["points"]) in ("Low", "Info"):
                groups.setdefault((f["check"], f["points"]), []).append(f)
        merged = set()
        for (check, points), fs in groups.items():
            if len(fs) < 3:
                continue
            merged.update(id(f) for f in fs)
            where = [f["data"] for f in fs]
            self.add(f"inspector_{check}", TITLES.get(check) or fs[0]["reason"].split(" (")[0],
                     f"{len(fs)} parts of this file have the same note, for example: {fs[0]['reason'].rstrip('.')}.",
                     severity_of(points), min(1.0, points / 60), f"{len(fs)} × {fs[0]['reason'][:120]}",
                     confidence="Low", reason="Found in the file's bytes by the File Inspector.",
                     technical=[{"label": "where", "value": " | ".join(w[:80] for w in where[:12])}],
                     subject=f"{self.path}:{check}:grouped", archive=rep["type"]["detected"] in inspector.ARCHIVE_FAMILIES)
        for f in rep["findings"]:
            if id(f) in merged:
                continue
            sev = severity_of(f["points"])
            title = TITLES.get(f["check"]) or f["reason"].split(" (")[0]
            if f["check"] == "file_type" and f["points"] < 15:
                title = "This kind of file runs code when opened"
            reason = f["reason"].rstrip(".")
            summary = reason[0].upper() + reason[1:] + "."
            if not fmt.wording.one_sentence(summary):
                summary = re.split(r"(?<=[a-z0-9)])[.;:]\s", reason)[0].rstrip(".") + "."
            self.add(f"inspector_{f['check']}", title, summary, sev, min(1.0, f["points"] / 60),
                     f["reason"][:160], likely=f.get("means"), confidence="High" if sev == "High" else "Medium" if sev != "Info" else "Low",
                     reason="Found in the file's bytes by the File Inspector.",
                     iocs=iocs if sev in ("High", "Medium") else (),
                     technical=[{"label": "where", "value": f["data"]}, {"label": "points", "value": str(f["points"])}],
                     subject=f"{self.path}:{f['check']}:{f['data'][:120]}",
                     archive=rep["type"]["detected"] in inspector.ARCHIVE_FAMILIES)

    # ---- 3. more disguise checks ----------------------------------------------------------------------

    def disguise(self, st, head, family):
        program = family in inspector.EXECUTABLE_FAMILIES or head.startswith(b"#!")
        runnable = bool(st.st_mode & 0o111)
        if self.downloads and self.path.startswith(self.downloads.rstrip("/") + "/") and (program or runnable):
            self.add("downloads_program", "A program is waiting in your Downloads folder",
                     f"{self.name} is {'a program' if program else 'marked runnable'} and sits in Downloads, "
                     "where you might start it by double-clicking.", "Medium", 0.6,
                     "Program file in Downloads" + (" with the executable bit set" if runnable else ""),
                     likely="Fine if you downloaded an installer on purpose; otherwise find out where it came from.",
                     reason="Downloads is where unwanted programs arrive.")
        if self.name.endswith(".desktop") or head.startswith(b"[Desktop Entry]"):
            self.desktop_entry(head.decode("utf-8", "replace"))

    def desktop_entry(self, text):
        execs = re.findall(r"^\s*Exec\s*=\s*(.+)$", text, re.M)
        shown = (re.findall(r"^\s*Name\s*=\s*(.+)$", text, re.M) or [""])[0].strip()
        for cmd in execs:
            bad = re.search(r"\b(curl|wget|base64|nc|ncat|socat)\b|\|\s*(ba|z)?sh\b|\b(ba|z)?sh\s+-c\b|"
                            r"\bpython[0-9.]*\s+-c\b|\bperl\s+-e\b|/dev/tcp|/tmp/|/\.cache/|/Downloads/|\$\(", cmd)
            if bad:
                self.add("desktop_command", "Launcher file runs a hidden command",
                         f"This .desktop file looks like '{shown or self.name}' but runs: {cmd[:140]}.", "High", 0.9,
                         f"Exec= uses {bad.group(0).strip()}",
                         likely="A launcher that downloads, decodes or runs a shell is a known Linux phishing trick.",
                         confidence="High", reason="Honest launchers start an installed program.",
                         evidence=[{"kind": "Exec", "value": cmd[:300]}], subject=f"{self.path}:desktop:{cmd[:80]}")
            elif self.downloads and self.path.startswith(self.downloads.rstrip("/") + "/"):
                self.add("desktop_download", "A launcher file arrived in Downloads",
                         f"This .desktop file runs '{cmd[:100]}' when double-clicked, even though it may look like a document.",
                         "Medium", 0.5, "Launcher (.desktop) in Downloads",
                         likely="Launchers are not documents; file managers may run them on double-click.",
                         reason="Rarely downloaded on purpose.", evidence=[{"kind": "Exec", "value": cmd[:300]}])
        if shown and re.search(r"\.(pdf|docx?|xlsx?|jpe?g|png|txt|odt)\b", shown, re.I):
            self.add("desktop_disguise", "Launcher pretends to be a document",
                     f"It shows the name '{shown}', which looks like a document, but it is a launcher.", "High", 0.8,
                     f"Name= {shown}", confidence="High", reason="A document name on a launcher has no honest use.",
                     likely="Phishing launchers pose as invoices and photos.")


def inspect_path(path, osr=None, now=None, downloads=None, clamav=None):
    """Full triage of one file. Returns a report dict (see module docstring)."""
    t = Triage(path, osr, now, downloads)
    st = os.lstat(t.path)
    rep = {"tool": TOOL, "path": t.path, "name": t.name, "size": st.st_size, "mode": oct(st.st_mode & 0o7777),
           "listing": None, "limits": [], "inspected_at": t.now}
    if stat.S_ISLNK(st.st_mode):
        target = os.readlink(t.path)
        t.add("is_link", "This is a link to another file",
              f"{t.name} is a symbolic link to {target}; Vigil did not follow it.", "Low", 0.2, f"Link to {target}",
              reason="Links are normal; check the target instead.")
        rep.update(findings=t.findings, verdict=NOTHING, type={"description": "symbolic link"}, hashes={})
        return rep
    if not stat.S_ISREG(st.st_mode):
        raise ValueError(f"{t.path} is not a regular file")
    with open(t.path, "rb") as fh:
        data = fh.read(READ_MAX)
    full = len(data) == st.st_size
    sha = hashlib.sha256(data)
    if not full:
        with open(t.path, "rb") as fh:
            fh.seek(len(data))
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                sha.update(chunk)
        rep["limits"].append(f"Only the first {READ_MAX // 2**20} MB were read for content checks; the hash covers it all.")
    ins = inspector.inspect_bytes(data, t.name)
    if clamav:
        clamav(ins, data)
    rep["inspector"] = {k: ins[k] for k in ("score", "verdict", "type", "details", "iocs", "limits", "hashes")
                        if k in ins}
    rep["type"] = ins["type"]
    rep["hashes"] = dict(ins["hashes"], sha256=sha.hexdigest())
    t.inspector(ins)
    lst = listing.list_archive(t.path)
    if lst:
        rep["listing"] = dict(lst, entries=lst["entries"][:2000], truncated=len(lst["entries"]) > 2000)
        t.archive(lst, st.st_size)
        rep["limits"] += lst["notes"]
    t.disguise(st, data[:65536], ins["type"]["detected"])
    worst = fmt.worst([f for f in t.findings if f["severity"] != "Info"])
    rep["findings"] = fmt.sort(_dedupe(t.findings))
    rep["verdict"] = VERDICTS.get(worst, NOTHING)
    rep["counts"] = {s: sum(f["severity"] == s for f in rep["findings"]) for s in fmt.SEVERITIES}
    rep["limits"] = list(dict.fromkeys(rep["limits"] + ins["limits"] + [
        "The archive was listed from its index; nothing was extracted to disk."] * bool(lst)))
    return rep


# The inspector and the index checks sometimes see the same thing; keep the stronger one.
SAME = {"archive_traversal": "inspector_path_traversal", "archive_overlap": "inspector_overlapping_entries",
        "archive_link_escape": "inspector_symlink_member", "archive_entries": "inspector_entry_flood",
        "archive_ratio": "inspector_decompression_bomb"}


def _dedupe(findings):
    by = {f["check"]: f for f in findings}
    drop = set()
    for mine, theirs in SAME.items():
        if mine in by and theirs in by:
            a, b = by[mine], by[theirs]
            drop.add(id(b) if fmt.SEVERITY_RANK[a["severity"]] >= fmt.SEVERITY_RANK[b["severity"]] else id(a))
    return [f for f in findings if id(f) not in drop]


def preview(path, limit=64 * 1024):
    """Safe preview: plain text only, at most `limit` bytes, never rendered. Anything that
    isn't text gets no preview at all (image and document parsers are where exploits live)."""
    with open(path, "rb") as fh:
        data = fh.read(limit + 1)
    fam = inspector.detect_type(data[:limit])
    if fam not in inspector.TEXT_FAMILIES or b"\0" in data[:limit]:
        return {"kind": "none", "why": "Not plain text. Vigil never renders images, documents or programs, "
                                       "because their parsers are where exploits live."}
    return {"kind": "text", "text": data[:limit].decode("utf-8", "replace"), "truncated": len(data) > limit}
