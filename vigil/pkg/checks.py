"""Static review of a PKGBUILD folder: every check in docs/SUITE.md ("Vigil Pkg").

Input is text only (PKGBUILD, .install files, .SRCINFO, other small files). Nothing is
run, sourced, built or downloaded here; `makepkg` is never called.

The review returns findings in the suite's format plus a verdict:
    Don't install       at least one High finding
    Review these lines  at least one Medium finding
    Looks normal        nothing above Low; never "safe"
"""

import difflib
import ipaddress
import re
import shlex
import time
import urllib.parse

from ..core import finding as fmt
from ..core import fixes as fx
from ..core.wording import fit_title
from . import names, parse

TOOL = "pkg"
VERDICTS = {"High": "Don't install", "Medium": "Review these lines"}
LOOKS_NORMAL = "Looks normal"

PASTEBINS = ("pastebin.com", "paste.ee", "hastebin.com", "hastebin.skyra.pw", "ghostbin.com", "ghostbin.co",
             "rentry.co", "rentry.org", "termbin.com", "dpaste.com", "dpaste.org", "controlc.com", "privatebin.net",
             "pastes.dev", "paste.rs", "bpa.st", "ix.io", "sprunge.us", "paste.c-net.org", "justpaste.it",
             "pastebin.pl", "paste.mozilla.org", "katb.in", "0bin.net", "paste.debian.net", "pastie.org")
SHORTENERS = ("bit.ly", "tinyurl.com", "t.co", "is.gd", "goo.gl", "cutt.ly", "rebrand.ly", "shorturl.at", "rb.gy",
              "ow.ly", "tiny.cc", "v.gd", "buff.ly", "t.ly", "s.id", "shorturl.gg", "lnkd.in", "1drv.ms", "git.io")
FILE_HOSTS = ("dropbox.com", "dropboxusercontent.com", "drive.google.com", "docs.google.com", "mega.nz", "mega.co.nz",
              "mediafire.com", "anonfiles.com", "gofile.io", "files.catbox.moe", "litter.catbox.moe", "0x0.st",
              "transfer.sh", "wetransfer.com", "sendspace.com", "pixeldrain.com", "file.io", "uploadfiles.io",
              "cdn.discordapp.com", "media.discordapp.net", "onedrive.live.com", "filebin.net", "temp.sh",
              "bashupload.com", "oshi.at", "krakenfiles.com", "workupload.com")
# Forges, registries and mirrors that host many projects: a source there is normal even
# when the project's url= is elsewhere.
COMMON_HOSTS = ("github.com", "githubusercontent.com", "codeload.github.com", "gitlab.com", "codeberg.org",
                "sourceforge.net", "sf.net", "pythonhosted.org", "pypi.org", "pypi.io", "npmjs.org", "crates.io",
                "rubygems.org", "bitbucket.org", "launchpad.net", "kernel.org", "gnu.org", "gnome.org", "kde.org",
                "freedesktop.org", "archlinux.org", "debian.org", "ubuntu.com", "fedoraproject.org", "mozilla.org",
                "mozilla.net", "googleapis.com", "dl.google.com", "golang.org", "go.dev", "sr.ht", "savannah.nongnu.org",
                "nongnu.org", "apache.org", "hackage.haskell.org", "cpan.org", "metacpan.org", "nodejs.org",
                "python.org", "rust-lang.org", "gitea.com", "notabug.org", "pagure.io", "salsa.debian.org",
                "electronjs.org", "nvidia.com", "jetbrains.com", "microsoft.com", "visualstudio.com", "flathub.org")
BINARY_EXT = (".deb", ".rpm", ".appimage", ".exe", ".bin", ".run", ".jar", ".msi", ".apk", ".pkg.tar.zst",
              ".pkg.tar.xz", ".snap", ".flatpak")
BUILD_FUNCS = ("prepare", "build", "check", "package", "pkgver")
INSTALL_FUNCS = ("pre_install", "post_install", "pre_upgrade", "post_upgrade", "pre_remove", "post_remove")
RC_FILES = re.compile(r"(\.bashrc|\.bash_profile|\.bash_login|\.profile|\.zshrc|\.zprofile|\.zshenv|\.zlogin|"
                      r"config\.fish|\.xinitrc|\.xprofile|\.config/autostart|\.config/systemd/user|\.ssh/authorized_keys|"
                      r"\.config/environment\.d)")
SENSITIVE = re.compile(r"(/etc/sudoers|/etc/ld\.so\.preload|/etc/pam\.d|/etc/cron|/var/spool/cron|/etc/profile|"
                       r"/etc/bash\.bashrc|/etc/environment|/etc/ssh/|/root/|authorized_keys|/etc/systemd/system/|"
                       r"/etc/xdg/autostart|/etc/udev/rules\.d|/etc/modules-load\.d|/etc/rc\.local)")
SAFE_ROOTS = ("$pkgdir", "${pkgdir}", '"$pkgdir', '"${pkgdir}', "$srcdir", "${srcdir}", '"$srcdir', '"${srcdir}',
              "$startdir", "${startdir}", '"$startdir', '"${startdir}', "/dev/null", "/dev/stdout", "/dev/stderr")

DOWNLOADER = r"(curl|wget|aria2c|axel|fetch|lynx\s+-source|links\s+-source)"
PATTERNS = [
    # (check, regex, severity, strength, title, summary, likely)
    ("pipe_to_shell", re.compile(rf"\b{DOWNLOADER}\b[^|;&]*\|\s*(sudo\s+)?(env\s+)?(ba|z|da|k|fi)?sh\b|"
                                 rf"\b{DOWNLOADER}\b[^|;&]*\|\s*(sudo\s+)?(python[0-9.]*|perl|ruby|node|php)\b"),
     "High", 1.0, "Downloads a script and runs it straight away",
     "This line pipes a download straight into a shell, so whatever the server sends is run.",
     "Legitimate packages list files in source= with checksums; piping a download into a shell skips all checks."),
    ("run_substitution", re.compile(rf"(ba|z)?sh\s+<\(\s*{DOWNLOADER}|(ba|z)?sh\s+-c\s+[\"']?\$\(\s*{DOWNLOADER}|"
                                    rf"(source|\.)\s+<\(\s*{DOWNLOADER}"),
     "High", 1.0, "Downloads a script and runs it straight away",
     "This line runs the output of a download as a script.",
     "Legitimate packages list files in source= with checksums; this runs unchecked code."),
    ("dev_tcp", re.compile(r"/dev/(tcp|udp)/"),
     "High", 0.9, "Opens a raw network connection from bash",
     "This line uses bash's /dev/tcp trick to talk to a server directly, a common reverse-shell technique.",
     "Build scripts have no reason to open raw connections."),
    ("decode_and_run", re.compile(r"(base64\s+(-d|--decode|-D)|openssl\s+(enc\s+)?(-d|-base64\s+-d)|xxd\s+-r|"
                                  r"\bgunzip\s+-c|\bzcat)\b[^\n]*\|\s*(sudo\s+)?(ba|z|da)?sh\b"),
     "High", 1.0, "Decodes hidden text and runs it as a script",
     "This line decodes hidden data and runs the result as a script.",
     "Hiding code in encoded text is how malicious packages avoid review."),
    ("decode", re.compile(r"base64\s+(-d|--decode|-D)\b|openssl\s+(enc\s+)?-d\b|\bxxd\s+-r\b|printf\s+['\"](\\x[0-9a-fA-F]{2}){8,}"),
     "Medium", 0.6, "Decodes hidden text during the build",
     "This line decodes encoded data, which hides what it really contains from a reader.",
     "Sometimes used for embedded icons or keys; also used to hide commands."),
    ("eval", re.compile(r"(^|[;&|({\s])eval\s"),
     "Medium", 0.6, "Builds a command from text and runs it",
     "This line uses eval, which runs text as a command, so the real command is hard to see.",
     "eval is rare in packaging and makes review unreliable."),
    ("download_to_tmp", re.compile(rf"\b{DOWNLOADER}\b[^\n]*(-o|-O|--output|>)\s*[\"']?/tmp/"),
     "Medium", 0.7, "Downloads a file to the temp folder while building",
     "This line saves a download to /tmp, outside the build folder and outside the checksums.",
     "Sources belong in source= so makepkg checks them."),
]
NET_IN_BUILD = [
    ("network_in_build", re.compile(rf"(^|[;&|`(]\s*|\$\(\s*|sudo\s+)\s*{DOWNLOADER}\s"), "Medium", 0.7,
     "Downloads files while building, outside source=",
     "This line downloads during the build, where makepkg's checksums don't cover it."),
    ("network_in_build", re.compile(r"\bgit\s+(clone|fetch|pull|ls-remote)\b"), "Medium", 0.6,
     "Fetches code with git while building, outside source=",
     "This line fetches code with git during the build, where makepkg's checksums don't cover it."),
    ("network_in_build", re.compile(r"\b(pip[0-9.]*|python[0-9.]*\s+-m\s+pip)\s+install\b"), "Medium", 0.6,
     "Installs Python packages from the internet while building",
     "This line runs pip install during the build, which downloads code the checksums don't cover."),
    ("network_in_build", re.compile(r"\b(nc|ncat|netcat|socat|telnet)\s+[^|]*\d"), "Medium", 0.7,
     "Opens a raw network connection while building",
     "This line opens a raw network connection during the build."),
    ("registry_in_build", re.compile(r"\b(npm|yarn|pnpm|bun)\s+(install|ci|add)\b|\bgo\s+(get|install)\s+\S+@|"
                                     r"\bcargo\s+install\b|\bgem\s+install\b|\bcomposer\s+(install|require)\b"),
     "Low", 0.3, "Fetches dependencies from a public registry while building",
     "This line downloads dependencies during the build; common for JavaScript and Go apps, but not covered by checksums."),
]
INSTALL_RULES = [
    ("install_network", re.compile(rf"(^|[;&|`(]\s*|\$\(\s*)\s*({DOWNLOADER}|git\s+clone|pip[0-9.]*\s+install)\b"),
     "High", 0.9, "Downloads something when the package is installed",
     "The install script downloads files as root when pacman installs the package."),
    ("install_service", re.compile(r"\bsystemctl\s+(--now\s+)?(enable|start|restart|reenable)\b|\bsystemctl\s+[^;|&]*--now\b"),
     "Medium", 0.6, "Turns on a service as soon as it is installed",
     "The install script enables or starts a service as root; Arch packages normally leave that to you."),
    ("install_user_service", re.compile(r"\bsystemctl\s+--user\b"),
     "High", 0.8, "Sets up a service in your home folder when installed",
     "The install script changes your user's services, which a system package never needs to do."),
    ("install_user_add", re.compile(r"\b(useradd|adduser|groupadd)\b"),
     "Low", 0.3, "Adds a user or group when installed",
     "The install script creates an account; common for services that run under their own user."),
    ("install_privilege", re.compile(r"\busermod\b[^\n]*-a?G\s*\S*(wheel|sudo|root|adm|docker|disk)\b|\b(chpasswd|passwd)\b"),
     "High", 0.9, "Gives an account admin rights or a password",
     "The install script adds an account to an admin group or sets a password."),
    ("install_setuid", re.compile(r"\bchmod\s+([ugoa]*\+[rwx]*s|[2467][0-7]{3})\b"),
     "High", 0.8, "Makes a program run with admin rights for anyone",
     "The install script sets the setuid bit, so the program always runs as its owner (usually root)."),
    ("install_cron", re.compile(r"\bcrontab\b|/etc/cron|/var/spool/cron"),
     "High", 0.8, "Schedules a task when the package is installed",
     "The install script adds a scheduled task, which keeps something running long after install."),
    ("security_off", re.compile(r"\bsetenforce\s+0\b|\bufw\s+disable\b|\biptables\s+-F\b|\bnft\s+flush\b|"
                                r"\bsystemctl\s+(stop|disable|mask)\s+(firewalld|ufw|apparmor|auditd|nftables)\b|"
                                r"\baa-teardown\b"),
     "High", 1.0, "Switches off a security feature when installed",
     "The install script turns off the firewall or another security feature."),
]


# ---- the review --------------------------------------------------------------------------

class Review:
    def __init__(self, files, folder=None, osr=None, trusted=None, aur=None, now=None):
        self.files = files                    # {relative name: text}
        self.folder = folder
        self.osr = osr or {}
        self.trusted = trusted                # {"files": {...}, "maintainers": [...], "version": ..., "ts": ...}
        self.aur = aur                        # AUR RPC info (opt-in), or None
        self.now = now or time.time()
        self.pkgbuild = parse.Script(files.get("PKGBUILD", ""), "PKGBUILD")
        self.findings = []
        self.seen = set()
        self.added = self._added_lines()

    # ---- helpers ---------------------------------------------------------------------------

    @property
    def pkgbase(self):
        return self.pkgbuild.get("pkgbase") or self.pkgname

    @property
    def pkgname(self):
        n = self.pkgbuild.get("pkgname")
        return (n[0] if isinstance(n, list) and n else n) or "unknown"

    def pkgnames(self):
        n = self.pkgbuild.get("pkgname")
        return n if isinstance(n, list) else [n] if n else []

    def _added_lines(self):
        """{file: set(line numbers)} that are new since the trusted version."""
        if not self.trusted:
            return None
        out = {}
        for name, text in self.files.items():
            old = (self.trusted.get("files") or {}).get(name)
            new_lines = text.split("\n")
            if old is None:
                out[name] = set(range(1, len(new_lines) + 1))
                continue
            sm = difflib.SequenceMatcher(None, old.split("\n"), new_lines, autojunk=False)
            out[name] = {j + 1 for tag, _, _, j1, j2 in sm.get_opcodes() if tag in ("replace", "insert")
                         for j in range(j1, j2)}
        return out

    def is_new(self, file, line):
        return bool(self.added and line in self.added.get(file, ()))

    def text_of(self, file, line):
        return self.files.get(file, "").replace("\r\n", "\n").split("\n")[line - 1].strip() if line else ""

    def path_of(self, file):
        return f"{self.folder.rstrip('/')}/{file}" if self.folder else file

    def fixes(self, severity, file=None, line=None, extra_check=()):
        check = list(extra_check)
        if file and line and self.folder:
            check.insert(0, fx.option(f"Show line {line} of {file}",
                                      "Prints just that line, so you can read it yourself.", "safe",
                                      [f"sed -n '{line}p' {shlex.quote(self.path_of(file))}"]))
        fix = []
        if severity == "High" and self.folder:
            fix.append(fx.option("Don't build it: delete the folder",
                                 f"Removes the downloaded build files for {self.pkgbase}. Nothing was built or installed.",
                                 "deletes", [f"rm -r {shlex.quote(self.folder.rstrip('/'))}"],
                                 [f"git clone https://aur.archlinux.org/{self.pkgbase}.git "
                                  f"{shlex.quote(self.folder.rstrip('/'))}"],
                                 lose="Only this copy of the build files."))
        if severity in ("High", "Medium"):
            fix.append(fx.option("Ask, or report it on the AUR",
                                 "The AUR page has comments and a request form for packages that look wrong.",
                                 "safe", steps=[f"Open https://aur.archlinux.org/packages/{self.pkgbase}",
                                                "Read the comments: others may have noticed the same line.",
                                                "If it looks malicious, use 'Submit Request' → Deletion, and say which line."]))
        return fx.panel(self.osr, check=check, fix=fix)

    def add(self, check, title, summary, severity, strength, signal_text, *, file=None, line=None, likely=None,
            confidence="Medium", reason="", iocs=(), extra_signals=(), subject=None, technical=(), fixes=None):
        key = (check, file, line, subject)
        if key in self.seen:
            return
        self.seen.add(key)
        signals = [fmt.signal(signal_text, strength, check)] + [fmt.signal(*s) for s in extra_signals]
        evidence = []
        if file:
            evidence.append({"kind": "line" if line else "file", "value": f"{file}:{line}" if line else file,
                             "note": self.text_of(file, line)[:300] if line else None})
            if line and self.is_new(file, line):
                signals.append(fmt.signal("This line is new since the version you approved", 0.4, "changed"))
        subject = subject or f"{self.pkgbase}:{file}:{line}:{check}"
        self.findings.append(fmt.make(
            TOOL, check, fit_title([title]), summary, severity, signals=signals, likely=likely,
            confidence=confidence, confidence_reason=reason, subject=subject,
            fixes=fixes if fixes is not None else self.fixes(severity, file, line),
            evidence=evidence, iocs=iocs, data=f"{file}:{line}" if file else "package metadata",
            when=self.now, technical=[{"label": "package", "value": self.pkgbase}] + list(technical),
            tags=["new"] if file and line and self.is_new(file, line) else []))

    # ---- run all checks --------------------------------------------------------------------

    def run(self):
        if "PKGBUILD" not in self.files:
            raise ValueError("no PKGBUILD in this folder")
        self.check_names()
        self.check_sources()
        self.check_checksums()
        self.check_top_level()
        self.check_lines(self.pkgbuild)
        for name in self.install_files():
            self.check_install(name)
        self.check_other_files()
        self.check_history()
        self.check_aur()
        return self.report()

    def install_files(self):
        named = self.pkgbuild.get("install")
        out = [n for n in self.files if n.endswith(".install")]
        if isinstance(named, str) and named in self.files and named not in out:
            out.append(named)
        return sorted(out)

    # ---- 1. names ----------------------------------------------------------------------------

    def check_names(self):
        for n in self.pkgnames():
            if n.lower() in names.HIJACKED:
                inc = next(i for i in names.INCIDENTS if i["id"] == names.HIJACKED[n.lower()])
                self.add("known_hijacked", "This package was taken over during an AUR malware wave",
                         f"{n} was named in reporting on {inc['what']} ({inc['start']} to {inc['end']}).", "Medium", 0.6,
                         f"{n} is on Vigil's list of hijacked AUR packages", file="PKGBUILD",
                         line=self.pkgbuild.vars.get("pkgname", {}).get("line"),
                         likely="The project is real; for a few days its AUR package was not. Read the diff since the "
                                "version you trust, and check the maintainer.",
                         confidence="Medium", reason="Taken from public reporting on the incident.")
            hit = names.check(n)
            if not hit:
                continue
            line = self.pkgbuild.vars.get("pkgname", {}).get("line")
            if hit["kind"] == "known":
                self.add("known_malicious", fit_title([f"Has the name of a known malicious package ({n})",
                                                       "Has the name of a known malicious package"]),
                         f"The name {n} belongs to a package that was {hit['why']}.", "High", 1.0,
                         f"{n} is on Vigil's list of malicious AUR names", file="PKGBUILD", line=line,
                         likely="A re-upload of the same malware, or a new package reusing the name.",
                         confidence="High", reason="The exact name was used for malware before.")
            elif hit["kind"] == "bait":
                self.add("lookalike_name", f"Name copies {hit['like']} and adds '{hit['word']}'",
                         f"The name {n} looks like the popular {hit['like']} package with '{hit['word']}' added.",
                         "Medium" if hit["strength"] < 0.85 else "High", hit["strength"],
                         f"Popular name {hit['like']} plus the word '{hit['word']}'", file="PKGBUILD", line=line,
                         likely="Malicious uploads in July 2025 used exactly this pattern (librewolf-fix-bin, "
                                "firefox-patch-bin); some honest forks do too.",
                         confidence="Medium", reason="The name pattern alone is suggestive, not proof.")
            else:
                self.add("lookalike_name", f"Name is one letter away from {hit['like']}",
                         f"The name {n} differs from the popular {hit['like']} package by a single letter.",
                         "Medium", hit["strength"], f"{n} is a near-copy of {hit['like']}", file="PKGBUILD", line=line,
                         likely="A typo-squat waiting for someone to mistype, or an unrelated project with a close name.",
                         confidence="Low", reason="Close names are often honest.")

    # ---- 2. sources --------------------------------------------------------------------------

    @staticmethod
    def host_of(url):
        try:
            return (urllib.parse.urlsplit(url).hostname or "").lower()
        except ValueError:
            return ""

    @staticmethod
    def matches(host, domains):
        return any(host == d or host.endswith("." + d) for d in domains)

    @staticmethod
    def site(host):
        parts = host.split(".")
        return ".".join(parts[-3:]) if len(parts) > 2 and len(parts[-2]) <= 3 and len(parts[-1]) == 2 else ".".join(parts[-2:])

    def check_sources(self):
        project = self.host_of(self.pkgbuild.get("url") or "")
        for s in parse.source_entries(self.pkgbuild):
            if s["kind"] == "local":
                continue
            url, host = s["url"], self.host_of(s["url"])
            ioc = [{"type": "url", "value": url.split("#")[0]}]
            try:
                ipaddress.ip_address(host.strip("[]"))
                ip = True
            except ValueError:
                ip = False
            if ip:
                self.add("source_raw_ip", "Downloads a source file from a bare IP address",
                         f"A source is fetched from {host}, an address with no domain name behind it.", "Medium", 0.7,
                         f"Source from a bare IP address ({host})", file="PKGBUILD", line=s["line"], iocs=ioc,
                         likely="Real projects publish downloads on named sites; bare IPs are typical of throwaway servers.",
                         reason="Unusual, but some self-hosted projects do this.")
            elif self.matches(host, PASTEBINS):
                self.add("source_pastebin", "Downloads part of the build from a pastebin",
                         f"A source is fetched from {host}, a pastebin where anyone can post and change text.", "High", 0.9,
                         f"Source hosted on a pastebin ({host})", file="PKGBUILD", line=s["line"], iocs=ioc,
                         likely="Pastebins are a favourite place to host a second-stage script.",
                         confidence="High", reason="Packages have no reason to build from pastebin text.")
            elif self.matches(host, SHORTENERS):
                self.add("source_shortener", "Downloads from a link shortener that hides the real site",
                         f"A source goes through {host}, a link shortener, so the real download site is hidden.", "High", 0.85,
                         f"Source behind a link shortener ({host})", file="PKGBUILD", line=s["line"], iocs=ioc,
                         likely="Shorteners hide where a file really comes from and can be re-pointed later.",
                         confidence="High", reason="Shortened links are not used in honest packaging.")
            elif self.matches(host, FILE_HOSTS):
                self.add("source_file_host", "Downloads from a personal file-sharing site",
                         f"A source is fetched from {host}, a file-sharing service, not the project's own site.", "Medium", 0.7,
                         f"Source on a personal file host ({host})", file="PKGBUILD", line=s["line"], iocs=ioc,
                         likely="Some small projects do this; it is also how malware gets hosted cheaply.",
                         reason="Possible either way; check who uploaded it.")
            elif project and host and self.site(host) != self.site(project) and not self.matches(host, COMMON_HOSTS) \
                    and not self.matches(project, COMMON_HOSTS):
                self.add("source_other_site", f"Downloads from {self.site(host)}, not the project's site",
                         f"The project's page is {project}, but a source comes from {host}.", "Low", 0.3,
                         f"Source site {host} differs from url= ({project})", file="PKGBUILD", line=s["line"], iocs=ioc,
                         likely="Often a mirror or CDN; worth a glance.", confidence="Low",
                         reason="Mirrors and CDNs are common.")
            if url.startswith("http://") and s["kind"] == "url":
                skip = all((v or "").upper() == "SKIP" for v in s["sums"].values()) or not s["sums"]
                self.add("source_plain_http", "Downloads a source over plain HTTP",
                         f"A source is fetched without encryption from {host}"
                         + (", and nothing checks what arrives." if skip else ", though its checksum is checked."),
                         "Medium" if skip else "Low", 0.6 if skip else 0.2, "Unencrypted download (http://)",
                         file="PKGBUILD", line=s["line"], iocs=ioc,
                         likely="Old project sites still use http; anyone on the network path could swap the file.",
                         reason="With a checksum the swap would be caught; without one it would not." )

    # ---- 3. checksums ------------------------------------------------------------------------

    def check_checksums(self):
        entries = [s for s in parse.source_entries(self.pkgbuild) if s["kind"] == "url"]
        if not entries:
            return
        binary = self.pkgname.endswith("-bin")
        any_sums = any(k.endswith("sums") or "sums_" in k for k in self.pkgbuild.vars)
        for s in entries:
            vals = [v for v in s["sums"].values() if v is not None]
            if vals and not all(v.upper() == "SKIP" for v in vals):
                continue
            lower = s["url"].lower().split("?")[0]
            prebuilt = binary or lower.endswith(BINARY_EXT)
            what = "a downloaded program" if prebuilt else "a downloaded release file"
            name = s["name"] or lower.rsplit("/", 1)[-1][:40]
            self.add("checksum_skip", f"Doesn't verify {what}",
                     f"The checksum for {name} is {'missing' if not vals else 'SKIP'}, so any file the server sends is accepted.",
                     "Medium", 0.8 if prebuilt else 0.6,
                     f"{'No checksum' if not vals else 'SKIP checksum'} for a downloaded {'binary' if prebuilt else 'file'}",
                     file="PKGBUILD", line=s["line"],
                     likely="Fine for git sources, which change every commit; for a fixed release file it means a "
                            "swapped download would go unnoticed.",
                     reason="Sometimes just laziness, but it removes the one check makepkg does.",
                     technical=[{"label": "source", "value": s["raw"]}, {"label": "any checksum arrays", "value": str(any_sums)}])
        algs = {a.split("_")[0] for a in self.pkgbuild.vars if a.split("_")[0] in parse.SUMS}
        if algs and algs <= {"md5sums", "sha1sums", "cksums"}:
            line = min(self.pkgbuild.vars[a]["line"] for a in self.pkgbuild.vars if a.split("_")[0] in algs)
            self.add("checksum_weak", "Uses only weak checksums (MD5 or SHA-1)",
                     "Every checksum in this PKGBUILD is MD5, SHA-1 or CRC, which can be forged.", "Low", 0.3,
                     "Only MD5/SHA-1/CRC checksums", file="PKGBUILD", line=line, confidence="Low",
                     likely="Usually an old PKGBUILD that was never updated.", reason="Weak, but rarely the attack.")

    # ---- 4. top-level code (runs on reading) -------------------------------------------------

    def check_top_level(self):
        for ln in self.pkgbuild.top:
            if re.match(r"^\s*(:|true|set\s+-[eu]+|shopt\s|unset\s|[}{]|fi|then|else|done|esac|if\s|case\s|for\s|elif\s)", ln.text):
                continue
            net = re.search(DOWNLOADER + r"\s|\bgit\s+clone|/dev/tcp", ln.text)
            self.add("top_level_command", "Runs a command as soon as the PKGBUILD is read",
                     "This line sits outside every function, so it runs whenever any tool reads the PKGBUILD.",
                     "High" if net else "Medium", 0.9 if net else 0.6,
                     "Top-level command" + (" that uses the network" if net else ""), file="PKGBUILD", line=ln.no,
                     likely="AUR helpers and makepkg read the PKGBUILD before you approve anything; code here runs first.",
                     confidence="High" if net else "Medium", reason="PKGBUILDs normally only set variables outside functions.")
        for ln in self.pkgbuild.assign_lines:
            if "$(" not in ln.text and "`" not in ln.text:
                continue
            net = re.search(DOWNLOADER + r"\s|\bgit\s+(clone|ls-remote)|/dev/tcp|base64", ln.text)
            if net:
                self.add("top_level_substitution", "Fetches something while the PKGBUILD is being read",
                         "A variable here is set from a command that uses the network, which runs on every read.", "High", 0.9,
                         "Command substitution with a network or decode command at the top level", file="PKGBUILD",
                         line=ln.no, confidence="High", reason="This runs before any review step can stop it.",
                         likely="Hiding a download in a variable is a way to run code before the build starts.")
            else:
                self.add("top_level_substitution", "Sets a variable by running a command on read",
                         "A variable is set from a command's output, which runs whenever the PKGBUILD is read.", "Low", 0.3,
                         "Command substitution at the top level", file="PKGBUILD", line=ln.no, confidence="Low",
                         reason="Usually harmless (a date, a version string).",
                         likely="Common for version strings; still runs before you approve anything.")

    # ---- 5–7. lines inside functions, .install scripts ---------------------------------------

    def check_lines(self, script, in_install=False):
        lines = script.all_lines()
        for ln in lines:
            t = ln.text
            if re.match(r"^\s*[A-Za-z_]\w*sums(_\w+)?=", t):
                continue
            self.line_patterns(ln, in_install)
            if not in_install and ln.func and (ln.func in BUILD_FUNCS or ln.func.startswith("package")):
                for check, rx, sev, st, title, summary in NET_IN_BUILD:
                    if rx.search(t) and not self.local_pip(t) and not re.search(r"protocol\.file\.allow", t):
                        self.add(check, title, summary, sev, st, f"Network command in {ln.func}()", file=ln.file,
                                 line=ln.no, likely="Sources belong in source=, where makepkg downloads and checks them.",
                                 reason="Some upstream build systems do this, but it defeats the checksums.",
                                 confidence="Medium" if sev != "Low" else "Low")
                        break
            self.writes(ln, in_install)
        self.chmod_then_run(lines)
        self.encoded_blobs(script)

    @staticmethod
    def local_pip(t):
        return bool(re.search(r"pip", t) and re.search(r"\.whl\b|--no-index|--no-deps|\bdist/", t))

    def line_patterns(self, ln, in_install):
        for check, rx, sev, st, title, summary, likely in PATTERNS:
            if rx.search(ln.text):
                if check == "decode" and any(c == "decode_and_run" and r.search(ln.text) for c, r, *_ in PATTERNS):
                    continue
                self.add(check, title + (" (as root, on install)" if in_install and len(title) < 42 else ""),
                         summary, sev, st, f"{title} in {ln.func or 'top level'} of {ln.file}",
                         file=ln.file, line=ln.no, likely=likely, confidence="High" if sev == "High" else "Medium",
                         reason="The line says it plainly." if sev == "High" else "Has rare honest uses.",
                         iocs=self.url_iocs(ln.text))
        if re.search(r"(^|[;&|(`]\s*|\$\(\s*)(sudo|doas|pkexec|su\s+-c)\b", ln.text):
            self.add("sudo", "Asks for admin rights inside the build script",
                     "This line uses sudo (or similar), which a PKGBUILD should never need.", "High", 0.9,
                     f"sudo in {ln.func or 'top level'} of {ln.file}", file=ln.file, line=ln.no,
                     likely="makepkg runs as you on purpose; admin rights in a build script are a red flag.",
                     confidence="High", reason="There is no honest need for sudo in a PKGBUILD.")
        if not in_install and re.search(r"\bsystemctl\s+--user\s+(--now\s+)?(enable|start|link)\b", ln.text):
            self.add("user_service", "Turns on a service in your home folder",
                     "This line enables a service for your own user while building, so it would start at every login.",
                     "High", 0.9, f"systemctl --user in {ln.func or 'top level'}", file=ln.file, line=ln.no,
                     likely="A build has no reason to change your services; this is a way to stay on the system.",
                     confidence="High", reason="Building a package never needs to enable anything.")
        if in_install:
            for check, rx, sev, st, title, summary in INSTALL_RULES:
                if rx.search(ln.text):
                    if check == "install_user_add" and re.search(r"\s(-r|--system)\b", ln.text):
                        sev, st = "Info", 0.1
                    self.add(check, title, summary, sev, st, f"{ln.func or 'top level'} in {ln.file} runs as root",
                             file=ln.file, line=ln.no,
                             likely="Install scripts run as root with no prompt, so they deserve the closest look.",
                             confidence="High" if sev == "High" else "Medium",
                             reason="Install scripts run as root." if sev != "Info" else "System accounts are normal.",
                             iocs=self.url_iocs(ln.text))

    @staticmethod
    def url_iocs(text):
        out = []
        for u in re.findall(r"https?://[^\s'\"|;)<>]+", text):
            if "$" not in u:
                out.append({"type": "url", "value": u})
        return out[:5]

    def writes(self, ln, in_install):
        """Writes outside $pkgdir, into a home folder, or into sensitive system files."""
        t = ln.text
        targets = []
        for m in re.finditer(r"(?<![0-9&<>])>>?\s*(\"[^\"]+\"|'[^']+'|[^\s;&|]+)", t):
            targets.append(m.group(1).strip("\"'"))
        try:
            w = shlex.split(t, posix=True)
        except ValueError:
            w = t.split()
        while w and (w[0] in ("sudo", "doas", "command", "env") or re.match(r"^\w+=", w[0])):
            w = w[1:]
        if w:
            cmd, args = w[0], [a for a in w[1:] if not a.startswith("-")]
            if cmd in ("install", "cp", "mv", "ln", "rsync") and args:
                targets.append(args[-1])
            elif cmd in ("mkdir", "touch", "rm", "chmod", "chown", "tee", "truncate", "shred", "unlink") or \
                    (cmd == "sed" and any(a.startswith("-i") for a in w)):
                targets += args
        for target in targets:
            raw = target
            if raw.startswith(SAFE_ROOTS) or not (raw.startswith(("/", "~", "$HOME", "${HOME}")) or "/home/" in raw):
                continue
            if raw.startswith("/dev/") or (not in_install and raw.startswith(("/tmp/", "/var/tmp/"))):
                continue  # scratch files while building: untidy, not a risk
            home = raw.startswith(("~", "$HOME", "${HOME}", "/home/", "/root"))
            sensitive = bool(RC_FILES.search(raw) or SENSITIVE.search(raw))
            if in_install and not home and not sensitive:
                # .install scripts run as root on the real system: writing to /usr is
                # unusual, writing to /etc is worth a look, /var/lib is common.
                if raw.startswith(("/var/lib/", "/var/cache/", "/var/log/", "/run/", "/tmp/", "/opt/")):
                    continue
            if home or sensitive:
                sev, st = "High", 0.9
                title = "Changes your shell or startup files" if RC_FILES.search(raw) else \
                    "Writes into a home folder" if home else "Changes a sensitive system file"
                summary = f"This line writes to {raw}, which {'an install script' if in_install else 'a package build'} has no reason to touch."
                likely = "Writing to shell start-up files, sudoers or scheduled tasks is how malware stays on a system."
            else:
                sev, st = "Medium", 0.6
                title = "Writes outside the package folder"
                summary = f"This line writes to {raw} directly instead of under $pkgdir."
                likely = ("Usually a packaging mistake (a missing $pkgdir); makepkg can't write there as you, "
                          "but it shows the script expects more access than it should.")
                if in_install:
                    title = "Changes files pacman doesn't track"
                    summary = f"The install script writes to {raw} as root, outside the package's own files."
                    likely = "Install scripts sometimes adjust config; pacman then can't undo the change."
            self.add("write_outside", title, summary, sev, st, f"Write target {raw}", file=ln.file, line=ln.no,
                     likely=likely, confidence="High" if sev == "High" else "Medium",
                     reason="The target path is written in the line.", subject=f"{self.pkgbase}:{ln.file}:{ln.no}:{raw}")
            break

    def chmod_then_run(self, lines):
        made = {}
        for ln in lines:
            m = re.search(r"\bchmod\s+(\+x|[ugoa]*\+[rw]*x[rw]*|[0-7]?[0-7][1357][0-7]?[0-7]?)\s+([\"']?)([^\s\"';|&]+)\2", ln.text)
            if m:
                made[m.group(3).rsplit("/", 1)[-1]] = (ln.func, m.group(3))
                continue
            for base, (func, path) in made.items():
                if ln.func != func or not base:
                    continue
                if re.match(rf"^\s*(sudo\s+)?(sh\s+|bash\s+)?[\"']?(\./|\$\{{?srcdir\}}?/|/tmp/|\S*/)?{re.escape(base)}[\"']?(\s|$)", ln.text):
                    self.add("chmod_run", "Makes a downloaded file runnable, then runs it",
                             f"The script marks {base} as a program and then runs it during the build.", "Medium", 0.7,
                             f"chmod +x {base}, then {base} is executed in {func}()", file=ln.file, line=ln.no,
                             likely="Installers sometimes ship this way; it also runs code nobody reviewed.",
                             reason="Common for vendor installers; check what the file is.")

    def encoded_blobs(self, script):
        for no, raw in enumerate(script.raw_lines, 1):
            if re.match(r"^\s*[A-Za-z_]\w*sums(_\w+)?=|^\s*'[0-9a-fA-F]{32,128}'\)?\s*$|^\s*\"[0-9a-fA-F]{32,128}\"\)?\s*$", raw):
                continue
            m = re.search(r"[A-Za-z0-9+/]{120,}={0,2}", raw)
            if m and not re.fullmatch(r"[0-9a-fA-F]+", m.group(0)):
                self.add("encoded_blob", "Contains a long block of encoded text",
                         f"Line {no} holds {len(m.group(0))} characters of base64-like text that a reader can't check.",
                         "Medium", 0.6, "Long encoded string", file=script.file, line=no,
                         likely="Sometimes an embedded key or icon; also how scripts hide their real commands.",
                         reason="Can't tell without decoding, which Vigil does not run.")

    def check_install(self, name):
        script = parse.Script(self.files[name], name)
        self.check_lines(script, in_install=True)
        unknown = [f for f in script.functions if f not in INSTALL_FUNCS]
        if script.top:
            ln = script.top[0]
            self.add("install_top_level", "Runs a command whenever pacman reads the install script",
                     f"{name} has commands outside its hook functions, which run as root whenever pacman loads it.",
                     "Medium", 0.6, f"Top-level command in {name}", file=name, line=ln.no,
                     reason="Install scripts normally only define hook functions.")
        for f in unknown:
            self.add("install_extra_function", "Install script defines an unexpected function",
                     f"{name} defines {f}(), which pacman never calls by itself.", "Low", 0.2,
                     f"Unexpected function {f}() in {name}", file=name, line=script.functions[f]["line"],
                     confidence="Low", reason="Often a helper; read where it is called.")

    # ---- other files in the folder --------------------------------------------------------------

    def check_other_files(self):
        for name, text in self.files.items():
            if name in ("PKGBUILD", ".SRCINFO") or name.endswith(".install"):
                continue
            if name.endswith((".sh", ".hook", ".service", ".timer", ".desktop", ".bash", ".zsh")):
                script = parse.Script(text, name)
                for ln in script.all_lines():
                    self.line_patterns(ln, in_install=False)
                if name.endswith(".hook") and re.search(r"Exec\s*=\s*\S*(curl|wget)", text):
                    self.add("hook_network", "Adds a pacman hook that downloads things",
                             f"{name} is a pacman hook whose command downloads files, as root, on every matching update.",
                             "High", 0.9, f"Network command in pacman hook {name}", file=name, confidence="High",
                             reason="Hooks run as root on later updates too.")
                if name.endswith(".desktop") and re.search(r"^Exec\s*=.*(curl|wget|base64|\|\s*sh\b)", text, re.M):
                    self.add("desktop_command", "Ships a menu entry that runs a hidden command",
                             f"{name} is a menu entry whose command downloads or decodes something.", "High", 0.9,
                             f"Suspicious Exec= in {name}", file=name, confidence="High",
                             reason="Menu entries should start the app and nothing else.")

    def add_folder_notes(self, notes):
        """Notes gathered while reading the folder (links, program files, skipped files)."""
        for n in notes:
            self.add(n["check"], n["title"], n["summary"], n["severity"], n["strength"], n["signal"],
                     file=n["file"], confidence=n.get("confidence", "Medium"), reason=n.get("reason", ""),
                     likely=n.get("likely"))

    # ---- 8. history ------------------------------------------------------------------------------

    def check_history(self):
        cur = [m for _, m in parse.maintainers(self.files["PKGBUILD"]) if _ == "maintainer"]
        if self.trusted:
            old = [m for k, m in self.trusted.get("maintainers", []) if k == "maintainer"]
            new = [m for m in cur if m not in old]
            if new and old:
                line = next((i for i, x in enumerate(self.files["PKGBUILD"].split("\n"), 1) if new[0] in x), None)
                self.add("new_maintainer", "Has a new maintainer since you approved it",
                         f"The PKGBUILD now names {new[0]} as maintainer; the version you approved named {old[0]}.",
                         "Medium", 0.7, f"Maintainer changed: {old[0]} → {new[0]}", file="PKGBUILD", line=line,
                         likely="Packages change hands for honest reasons; the 2018 AUR malware arrived this way.",
                         reason="A handover is when to read the diff most carefully.")
        else:
            self.add("first_review", "First time you've reviewed this package",
                     f"You haven't approved a version of {self.pkgbase} before, so there is no earlier version to compare.",
                     "Info", 0.1, "No approved version to compare against", subject=f"{self.pkgbase}:first_review",
                     confidence="High", reason="Vigil keeps the versions you approve.")
        si = self.files.get(".SRCINFO")
        if si:
            info = parse.srcinfo(si)
            pb_src = [s["raw"] for s in parse.source_entries(self.pkgbuild) if s["arch"] is None]
            si_src = info.get("source", [])
            pb_ver, si_ver = self.pkgbuild.get("pkgver"), (info.get("pkgver") or [None])[0]
            if (si_src and pb_src and set(si_src) != set(pb_src)) or (pb_ver and si_ver and pb_ver != si_ver
                                                                         and "$" not in str(pb_ver)):
                diff = sorted(set(pb_src) ^ set(si_src))[:4]
                self.add("srcinfo_mismatch", "The .SRCINFO doesn't match the PKGBUILD",
                         "The AUR web page shows the .SRCINFO, but the PKGBUILD that would be built says something different.",
                         "Medium", 0.7, "Sources or version differ between .SRCINFO and PKGBUILD", file=".SRCINFO",
                         likely="Often a forgotten `makepkg --printsrcinfo`; it can also hide a real source from the web page.",
                         reason="Usually carelessness, occasionally deliberate.",
                         technical=[{"label": "differs", "value": " | ".join(diff)},
                                    {"label": "versions", "value": f"PKGBUILD {pb_ver} / .SRCINFO {si_ver}"}])

    def check_aur(self):
        a = self.aur
        if not a:
            return
        day = 86400
        if a.get("Maintainer") in (None, ""):
            self.add("aur_orphan", "Package has no maintainer on the AUR",
                     "The AUR lists this package as orphaned, so anyone could adopt it and push an update.",
                     "Low", 0.4, "Orphaned on the AUR", subject=f"{self.pkgbase}:aur_orphan", confidence="Low",
                     reason="Many orphans are fine; adoption is the moment to watch.",
                     likely="The 2018 AUR malware came from adopted orphans.")
        first = a.get("FirstSubmitted")
        if first and self.now - first < 30 * day:
            self.add("aur_new_package", "Package is less than a month old",
                     f"It was first uploaded {int((self.now - first) // day)} days ago, so few people have looked at it.",
                     "Medium", 0.6, "First submitted under 30 days ago", subject=f"{self.pkgbase}:aur_new",
                     reason="New packages are usually honest, but malware is always new.",
                     likely="The July 2025 AUR malware was removed about two days after upload.")
        if a.get("Maintainer") and a.get("Submitter") and a["Maintainer"] != a["Submitter"]:
            recent = a.get("LastModified") and self.now - a["LastModified"] < 14 * day
            self.add("aur_changed_hands", "Package changed hands" + (" recently" if recent else ""),
                     f"It was first uploaded by {a['Submitter']} and is now maintained by {a['Maintainer']}.",
                     "Medium" if recent else "Low", 0.6 if recent else 0.3,
                     f"Submitter {a['Submitter']} ≠ maintainer {a['Maintainer']}", subject=f"{self.pkgbase}:aur_hands",
                     confidence="Low", reason="Handovers are normal; a fresh one deserves a diff review.",
                     likely="Adopting an orphan and pushing a bad update is a known AUR attack.")
        oldest = a.get("_maintainer_oldest")
        if oldest and self.now - oldest < 30 * day:
            self.add("aur_new_account", "Maintainer's account looks brand new",
                     "Every package this maintainer has on the AUR was first uploaded within the last month.",
                     "Medium", 0.6, "Maintainer's oldest package is under 30 days old", subject=f"{self.pkgbase}:aur_account",
                     reason="The AUR doesn't publish account ages; this is the closest public sign.",
                     likely="Throwaway accounts were used for the 2025 AUR malware.")
        if (a.get("NumVotes") or 0) == 0 and not a.get("Popularity"):
            self.add("aur_unused", "Nobody has voted for this package",
                     "It has no votes and no recent popularity on the AUR, so few others have built it.", "Low", 0.3,
                     "0 votes, popularity 0", subject=f"{self.pkgbase}:aur_votes", confidence="Low",
                     reason="Niche packages are often unvoted.")

    # ---- the report ------------------------------------------------------------------------------

    # Checks that restate a stronger finding on the same line: kept only when nothing
    # stronger was found there, so one bad line reads as one finding.
    OVERLAP = {"network_in_build", "download_to_tmp", "registry_in_build", "decode", "eval"}

    def dedupe(self):
        rank = fmt.SEVERITY_RANK
        best = {}
        for f in self.findings:
            ev = (f["evidence"] or [{}])[0].get("value")
            if ev:
                best[ev] = max(best.get(ev, 0), rank[f["severity"]])
        return [f for f in self.findings
                if not (f["check"] in self.OVERLAP and (f["evidence"] or [{}])[0].get("value")
                        and rank[f["severity"]] < best[f["evidence"][0]["value"]])]

    def report(self):
        fs = fmt.sort(self.dedupe())
        worst = fmt.worst([f for f in fs if f["severity"] != "Info"])
        verdict = VERDICTS.get(worst, LOOKS_NORMAL)
        srcs = parse.source_entries(self.pkgbuild)
        return {
            "tool": TOOL, "package": {"pkgbase": self.pkgbase, "pkgname": self.pkgnames(),
                                      "version": f"{self.pkgbuild.get('pkgver')}-{self.pkgbuild.get('pkgrel')}",
                                      "url": self.pkgbuild.get("url"), "maintainers": parse.maintainers(self.files["PKGBUILD"]),
                                      "install": self.install_files()},
            "folder": self.folder, "verdict": verdict, "findings": fs,
            "counts": {s: sum(f["severity"] == s for f in fs) for s in fmt.SEVERITIES},
            "sources": [{"url": s["url"], "kind": s["kind"], "arch": s["arch"], "line": s["line"],
                         "checked": any((v or "").upper() not in ("", "SKIP") for v in s["sums"].values())} for s in srcs],
            "files": {n: t for n, t in self.files.items()},
            "diff": self.diff(),
            "trusted": {"version": self.trusted.get("version"), "ts": self.trusted.get("ts")} if self.trusted else None,
            "aur": self.aur, "reviewed_at": self.now,
            "limits": [
                "Vigil read these files as text. It did not run makepkg, source the PKGBUILD or download anything.",
                "It cannot see inside the downloaded sources: a -bin package's program could still do anything.",
                "A shell script can hide intent in ways no static reader catches; "
                "'Looks normal' means nothing matched Vigil's checks, not that the package is safe.",
            ],
        }

    def diff(self):
        if not self.trusted:
            return None
        out = []
        for name in sorted(set(self.files) | set(self.trusted.get("files") or {})):
            old = (self.trusted.get("files") or {}).get(name, "")
            new = self.files.get(name, "")
            if old != new:
                out.append({"file": name, "unified": "".join(difflib.unified_diff(
                    old.splitlines(True), new.splitlines(True), f"approved/{name}", f"now/{name}"))})
        return out
