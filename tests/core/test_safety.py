"""Suite-wide safety rules, checked against the source of every tool.

- No fix module (anything that builds Check / Fix / Undo commands) can run a command.
- Only core/netfetch.py can open a URL.
- Only core/web.py creates a listening server, and it binds 127.0.0.1.
- Modules that inspect files or packages cannot start processes or load code.
"""

import re
import unittest
from pathlib import Path

PKG = Path(__file__).resolve().parent.parent.parent / "vigil"
RUNS = re.compile(r"\b(subprocess|os\.system|os\.popen|popen|os\.exec\w*|os\.spawn\w*|pty|shutil\.which|"
                  r"asyncio\.create_subprocess\w*)\b")
LOADS = re.compile(r"\b(exec\(|eval\(|importlib|pickle|marshal|ctypes|os\.startfile|webbrowser|runpy|"
                   r"tarfile\.extractall|\.extractall\(|zipfile\.ZipFile\([^)]*\)\.extract\()")
# Opening a file with its default app: xdg-open & co. used as a command (an argv entry or
# a shell string). Naming them in a pattern (Tasks recognises them as harmless children)
# opens nothing; starting them would also need subprocess, which the next rule forbids.
OPENS = re.compile(r"""["'](xdg-open|gio\s+open|kde-open\d*|exo-open)["']\s*[,\]]|"""
                   r"""(run|Popen|call|check_output|system)\([^)]*(xdg-open|gio open|kde-open|exo-open)""")

# Modules that build commands for the user to copy. Every tool's fixes.py is included
# automatically, so a new tool is covered the day it is added.
FIX_BUILDERS = ["core/commands.py", "core/wording.py", "core/catalogue.py", "core/finding.py", "core/fixes.py",
                "core/pkgdb.py", "net/wording.py", "net/cleanup.py"]
# Modules allowed to start a process, and why.
MAY_RUN = {
    "core/runner.py": "sudo mode: runs only Vigil's own generated commands, on the user's press",
    "core/system.py": "rpm -qf (read-only package query) when the RPM database must be asked",
    "files/engines.py": "ClamAV, on the user's request, reading the bytes on stdin",
    "net/scans.py": "ClamAV/YARA folder scans, on the user's request",
    "net/desktop.py": "opens the app window (a browser or webview), on the user's request",
}


def code_of(path):
    src = path.read_text()
    src = re.sub(r'"""(?:.|\n)*?"""', "", src)          # docstrings may state the rules
    return "\n".join(line.split("#", 1)[0] for line in src.splitlines())


def modules():
    return sorted(p for p in PKG.rglob("*.py") if "__pycache__" not in p.parts)


class SafetyRules(unittest.TestCase):
    def test_no_fix_module_can_run_a_command(self):
        builders = set(FIX_BUILDERS) | {str(p.relative_to(PKG)) for p in PKG.glob("*/fixes.py")}
        self.assertIn("core/fixes.py", builders)
        for rel in sorted(builders):
            with self.subTest(rel):
                hit = RUNS.search(code_of(PKG / rel))
                self.assertIsNone(hit, f"{rel} must not be able to run anything ({hit and hit.group()})")

    def test_only_listed_modules_start_processes(self):
        for p in modules():
            rel = str(p.relative_to(PKG))
            if rel in MAY_RUN:
                continue
            with self.subTest(rel):
                self.assertIsNone(re.search(r"\bimport subprocess\b|\bos\.system\(|\bos\.popen\(|\bpty\b", code_of(p)), rel)

    def test_only_netfetch_opens_urls(self):
        uses = [str(p.relative_to(PKG)) for p in modules() if re.search(r"\burlopen\(", code_of(p))]
        self.assertEqual(uses, ["core/netfetch.py"])

    def test_only_the_web_kit_listens_and_only_on_loopback(self):
        uses = [str(p.relative_to(PKG)) for p in modules()
                if re.search(r"Server\(\(|\.bind\(\(|\.listen\(", code_of(p))]
        self.assertEqual(uses, ["core/web.py"])
        self.assertIn('HOST = "127.0.0.1"', (PKG / "core/web.py").read_text())

    def test_inspection_modules_never_load_or_extract(self):
        inspecting = [p for p in modules() if p.parent.name in ("pkg", "files", "persist", "tasks", "cases")
                      and p.name not in ("engines.py",)]
        for p in inspecting:
            with self.subTest(str(p.relative_to(PKG))):
                self.assertIsNone(LOADS.search(code_of(p)), p.name)
                self.assertIsNone(OPENS.search(code_of(p)), p.name)

    def test_the_ai_provider_is_the_only_other_network_door(self):
        # Anthropic's SDK is optional; only ai/providers.py may import it, and only inside the
        # functions that run on an explicit "Ask" (never at import time).
        uses = [str(p.relative_to(PKG)) for p in modules() if re.search(r"\bimport anthropic\b|from anthropic\b", code_of(p))]
        self.assertEqual(uses, ["ai/providers.py"])
        for line in (PKG / "ai/providers.py").read_text().splitlines():
            if re.search(r"\bimport anthropic\b", line):
                self.assertTrue(line.startswith("        "), "anthropic must be imported inside a function")
        for mod in ("ai/context.py", "ai/analyst.py"):
            self.assertIsNone(re.search(r"\b(socket\.(create_connection|connect)|urllib|http\.client|anthropic)\b",
                                        code_of(PKG / mod).replace("socket.gethostname", "")), mod)

    def test_the_open_with_app_rule_catches_real_launches(self):
        self.assertTrue(OPENS.search('subprocess.run(["xdg-open", path])'))
        self.assertTrue(OPENS.search("os.system('xdg-open ' + path)"))
        self.assertIsNone(OPENS.search('HARMLESS = re.compile(r"(xdg-open|gio)")'))

    def test_nothing_runs_makepkg_or_sources_a_pkgbuild(self):
        for p in modules():
            code = code_of(p)
            with self.subTest(str(p.relative_to(PKG))):
                self.assertIsNone(re.search(r"""["']makepkg["']\s*[,\]]""", code), p.name)
                self.assertIsNone(re.search(r"""(run|Popen|call|check_call|check_output|spawn\w*|exec\w*)\(\s*\[\s*["'](bash|sh|zsh|source|\.)["']""", code), p.name)


if __name__ == "__main__":
    unittest.main()
