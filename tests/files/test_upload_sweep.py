"""Vigil Files additions: dropped files (upload into the inbox) and checking a whole folder."""

import os
import stat
import tempfile
import time
import unittest
from pathlib import Path

from vigil.files.server import App, safe_name


class UploadSweepTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.d = Path(self.tmp.name)
        self.app = App(self.d / "data", home=str(self.d / "home"))
        self.addCleanup(self.app.close)

    def test_safe_name(self):
        self.assertEqual(safe_name("../../.bashrc"), "bashrc")
        self.assertEqual(safe_name("a\x00b\nc.txt"), "abc.txt")
        self.assertEqual(safe_name(""), "upload.bin")
        self.assertEqual(safe_name("C:\\Users\\x\\invoice.pdf.exe"), "invoice.pdf.exe")

    def test_upload_is_stored_unrunnable_and_inspected(self):
        pe = b"MZ" + b"\0" * 58 + b"\x40\0\0\0PE\0\0" + b"\0" * 64
        rep = self.app.api_upload({}, pe, {"X-Filename": "..%2F..%2Finvoice.pdf.exe"})
        self.assertEqual(rep["verdict"], "Likely malicious")
        p = Path(rep["path"])
        self.assertEqual(p.name, "invoice.pdf.exe")
        self.assertTrue(str(p).startswith(str(self.d / "data" / "inbox")))
        self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(p.parent.stat().st_mode), 0o700)

    def test_sweep_a_folder(self):
        dl = self.d / "dl"
        dl.mkdir()
        (dl / "notes.txt").write_text("hello")
        (dl / "invoice.pdf.exe").write_bytes(b"MZ" + b"\0" * 58 + b"\x40\0\0\0PE\0\0" + b"\0" * 64)
        (dl / ".hidden").write_text("skipped")
        (dl / "sub").mkdir()
        s = self.app.api_sweep_start({}, f'{{"path": "{dl}"}}'.encode(), {})
        self.assertEqual(s["total"], 2)
        deadline = time.time() + 10
        while self.app.api_sweep({})["running"] and time.time() < deadline:
            time.sleep(0.05)
        r = {x["name"]: x for x in self.app.api_sweep({})["results"]}
        self.assertEqual(r["invoice.pdf.exe"]["verdict"], "Likely malicious")
        self.assertEqual(r["notes.txt"]["verdict"], "No suspicious indicators found")
        self.assertEqual(sorted(os.listdir(dl)), [".hidden", "invoice.pdf.exe", "notes.txt", "sub"])   # nothing moved


if __name__ == "__main__":
    unittest.main()
