"""Archive-bomb detection. Every bomb here is SYNTHETIC and small, built at test time;
the size thresholds are scaled down so the same logic triggers in milliseconds.
"""

import bz2
import gzip
import io
import struct
import tracemalloc
import unittest
import zipfile
import zlib
from unittest import mock

from vigil import archives, inspector
from . import synth

MB = 1000 ** 2


def deflate(data):
    c = zlib.compressobj(9, zlib.DEFLATED, -15)
    return c.compress(data) + c.flush()


def raw_zip(entries, payloads, forge_count=None):
    """Hand-built zip: payloads are (name, compressed bytes, real size); entries are
    (name, payload index, declared size) so several entries can share one payload."""
    out, offsets = bytearray(), []
    for name, comp, size in payloads:
        offsets.append(len(out))
        crc = 0
        out += struct.pack("<IHHHHHIIIHH", 0x04034B50, 20, 0, 8, 0, 0, crc, len(comp), size,
                           len(name), 0) + name.encode() + comp
    cd = bytearray()
    for name, idx, declared in entries:
        comp = payloads[idx][1]
        cd += struct.pack("<IHHHHHHIIIHHHHHII", 0x02014B50, 20, 20, 0, 8, 0, 0, 0, len(comp),
                          declared, len(name), 0, 0, 0, 0, 0, offsets[idx]) + name.encode()
    count = len(entries) if forge_count is None else forge_count
    eocd = struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, count, count, len(cd), len(out), 0)
    return bytes(out + cd + eocd)


def zip_of(files, method=zipfile.ZIP_DEFLATED):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", method) as z:
        for name, data in files:
            z.writestr(name, data)
    return buf.getvalue()


SMALL = mock.patch.multiple(inspector, BOMB_SEVERE=60 * MB, BOMB_LARGE=20 * MB, BOMB_NOTE=5 * MB)


class ArchiveBombTests(unittest.TestCase):
    def checks(self, data, name):
        r = inspector.inspect_bytes(data, name)
        return r, {f["check"]: f for f in r["findings"]}

    @SMALL
    def test_recursive_bomb(self):
        # 4 zips, each holding 4 files of 5 MB of zeros: 80 MB from a few kB.
        inner = zip_of([(f"{i}.bin", b"\0" * (5 * MB)) for i in range(4)])
        outer = zip_of([(f"layer{i}.zip", inner) for i in range(4)])
        r, c = self.checks(outer, "photos.zip")
        self.assertEqual(r["verdict"], "Likely malicious")
        self.assertIn("decompression_bomb", c)
        self.assertEqual(r["details"]["expansion"]["estimated"], 80 * MB)
        self.assertEqual(r["details"]["expansion"]["depth"], 1)
        self.assertIn("Do not extract it", c["decompression_bomb"]["means"])
        self.assertTrue(any("not unpacked" in l for l in r["limits"]))

    @SMALL
    def test_overlapping_entries_with_lying_sizes(self):
        # One 8 MB block of zeros, 12 names pointing at it, each claiming 2 bytes.
        block = deflate(b"\0" * (8 * MB))
        data = raw_zip([(f"f/{i:02x}.txt", 0, 2) for i in range(12)], [("f/00.txt", block, 8 * MB)])
        r, c = self.checks(data, "location.zip")
        self.assertEqual(c["overlapping_entries"]["points"], 60)
        self.assertIn("12 file names point at the same compressed data", c["overlapping_entries"]["reason"])
        self.assertIn("claims to be 2 bytes but produces", c["size_lie"]["reason"])
        self.assertEqual(r["details"]["expansion"]["estimated"], 12 * 8 * MB)
        self.assertEqual(r["verdict"], "Likely malicious")

    def test_forged_directory_counts(self):
        payload = deflate(b"hello")
        data = raw_zip([("a.txt", 0, 5)], [("a.txt", payload, 5)], forge_count=256)
        inner_outer = zip_of([("32-256.zip", data)])
        r, c = self.checks(inner_outer, "x.zip")
        self.assertIn("claims 256 entries", c["forged_directory"]["reason"])

    @SMALL
    def test_single_member_that_lies_about_its_size(self):
        block = deflate(b"\0" * (25 * MB))
        data = raw_zip([("notes.txt", 0, 120)], [("notes.txt", block, 25 * MB)])
        r, c = self.checks(data, "notes.zip")
        self.assertIn("claims to be 120 bytes but produces", c["size_lie"]["reason"])
        self.assertIn("decompression_bomb", c)

    @SMALL
    def test_limit_makes_a_lower_bound(self):
        block = deflate(b"\0" * (30 * MB))
        data = raw_zip([("big.bin", 0, 30 * MB)], [("big.bin", block, 30 * MB)])
        with mock.patch.object(archives, "COUNT_LIMIT", 10 * MB):
            r, c = self.checks(data, "big.zip")
        self.assertIn("at least", c["decompression_bomb"]["reason"])
        self.assertTrue(r["details"]["expansion"]["lower_bound"])
        self.assertTrue(any("larger than reported" in l for l in r["limits"]))

    def test_zip_slip_and_symlinks(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("../../.bashrc", "echo hi\n")
            link = zipfile.ZipInfo("docs/link")
            link.external_attr = (0o120777 << 16)
            z.writestr(link, "/etc/passwd")
        r, c = self.checks(buf.getvalue(), "docs.zip")
        self.assertIn("../../.bashrc", c["path_traversal"]["reason"])
        self.assertIn("docs/link", c["symlink_member"]["reason"])

    @SMALL
    def test_gzip_bzip2_xz(self):
        import lzma
        zeros = b"\0" * (25 * MB)
        for data, name in ((gzip.compress(zeros), "a.gz"), (bz2.compress(zeros), "a.bz2"),
                           (lzma.compress(zeros), "a.xz")):
            with self.subTest(name):
                r, c = self.checks(data, name)
                self.assertIn("decompression_bomb", c)
        # A harmless gzip is unpacked and its content inspected.
        r, c = self.checks(gzip.compress(synth.SHELL_DROPPER), "install.sh.gz")
        self.assertIn("pipe_to_shell", c)
        self.assertTrue(c["pipe_to_shell"]["reason"].startswith("Inside (install.sh)"))

    def test_ordinary_archives_are_not_bombs(self):
        text = b"".join(f"line {i}: the quick brown fox\n".encode() for i in range(20000))
        r, c = self.checks(zip_of([("notes.txt", text), ("readme.md", b"# hi\n")]), "notes.zip")
        self.assertFalse({"decompression_bomb", "overlapping_entries", "size_lie"} & set(c))
        r, c = self.checks(synth.docm_dropper(), "invoice.docm")
        self.assertNotIn("decompression_bomb", c)

    @SMALL
    def test_analyzer_rows(self):
        block = deflate(b"\0" * (8 * MB))
        data = raw_zip([(f"f/{i:02x}.txt", 0, 2) for i in range(12)], [("f/00.txt", block, 8 * MB)])
        r = inspector.inspect_bytes(data, "location.zip")
        rows = {a["id"]: a for a in r["analyzers"]}
        self.assertEqual(rows["archive"]["status"], "flagged")
        self.assertIn("decompression_bomb", rows["archive"]["checks"])
        self.assertEqual(rows["identity"]["status"], "nothing")
        self.assertEqual(rows["pdf"]["status"], "skipped")
        self.assertEqual(rows["intel"]["status"], "skipped")  # no feeds outside the app
        self.assertNotIn("clean", {a["status"] for a in r["analyzers"]})

    def test_memory_stays_flat(self):
        # 200 MB of output is counted, not kept: Python allocations stay small.
        block = deflate(b"\0" * (200 * MB))
        data = raw_zip([(f"f{i}", 0, 1) for i in range(3)], [("f0", block, 200 * MB)])
        tracemalloc.start()
        archives.check_zip(data)
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        self.assertLess(peak, 16 * MB)



def zeros_deflate(megabytes):
    """A raw deflate stream of `megabytes` MB of zeros, built without compressing them all:
    after a full flush, each 1 MB of zeros compresses to the same independent bytes."""
    c = zlib.compressobj(9, zlib.DEFLATED, -15)
    mb = b"\0" * MB
    first = c.compress(mb) + c.flush(zlib.Z_FULL_FLUSH)
    mid = c.compress(mb) + c.flush(zlib.Z_FULL_FLUSH)
    assert mid == c.compress(mb) + c.flush(zlib.Z_FULL_FLUSH)  # periodic from here on
    return first + mid * (megabytes - 2) + c.compress(mb) + c.flush()


def zip64_overlap(kernel, names, declared=2):
    """SYNTHETIC non-recursive bomb: `names` Zip64 directory records all pointing at one
    deflate kernel, each declaring `declared` bytes."""
    lh = struct.pack("<IHHHHHIIIHH", 0x04034B50, 45, 0, 8, 0, 0, 0, len(kernel), declared, 1, 0) + b"k"
    out = bytearray(lh + kernel)
    cd = bytearray()
    for i in range(names):
        name = f"d/{i:05d}.bin".encode()
        extra = struct.pack("<HHQQ", 1, 16, declared, len(kernel))
        cd += struct.pack("<IHHHHHHIIIHHHHHII", 0x02014B50, 45, 45, 0, 8, 0, 0, 0, 0xFFFFFFFF,
                          0xFFFFFFFF, len(name), len(extra), 0, 0, 0, 0, 0) + name + extra
    eocd = struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, names, names, len(cd), len(out), 0)
    return bytes(out + cd + eocd)


class TerabyteBombTests(unittest.TestCase):
    """Bombs over 1 TB, at real scale. Vigil counts 1 GB per stream, then extrapolates."""

    def test_zip64_overlapping_bomb_over_a_terabyte(self):
        kernel = zeros_deflate(4096)                     # one 4 GB stream, about 4 MB compressed
        bomb = zip64_overlap(kernel, 300)                # 300 names x 4 GB = about 1.3 TB
        r, c = ArchiveBombTests.checks(self, bomb, "big.zip")
        exp = r["details"]["expansion"]
        self.assertGreater(exp["estimated"], 1e12)
        self.assertIn("TB", c["decompression_bomb"]["reason"])
        self.assertIn("about", c["decompression_bomb"]["reason"])
        self.assertIn("overlapping_entries", c)
        self.assertEqual(r["verdict"], "Likely malicious")

    def test_same_bomb_nested_inside_another_zip(self):
        bomb = zip64_overlap(zeros_deflate(4096), 300)
        outer = zip_of([("inner.zip", bomb)], zipfile.ZIP_STORED)
        r, c = ArchiveBombTests.checks(self, outer, "outer.zip")
        self.assertGreater(r["details"]["expansion"]["estimated"], 1e12)  # Zip64 records read inside

    def test_crafted_directory_python_rejects(self):
        bomb = bytearray(zip64_overlap(zeros_deflate(64), 40))
        bomb[-22 + 10:-22 + 14] = struct.pack("<HH", 0xFFFF, 0xFFFF)  # nonsense counts
        bomb[-22 + 12:-22 + 16] = struct.pack("<I", 0xFFFFFFF0)         # and directory size
        r, c = ArchiveBombTests.checks(self, bytes(bomb), "odd.zip")
        self.assertIn("overlapping_entries", c)

    @mock.patch.object(archives, "SAMPLES_PER_LEVEL", 1)
    def test_unmeasured_siblings_use_measured_expansion(self):
        # 8 identical nested zips whose members lie about their size; only 2 get measured.
        inner = raw_zip([("x.bin", 0, 10)], [("x.bin", deflate(b"\0" * (8 * MB)), 8 * MB)])
        outer = zip_of([(f"n{i}.zip", inner) for i in range(8)])
        with SMALL:
            r, c = ArchiveBombTests.checks(self, outer, "nest.zip")
        exp = r["details"]["expansion"]
        self.assertGreaterEqual(exp["estimated"], 8 * 8 * MB)
        self.assertGreater(exp["inferred_members"], 0)


if __name__ == "__main__":
    unittest.main()
