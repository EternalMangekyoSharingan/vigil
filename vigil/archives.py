"""Decompression-bomb and archive-abuse checks that never hold expanded data.

A zip bomb is harmless until something extracts it. To judge one safely, members are
decompressed as a stream: output is counted and thrown away, keeping only the first
4 KB (to recognise what it is) and the last 1 MB (where a zip keeps its directory).
That way a nested archive's directory can be read, and its own members measured,
level after level, in constant memory and under a time limit. Nothing is written to
disk and nothing is kept.

What it finds:
- expansion: declared and measured sizes, ratios, and an estimate of the total if
  every nested archive were extracted;
- overlapping entries: many directory entries pointing at the same compressed data
  (the "non-recursive" zip bomb);
- size lies: a member producing more data than its header declares;
- extraction tricks: paths that escape the target folder ("zip slip"), symlinks,
  absurd entry counts;
- the same expansion check for top-level gzip, bzip2 and xz files.
"""

import bz2
import io
import lzma
import struct
import time
import zipfile
import zlib

HEAD = 4096
TAIL = 1 << 20
STEP = 1 << 20
COUNT_LIMIT = 1024 ** 3        # stop counting a single stream after 1 GB: a bomb either way
TIME_LIMIT = 12.0              # seconds for all expansion work in one inspection
MAX_DEPTH = 6
SAMPLES_PER_LEVEL = 3          # nested archives expanded per level; the rest are estimated
CAPTURE_MAX = 64 * 1024 * 1024 # compressed bytes copied out for the next level
ARCHIVE_MAGIC = (b"PK\x03\x04", b"PK\x05\x06", b"\x1f\x8b", b"BZh", b"\xfd7zXZ\x00")
MAX_DEFLATE_RATIO = 1032       # the most deflate can achieve on any input


def human(n):
    for unit in ("bytes", "KB", "MB", "GB", "TB", "PB", "EB"):
        if n < 1000 or unit == "EB":
            return f"{n:,.0f} {unit}" if unit == "bytes" else f"{n:,.1f} {unit}"
        n /= 1000
    return f"{n} bytes"


class Budget:
    def __init__(self, seconds=TIME_LIMIT):
        self.deadline = time.monotonic() + seconds
        self.streamed = 0

        self.counted = 0  # output of the stream being expanded right now
        self.consumed = 0  # compressed input it has used so far

    def out(self):
        return time.monotonic() > self.deadline

    def over(self):
        return self.counted > COUNT_LIMIT


def _decompressor(method):
    if method == 0:
        return None
    if method == 8:
        return zlib.decompressobj(-15)
    if method == 12:
        return bz2.BZ2Decompressor()
    raise ValueError(f"compression method {method} is not expanded")


def _pump(d, data, take, budget):
    """Feed `data` through decompressor `d`, STEP bytes of output at a time.

    Returns True if the stream ended, False if a limit stopped it first.
    zlib objects hold back input in unconsumed_tail; bz2/lzma ones ask for input.
    """
    if hasattr(d, "unconsumed_tail"):
        # Feed 64 KB at a time: handing over all the input on every call would copy
        # the whole remainder each step.
        pos, buf = 0, b""
        while not d.eof:
            if not buf:
                if pos >= len(data):
                    return False  # truncated stream
                buf, pos = data[pos:pos + 65536], pos + 65536
            chunk = d.decompress(buf, STEP)
            buf = d.unconsumed_tail
            budget.consumed = pos - len(buf)
            take(chunk)
            if budget.out() or budget.over():
                return False
        return True
    pos = 0
    while not d.eof:
        if d.needs_input:
            if pos >= len(data):
                return False  # truncated stream
            inp, pos = data[pos:pos + 65536], pos + 65536
        else:
            inp = b""
        take(d.decompress(inp, STEP))
        budget.consumed = pos
        if budget.out() or budget.over():
            return False
    return True


def stream(comp, method, budget, capture=()):
    """Expand `comp` without keeping it: returns size, head, tail, whether it finished,
    and any requested output ranges (start, end) copied out."""
    state = {"size": 0, "tail": b""}
    head = bytearray()
    kept = {r: bytearray() for r in capture}

    def take(chunk):
        size = state["size"]
        if len(head) < HEAD:
            head.extend(chunk[:HEAD - len(head)])
        for (a, b), buf in kept.items():
            lo, hi = max(a, size), min(b, size + len(chunk))
            if lo < hi:
                buf.extend(chunk[lo - size:hi - size])
        state["size"] = size + len(chunk)
        state["tail"] = (state["tail"] + chunk)[-TAIL:]
        budget.counted = state["size"]

    d = _decompressor(method)
    budget.counted = 0
    budget.consumed = 0
    if d is None:
        take(bytes(comp))
        complete = True
    else:
        try:
            complete = _pump(d, bytes(comp), take, budget)
        except (zlib.error, OSError, EOFError, ValueError):
            complete = False
    budget.streamed += state["size"]
    return {"size": state["size"], "head": bytes(head), "tail": state["tail"],
            "complete": complete, "kept": kept, "consumed": budget.consumed}


def extrapolate(produced, consumed, total_input):
    """Estimate a stream's full output from the part we counted.

    Bomb streams compress uniformly (long runs of the same bytes), so output per byte
    of input stays steady: produced * total_input / consumed. Never less than what was
    actually counted."""
    if consumed <= 0 or total_input <= consumed:
        return produced
    return max(produced, int(produced * (total_input / consumed)))


def _record(tail, pos):
    """One central-directory record at pos, or None if it does not fit or parse."""
    if tail[pos:pos + 4] != b"PK\x01\x02" or pos + 46 > len(tail):
        return None
    method = struct.unpack_from("<H", tail, pos + 10)[0]
    csize, usize = struct.unpack_from("<II", tail, pos + 20)
    nlen, xlen, clen = struct.unpack_from("<HHH", tail, pos + 28)
    attr, off = struct.unpack_from("<II", tail, pos + 38)
    if pos + 46 + nlen > len(tail):
        return None
    name = tail[pos + 46:pos + 46 + nlen].decode("utf-8", "replace")
    if 0xFFFFFFFF in (csize, usize, off):  # Zip64: real values sit in extra field 0x0001
        extra = tail[pos + 46 + nlen:pos + 46 + nlen + xlen]
        i = 0
        while i + 4 <= len(extra):
            hid, hlen = struct.unpack_from("<HH", extra, i)
            if hid == 1:
                vals, j = [], i + 4
                while j + 8 <= i + 4 + hlen:
                    vals.append(struct.unpack_from("<Q", extra, j)[0])
                    j += 8
                # order: uncompressed, compressed, offset; only the ones that were 0xFFFFFFFF
                if usize == 0xFFFFFFFF and vals:
                    usize = vals.pop(0)
                if csize == 0xFFFFFFFF and vals:
                    csize = vals.pop(0)
                if off == 0xFFFFFFFF and vals:
                    off = vals.pop(0)
                break
            i += 4 + hlen
    return (name, method, csize, usize, off, attr >> 16), pos + 46 + nlen + xlen + clen


def directory_from_tail(tail):
    """Read a zip's central directory from the last bytes of the archive.

    Returns (entries, notes): entries are (name, method, compressed, size, offset, mode).
    The end record's counts and sizes are not trusted, since crafted bombs falsify them
    to confuse tools. Records are found by their own signatures instead, and any
    disagreement is reported in notes.
    """
    eocd = tail.rfind(b"PK\x05\x06")
    if eocd < 0 or eocd + 22 > len(tail):
        return None, []
    _, _, on_disk, total, cd_size, _cd_offset, _ = struct.unpack_from("<HHHHIIH", tail, eocd + 4)
    out, notes = [], []
    pos = tail.find(b"PK\x01\x02", max(0, eocd - cd_size - 65536))
    first = pos
    while 0 <= pos < eocd:
        rec = _record(tail, pos)
        if rec is None:
            pos = tail.find(b"PK\x01\x02", pos + 4)
            continue
        out.append(rec[0])
        pos = rec[1] if tail[rec[1]:rec[1] + 4] == b"PK\x01\x02" else tail.find(b"PK\x01\x02", pos + 4)
    if total == 0xFFFF or cd_size == 0xFFFFFFFF:
        pass  # Zip64 placeholders: the Zip64 end record holds the real counts
    elif on_disk != total or total != len(out):
        notes.append(f"the end record claims {total} entries ({on_disk} on this disk); {len(out)} were found")
    if first >= 0 and cd_size != 0xFFFFFFFF and eocd - first - _zip64_tail_len(tail, eocd) != cd_size:
        notes.append(f"the end record claims a {cd_size}-byte directory; the records span {eocd - first} bytes")
    return out, notes


def _zip64_tail_len(tail, eocd):
    """Bytes of Zip64 end record + locator sitting between the directory and the end record."""
    loc = eocd - 20
    if loc >= 0 and tail[loc:loc + 4] == b"PK\x06\x07":
        rec = tail.rfind(b"PK\x06\x06", 0, loc)
        if rec >= 0:
            return eocd - rec
    return 0


def local_data_range(blob, offset, csize):
    """Where a member's compressed bytes sit, from its local header."""
    hdr = blob[offset:offset + 30]
    if len(hdr) < 30 or hdr[:4] != b"PK\x03\x04":
        return None
    nlen, xlen = struct.unpack_from("<HH", hdr, 26)
    start = offset + 30 + nlen + xlen
    return start, start + csize


def is_archive(head):
    return head.startswith(ARCHIVE_MAGIC)


class Report:
    def __init__(self):
        self.levels = []          # per-depth notes
        self.overlaps = 0
        self.forged = []          # end-record fields that disagree with the records
        self.shared = []          # (name, entries sharing its data, size of one copy)
        self.lies = []            # (name, declared, measured)
        self.slip = []
        self.symlinks = []
        self.max_ratio = 0.0
        self.entries = 0
        self.unfinished = []      # streams stopped by a limit
        self.unexpanded = []      # methods we do not expand
        self.depth = 0
        self.extrapolated = []    # (name, counted, estimate) for streams cut short by a limit
        self.inferred = 0         # members sized from measured siblings, not measured themselves


NESTED = (".zip", ".gz", ".tgz", ".bz2", ".xz", ".jar", ".apk")


def plan(entries):
    """Group entries that share compressed data, and pick which groups to measure.

    Shared data (several names, one stream) is how non-recursive bombs multiply; nested
    archives are how recursive ones do; big members are where a size lie matters most.
    """
    groups = {}
    for e in entries:
        groups.setdefault((e[4], e[2], e[1]), []).append(e)
    ranked = sorted(groups.items(), key=lambda kv: (
        len(kv[1]) > 1, kv[1][0][0].lower().endswith(NESTED), kv[0][1]), reverse=True)
    # A member's declared size can lie, so any member that *could* expand past 1 MB
    # (deflate reaches about 1,032:1) is worth measuring, biggest first.
    sample = [k for k, items in ranked
              if len(items) > 1 or items[0][0].lower().endswith(NESTED)
              or k[1] * MAX_DEFLATE_RATIO >= 1 << 20]
    return groups, sample[:SAMPLES_PER_LEVEL * 2]


def analyse_entries(entries, blob, depth, budget, rep, where):
    """Measure a list of directory entries; returns the estimated expanded size."""
    rep.entries += len(entries)
    rep.depth = max(rep.depth, depth)
    for name, _method, csize, usize, _off, mode in entries:
        if (mode & 0o170000) == 0o120000:
            rep.symlinks.append(f"{where}{name}")
        norm = "/" + name.replace("\\", "/")
        if norm.startswith("//") or (len(name) > 1 and name[1] == ":") or "/../" in norm + "/":
            rep.slip.append(f"{where}{name}")
        if csize:
            rep.max_ratio = max(rep.max_ratio, usize / csize)
    # Overlap: entries whose compressed data start inside another entry's data.
    spans = sorted({(e[4], e[4] + 30 + e[2]) for e in entries})
    starts = [e[4] for e in entries]
    rep.overlaps += len(starts) - len(set(starts))
    rep.overlaps += sum(1 for (a0, a1), (b0, _b1) in zip(spans, spans[1:]) if b0 < a1)
    groups, sample = plan(entries)
    sizes, ratios = {}, {}
    for key in [k for k in sample if k in groups] + [k for k in groups if k not in sample]:
        off, csize, method = key
        name, usize = groups[key][0][0], groups[key][0][3]
        kind = (method, name.lower().endswith(NESTED))
        per_copy = None
        if key in sample and blob is not None and depth < MAX_DEPTH and not budget.out():
            per_copy = expand_member(blob, name, method, csize, usize, off, depth, budget, rep, where)
            if per_copy is not None and csize and per_copy > usize:
                ratios[kind] = max(ratios.get(kind, 0), per_copy / csize)
        if per_copy is None:
            per_copy = usize
            if ratios.get(kind) and csize:
                guess = int(ratios[kind] * csize)
                if guess > usize:
                    per_copy = guess
                    rep.inferred += len(groups[key])
        sizes[key] = per_copy
    total = 0
    for key, items in groups.items():
        total += sizes[key] * len(items)
        if len(items) > 1:
            rep.shared.append((f"{where}{items[0][0]}", len(items), sizes[key]))
    return total


def expand_member(blob, name, method, csize, usize, off, depth, budget, rep, where):
    """Stream one member (counting, not keeping); recurse if it is an archive.

    Returns the estimated size of one extraction of this member.
    """
    rng = local_data_range(blob, off, csize)
    if rng is None:
        return None
    comp = blob[rng[0]:rng[1]]
    if len(comp) < min(csize, 1 << 30):
        return None  # we did not keep these bytes
    try:
        first = stream(comp, method, budget)
    except ValueError:
        rep.unexpanded.append(f"{where}{name}")
        return None
    if not first["complete"]:
        est = extrapolate(first["size"], first["consumed"], len(comp))
        rep.unfinished.append((f"{where}{name}", first["size"]))
        if est > first["size"]:
            rep.extrapolated.append((f"{where}{name}", first["size"], est))
        if first["size"] > usize:
            rep.lies.append((f"{where}{name}", usize, first["size"]))
        return max(est, usize)
    if first["size"] != usize:
        rep.lies.append((f"{where}{name}", usize, first["size"]))
    head = first["head"]
    if head.startswith((b"PK\x03\x04", b"PK\x05\x06")):
        inner, notes = directory_from_tail(first["tail"])
        rep.forged.extend(f"{where}{name}: {n}" for n in notes)
        if not inner:
            return first["size"]
        # Second pass: copy out only the compressed bytes of the groups we will measure.
        _groups, sample = plan(inner)
        wanted, captured = [], 0
        for off2, csize2, _m in sample:
            span = (off2, off2 + 30 + 65536 + csize2)
            if captured + (span[1] - span[0]) <= CAPTURE_MAX:
                wanted.append(span)
                captured += span[1] - span[0]
        pieces = {}
        if wanted and not budget.out():
            pieces = stream(comp, method, budget, capture=tuple(wanted))["kept"]
        return analyse_entries(inner, _SparseBlob(pieces), depth + 1, budget, rep, f"{where}{name} › ")
    return first["size"]


class _SparseBlob:
    """The few byte ranges of an expanded archive we copied out, addressable by offset."""

    def __init__(self, pieces):
        self.pieces = pieces

    def __getitem__(self, s):
        for (a, _b), buf in self.pieces.items():
            if a <= s.start and s.start < a + len(buf):
                return bytes(buf[s.start - a:max(s.start - a, s.stop - a)])
        return b""


def check_zip(data, budget=None):
    budget = budget or Budget()
    rep = Report()
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
        infos = zf.infolist()
        entries = [(i.filename, i.compress_type, i.compress_size, i.file_size, i.header_offset,
                    i.external_attr >> 16) for i in infos]
    except (zipfile.BadZipFile, ValueError, OSError, struct.error):
        # Crafted archives can trip Python's reader; read the records ourselves.
        entries, notes = directory_from_tail(data)
        if not entries:
            return None
        rep.forged.extend(notes or ["Python's zip reader rejects this archive's directory"])
    total = analyse_entries(entries, data, 0, budget, rep, "")
    return rep, total


def check_stream(data, kind, budget=None):
    """gzip / bzip2 / xz at the top level: measure the expansion by counting."""
    budget = budget or Budget()
    d = {"gzip": lambda: zlib.decompressobj(31), "bzip2": bz2.BZ2Decompressor,
         "xz": lzma.LZMADecompressor}[kind]()
    size = 0

    def take(chunk):
        nonlocal size
        size += len(chunk)
        budget.counted = size

    budget.counted = 0
    budget.consumed = 0
    try:
        complete = _pump(d, data, take, budget)
    except (zlib.error, OSError, EOFError, lzma.LZMAError, ValueError):
        complete = False
    if not complete and budget.over():
        size = extrapolate(size, budget.consumed, len(data))
    return size, complete and not budget.over()
