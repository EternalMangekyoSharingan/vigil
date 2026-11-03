"""List what is inside an archive from its index, without extracting anything.

Formats: zip (central directory and local headers), tar and tar.gz/.bz2/.xz/.zst
(headers read from a decompressing stream that stops at a hard cap), 7z (signature
header, plain or LZMA-compressed header) and rar (RAR4 and RAR5 block headers).
Nothing is written to disk and no member is decompressed except a tar stream's
headers, which have to be reached through the compression; that is capped by
STREAM_CAP bytes and TIME_CAP seconds.

Every entry is {"name", "type", "size", "csize", "mode", "link", "offset", "end"}:
type is file / dir / symlink / hardlink / chardev / blockdev / fifo / other.
"""

import bz2
import io
import lzma
import stat
import struct
import tarfile
import time
import zipfile
import zlib

STREAM_CAP = 1 << 30          # decompressed bytes read to list a compressed tar
TIME_CAP = 10.0
ENTRY_CAP = 200_000           # entries listed before stopping
HEADER_CAP = 64 * 1024 * 1024  # largest 7z header decoded

try:  # Python 3.14+
    from compression import zstd as _zstd  # type: ignore
except ImportError:  # pragma: no cover - depends on the Python version
    _zstd = None


class Listing:
    def __init__(self, fmt):
        self.format = fmt
        self.entries = []
        self.notes = []            # limits and anomalies seen while listing
        self.complete = True
        self.encrypted_names = False
        self.unpacked_read = None  # bytes decompressed to list (tar streams)
        self.declared_total = 0
        self.overlaps = []         # zip: pairs of names whose data ranges overlap

    def add(self, **e):
        e.setdefault("csize", None)
        e.setdefault("mode", None)
        e.setdefault("link", None)
        e.setdefault("offset", None)
        e.setdefault("end", None)
        self.entries.append(e)
        if e["type"] == "file" and e.get("size"):
            self.declared_total += e["size"]
        if len(self.entries) >= ENTRY_CAP:
            self.complete = False
            self.notes.append(f"Stopped listing after {ENTRY_CAP:,} entries.")
            raise _Stop()

    def as_dict(self):
        return {"format": self.format, "entries": self.entries, "notes": self.notes, "complete": self.complete,
                "encrypted_names": self.encrypted_names, "unpacked_read": self.unpacked_read,
                "declared_total": self.declared_total, "overlaps": self.overlaps, "count": len(self.entries)}


class _Stop(Exception):
    pass


def sniff(head):
    if head.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        return "zip"
    if head.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "7z"
    if head.startswith(b"Rar!\x1a\x07\x01\x00"):
        return "rar5"
    if head.startswith(b"Rar!\x1a\x07\x00"):
        return "rar4"
    if head.startswith(b"\x1f\x8b"):
        return "gzip"
    if head.startswith(b"BZh"):
        return "bzip2"
    if head.startswith(b"\xfd7zXZ\x00"):
        return "xz"
    if head.startswith(b"\x28\xb5\x2f\xfd"):
        return "zstd"
    if len(head) >= 262 and head[257:262] == b"ustar":
        return "tar"
    return None


def list_archive(path):
    """Listing (as a dict) of the archive at `path`, or None if it isn't one we list."""
    with open(path, "rb") as fh:
        head = fh.read(512)
        kind = sniff(head)
        if kind is None:
            return None
        fh.seek(0)
        lst = Listing(kind)
        try:
            if kind == "zip":
                _zip(fh, lst)
            elif kind in ("gzip", "bzip2", "xz", "zstd", "tar"):
                _tar(fh, kind, lst)
            elif kind == "7z":
                _sevenzip(fh, lst)
            else:
                _rar(fh, kind, lst)
        except _Stop:
            pass
        except Exception as exc:  # a crafted archive must never take the tool down
            lst.complete = False
            lst.notes.append(f"Listing stopped: the index is damaged or crafted ({type(exc).__name__}: {exc}).")
        return lst.as_dict()


# ---- zip ------------------------------------------------------------------------------------

def _zip_mode_type(zi):
    mode = (zi.external_attr >> 16) & 0xFFFF
    if zi.create_system == 3 and mode:          # made on Unix: the top 16 bits are st_mode
        fmt = stat.S_IFMT(mode)
        t = {stat.S_IFLNK: "symlink", stat.S_IFDIR: "dir", stat.S_IFCHR: "chardev", stat.S_IFBLK: "blockdev",
             stat.S_IFIFO: "fifo", stat.S_IFREG: "file"}.get(fmt, "file" if not fmt else "other")
        return mode, t
    return None, "dir" if zi.filename.endswith("/") else "file"


def _zip(fh, lst):
    fh.seek(0, 2)
    size = fh.tell()
    try:
        zf = zipfile.ZipFile(fh)
    except (zipfile.BadZipFile, ValueError, OSError) as exc:
        lst.complete = False
        lst.notes.append(f"The zip directory could not be read ({exc}).")
        return
    ranges = []
    for zi in zf.infolist():
        mode, t = _zip_mode_type(zi)
        if zi.flag_bits & 0x1:
            lst.encrypted_names = lst.encrypted_names or False
        link = None
        if t == "symlink" and zi.compress_type == 0 and zi.file_size <= 4096:
            # A link's target is its (stored) data: read just those bytes from the local
            # record, which is not extracting anything to disk.
            try:
                fh.seek(zi.header_offset)
                hdr = fh.read(30)
                n, m = struct.unpack("<HH", hdr[26:30])
                fh.seek(zi.header_offset + 30 + n + m)
                link = fh.read(zi.compress_size).decode("utf-8", "replace")
            except (OSError, struct.error):
                link = None
        start = zi.header_offset
        try:
            fh.seek(start)
            hdr = fh.read(30)
            if hdr[:4] == b"PK\x03\x04":
                n, m = struct.unpack("<HH", hdr[26:30])
                start = zi.header_offset + 30 + n + m
        except (OSError, struct.error):
            pass
        end = start + zi.compress_size
        lst.add(name=zi.filename, type=t, size=zi.file_size, csize=zi.compress_size, mode=mode, link=link,
                offset=start, end=end, method=zi.compress_type, encrypted=bool(zi.flag_bits & 0x1))
        if zi.compress_size and t == "file":
            ranges.append((start, end, zi.filename))
        if end > size:
            lst.notes.append(f"{zi.filename}: its data would end past the end of the file.")
    ranges.sort()
    reach, holder = -1, None
    for s, e, n in ranges:
        if s < reach:
            lst.overlaps.append((holder, n))
        if e > reach:
            reach, holder = e, n


# ---- tar (plain or compressed): headers through a capped decompressing reader -------------

class _Capped(io.RawIOBase):
    """Decompress `raw` on the fly; stop with _Stop after STREAM_CAP bytes or TIME_CAP s."""

    def __init__(self, raw, kind, lst):
        self.raw, self.lst = raw, lst
        self.d = {"gzip": lambda: zlib.decompressobj(47), "bzip2": bz2.BZ2Decompressor,
                  "xz": lzma.LZMADecompressor, "tar": None,
                  "zstd": (lambda: _zstd.ZstdDecompressor()) if _zstd else None}[kind]
        self.dec = self.d() if self.d else None
        self.buf = b""
        self.out = 0
        self.t0 = time.monotonic()
        self.eof = False

    def readable(self):
        return True

    def _next(self):
        """The next piece of decompressed data (at most 1 MB), b"" at the end."""
        d = self.dec
        if d is None:
            c = self.raw.read(1 << 16)
            self.eof = not c
            return c
        if hasattr(d, "unconsumed_tail"):           # zlib
            if d.unconsumed_tail:
                return d.decompress(d.unconsumed_tail, 1 << 20)
        elif not d.needs_input and not d.eof:      # bz2, lzma, zstd
            return d.decompress(b"", 1 << 20)
        if getattr(d, "eof", False):
            self.eof = True
            return b""
        c = self.raw.read(1 << 16)
        if not c:
            self.eof = True
            return b""
        return d.decompress(c, 1 << 20)

    def _fill(self, n):
        while len(self.buf) < n and not self.eof:
            if self.out > STREAM_CAP or time.monotonic() - self.t0 > TIME_CAP:
                self.lst.complete = False
                self.lst.notes.append(f"Stopped reading after {self.out / 2**20:,.0f} MB of decompressed data "
                                      f"({'size' if self.out > STREAM_CAP else 'time'} limit).")
                raise _Stop()
            data = self._next()
            self.out += len(data)
            self.buf += data

    def readinto(self, b):
        self._fill(len(b))
        n = min(len(b), len(self.buf))
        b[:n] = self.buf[:n]
        self.buf = self.buf[n:]
        return n


TAR_TYPES = ((tarfile.TarInfo.issym, "symlink"), (tarfile.TarInfo.islnk, "hardlink"),
             (tarfile.TarInfo.ischr, "chardev"), (tarfile.TarInfo.isblk, "blockdev"),
             (tarfile.TarInfo.isfifo, "fifo"), (tarfile.TarInfo.isdir, "dir"), (tarfile.TarInfo.isreg, "file"))


def _tar(fh, kind, lst):
    if kind == "zstd" and _zstd is None:
        lst.complete = False
        lst.notes.append("This is Zstandard-compressed; Python before 3.14 has no decoder for it, so the "
                         "contents could not be listed.")
        return
    reader = _Capped(fh, kind, lst)
    try:
        tf = tarfile.open(fileobj=io.BufferedReader(reader, 1 << 16), mode="r|")
    except tarfile.ReadError:
        lst.format = kind  # compressed, but not a tar inside
        lst.notes.append("The compressed stream does not hold a tar archive.")
        lst.unpacked_read = reader.out
        return
    lst.format = "tar" if kind == "tar" else f"tar.{ {'gzip': 'gz', 'bzip2': 'bz2', 'xz': 'xz', 'zstd': 'zst'}[kind]}"
    try:
        for ti in tf:
            t = next((name for test, name in TAR_TYPES if test(ti)), "other")
            lst.add(name=ti.name, type=t, size=ti.size if t == "file" else 0, mode=ti.mode | _tar_fmt(t),
                    link=ti.linkname or None)
    finally:
        lst.unpacked_read = reader.out


def _tar_fmt(t):
    return {"file": stat.S_IFREG, "dir": stat.S_IFDIR, "symlink": stat.S_IFLNK, "hardlink": stat.S_IFREG,
            "chardev": stat.S_IFCHR, "blockdev": stat.S_IFBLK, "fifo": stat.S_IFIFO}.get(t, 0)


# ---- 7z ---------------------------------------------------------------------------------------

class _B:
    def __init__(self, data):
        self.d, self.p = data, 0

    def byte(self):
        if self.p >= len(self.d):
            raise ValueError("7z header ends early")
        b = self.d[self.p]
        self.p += 1
        return b

    def take(self, n):
        if n < 0 or self.p + n > len(self.d):
            raise ValueError("7z header ends early")
        out = self.d[self.p:self.p + n]
        self.p += n
        return out

    def num(self):
        first = self.byte()
        mask, value = 0x80, 0
        for i in range(8):
            if not first & mask:
                return value | ((first & (mask - 1)) << (8 * i))
            value |= self.byte() << (8 * i)
            mask >>= 1
        return value

    def bits(self, n):
        out, b, mask = [], 0, 0
        for _ in range(n):
            if mask == 0:
                b, mask = self.byte(), 0x80
            out.append(bool(b & mask))
            mask >>= 1
        return out

    def defined(self, n):
        all_defined = self.byte()
        return [True] * n if all_defined else self.bits(n)


def _streams_info(b):
    info = {"pack_pos": 0, "pack_sizes": [], "folders": [], "unpack": [], "substreams": None}
    while True:
        prop = b.num()
        if prop == 0x00:
            return info
        if prop == 0x06:  # PackInfo
            info["pack_pos"] = b.num()
            n = b.num()
            while True:
                p = b.num()
                if p == 0x00:
                    break
                if p == 0x09:
                    info["pack_sizes"] = [b.num() for _ in range(n)]
                elif p == 0x0A:
                    d = b.defined(n)
                    b.take(4 * sum(d))
        elif prop == 0x07:  # UnPackInfo
            if b.num() != 0x0B:
                raise ValueError("7z: expected folder list")
            nf = b.num()
            if b.byte():
                raise ValueError("7z: external folders are not supported")
            for _ in range(nf):
                coders, total_out, total_in = [], 0, 0
                for _ in range(b.num()):
                    flag = b.byte()
                    cid = b.take(flag & 0x0F)
                    nin, nout = (b.num(), b.num()) if flag & 0x10 else (1, 1)
                    props = b.take(b.num()) if flag & 0x20 else b""
                    coders.append({"id": cid.hex(), "props": props, "in": nin, "out": nout})
                    total_in, total_out = total_in + nin, total_out + nout
                binds = [(b.num(), b.num()) for _ in range(total_out - 1)]
                npacked = total_in - len(binds)
                if npacked > 1:
                    for _ in range(npacked):
                        b.num()
                info["folders"].append({"coders": coders, "binds": binds, "outs": total_out})
            if b.num() != 0x0C:
                raise ValueError("7z: expected unpack sizes")
            for f in info["folders"]:
                sizes = [b.num() for _ in range(f["outs"])]
                bound = {o for _, o in f["binds"]}
                main = next((i for i in range(f["outs"]) if i not in bound), 0)
                info["unpack"].append(sizes[main])
            while True:
                p = b.num()
                if p == 0x00:
                    break
                if p == 0x0A:
                    d = b.defined(len(info["folders"]))
                    b.take(4 * sum(d))
        elif prop == 0x08:  # SubStreamsInfo
            nums = [1] * len(info["folders"])
            sizes = []
            p = b.num()
            if p == 0x0D:
                nums = [b.num() for _ in info["folders"]]
                p = b.num()
            if p == 0x09:
                for k, f_size in zip(nums, info["unpack"]):
                    part = [b.num() for _ in range(k - 1)] if k else []
                    if k:
                        sizes += part + [f_size - sum(part)]
                p = b.num()
            else:
                for k, f_size in zip(nums, info["unpack"]):
                    if k == 1:
                        sizes.append(f_size)
            while p != 0x00:
                if p == 0x0A:
                    unknown = sum(k for k in nums if k != 1) or len(sizes)
                    d = b.defined(unknown)
                    b.take(4 * sum(d))
                p = b.num()
            info["substreams"] = sizes
        else:
            raise ValueError(f"7z: unexpected property {prop:#x} in streams info")


def _decode_folder(fh, info, base):
    f = info["folders"][0]
    c = f["coders"][0]
    if len(f["coders"]) != 1:
        if any(x["id"] == "06f10701" for x in f["coders"]):
            return None, "encrypted"
        return None, f"coders {[x['id'] for x in f['coders']]}"
    size = info["unpack"][0]
    if size > HEADER_CAP:
        return None, "header too large"
    fh.seek(base + info["pack_pos"])
    packed = fh.read(info["pack_sizes"][0] if info["pack_sizes"] else 0)
    if c["id"] == "030101":
        p = c["props"]
        d, ds = p[0], struct.unpack("<I", p[1:5])[0]
        filt = {"id": lzma.FILTER_LZMA1, "dict_size": ds, "lc": d % 9, "lp": (d // 9) % 5, "pb": d // 45}
    elif c["id"] == "21":
        filt = {"id": lzma.FILTER_LZMA2, "dict_size": min(1 << 30, 2 << 20)}
        bits = c["props"][0] if c["props"] else 0
        filt["dict_size"] = min((2 | (bits & 1)) << (bits // 2 + 11), 1 << 30)
    elif c["id"] == "00":
        return packed[:size], None
    elif c["id"] == "06f10701":
        return None, "encrypted"
    else:
        return None, f"coder {c['id']}"
    dec = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=[filt])
    return dec.decompress(packed, max_length=size), None


def _sevenzip(fh, lst):
    sig = fh.read(32)
    if len(sig) < 32:
        raise ValueError("7z signature header is truncated")
    off, size = struct.unpack("<QQ", sig[12:28])
    if size > HEADER_CAP:
        raise ValueError("7z header claims to be larger than 64 MB")
    fh.seek(32 + off)
    data = fh.read(size)
    b = _B(data)
    kind = b.num()
    if kind == 0x17:  # EncodedHeader: the real header is compressed
        info = _streams_info(b)
        data, why = _decode_folder(fh, info, 32)
        if data is None:
            lst.complete = False
            if why == "encrypted":
                lst.encrypted_names = True
                lst.notes.append("The file names are encrypted (a password-protected 7z), so nothing can be listed.")
            else:
                lst.notes.append(f"The 7z header uses a method Vigil can't read ({why}).")
            return
        b = _B(data)
        kind = b.num()
    if kind != 0x01:
        raise ValueError("7z: no header")
    info = {"unpack": [], "substreams": None}
    while True:
        prop = b.num()
        if prop == 0x00:
            break
        if prop == 0x02:  # ArchiveProperties
            while b.num():
                b.take(b.num())
        elif prop == 0x03:
            _streams_info(b)
        elif prop == 0x04:
            info = _streams_info(b)
        elif prop == 0x05:
            _seven_files(b, lst, info)
            break
        else:
            raise ValueError(f"7z: unexpected property {prop:#x}")


def _seven_files(b, lst, info):
    n = b.num()
    empty_stream = [False] * n
    empty_file = []
    names, attrs = [None] * n, [None] * n
    while True:
        prop = b.num()
        if prop == 0x00:
            break
        size = b.num()
        end = b.p + size
        if prop == 0x0E:
            empty_stream = b.bits(n)
        elif prop == 0x0F:
            empty_file = b.bits(sum(empty_stream))
        elif prop == 0x11:
            if b.byte():
                raise ValueError("7z: external names are not supported")
            raw = b.take(end - b.p).decode("utf-16-le", "replace")
            names = raw.split("\0")[:n]
        elif prop == 0x15:
            d = b.defined(n)
            if b.byte():
                raise ValueError("7z: external attributes are not supported")
            for i in range(n):
                if d[i]:
                    attrs[i] = struct.unpack("<I", b.take(4))[0]
        b.p = end
    sizes = list(info.get("substreams") or info.get("unpack") or [])
    k = ei = 0
    for i in range(n):
        attr = attrs[i]
        mode = (attr >> 16) if attr is not None and attr & 0x8000 else None
        if empty_stream[i]:
            is_dir = not (empty_file[ei] if ei < len(empty_file) else False)
            ei += 1
            t, sz = ("dir" if is_dir else "file"), 0
        else:
            t, sz = "file", sizes[k] if k < len(sizes) else 0
            k += 1
        if mode:
            fmt = stat.S_IFMT(mode)
            t = {stat.S_IFLNK: "symlink", stat.S_IFDIR: "dir", stat.S_IFCHR: "chardev", stat.S_IFBLK: "blockdev",
                 stat.S_IFIFO: "fifo"}.get(fmt, t)
        elif attr is not None and attr & 0x10:
            t = "dir"
        lst.add(name=names[i] if i < len(names) else f"#{i}", type=t, size=sz, mode=mode)


# ---- rar ----------------------------------------------------------------------------------

def _vint(data, p):
    v, shift = 0, 0
    while True:
        if p >= len(data):
            raise ValueError("rar header ends early")
        b = data[p]
        p += 1
        v |= (b & 0x7F) << shift
        if not b & 0x80:
            return v, p
        shift += 7
        if shift > 63:
            raise ValueError("rar number too long")


def _rar(fh, kind, lst):
    fh.seek(0, 2)
    total = fh.tell()
    if kind == "rar5":
        pos = 8
        while pos < total:
            fh.seek(pos)
            head = fh.read(4 + 3)
            if len(head) < 5:
                break
            hsize, p = _vint(head, 4)
            fh.seek(pos)
            block = fh.read(p + hsize)
            if len(block) < p + hsize:
                raise ValueError("rar block is truncated")
            q = p
            htype, q = _vint(block, q)
            hflags, q = _vint(block, q)
            extra = data_size = 0
            if hflags & 0x1:
                extra, q = _vint(block, q)
            if hflags & 0x2:
                data_size, q = _vint(block, q)
            if htype == 4:
                lst.encrypted_names = True
                lst.complete = False
                lst.notes.append("The headers are encrypted (a password-protected rar), so nothing can be listed.")
                return
            if htype == 5:
                break
            if htype == 2:
                fflags, q = _vint(block, q)
                usize, q = _vint(block, q)
                attr, q = _vint(block, q)
                if fflags & 0x2:
                    q += 4
                if fflags & 0x4:
                    q += 4
                _, q = _vint(block, q)
                host, q = _vint(block, q)
                nlen, q = _vint(block, q)
                name = block[q:q + nlen].decode("utf-8", "replace")
                q += nlen
                t, link, mode = ("dir" if fflags & 0x1 else "file"), None, None
                if host == 1:
                    mode = attr
                    fmt = stat.S_IFMT(attr)
                    t = {stat.S_IFLNK: "symlink", stat.S_IFDIR: "dir", stat.S_IFCHR: "chardev",
                         stat.S_IFBLK: "blockdev", stat.S_IFIFO: "fifo"}.get(fmt, t)
                end_extra = p + hsize
                while extra and q < end_extra:
                    rsize, q2 = _vint(block, q)
                    rtype, q3 = _vint(block, q2)
                    if rtype == 5:
                        rt, q4 = _vint(block, q3)
                        _, q4 = _vint(block, q4)
                        ln, q4 = _vint(block, q4)
                        link = block[q4:q4 + ln].decode("utf-8", "replace")
                        t = "hardlink" if rt == 4 else "symlink"
                    q = q2 + rsize
                lst.add(name=name, type=t, size=usize if t == "file" else 0, csize=data_size, mode=mode, link=link)
            pos += p + hsize + data_size
        return
    pos = 7
    while pos + 7 <= total:
        fh.seek(pos)
        h = fh.read(7)
        _, htype, flags, hsize = struct.unpack("<HBHH", h)
        if hsize < 7:
            raise ValueError("rar block size is invalid")
        fh.seek(pos)
        block = fh.read(hsize)
        add = struct.unpack("<I", block[7:11])[0] if flags & 0x8000 and len(block) >= 11 else 0
        if htype == 0x73 and flags & 0x0080:
            lst.encrypted_names = True
            lst.complete = False
            lst.notes.append("The headers are encrypted (a password-protected rar), so nothing can be listed.")
            return
        if htype == 0x7B:
            break
        if htype == 0x74:
            pack, unp, host, _, _, _, _, nsize, attr = struct.unpack("<IIBIIBBHI", block[7:32])
            q = 32
            if flags & 0x100:
                hp, hu = struct.unpack("<II", block[32:40])
                pack, unp, q = pack | hp << 32, unp | hu << 32, 40
            raw = block[q:q + nsize]
            name = raw.split(b"\0")[0].decode("utf-8" if flags & 0x200 else "latin-1", "replace")
            t, mode = ("dir" if (flags & 0xE0) == 0xE0 else "file"), None
            if host == 3:
                mode = attr
                fmt = stat.S_IFMT(attr)
                t = {stat.S_IFLNK: "symlink", stat.S_IFDIR: "dir", stat.S_IFCHR: "chardev",
                     stat.S_IFBLK: "blockdev", stat.S_IFIFO: "fifo"}.get(fmt, t)
            lst.add(name=name.replace("\\", "/"), type=t, size=unp if t == "file" else 0, csize=pack, mode=mode)
            add = pack
        pos += hsize + add
