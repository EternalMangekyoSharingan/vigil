"""Read-only parsing of OLE2 compound files and the VBA macros inside them.

Compound files (MS-CFB) hold legacy Office documents and the vbaProject.bin inside
.docm/.xlsm files. VBA source is stored compressed (MS-OVBA). Everything here works
on bytes in memory, checks every offset, and refuses loops, so a hostile file can
make parsing fail but cannot make it run code or hang.
"""

import struct

MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
FREESECT, ENDOFCHAIN = 0xFFFFFFFF, 0xFFFFFFFE
NOSTREAM = 0xFFFFFFFF
STORAGE, STREAM, ROOT = 1, 2, 5


class OleError(ValueError):
    pass


class OleFile:
    """A compound file: a small filesystem of storages (folders) and streams (files)."""

    def __init__(self, data):
        if len(data) < 512 or data[:8] != MAGIC:
            raise OleError("not an OLE2 compound file")
        self.data = data
        major = struct.unpack_from("<H", data, 0x1A)[0]
        shift, mini_shift = struct.unpack_from("<HH", data, 0x1E)
        if shift not in (9, 12) or mini_shift != 6:
            raise OleError(f"unsupported sector sizes (2^{shift}, 2^{mini_shift})")
        self.ss, self.mss = 1 << shift, 1 << mini_shift
        (num_fat, first_dir, _sig, self.cutoff, first_minifat, num_minifat, first_difat,
         num_difat) = struct.unpack_from("<IIIIIIII", data, 0x2C)
        self.nsect = max(0, (len(data) - self.ss) // self.ss) + 1
        # The DIFAT lists the sectors holding the FAT: 109 in the header, then a chain.
        difat = list(struct.unpack_from("<109I", data, 0x4C))
        sect, seen = first_difat, set()
        while sect not in (FREESECT, ENDOFCHAIN) and len(seen) < num_difat + 1:
            if sect in seen or sect >= self.nsect:
                raise OleError("broken DIFAT chain")
            seen.add(sect)
            words = struct.unpack(f"<{self.ss // 4}I", self._sector(sect))
            difat.extend(words[:-1])
            sect = words[-1]
        fat_sectors = [s for s in difat if s not in (FREESECT, ENDOFCHAIN)][:num_fat]
        raw = b"".join(self._sector(s) for s in fat_sectors)
        self.fat = struct.unpack(f"<{len(raw) // 4}I", raw)
        self.entries = self._directory(self._chain_bytes(first_dir, self.fat, self.ss), major)
        if not self.entries or self.entries[0]["type"] != ROOT:
            raise OleError("no root entry")
        root = self.entries[0]
        self.ministream = self._chain_bytes(root["start"], self.fat, self.ss)[:root["size"]]
        mraw = self._chain_bytes(first_minifat, self.fat, self.ss) if num_minifat else b""
        self.minifat = struct.unpack(f"<{len(mraw) // 4}I", mraw)
        self.paths = self._walk()

    def _sector(self, n):
        off = (n + 1) * self.ss
        if n >= self.nsect or off + self.ss > len(self.data) + self.ss:
            raise OleError(f"sector {n} outside the file")
        return self.data[off:off + self.ss].ljust(self.ss, b"\0")

    def _chain(self, start, fat):
        out, seen = [], set()
        while start not in (FREESECT, ENDOFCHAIN):
            if start in seen or start >= len(fat):
                raise OleError("broken sector chain")
            seen.add(start)
            out.append(start)
            start = fat[start]
        return out

    def _chain_bytes(self, start, fat, size):
        if size == self.ss:
            return b"".join(self._sector(s) for s in self._chain(start, fat))
        mini = self.ministream
        parts = []
        for s in self._chain(start, fat):
            if (s + 1) * size > len(mini):
                raise OleError("mini sector outside the mini stream")
            parts.append(mini[s * size:(s + 1) * size])
        return b"".join(parts)

    def _directory(self, raw, major):
        entries = []
        for off in range(0, len(raw) - 127, 128):
            name_len, etype = struct.unpack_from("<HB", raw, off + 64)
            name = raw[off:off + max(0, min(name_len, 64) - 2)].decode("utf-16-le", "replace")
            left, right, child = struct.unpack_from("<III", raw, off + 68)
            start, size = struct.unpack_from("<IQ", raw, off + 116)
            if major == 3:
                size &= 0xFFFFFFFF  # version 3 files leave the high half undefined
            entries.append({"name": name, "type": etype, "left": left, "right": right,
                            "child": child, "start": start, "size": size})
        return entries

    def _walk(self):
        """Map every stream and storage to its path, e.g. ('Macros', 'VBA', 'dir')."""
        paths, seen = {}, set()
        stack = [(self.entries[0]["child"], ())]
        while stack:
            idx, parent = stack.pop()
            if idx == NOSTREAM or idx >= len(self.entries) or idx in seen:
                continue
            seen.add(idx)
            e = self.entries[idx]
            stack += [(e["left"], parent), (e["right"], parent)]
            if e["type"] in (STORAGE, STREAM):
                path = parent + (e["name"],)
                paths[path] = idx
                if e["type"] == STORAGE:
                    stack.append((e["child"], path))
        return paths

    def streams(self):
        return sorted(p for p, i in self.paths.items() if self.entries[i]["type"] == STREAM)

    def find(self, *names):
        """Paths whose last parts match `names`, case-insensitively."""
        want = tuple(n.lower() for n in names)
        return [p for p in self.paths if tuple(x.lower() for x in p[-len(want):]) == want]

    def read(self, path):
        e = self.entries[self.paths[path]]
        if e["type"] != STREAM:
            raise OleError(f"{'/'.join(path)} is not a stream")
        if e["size"] < self.cutoff:
            data = self._chain_bytes(e["start"], self.minifat, self.mss)
        else:
            data = self._chain_bytes(e["start"], self.fat, self.ss)
        return data[:e["size"]]


def decompress(data):
    """MS-OVBA 2.4.1 decompression of a CompressedContainer."""
    if not data or data[0] != 1:
        raise OleError("not a VBA compressed container")
    out = bytearray()
    pos = 1
    while pos + 2 <= len(data):
        header = struct.unpack_from("<H", data, pos)[0]
        end = min(pos + (header & 0x0FFF) + 3, len(data))
        pos += 2
        chunk_start = len(out)
        if not header & 0x8000:  # stored chunk: 4096 raw bytes
            out += data[pos:pos + 4096]
            pos += 4096
            continue
        while pos < end:
            flags = data[pos]
            pos += 1
            for bit in range(8):
                if pos >= end:
                    break
                if not flags >> bit & 1:
                    out.append(data[pos])
                    pos += 1
                    continue
                if pos + 2 > end:
                    pos = end
                    break
                token = struct.unpack_from("<H", data, pos)[0]
                pos += 2
                bits = max((len(out) - chunk_start - 1).bit_length(), 4)
                length = (token & (0xFFFF >> bits)) + 3
                src = len(out) - ((token >> (16 - bits)) + 1)
                if src < chunk_start:
                    raise OleError("copy token points before its chunk")
                for _ in range(length):  # byte by byte: copies may overlap themselves
                    out.append(out[src])
                    src += 1
        pos = end
    return bytes(out)


def vba_modules(ole):
    """All VBA modules in a compound file: [{'name', 'stream', 'source'}].

    A VBA project is a storage holding a 'dir' stream (compressed) that lists the
    modules and where each one's compressed source starts in its stream.
    """
    modules = []
    for dir_path in ole.find("dir"):
        base = dir_path[:-1]
        if (base + ("_VBA_PROJECT",)) not in ole.paths and not any(
                p[:-1] == base and p[-1].lower() == "_vba_project" for p in ole.paths):
            continue
        info = decompress(ole.read(dir_path))
        codepage, current, found = 1252, None, []
        pos = 0
        while pos + 6 <= len(info):
            rid, size = struct.unpack_from("<HI", info, pos)
            pos += 6
            if rid == 0x0009:  # PROJECTVERSION: its size field says 4, but 6 bytes follow
                size = 6
            value = info[pos:pos + size]
            pos += size
            if rid == 0x0003 and size == 2:
                codepage = struct.unpack("<H", value)[0]
            elif rid == 0x0019:
                current = {"name": value.decode("latin-1"), "stream": None, "offset": 0}
                found.append(current)
            elif rid == 0x0047 and current:
                current["name"] = value.decode("utf-16-le", "replace")
            elif rid == 0x001A and current:
                current["stream"] = value.decode("latin-1")
            elif rid == 0x0032 and current:
                current["stream"] = value.decode("utf-16-le", "replace")
            elif rid == 0x0031 and current and size == 4:
                current["offset"] = struct.unpack("<I", value)[0]
        encoding = f"cp{codepage}"
        try:
            "".encode(encoding)
        except LookupError:
            encoding = "cp1252"
        for m in found:
            matches = [p for p in ole.paths if p[:-1] == base and
                       p[-1].lower() == (m["stream"] or m["name"]).lower()]
            if not matches:
                continue
            raw = ole.read(matches[0])
            source = decompress(raw[m["offset"]:]).decode(encoding, "replace")
            modules.append({"name": m["name"], "stream": "/".join(matches[0]),
                            "source": source})
    return modules
