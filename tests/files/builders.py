"""Byte-level builders for SYNTHETIC archives the standard library can't write: 7z (plain
and LZMA-compressed headers) and RAR4 / RAR5 block headers. Only the index parts that a
lister reads are built; the data areas are filler. Nothing here is real malware."""

import lzma
import stat
import struct
import zlib


# ---- 7z ---------------------------------------------------------------------------------

def _num(n):
    """7z variable-length number."""
    if n < 0x80:
        return bytes([n])
    for i in range(1, 9):
        if n < (1 << (7 * (i + 1))) or i == 8:
            first = (0xFF << (8 - i)) & 0xFF
            if i < 8:
                first |= n >> (8 * i)
            return bytes([first]) + (n & ((1 << (8 * i)) - 1)).to_bytes(i, "little")


def _bits(flags):
    out, b, mask = bytearray(), 0, 0x80
    for f in flags:
        if f:
            b |= mask
        mask >>= 1
        if not mask:
            out.append(b)
            b, mask = 0, 0x80
    if mask != 0x80:
        out.append(b)
    return bytes(out)


def _streams(pack_pos, pack_size, unpack_sizes, coder_id=b"\x00", props=b""):
    """MainStreamsInfo with one folder (one coder) and one substream per file."""
    s = b"\x06" + _num(pack_pos) + _num(1) + b"\x09" + _num(pack_size) + b"\x00"
    flag = len(coder_id) | (0x20 if props else 0)
    coder = bytes([flag]) + coder_id + (_num(len(props)) + props if props else b"")
    total = sum(unpack_sizes)
    s += b"\x07\x0b" + _num(1) + b"\x00" + _num(1) + coder + b"\x0c" + _num(total) + b"\x00"
    s += b"\x08\x0d" + _num(len(unpack_sizes))
    if len(unpack_sizes) > 1:
        s += b"\x09" + b"".join(_num(x) for x in unpack_sizes[:-1])
    s += b"\x00"
    return s + b"\x00"


def sevenzip(files, encode_header=False, encrypt_header=False):
    """files: [(name, size, unix_mode or None, is_dir)]. Returns 7z bytes."""
    data = b"\0" * sum(f[1] for f in files if not f[3] and f[1])   # stored ("copy") data
    plain = plain_header(files)
    header, body = plain, data
    if encode_header or encrypt_header:
        if encrypt_header:
            packed, cid, cprops = b"\x00" * 32, bytes.fromhex("06f10701"), b"\x00" * 10
        else:
            filt = {"id": lzma.FILTER_LZMA1, "dict_size": 1 << 16, "lc": 3, "lp": 0, "pb": 2}
            packed = lzma.compress(plain, format=lzma.FORMAT_RAW, filters=[filt])
            cid, cprops = bytes.fromhex("030101"), bytes([3 + 0 * 9 + 2 * 45]) + struct.pack("<I", 1 << 16)
        pos = len(body)
        body += packed
        coder = bytes([len(cid) | 0x20]) + cid + _num(len(cprops)) + cprops
        header = (b"\x17" + b"\x06" + _num(pos) + _num(1) + b"\x09" + _num(len(packed)) + b"\x00"
                  + b"\x07\x0b" + _num(1) + b"\x00" + _num(1) + coder + b"\x0c" + _num(len(plain)) + b"\x00"
                  + b"\x00")
    start = struct.pack("<QQI", len(body), len(header), zlib.crc32(header))
    return b"7z\xbc\xaf\x27\x1c\x00\x04" + struct.pack("<I", zlib.crc32(start)) + start + body + header


def plain_header(files):
    with_data = [f for f in files if not f[3] and f[1]]
    data_len = sum(f[1] for f in with_data)
    header = b"\x01"
    if with_data:
        header += b"\x04" + _streams(0, data_len, [f[1] for f in with_data])
    props = b""
    empty = [f[3] or not f[1] for f in files]
    if any(empty):
        bits = _bits(empty)
        props += b"\x0e" + _num(len(bits)) + bits
        ef = _bits([not f[3] for f, e in zip(files, empty) if e])
        props += b"\x0f" + _num(len(ef)) + ef
    names = b"\x00" + b"".join(f[0].encode("utf-16-le") + b"\0\0" for f in files)
    props += b"\x11" + _num(len(names)) + names
    attrs = b"\x01\x00" + b"".join(struct.pack("<I", ((f[2] << 16) | 0x8000 if f[2] else 0) | (0x10 if f[3] else 0))
                                   for f in files)
    props += b"\x15" + _num(len(attrs)) + attrs
    return header + b"\x05" + _num(len(files)) + props + b"\x00\x00"


# ---- RAR5 ---------------------------------------------------------------------------------

def _vint(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def _rar5_block(htype, flags, body, extra=b"", data_size=0):
    fields = _vint(htype) + _vint(flags | (0x1 if extra else 0) | (0x2 if data_size else 0))
    if extra:
        fields += _vint(len(extra))
    if data_size:
        fields += _vint(data_size)
    h = fields + body + extra
    sized = _vint(len(h)) + h
    return struct.pack("<I", zlib.crc32(sized)) + sized


def rar5(files, encrypted=False):
    """files: [(name, size, unix_mode, link or None, link_type)]; link_type 1 symlink, 4 hardlink."""
    out = b"Rar!\x1a\x07\x01\x00"
    if encrypted:
        out += _rar5_block(4, 0, _vint(0) + _vint(0) + b"\0" * 16 + b"\0" * 16)
        return out + b"\0" * 64
    out += _rar5_block(1, 0, _vint(0))
    for name, size, mode, link, ltype in files:
        is_dir = stat.S_ISDIR(mode)
        body = _vint(0x1 if is_dir else 0) + _vint(size) + _vint(mode) + _vint(0) + _vint(1)
        nb = name.encode()
        body += _vint(len(nb)) + nb
        extra = b""
        if link:
            lb = link.encode()
            rec = _vint(5) + _vint(ltype) + _vint(0) + _vint(len(lb)) + lb
            extra = _vint(len(rec)) + rec
        out += _rar5_block(2, 0, body, extra, data_size=size) + b"\0" * size
    return out + _rar5_block(5, 0, _vint(0))


# ---- RAR4 ----------------------------------------------------------------------------------

def rar4(files, encrypted=False):
    """files: [(name, size, unix_mode)]."""
    out = b"Rar!\x1a\x07\x00"
    main_flags = 0x0080 if encrypted else 0
    out += struct.pack("<HBHH", 0, 0x73, main_flags, 13) + b"\0" * 6
    if encrypted:
        return out + b"\0" * 64
    for name, size, mode in files:
        nb = name.encode()
        flags = 0x8000 | (0xE0 if stat.S_ISDIR(mode) else 0)
        hsize = 32 + len(nb)
        hdr = struct.pack("<HBHH", 0, 0x74, flags, hsize) + struct.pack("<IIBIIBBHI", size, size, 3, 0, 0, 29, 0x30,
                                                                         len(nb), mode) + nb
        out += hdr + b"\0" * size
    return out + struct.pack("<HBHH", 0, 0x7B, 0, 7)
