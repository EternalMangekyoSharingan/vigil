"""Quarantine: move a file out of the way, remove every permission, remember where it
came from; restore puts it back exactly. Both happen only when the user confirms.

    data/files/quarantine/<id>/item        the file, mode 000
    data/files/quarantine/<id>/record.json original path, mode, size, mtime, SHA-256, time, reason

The folder itself is 0700. Making it `noexec` needs a mount option, which only an
admin can set; Vigil says whether the folder's file system is mounted noexec, and in any
case a file with mode 000 cannot be run (or read) until it is restored.
"""

import hashlib
import json
import os
import shutil
import time
import uuid
from pathlib import Path


class QuarantineError(Exception):
    pass


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def mount_options(path, mountinfo="/proc/self/mountinfo"):
    """Mount options of the file system holding `path` (from /proc/self/mountinfo)."""
    path = os.path.realpath(path)
    best, opts = "", []
    try:
        with open(mountinfo, encoding="utf-8") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) < 6:
                    continue
                mnt = parts[4].replace("\\040", " ")
                if (path == mnt or path.startswith(mnt.rstrip("/") + "/")) and len(mnt) >= len(best):
                    best, opts = mnt, parts[5].split(",")
    except OSError:
        return None
    return {"mount": best, "options": opts, "noexec": "noexec" in opts}


class Quarantine:
    def __init__(self, folder):
        self.dir = Path(folder)
        self.dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.dir, 0o700)

    def status(self):
        m = mount_options(str(self.dir))
        return {"folder": str(self.dir), "noexec": bool(m and m["noexec"]), "mount": m and m["mount"],
                "note": None if m and m["noexec"] else
                "This folder's file system is not mounted noexec (only an admin can do that). Quarantined files "
                "have every permission removed instead, so they can't be run or read until restored."}

    def put(self, path, reason="", report_sha256=None):
        """Move `path` into quarantine. Returns the record."""
        src = os.path.abspath(path)
        st = os.lstat(src)
        if not os.path.isfile(src) or os.path.islink(src):
            raise QuarantineError("only regular files can be quarantined")
        digest = _sha256(src)
        if report_sha256 and report_sha256 != digest:
            raise QuarantineError("the file changed since it was inspected; inspect it again first")
        qid = uuid.uuid4().hex[:12]
        box = self.dir / qid
        box.mkdir(mode=0o700)
        item = box / "item"
        rec = {"id": qid, "original": src, "mode": st.st_mode & 0o7777, "size": st.st_size, "mtime": st.st_mtime,
               "sha256": digest, "quarantined_at": time.time(), "reason": reason, "uid": st.st_uid}
        (box / "record.json").write_text(json.dumps(rec, indent=2))
        try:
            shutil.move(src, item)          # a rename on the same file system, else copy then delete
        except OSError as exc:
            shutil.rmtree(box, ignore_errors=True)
            raise QuarantineError(f"could not move the file: {exc.strerror}") from None
        os.chmod(item, 0)
        return rec

    def items(self):
        out = []
        for rec in sorted(self.dir.glob("*/record.json")):
            try:
                out.append(json.loads(rec.read_text()))
            except (OSError, ValueError):
                continue
        return sorted(out, key=lambda r: -r["quarantined_at"])

    def record(self, qid):
        if not qid or not qid.isalnum():
            raise QuarantineError("bad quarantine id")
        p = self.dir / qid / "record.json"
        if not p.exists():
            raise QuarantineError("no such quarantined file")
        return json.loads(p.read_text())

    def restore(self, qid, to=None):
        """Put the file back where it was (or at `to`), with its permissions and time."""
        rec = self.record(qid)
        box = self.dir / qid
        item = box / "item"
        dest = os.path.abspath(to or rec["original"])
        if os.path.lexists(dest):
            raise QuarantineError(f"{dest} already exists; choose another place to restore to")
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        os.chmod(item, 0o600)
        if _sha256(item) != rec["sha256"]:
            os.chmod(item, 0)
            raise QuarantineError("the quarantined copy does not match its record; left in quarantine")
        shutil.move(str(item), dest)
        os.chmod(dest, rec["mode"])
        os.utime(dest, (rec["mtime"], rec["mtime"]))
        shutil.rmtree(box)
        return dict(rec, restored_to=dest)

    def delete(self, qid):
        """Delete a quarantined file for good (the user's explicit choice)."""
        self.record(qid)
        box = self.dir / qid
        os.chmod(box / "item", 0o600)
        shutil.rmtree(box)
        return {"ok": True}
