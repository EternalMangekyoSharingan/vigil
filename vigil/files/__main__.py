"""python -m vigil.files [serve | inspect FILE | ls DIR | quarantine FILE | quarantined | restore ID | watch [DIR]]"""

import argparse
import json
import sys
import time

from ..core.store import default_data_dir

MARK = {"High": "!!", "Medium": "! ", "Low": "· ", "Info": "  "}


def show(rep):
    print(f"{rep['verdict'].upper()}  {rep['name']}  ({rep['type'].get('description')}, {rep['size']} bytes)")
    print(f"  sha256 {rep['hashes'].get('sha256')}")
    for f in rep["findings"]:
        print(f"{MARK[f['severity']]} {f['severity']:6} {f['title']}\n          {f['summary']}")
    if rep.get("listing"):
        l = rep["listing"]
        print(f"\n  {l['format']}: {l['count']} entries, {l['declared_total']} bytes declared"
              + ("" if l["complete"] else " (listing incomplete)"))
    print("\nLimits:\n  - " + "\n  - ".join(rep["limits"]))


def main(argv=None):
    p = argparse.ArgumentParser(prog="vigil.files", description="Is this file or archive safe to open? "
                                "Reads bytes only: never opens, extracts or runs the file.")
    p.add_argument("--data", default=None, help="evidence store directory (default: data/files)")
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--data", default=argparse.SUPPRESS, help=argparse.SUPPRESS)
    sub = p.add_subparsers(dest="cmd")
    s = sub.add_parser("serve", parents=[common], help="open the page on 127.0.0.1 (default)")
    s.add_argument("--port", type=int, default=8767)
    s.add_argument("--verbose", action="store_true")
    i = sub.add_parser("inspect", parents=[common], help="triage one file in the terminal")
    i.add_argument("file")
    i.add_argument("--json", action="store_true")
    ls = sub.add_parser("ls", parents=[common], help="list a folder with each file's real type")
    ls.add_argument("folder", nargs="?")
    qp = sub.add_parser("quarantine", parents=[common], help="move a file into quarantine (asks first)")
    qp.add_argument("file")
    qp.add_argument("--yes", action="store_true", help="don't ask")
    sub.add_parser("quarantined", parents=[common], help="list quarantined files")
    r = sub.add_parser("restore", parents=[common], help="put a quarantined file back")
    r.add_argument("id")
    r.add_argument("--to", help="restore somewhere else")
    w = sub.add_parser("watch", parents=[common], help="check new files in Downloads as they arrive")
    w.add_argument("folder", nargs="?")
    a = p.parse_args(argv)
    data = a.data or str(default_data_dir() / "files")
    from .server import App
    if a.cmd in (None, "serve"):
        from .server import serve
        serve(data, port=getattr(a, "port", 8767), verbose=getattr(a, "verbose", False))
        return 0
    app = App(data)
    try:
        if a.cmd == "inspect":
            rep = app.inspect(a.file)
            if a.json:
                print(json.dumps(rep, indent=2, default=str))
            else:
                show(rep)
            return {"Likely malicious": 2, "Suspicious": 1}.get(rep["verdict"], 0)
        if a.cmd == "ls":
            b = app.api_browse({"path": a.folder} if a.folder else {})
            print(b["folder"])
            for e in b["entries"]:
                flag = f"  [{e['flag']['severity']}: {e['flag']['text']}]" if e["flag"] else ""
                print(f"  {e['kind']:5} {e['size']:>12}  {e['name']}  ({e['type'] or '-'}){flag}")
            return 0
        if a.cmd == "quarantine":
            if not a.yes and input(f"Move {a.file} into quarantine and remove its permissions? [y/N] ").lower() != "y":
                print("Nothing changed.")
                return 1
            rec = app.quarantine.put(a.file, "command line")
            print(f"Quarantined as {rec['id']} (restore with: python3 -m vigil.files restore {rec['id']})")
            return 0
        if a.cmd == "quarantined":
            for rec in app.quarantine.items():
                print(f"  {rec['id']}  {time.strftime('%Y-%m-%d %H:%M', time.localtime(rec['quarantined_at']))}  "
                      f"{rec['original']}")
            return 0
        if a.cmd == "restore":
            rec = app.quarantine.restore(a.id, a.to)
            print(f"Restored to {rec['restored_to']}")
            return 0
        if a.cmd == "watch":
            from .watch import Watcher
            w = Watcher(a.folder or app.downloads, app.inspect)
            print(f"Watching {w.folder} for new files (Ctrl+C to stop)…")
            try:
                while True:
                    for ev in w.tick():
                        print(f"{time.strftime('%H:%M:%S')}  {ev.get('verdict') or ev.get('error')}  {ev['path']}"
                              + (f"  — {ev['top']}" if ev.get("top") else ""))
                    time.sleep(w.interval)
            except KeyboardInterrupt:
                return 0
    finally:
        app.close()


if __name__ == "__main__":
    sys.exit(main())
