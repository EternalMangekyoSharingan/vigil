"""python -m vigil.cases [serve | import | timeline | new TITLE | add CASE KEY | note | export CASE]"""

import argparse
import json
import sys
from pathlib import Path

from ..core.export import local
from ..core.store import default_data_dir


def main(argv=None):
    p = argparse.ArgumentParser(prog="vigil.cases", description="One timeline of findings from every Vigil tool, "
                                "cases with notes, and CSV / STIX 2.1 / Markdown exports.")
    p.add_argument("--data", default=None, help="the Vigil data folder holding each tool's folder (default: data/)")
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--data", default=argparse.SUPPRESS, help=argparse.SUPPRESS)
    sub = p.add_subparsers(dest="cmd")
    s = sub.add_parser("serve", parents=[common], help="open the page on 127.0.0.1 (default)")
    s.add_argument("--port", type=int, default=8770)
    s.add_argument("--verbose", action="store_true")
    im = sub.add_parser("import", parents=[common], help="import findings from every tool (or a .jsonl file)")
    im.add_argument("file", nargs="?")
    tl = sub.add_parser("timeline", parents=[common], help="print the timeline")
    tl.add_argument("--case", type=int)
    sub.add_parser("cases", parents=[common], help="list cases")
    n = sub.add_parser("new", parents=[common], help="open a case")
    n.add_argument("title")
    n.add_argument("--tags", default="")
    ad = sub.add_parser("add", parents=[common], help="add a finding (by key, see timeline) to a case")
    ad.add_argument("case", type=int)
    ad.add_argument("key")
    no = sub.add_parser("note", parents=[common], help="add a note to a case")
    no.add_argument("case", type=int)
    no.add_argument("text")
    ex = sub.add_parser("export", parents=[common], help="write a case's report or indicators to stdout")
    ex.add_argument("case", type=int, nargs="?", help="omit for every finding")
    ex.add_argument("--format", choices=["md", "csv", "csv-findings", "stix"], default="md")
    a = p.parse_args(argv)
    root = Path(a.data) if a.data else default_data_dir()
    from .server import App, serve
    if a.cmd in (None, "serve"):
        serve(str(root / "cases"), port=getattr(a, "port", 8770), verbose=getattr(a, "verbose", False), data_root=root)
        return 0
    app = App(str(root / "cases"), root)
    try:
        if a.cmd == "import":
            from . import importer
            res = ([importer.import_text(app.store, Path(a.file).read_text(), a.file)] if a.file
                   else importer.import_all(app.store, root))
            for r in res:
                print(json.dumps(r))
        elif a.cmd == "timeline":
            for e in reversed(app.store.timeline(a.case)):
                if e["kind"] == "finding":
                    print(f"{local(e['ts'])}  {e['severity']:6} {e['tool']:7} {e['title']}   [{e['key']}]")
                else:
                    print(f"{local(e['ts'])}  {e['kind']:6}         {e.get('text')}")
        elif a.cmd == "cases":
            for c in app.store.cases():
                print(f"  #{c['id']}  {c['status']:13} {c['n']:>4} findings  {c['title']}")
        elif a.cmd == "new":
            c = app.store.create(a.title, a.tags.split(","))
            print(f"Opened case #{c['id']}: {c['title']}")
        elif a.cmd == "add":
            app.store.attach(a.case, a.key)
            print("Added.")
        elif a.cmd == "note":
            app.store.note(a.text, case_id=a.case)
            print("Noted.")
        elif a.cmd == "export":
            data, _, _ = app.api_export({"case": a.case, "format": a.format} if a.case else {"format": a.format})
            sys.stdout.write(data.decode())
        return 0
    finally:
        app.close()


if __name__ == "__main__":
    sys.exit(main())
