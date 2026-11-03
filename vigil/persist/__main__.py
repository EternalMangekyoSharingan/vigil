"""python -m vigil.persist [serve | scan | accept]"""

import argparse
import json
import sys

from ..core.store import default_data_dir

MARK = {"High": "!!", "Medium": "! ", "Low": "· ", "Info": "  "}


def main(argv=None):
    p = argparse.ArgumentParser(prog="vigil.persist", description="What starts automatically, and what changed "
                                "since the baseline? Read-only.")
    p.add_argument("--data", default=None, help="evidence store directory (default: data/persist)")
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--data", default=argparse.SUPPRESS, help=argparse.SUPPRESS)
    sub = p.add_subparsers(dest="cmd")
    s = sub.add_parser("serve", parents=[common], help="open the page on 127.0.0.1 (default)")
    s.add_argument("--port", type=int, default=8768)
    s.add_argument("--verbose", action="store_true")
    sc = sub.add_parser("scan", parents=[common], help="scan now and print findings (the first scan is the baseline)")
    sc.add_argument("--json", action="store_true")
    sc.add_argument("--all", action="store_true", help="also list every autostart entry")
    sub.add_parser("accept", parents=[common], help="scan, then make what is there now the new baseline")
    a = p.parse_args(argv)
    data = a.data or str(default_data_dir() / "persist")
    from .server import App, serve
    if a.cmd in (None, "serve"):
        serve(data, port=getattr(a, "port", 8768), verbose=getattr(a, "verbose", False))
        return 0
    app = App(data)
    try:
        rep = app.scan()
        if a.cmd == "accept":
            app.accept()
            print(f"Baseline updated: {len(rep['entries'])} entries.")
            return 0
        if a.json:
            print(json.dumps(rep, indent=2, default=str))
            return 0
        d = rep["diff"]
        print(f"{len(rep['entries'])} autostart entries; package database: {rep['package_db'] or 'none'}"
              + ("; baseline taken now" if rep.get("baseline_created") else
                 f"; vs baseline: {len(d['added'])} new, {len(d['changed'])} changed, {len(d['removed'])} gone"))
        for f in rep["findings"]:
            print(f"{MARK[f['severity']]} {f['severity']:6} {f['title']}\n          {f['summary'][:200]}")
        if a.all:
            for e in rep["entries"]:
                print(f"  {e['group']:9} {e['scope']:6} {e['path']}"
                      + (f"  [{e['package']}: {e['integrity']}]" if e.get("package") else ""))
        print("\nLimits:\n  - " + "\n  - ".join(rep["limits"]))
        return 2 if rep["counts"]["High"] else 1 if rep["counts"]["Medium"] else 0
    finally:
        app.close()


if __name__ == "__main__":
    sys.exit(main())
