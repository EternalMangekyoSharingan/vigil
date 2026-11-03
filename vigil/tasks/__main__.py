"""python -m vigil.tasks [serve | scan | tree]"""

import argparse
import json
import sys

from ..core.store import default_data_dir

MARK = {"High": "!!", "Medium": "! ", "Low": "· ", "Info": "  "}


def main(argv=None):
    p = argparse.ArgumentParser(prog="vigil.tasks", description="What is running, where did it come from, and "
                                "should it be? Read-only.")
    p.add_argument("--data", default=None, help="evidence store directory (default: data/tasks)")
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--data", default=argparse.SUPPRESS, help=argparse.SUPPRESS)
    sub = p.add_subparsers(dest="cmd")
    s = sub.add_parser("serve", parents=[common], help="open the page on 127.0.0.1 (default)")
    s.add_argument("--port", type=int, default=8769)
    s.add_argument("--verbose", action="store_true")
    sc = sub.add_parser("scan", parents=[common], help="print flagged processes and save them for Vigil Cases")
    sc.add_argument("--json", action="store_true")
    sub.add_parser("tree", parents=[common], help="print the process tree")
    a = p.parse_args(argv)
    data = a.data or str(default_data_dir() / "tasks")
    from .server import App, serve
    if a.cmd in (None, "serve"):
        serve(data, port=getattr(a, "port", 8769), verbose=getattr(a, "verbose", False))
        return 0
    app = App(data)
    try:
        if a.cmd == "scan":
            r = app.api_scan({}, b"{}", {})
            if a.json:
                print(json.dumps(r["findings"], indent=2, default=str))
                return 0
            for f in r["findings"]:
                print(f"{MARK[f['severity']]} {f['severity']:6} {f['title']}\n          {f['summary']}")
            if not r["findings"]:
                print("No process matched Vigil's checks.")
            return 2 if any(f["severity"] == "High" for f in r["findings"]) else 0
        t = app.api_tree({})
        nodes = t["nodes"]

        def walk(pid, prefix, last, depth):
            n = nodes[pid]
            if n["kernel"] and depth > 1:
                return
            flag = "  [" + ", ".join(f["severity"] + ": " + f["check"] for f in n["flags"]) + "]" if n["flags"] else ""
            print(f"{prefix}{'' if depth == 0 else ('└─ ' if last else '├─ ')}{pid} {n['name']}  {n['user']}"
                  + (f"  {n['package']}" if n["package"] else "") + flag)
            kids = [k for k in n["children"] if not nodes[k]["kernel"]]
            for i, k in enumerate(kids):
                walk(k, prefix + ("" if depth == 0 else ("   " if last else "│  ")), i == len(kids) - 1, depth + 1)
        for i, r in enumerate(t["roots"]):
            walk(r, "", i == len(t["roots"]) - 1, 0)
        return 0
    finally:
        app.close()


if __name__ == "__main__":
    sys.exit(main())
