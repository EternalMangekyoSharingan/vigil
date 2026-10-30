"""Command line: `python3 -m vigil` starts the local web UI; other commands work offline."""

import argparse
import json
import os
import sys
from pathlib import Path

from . import collector

DEFAULT_DATA = os.environ.get("VIGIL_DATA") or str(Path(__file__).resolve().parent.parent / "data")


def cmd_serve(args):
    from .server import serve
    serve(args.data, port=args.port, interval=args.interval, verbose=args.verbose)


def cmd_snapshot(args):
    """One read-only pass over /proc, printed as a table (or JSON)."""
    snap = collector.snapshot(args.proc)
    if args.json:
        json.dump(snap, sys.stdout, indent=2, default=str)
        print()
        return
    rows = [s for s in snap["sockets"] if args.all or s["kind"] == "connection"]
    print(f"{'PROTO':5} {'STATE':12} {'LOCAL':24} {'REMOTE':24} {'PID':>7}  PROGRAM")
    for s in sorted(rows, key=lambda s: (s["kind"], s["program"] or "~", s["remote_ip"])):
        local = f"{s['local_ip']}:{s['local_port']}"
        remote = f"{s['remote_ip']}:{s['remote_port']}"
        if s["program"]:
            who = snap["processes"][s["pid"]]["name"]
        else:
            who = f"({s['hidden']['label'].lower()}, uid {s['uid']})"
        print(f"{s['proto']:5} {s['state']:12} {local:24} {remote:24} {s['pid'] or '-':>7}  {who}")
    v = snap["viewer"]
    print(f"\n{len(snap['sockets'])} sockets, {len(rows)} shown; viewing as {v['user']} "
          f"(uid {v['uid']}); {snap['pids_visible']} processes visible")
    for reason, n in sorted(snap["hidden_counts"].items()):
        print(f"  {n} not attributed: {collector.HIDDEN_LABELS[reason]}")
    if snap["missing_tables"]:
        print(f"  not present on this kernel: {', '.join(snap['missing_tables'])}")


COMMANDS = ("serve", "snapshot")


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not any(a in COMMANDS for a in argv) and not {"-h", "--help"} & set(argv):
        argv.insert(0, "serve")  # `python3 -m vigil` alone starts the UI
    p = argparse.ArgumentParser(prog="vigil", description="Personal blue-team lab.")
    p.add_argument("--data", default=DEFAULT_DATA, help="evidence store directory (default: %(default)s)")
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--data", default=argparse.SUPPRESS, help=argparse.SUPPRESS)
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("serve", parents=[common], help="start the web UI on 127.0.0.1 (default)")
    s.add_argument("--port", type=int, default=8765)
    s.add_argument("--interval", type=float, default=2.0, help="seconds between /proc polls")
    s.add_argument("--verbose", action="store_true", help="log every HTTP request")
    s.set_defaults(func=cmd_serve)
    n = sub.add_parser("snapshot", parents=[common], help="print current connections once and exit")
    n.add_argument("--json", action="store_true")
    n.add_argument("--all", action="store_true", help="include listening sockets")
    n.add_argument("--proc", default="/proc", help=argparse.SUPPRESS)
    n.set_defaults(func=cmd_snapshot)
    args = p.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
