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


def _offline(args):
    from .enrich import Enricher
    from .store import Store
    Path(args.data).mkdir(parents=True, exist_ok=True, mode=0o700)
    store = Store(str(Path(args.data) / "vigil.db"))
    return store, Enricher(store, args.data)


def _report(results):
    for r in results:
        if r["ok"]:
            size = f"{r['entries']} indicators" if "entries" in r else f"{r['ranges']} ranges"
            print(f"  {r['name']:8} ok      {size}")
        else:
            print(f"  {r['name']:8} FAILED  {r['error']}")
    return 0 if all(r["ok"] for r in results) else 1


def cmd_update_feeds(args):
    """Download the abuse.ch feeds. This is a network call, made because you asked."""
    from .enrich import FEEDS
    unknown = sorted(set(args.feed) - set(FEEDS))
    if unknown:
        sys.exit(f"unknown feed {', '.join(unknown)}; choose from {', '.join(FEEDS)}")
    store, enricher = _offline(args)
    print("Downloading threat feeds (public lists; nothing about your traffic is sent)…")
    code = _report(enricher.update_feeds(args.feed or None))
    store.close()
    sys.exit(code)


def cmd_update_geo(args):
    store, enricher = _offline(args)
    if args.file:
        print(f"Loading country/ASN database from {args.file}…")
    else:
        print("Downloading the IPtoASN country/ASN database (public, ~7 MB)…")
    code = _report([enricher.update_geo(path=args.file)])
    store.close()
    sys.exit(code)


def cmd_lookup(args):
    """What Vigil knows about an address, offline."""
    store, enricher = _offline(args)
    info = enricher.describe(args.ip)
    print(f"{args.ip}  ({collector.scope_of(args.ip)})")
    g = info["geo"]
    if g:
        print(f"  owner    AS{g['asn']} {g['owner']}")
        print(f"  country  {g['country_name']} ({g['country']})" if g["country"] else "  country  unknown")
        print(f"  range    {g['range']}")
    else:
        print("  owner    not in the country/ASN database (run update-geo, or the address is not routed)")
    for h in info["intel"]:
        print(f"  intel    {h['title']}: {h['label']} ({h['indicator']})")
    if not info["intel"]:
        print("  intel    not listed in the downloaded feeds")
    store.close()


def cmd_inspect(args):
    """Static triage of a file on disk: its bytes are read, nothing is opened or run."""
    from . import engines, inspector
    path = Path(args.file)
    data = path.read_bytes()
    report = inspector.inspect_bytes(data, path.name)
    inspector.run_clamav(report, data, available=engines.clamav_available)
    store, enricher = _offline(args)
    inspector.link_context(report, store, enricher)
    if not args.no_save:
        inspector.save(store, report, f"command line: {path.resolve()}")
    store.close()
    if args.json:
        json.dump(report, sys.stdout, indent=2)
        print()
        return
    print(f"{report['verdict'].upper()}  (score {report['score']:.0f}/100)  {path.name}")
    print(f"  {report['type']['description']}, {report['size']} bytes")
    print(f"  sha256 {report['hashes']['sha256']}")
    if report["findings"]:
        print("\nFindings:")
        for f in report["findings"]:
            print(f"  +{f['points']:<4.0f} {f['reason']}\n         {f['check']} · {f['data']}")
    if report["iocs"]:
        print("\nIndicators:")
        for i in report["iocs"][:50]:
            note = "  [listed: " + ", ".join(h["feed"] for h in i["intel"]) + "]" if i.get("intel") else ""
            print(f"  {i['type']:7} {i['value']}{note}")
    print("\nLimits:")
    for line in report["limits"]:
        print(f"  - {line}")


def cmd_app(args):
    """Vigil in its own window; it stops when the window closes."""
    from . import desktop
    how = desktop.run(args.data, port=args.port, interval=args.interval, mode=args.window)
    print(f"Window closed ({how}).")


def cmd_install_desktop(args):
    from . import desktop
    entry, icon = desktop.install_launcher(data_dir=args.data if args.data != DEFAULT_DATA else None)
    print(f"Added Vigil to your application menu:\n  {entry}\n  {icon}")
    print("It runs as your user; nothing outside your home directory was changed.")


def cmd_uninstall_desktop(args):
    from . import desktop
    removed = desktop.uninstall_launcher()
    print("Removed:\n  " + "\n  ".join(map(str, removed)) if removed else "No Vigil menu entry was installed.")


COMMANDS = ("serve", "app", "install-desktop", "uninstall-desktop", "snapshot", "update-feeds",
            "update-geo", "lookup", "inspect")


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
    a = sub.add_parser("app", parents=[common], help="open Vigil as a desktop app in its own window")
    a.add_argument("--port", type=int, default=0, help="default: any free port")
    a.add_argument("--interval", type=float, default=2.0, help="seconds between /proc polls")
    a.add_argument("--window", choices=["auto", "native", "chromium", "browser"], default="auto",
                   help="how to show the window (default: the best available)")
    a.set_defaults(func=cmd_app)
    sub.add_parser("install-desktop", parents=[common],
                   help="add Vigil to your application menu (per user, no root)"
                   ).set_defaults(func=cmd_install_desktop)
    sub.add_parser("uninstall-desktop", parents=[common], help="remove the menu entry"
                   ).set_defaults(func=cmd_uninstall_desktop)
    n = sub.add_parser("snapshot", parents=[common], help="print current connections once and exit")
    n.add_argument("--json", action="store_true")
    n.add_argument("--all", action="store_true", help="include listening sockets")
    n.add_argument("--proc", default="/proc", help=argparse.SUPPRESS)
    n.set_defaults(func=cmd_snapshot)
    f = sub.add_parser("update-feeds", parents=[common],
                       help="download abuse.ch threat feeds now (network)")
    f.add_argument("feed", nargs="*", help="feodo, sslbl and/or urlhaus (default: all)")
    f.set_defaults(func=cmd_update_feeds)
    g = sub.add_parser("update-geo", parents=[common],
                       help="download the IPtoASN country/ASN database now (network)")
    g.add_argument("--file", help="load a downloaded ip2asn-combined.tsv(.gz) instead")
    g.set_defaults(func=cmd_update_geo)
    lk = sub.add_parser("lookup", parents=[common], help="offline: owner, country, intel for an IP")
    lk.add_argument("ip")
    lk.set_defaults(func=cmd_lookup)
    ins = sub.add_parser("inspect", parents=[common],
                         help="static triage of a file (reads bytes; never opens or runs it)")
    ins.add_argument("file")
    ins.add_argument("--json", action="store_true")
    ins.add_argument("--no-save", action="store_true", help="don't record the report")
    ins.set_defaults(func=cmd_inspect)
    args = p.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
