"""python -m vigil.suite: start Home and every tool, each on its own port, in one process."""

import argparse
import sys

from ..core.store import default_data_dir


def main(argv=None):
    p = argparse.ArgumentParser(prog="vigil.suite", description="Start Vigil Home and every tool in one process. "
                                "Everything listens on 127.0.0.1 only and only reads.")
    p.add_argument("--data", default=None, help="the Vigil data folder (default: data/)")
    p.add_argument("--no-net", action="store_true", help="don't start the Network Map's background monitor")
    p.add_argument("--only", nargs="*", help="start only these tools (net tasks persist files pkg cases)")
    p.add_argument("--verbose", action="store_true")
    p.add_argument("--checkup", action="store_true", help="run the full check-up once in the terminal and exit")
    a = p.parse_args(argv)
    root = a.data or str(default_data_dir())
    if a.checkup:
        from .checkup import STEPS, Runner
        r = Runner(root, {})
        worst = 0
        for sid, label in STEPS:
            try:
                print(f"✓ {label}: {r.step(sid)}")
            except Exception as exc:
                worst = 1
                print(f"✗ {label}: {type(exc).__name__}: {exc}")
        from .overview import overview
        o = overview(root, {})
        print(f"\n{o['verdict']['word']}. {o['verdict']['text']}")
        for n in o["needs_look"][:10]:
            print(f"  {n['severity']:6} {n['tool_name']:7} {n['title']}")
        return worst
    from .server import launch
    print("Starting Vigil (127.0.0.1 only):")
    httpd, stop = launch(root, with_net=not a.no_net, verbose=a.verbose, only=a.only)
    print(f"\n  Home     http://127.0.0.1:{httpd.server_address[1]}/   ← start here\n\nCtrl+C stops everything.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
        stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
