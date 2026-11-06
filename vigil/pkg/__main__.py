"""python -m vigil.pkg [serve | review DIR [--fail-on high|medium] | installed | trusted | gate]"""

import argparse
import json
import sys

from ..core.store import default_data_dir
from . import gate, installed, review

SEV_MARK = {"High": "!!", "Medium": "! ", "Low": "· ", "Info": "  "}


def print_findings(findings):
    for f in findings:
        ev = f["evidence"][0] if f["evidence"] else None
        where = f"  [{ev['value']}]" if ev else ""
        print(f"{SEV_MARK[f['severity']]} {f['severity']:6} {f['title']}{where}")
        print(f"          {f['summary']}")
        if ev and ev.get("note"):
            print(f"          > {ev['note']}")


def main(argv=None):
    p = argparse.ArgumentParser(prog="vigil.pkg", description="Static PKGBUILD / AUR package review. "
                                "Never runs makepkg or any part of a PKGBUILD.")
    p.add_argument("--data", default=None, help="evidence store directory (default: data/pkg)")
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--data", default=argparse.SUPPRESS, help=argparse.SUPPRESS)
    sub = p.add_subparsers(dest="cmd")
    s = sub.add_parser("serve", parents=[common], help="open the page on 127.0.0.1 (default)")
    s.add_argument("--port", type=int, default=8766)
    s.add_argument("--verbose", action="store_true")
    r = sub.add_parser("review", parents=[common], help="review a PKGBUILD folder in the terminal")
    r.add_argument("folder")
    r.add_argument("--json", action="store_true")
    r.add_argument("--approve", action="store_true", help="after reviewing, remember this version as approved")
    r.add_argument("--aur", action="store_true", help="also fetch AUR metadata (network: sends the package name)")
    r.add_argument("--fail-on", choices=("high", "medium", "never"), default=None,
                   help="exit 2 if any finding is at least this severe (for a build gate, e.g. paru's "
                        "PreBuildCommand); without it: 2 for Don't install, 1 for Review these lines")
    g = sub.add_parser("gate", parents=[common], help="print the paru.conf lines that make Vigil review before each build")
    g.add_argument("--fail-on", choices=("high", "medium"), default="high")
    i = sub.add_parser("installed", parents=[common], help="audit foreign packages already installed")
    i.add_argument("--json", action="store_true")
    i.add_argument("--no-verify", action="store_true", help="skip the pacman -Qkk-style file check")
    sub.add_parser("trusted", parents=[common], help="list approved package versions")
    a = p.parse_args(argv)
    data = a.data or str(default_data_dir() / "pkg")
    if a.cmd in (None, "serve"):
        from .server import serve
        serve(data, port=getattr(a, "port", 8766), verbose=getattr(a, "verbose", False))
        return 0
    store = review.open_store(data)
    try:
        if a.cmd == "review":
            info = None
            if a.aur:
                files, _ = review.read_folder(a.folder)
                from . import parse
                sc = parse.Script(files["PKGBUILD"])
                print("Fetching AUR metadata (sends the package name to aur.archlinux.org)…", file=sys.stderr)
                info = review.aur_info(sc.get("pkgbase") or sc.array("pkgname")[0])
                info = info if info.get("found") else None
            rep = review.review_folder(a.folder, store=store, aur=info)
            if a.json:
                print(json.dumps({k: v for k, v in rep.items() if k != "files"}, indent=2, default=str))
            else:
                pk = rep["package"]
                print(f"{rep['verdict'].upper()}  {pk['pkgbase']} {pk['version']}  ({rep['folder']})\n")
                print_findings(rep["findings"])
                print("\nLimits:\n  - " + "\n  - ".join(rep["limits"]))
            if a.approve:
                files, _ = review.read_folder(a.folder)
                review.Trusted(store).approve(rep["package"]["pkgbase"], files, rep["package"]["version"])
                print(f"\nApproved {rep['package']['pkgbase']} {rep['package']['version']}: "
                      "the next review shows what changed.")
            if a.fail_on:
                code = gate.exit_code(rep["findings"], a.fail_on)
                if code:
                    print(f"\nVigil Pkg: stopping the build ({rep['package']['pkgbase']} has findings at "
                          f"{a.fail_on} or above). Read them above; approve with --approve if they are expected.",
                          file=sys.stderr)
                return code
            return {"Don't install": 2, "Review these lines": 1}.get(rep["verdict"], 0)
        if a.cmd == "installed":
            rep = installed.audit(verify=not a.no_verify)
            if a.json:
                print(json.dumps(rep, indent=2, default=str))
                return 0
            if not rep["supported"]:
                print(rep["note"])
                return 0
            store.add_run("installed", rep["findings"], {"foreign": len(rep["foreign"]), "how": rep["how"]})
            print(f"{len(rep['foreign'])} foreign packages (found by: {rep['how']})")
            for row in rep["foreign"]:
                v = row["verify"]
                print(f"  {row['name']:32} {row['version']:20} "
                      + (f"{v['changed']} changed of {v['checked']}" if v and not v["error"] else (v or {}).get("error") or ""))
            print()
            print_findings(rep["findings"])
            return 0
        if a.cmd == "gate":
            sn = gate.snippet(fail_on=a.fail_on)
            print(f"# {sn['file']}  (check `{sn['check']}` first)\n{sn['text']}\n# {sn['note']}")
            return 0
        if a.cmd == "trusted":
            for t in review.Trusted(store).all():
                print(f"  {t['pkgbase']:32} {t['version']}")
            return 0
    finally:
        store.close()


if __name__ == "__main__":
    sys.exit(main())
