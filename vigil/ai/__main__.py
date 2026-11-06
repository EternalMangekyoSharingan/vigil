"""python3 -m vigil.ai  evals | investigate

    evals                          score the offline analyst on the synthetic scenarios (no network)
    evals --claude [--lookups] --yes
                                   also ask Claude: sends each SYNTHETIC scenario, never your data
    investigate "question" --lookups [--yes] [--no-redact]
                                   Claude investigates your Cases findings with read-only lookups.
                                   Without --yes it only shows what it would do. Needs "Allow sending"
                                   on in Cases → Analyst, and is logged there like an Ask.
"""

import argparse
import json
import sys
from pathlib import Path

from ..core.store import default_data_dir


def main(argv=None):
    p = argparse.ArgumentParser(prog="vigil.ai", description="Vigil's AI layer: evals and read-only investigations.")
    sub = p.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("evals", help="score answers on the synthetic scenarios")
    e.add_argument("--claude", action="store_true", help="also score Claude (network: sends the synthetic scenarios)")
    e.add_argument("--lookups", action="store_true", help="with --claude: also score Claude with read-only lookups")
    e.add_argument("--yes", action="store_true", help="really send (otherwise only the offline baseline runs)")
    e.add_argument("--json", action="store_true")
    i = sub.add_parser("investigate", help="ask Claude about your findings, letting it look things up (read-only)")
    i.add_argument("question")
    i.add_argument("--lookups", action="store_true", help="required: lets the model use the read-only lookups")
    i.add_argument("--yes", action="store_true", help="really send; without it, show what would happen")
    i.add_argument("--no-redact", action="store_true", help="send home paths, user, host and LAN addresses as they are")
    i.add_argument("--data", default=None, help="Vigil's data folder (default: data/)")
    a = p.parse_args(argv)

    if a.cmd == "evals":
        from . import evals
        responders = ["offline"]
        if a.claude:
            if not a.yes:
                print("--claude sends every synthetic scenario to Anthropic's API (about 6 requests"
                      f"{', plus lookups' if a.lookups else ''}). Add --yes to do it. Running the offline baseline only.\n",
                      file=sys.stderr)
            else:
                responders += ["claude"] + (["claude+lookups"] if a.lookups else [])
        try:
            results = evals.run(responders)
        except evals.EvalError as exc:
            print(exc, file=sys.stderr)
            return 1
        print(json.dumps(results, indent=1) if a.json else evals.table(results))
        return 0

    from ..cases.store import CaseStore
    from . import investigate, providers
    if not a.lookups:
        print("Add --lookups to let the model look things up (read-only, over Vigil's own findings). Without it, use "
              "the Analyst tab in Cases, which sends one previewed bundle.", file=sys.stderr)
        return 2
    root = a.data or str(default_data_dir())
    if not (Path(root) / "cases" / "cases.db").exists():
        print("Nothing to investigate yet: open Vigil Cases and press Import from all tools first.", file=sys.stderr)
        return 2
    store = CaseStore(f"{root}/cases")
    try:
        settings = store.get_meta_ai()
        n = len(store.findings())
        if not settings.get("enabled"):
            print("Sending is off. Turn on “Allow sending” in Cases → Analyst first (it is off by default).", file=sys.stderr)
            return 2
        redact = settings.get("redact", True) and not a.no_redact
        plan = (f"Would ask {providers.MODEL} about {n} findings in {root}/cases, letting it use these read-only lookups: "
                "search_findings, get_finding, pivot, list_storylines, get_storyline, attack_technique.\n"
                f"Each result is {'redacted (home, user, host, LAN addresses, secrets) and ' if redact else ''}"
                "fenced as data; nothing is changed, run or opened. The run is logged in Cases → Analyst.")
        if not a.yes:
            print(plan + "\n\nAdd --yes to send.")
            return 0
        print(plan + "\n", file=sys.stderr)
        try:
            out = investigate.investigate(store, root, a.question, redact=redact)
        except providers.ProviderError as exc:
            print(f"Not sent / failed: {exc}", file=sys.stderr)
            return 1
        for c in out["lookups"]:
            print(f"  lookup {c['name']}({json.dumps(c['input'])}) → {c['bytes']} bytes{' (error)' if c.get('error') else ''}",
                  file=sys.stderr)
        if out["injection"]:
            print("\nPossible tampering: text addressed to an AI was in the evidence it read:", file=sys.stderr)
            for x in out["injection"]:
                print(f"  {x['where']}: {x['text']}", file=sys.stderr)
        print()
        print(out["answer"] or out.get("note") or "(no answer)")
        if out["not_from_vigil"]:
            print("\nNot from Vigil (check before running):\n  " + "\n  ".join(out["not_from_vigil"]))
        if out.get("note"):
            print(f"\n({out['note']})")
        return 0
    finally:
        store.close()


if __name__ == "__main__":
    sys.exit(main())
