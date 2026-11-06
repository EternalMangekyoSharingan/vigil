"""Static checks on the pages' JavaScript (no browser needed)."""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent / "vigil"


def append_args(src):
    """Top-level arguments of every .append( / .prepend( call."""
    for m in re.finditer(r"\.(append|prepend)\(", src):
        i, depth = m.end(), 1
        while depth and i < len(src):
            depth += {"(": 1, ")": -1}.get(src[i], 0)
            i += 1
        args, d, cur = [], 0, ""
        for ch in src[m.end():i - 1]:
            d += ch in "([{"
            d -= ch in ")]}"
            if ch == "," and d == 0:
                args.append(cur)
                cur = ""
            else:
                cur += ch
        yield src[:m.start()].count("\n") + 1, args + [cur]


class PageTests(unittest.TestCase):
    def test_no_null_reaches_dom_append(self):
        # Element.append(null) inserts the text "null"; conditional children go through put() or el().
        bad = []
        for js in sorted(ROOT.glob("*/static/*.js")):
            for line, args in append_args(js.read_text()):
                for a in args:
                    a = a.strip()
                    if a in ("null", "undefined") or ("?" in a and re.search(r":\s*(null|undefined)\s*$", a)):
                        bad.append(f"{js.relative_to(ROOT)}:{line}")
        self.assertEqual(bad, [])

    def test_the_rule_catches_the_mistake(self):
        src = 'box.append(el("h3"), cond ? el("p", { a: 1 }) : null, x);\nput(box, cond ? y : null);'
        hits = [line for line, args in append_args(src) for a in args if "?" in a and a.strip().endswith("null")]
        self.assertEqual(hits, [1])


if __name__ == "__main__":
    unittest.main()
