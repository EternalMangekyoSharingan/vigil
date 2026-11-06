"""Vigil Pkg as a build gate (--fail-on, the paru.conf lines). PKGBUILDs are the SYNTHETIC
fixtures in tests/fixtures/pkg; nothing is built or run."""

import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from vigil.pkg import gate
from vigil.pkg.__main__ import main

FIX = Path(__file__).parent.parent / "fixtures" / "pkg"


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(list(argv))
    return code, out.getvalue(), err.getvalue()


class GateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_exit_codes(self):
        hi = [{"severity": "High"}]
        med = [{"severity": "Medium"}, {"severity": "Low"}]
        self.assertEqual(gate.exit_code(hi, "high"), 2)
        self.assertEqual(gate.exit_code(med, "high"), 0)
        self.assertEqual(gate.exit_code(med, "medium"), 2)
        self.assertEqual(gate.exit_code([{"severity": "Low"}], "medium"), 0)
        self.assertEqual(gate.exit_code(hi, "never"), 0)

    def test_cli_stops_a_bad_package_and_passes_a_clean_one(self):
        code, out, err = run("--data", self.tmp.name, "review", str(FIX / "builder"), "--fail-on", "high")
        self.assertEqual(code, 2)
        self.assertIn("stopping the build", err)
        code, _, err = run("--data", self.tmp.name, "review", str(FIX / "benign"), "--fail-on", "high")
        self.assertEqual(code, 0)
        self.assertEqual(err, "")

    def test_snippet_is_copy_only_and_points_at_this_checkout(self):
        sn = gate.snippet("/opt/vigil")
        self.assertEqual(sn["lines"], ["[bin]", "PreBuildCommand = env PYTHONPATH=/opt/vigil python3 -m vigil.pkg "
                                                "review . --fail-on high"])
        self.assertIn("man paru.conf", sn["note"])
        self.assertIn("never edits paru.conf", sn["note"])
        self.assertTrue((gate.VIGIL_DIR / "vigil" / "pkg" / "gate.py").exists())
        code, out, _ = run("--data", self.tmp.name, "gate", "--fail-on", "medium")
        self.assertEqual(code, 0)
        self.assertIn("--fail-on medium", out)


if __name__ == "__main__":
    unittest.main()
