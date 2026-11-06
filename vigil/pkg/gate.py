"""Vigil Pkg as a build gate: review a PKGBUILD folder and fail when it finds something.

    python3 -m vigil.pkg review DIR --fail-on high      exit 2 if anything is High
    python3 -m vigil.pkg review DIR --fail-on medium    exit 2 if anything is High or Medium

paru can run a command in each package's build folder before it builds (PreBuildCommand
in paru.conf); a non-zero exit stops the build. Vigil only prints the lines to add; it
never edits paru.conf. Whether your paru has the option, and exactly how it runs it, is
paru.conf(5)'s to say: check `man paru.conf` first.
"""

from pathlib import Path

from ..core import finding as fmt

LEVELS = {"high": "High", "medium": "Medium"}
VIGIL_DIR = Path(__file__).resolve().parents[2]


def exit_code(findings, fail_on):
    """2 if any finding reaches the level, else 0. fail_on: 'high', 'medium' or 'never'."""
    if fail_on == "never":
        return 0
    need = fmt.SEVERITY_RANK[LEVELS[fail_on]]
    return 2 if any(fmt.SEVERITY_RANK[f["severity"]] >= need for f in findings) else 0


def snippet(vigil_dir=None, fail_on="high"):
    d = str(vigil_dir or VIGIL_DIR)
    line = f"PreBuildCommand = env PYTHONPATH={d} python3 -m vigil.pkg review . --fail-on {fail_on}"
    return {
        "file": "~/.config/paru/paru.conf",
        "section": "[bin]",
        "lines": ["[bin]", line],
        "text": "[bin]\n" + line + "\n",
        "check": "man paru.conf",
        "note": ("Add these lines under [bin] in your paru.conf (create the file if it does not exist). paru then runs "
                 "Vigil's review in each package's folder before building, and stops if the review finds anything "
                 f"{LEVELS[fail_on]}{' or worse' if fail_on == 'medium' else ''}. Read `man paru.conf` first: if your "
                 "paru has no PreBuildCommand, or runs it differently, follow the manual, not this. To undo, delete "
                 "the line. Vigil never edits paru.conf itself."),
    }
