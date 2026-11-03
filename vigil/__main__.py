"""`python -m vigil` is the Network Map, as before (same commands and options).

The other tools run on their own:
    python -m vigil.net      Network Map (same as python -m vigil)
    python -m vigil.pkg      PKGBUILD / AUR package review
    python -m vigil.files    file and archive triage, quarantine, Downloads watcher
    python -m vigil.persist  autostart baseline and diff
    python -m vigil.tasks    process tree
    python -m vigil.cases    timeline, notes and exports across all tools
"""

from .net.__main__ import main

if __name__ == "__main__":
    main()
