"""The suite's tools: one registry used by the launcher, the Home page and the switcher
shown on every page. Ports are fixed so links between tools keep working."""

TOOLS = [
    {"id": "home", "name": "Home", "port": 8760, "module": "vigil.suite",
     "question": "How is this PC doing, and what needs a look?"},
    {"id": "net", "name": "Net", "port": 8765, "module": "vigil.net",
     "question": "Who is this PC talking to, and which program?"},
    {"id": "tasks", "name": "Tasks", "port": 8769, "module": "vigil.tasks",
     "question": "What is running, and should it be?"},
    {"id": "persist", "name": "Persist", "port": 8768, "module": "vigil.persist",
     "question": "What starts by itself, and what changed?"},
    {"id": "files", "name": "Files", "port": 8767, "module": "vigil.files",
     "question": "Is this file or archive safe to open?"},
    {"id": "pkg", "name": "Pkg", "port": 8766, "module": "vigil.pkg",
     "question": "Is this AUR package safe to build?"},
    {"id": "cases", "name": "Cases", "port": 8770, "module": "vigil.cases",
     "question": "What happened, across all of the above?"},
]
BY_ID = {t["id"]: t for t in TOOLS}


def url(tool_id, host="127.0.0.1"):
    return f"http://{host}:{BY_ID[tool_id]['port']}/"
