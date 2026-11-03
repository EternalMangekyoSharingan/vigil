"""Read a PKGBUILD (and .install / .SRCINFO) as text. Nothing here runs it.

A PKGBUILD is a bash script, and makepkg *sources* it: any top-level command runs as
soon as anything reads it the normal way. Vigil never does that. This module splits the
text into what it would mean to bash, well enough for review:

- variables: `name=value`, `name=(array ...)`, `name+=(...)`, with line numbers;
- functions: `name() { ... }` / `function name { ... }`, as logical lines;
- top-level commands: anything else outside functions (these run on *reading*);
- variable references are expanded from plain assignments only; `$(...)` and
  backticks are never evaluated, only reported.

It is a reviewer's parser, not bash: on odd input it errs on the side of showing more.
"""

import re
import shlex

ASSIGN = re.compile(r"^\s*(?:declare\s+-a\s+|local\s+|export\s+|readonly\s+)?([A-Za-z_][A-Za-z0-9_]*)(\+?)=(.*)$", re.S)
FUNC = re.compile(r"^\s*(?:function\s+)?([A-Za-z_][A-Za-z0-9_.:-]*)\s*(?:\(\s*\))\s*\{?\s*$|^\s*function\s+([A-Za-z_][A-Za-z0-9_.:-]*)\s*\{?\s*$")
HEREDOC = re.compile(r"<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1")
VAR = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)")
VCS = ("git+", "svn+", "hg+", "bzr+", "fossil+")
SUMS = ("sha256sums", "sha512sums", "b2sums", "sha384sums", "sha224sums", "sha1sums", "md5sums", "cksums")
ARCHES = ("x86_64", "i686", "aarch64", "armv7h", "armv6h", "arm", "pentium4", "riscv64", "loong64", "any")


class Line:
    """One logical line: continuations joined, with the number of its first physical line."""
    __slots__ = ("no", "text", "func", "file")

    def __init__(self, no, text, func, file):
        self.no, self.text, self.func, self.file = no, text, func, file

    def __repr__(self):
        return f"{self.file}:{self.no} [{self.func or 'top'}] {self.text!r}"


def _strip_comment(s):
    """Drop a trailing # comment that is outside quotes (bash: # starts a word)."""
    out, q, i = [], None, 0
    while i < len(s):
        c = s[i]
        if q:
            if c == "\\" and q == '"' and i + 1 < len(s):
                out.append(s[i:i + 2])
                i += 2
                continue
            if c == q:
                q = None
        elif c in "'\"":
            q = c
        elif c == "\\" and i + 1 < len(s):
            out.append(s[i:i + 2])
            i += 2
            continue
        elif c == "#" and (i == 0 or s[i - 1] in " \t;|&("):
            break
        out.append(c)
        i += 1
    return "".join(out).rstrip(), q


def _balance(s):
    """(open parens, open braces, open quote) of s outside quotes, for array/function spans."""
    par = br = 0
    q = None
    i = 0
    while i < len(s):
        c = s[i]
        if q:
            if c == "\\" and q == '"':
                i += 2
                continue
            if c == q:
                q = None
        elif c in "'\"":
            q = c
        elif c == "\\":
            i += 2
            continue
        elif c == "(":
            par += 1
        elif c == ")":
            par -= 1
        elif c == "{":
            br += 1
        elif c == "}":
            br -= 1
        i += 1
    return par, br, q


def logical_lines(text, file="PKGBUILD"):
    """[(first line number, text)] with comments dropped, continuations and open
    quotes/arrays joined, and here-documents kept as their own lines."""
    phys = text.replace("\r\n", "\n").split("\n")
    out, i = [], 0
    while i < len(phys):
        start = i + 1
        buf, open_q = _strip_comment(phys[i])
        i += 1
        while True:
            if buf.endswith("\\") and not buf.endswith("\\\\"):
                if i >= len(phys):
                    break
                nxt, open_q = _strip_comment(phys[i])
                buf = buf[:-1] + " " + nxt.lstrip()
                i += 1
                continue
            par, _, q = _balance(buf)
            if (q or (par > 0 and re.match(r"^\s*[A-Za-z_][A-Za-z0-9_]*\+?=\(", buf))) and i < len(phys):
                nxt = phys[i] if q else _strip_comment(phys[i])[0]
                buf = buf + ("\n" if q else " ") + nxt.strip()
                i += 1
                continue
            break
        if buf.strip():
            out.append((start, buf.strip()))
        m = HEREDOC.search(buf)
        if m and not (m.group(0).startswith("<<<")):
            end = m.group(2)
            while i < len(phys) and phys[i].strip() != end:
                out.append((i + 1, "  " + phys[i]))  # body: kept, indented, so checks see it
                i += 1
            i += 1
    return out


def words(value):
    """Split an assignment value or array body into words, keeping $vars unexpanded."""
    v = value.strip()
    if v.startswith("(") and v.endswith(")"):
        v = v[1:-1]
    try:
        return shlex.split(v, comments=False, posix=True)
    except ValueError:
        return v.split()


def expand(s, scalars, depth=0):
    """Expand ${var} / $var from plain assignments. Unknown ones stay as written."""
    if depth > 5:
        return s

    def rep(m):
        name = m.group(1) or m.group(2)
        v = scalars.get(name)
        return expand(v, scalars, depth + 1) if isinstance(v, str) else m.group(0)
    return VAR.sub(rep, s)


def _is_assignment(text, m):
    """`x=1` and `x=(a b)` are assignments; `X=1 make install` is a command with an
    environment prefix."""
    if m.group(3).startswith(("(", "$(", "`", '"', "'")) and not re.search(r"""^["'][^"']*["']\s+\S""", m.group(3)):
        return True
    try:
        w = shlex.split(text, posix=True)
    except ValueError:
        return True
    return all(re.match(r"^[A-Za-z_][A-Za-z0-9_]*\+?=", x) for x in w)


class Script:
    """A parsed PKGBUILD or .install file."""

    def __init__(self, text, file="PKGBUILD"):
        self.file = file
        self.text = text
        self.raw_lines = text.replace("\r\n", "\n").split("\n")
        self.vars = {}        # name -> {"value": str|list, "line": n, "raw": text, "subst": bool}
        self.functions = {}   # name -> {"line": n, "lines": [Line]}
        self.top = []         # top-level commands (Line), excluding assignments
        self.assign_lines = []  # top-level assignment Lines (they run on read too)
        self._parse()

    def _parse(self):
        func, depth = None, 0
        for no, text in logical_lines(self.text, self.file):
            if func is None:
                m = FUNC.match(text)
                if m:
                    func = m.group(1) or m.group(2)
                    self.functions[func] = {"line": no, "lines": []}
                    depth = 1 if text.rstrip().endswith("{") else 0
                    continue
                if text.startswith("{") and self.functions and depth == 0 and not self.functions[list(self.functions)[-1]]["lines"]:
                    func = list(self.functions)[-1]
                    depth = 1
                    continue
                a = ASSIGN.match(text)
                if a and _is_assignment(text, a):
                    self._assign(a, no, text)
                    self.assign_lines.append(Line(no, text, None, self.file))
                    continue
                self.top.append(Line(no, text, None, self.file))
                continue
            _, br, _ = _balance(text)
            if depth + br <= 0 and text.strip().endswith("}"):
                body = text.strip()[:-1].strip()
                if body:
                    self.functions[func]["lines"].append(Line(no, body, func, self.file))
                func, depth = None, 0
                continue
            depth += br
            self.functions[func]["lines"].append(Line(no, text, func, self.file))

    def _assign(self, m, no, text):
        name, plus, value = m.group(1), m.group(2), m.group(3)
        subst = "$(" in value or "`" in value
        if value.startswith("("):
            items = words(value)
            if plus and isinstance(self.vars.get(name, {}).get("value"), list):
                items = self.vars[name]["value"] + items
            self.vars[name] = {"value": items, "line": no, "raw": text, "subst": subst}
        else:
            w = words(value)
            v = " ".join(w) if w else ""
            if plus and isinstance(self.vars.get(name, {}).get("value"), str):
                v = self.vars[name]["value"] + v
            self.vars[name] = {"value": v, "line": no, "raw": text, "subst": subst}

    # ---- convenient views ---------------------------------------------------------------

    def scalars(self):
        return {k: v["value"] for k, v in self.vars.items() if isinstance(v["value"], str)}

    def get(self, name, default=None):
        v = self.vars.get(name)
        if not v:
            return default
        sc = self.scalars()
        if isinstance(v["value"], list):
            return [expand(x, sc) for x in v["value"]]
        return expand(v["value"], sc)

    def array(self, name):
        v = self.get(name, [])
        return v if isinstance(v, list) else [v] if v else []

    def all_lines(self):
        """Every logical line that bash would run: top level, assignments and function bodies."""
        out = list(self.assign_lines) + list(self.top)
        for f in self.functions.values():
            out += f["lines"]
        return sorted(out, key=lambda x: x.no)

    def find_line(self, needle, start):
        """The physical line, at or after `start`, that holds `needle` (else `start`)."""
        for no in range(start, min(len(self.raw_lines), start + 400) + 1):
            if needle and needle in self.raw_lines[no - 1]:
                return no
        return start

    def line_text(self, no):
        return self.raw_lines[no - 1] if 0 < no <= len(self.raw_lines) else ""


def source_entries(script):
    """Every source with its checksum per algorithm:
    [{"arch", "index", "raw", "name", "url", "kind", "line", "sums": {alg: value}}]."""
    out = []
    for arch in (None,) + ARCHES:
        key = "source" if arch is None else f"source_{arch}"
        if key not in script.vars:
            continue
        sums = {}
        for alg in SUMS:
            skey = alg if arch is None else f"{alg}_{arch}"
            if skey in script.vars:
                sums[alg] = script.array(skey)
        unexpanded = script.vars[key]["value"]
        for i, raw in enumerate(script.array(key)):
            line = script.find_line(unexpanded[i] if i < len(unexpanded) else raw, script.vars[key]["line"])
            name, sep, rest = raw.partition("::")
            target = rest if sep else raw
            kind = "vcs" if target.startswith(VCS) else "url" if "://" in target else "local"
            url = target.split("+", 1)[1] if kind == "vcs" else target
            out.append({"arch": arch, "index": i, "raw": raw, "name": name if sep else None, "url": url,
                        "kind": kind, "line": line,
                        "sums": {alg: (vals[i] if i < len(vals) else None) for alg, vals in sums.items()}})
    return out


def srcinfo(text):
    """.SRCINFO: key = value lines (pkgbase section, then pkgname sections)."""
    out = {}
    for line in text.splitlines():
        k, sep, v = line.strip().partition(" = ")
        if sep:
            out.setdefault(k, []).append(v)
    return out


def maintainers(text):
    """The '# Maintainer:' / '# Contributor:' header comments, in order."""
    return [(m.group(1).lower(), m.group(2).strip())
            for m in re.finditer(r"^\s*#\s*(Maintainer|Contributor)\s*:\s*(.+)$", text, re.M | re.I)]
