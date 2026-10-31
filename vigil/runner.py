"""Sudo mode: run a command Vigil generated, after the user pressed Run, and show the output.

The one module in Vigil that runs fix commands. Its rules:

- Off by default; the owner switches it on in Settings ("sudo_mode" in settings.json).
- Only commands Vigil generated itself: the caller re-generates the option's command
  list server-side and passes it in; the requested text must be one of them exactly.
  Text from the page is never run otherwise.
- No shell: commands are split with shlex and run as an argument list. Commands with
  shell syntax (pipes, &&, redirects, globs) are refused.
- Admin commands (sudo, doas) run through pkexec, so the *system's* password dialog
  (polkit) shows the exact command and takes the password. Vigil never sees,
  handles or stores a password.
- One command per click, with a timeout. Every run is recorded (command, exit code,
  output, time) in the evidence store's event log.
"""

import os
import shlex
import shutil
import subprocess
import time

ADMIN = ("sudo", "doas", "pkexec")
NOT_RUNNABLE = ("sudoedit",)          # interactive editor: copy only
SHELL_SYNTAX = ("|", "&&", "||", ";", ">", "<", "`", "$(", "*", "?")
TIMEOUT = 600
OUTPUT_MAX = 64 * 1024


class Refused(Exception):
    pass


def argv_for(command, which=shutil.which):
    """The argument list Vigil would run for a command, or raise Refused with why."""
    try:
        words = shlex.split(command)
    except ValueError as exc:
        raise Refused(f"cannot parse the command: {exc}") from None
    if not words:
        raise Refused("empty command")
    unquoted = _unquoted_text(command)
    if any(tok in unquoted for tok in SHELL_SYNTAX):
        raise Refused("contains shell syntax (pipes, chains, redirects or wildcards); copy it instead")
    if words[0] in NOT_RUNNABLE:
        raise Refused(f"{words[0]} opens an editor; copy it and run it in a terminal")
    admin = words[0] in ADMIN
    if admin:
        words = words[1:]
        if not words:
            raise Refused("nothing to run")
    prog = which(words[0])
    if not prog:
        raise Refused(f"{words[0]} is not installed")
    argv = [prog] + [os.path.expanduser(w) if w.startswith("~/") else w for w in words[1:]]
    if admin:
        pk = which("pkexec")
        if not pk:
            raise Refused("pkexec (polkit) is not installed, so Vigil cannot ask for your password safely")
        argv = [pk] + argv
    return argv, admin


def _unquoted_text(command):
    """The command with quoted parts removed (quoted text is data, not shell syntax)."""
    out, quote = [], None
    for ch in command:
        if quote:
            if ch == quote:
                quote = None
        elif ch in "'\"":
            quote = ch
        else:
            out.append(ch)
    return "".join(out)


def run(command, allowed, store=None, runner=subprocess.run, which=shutil.which):
    """Run `command` if it is exactly one of `allowed` (texts Vigil generated)."""
    if command not in allowed:
        raise Refused("Vigil only runs commands it generated itself; this one is not among them")
    argv, admin = argv_for(command, which=which)
    started = time.time()
    try:
        r = runner(argv, capture_output=True, timeout=TIMEOUT, stdin=subprocess.DEVNULL)
        code, out, err = r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired as exc:
        code, out, err = None, exc.stdout or b"", (exc.stderr or b"") + f"\n(stopped after {TIMEOUT} s)".encode()
    except OSError as exc:
        raise Refused(f"could not start it: {exc.strerror}") from None
    result = {"command": command, "argv": argv, "admin": admin, "exit": code,
              "stdout": out[-OUTPUT_MAX:].decode("utf-8", "replace"),
              "stderr": err[-OUTPUT_MAX:].decode("utf-8", "replace"),
              "started": started, "seconds": round(time.time() - started, 2)}
    if admin and code in (126, 127):
        result["note"] = "The password dialog was cancelled or authorisation was refused; nothing ran."
    if store is not None:
        store.event(started, "action", f"Ran (sudo mode): {command} → exit {code}",
                     "runner: pressed Run in the Vigil page" + (" (via pkexec)" if admin else ""),
                     detail={"exit": code, "seconds": result["seconds"], "stderr": result["stderr"][-2000:]})
    return result
