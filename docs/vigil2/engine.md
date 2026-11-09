# Engines: vigil-engine

Engines turn what the sensor sees into findings. They are pure: they read facts and return
findings in Vigil 1's format, and never touch the system. The daemon runs them.

## Processes (milestone 3)

`tasks.rs` is Vigil 1's `tasks/procs.py` `flags` and `tasks/findings.py` `build`; `secrets.rs`
is `tasks/secrets.py`. The golden test (`tests/golden.rs`) runs both against
`vigil2/tests/golden/tasks.json`, which `make_golden.py` writes by running Vigil 1 on the
synthetic /proc fixture and on 34 hand-made SYNTHETIC processes that reach every rule.
Rust and Python must give the same check, severity, strength and sentence for each.

| check | severity | what it means |
| --- | --- | --- |
| memory_only | High | runs from memory (memfd), no file on disk |
| deleted_binary / replaced_binary | High / Low | its file was deleted while running (an update replaces it: Low) |
| temp_binary, cache_binary, downloads_binary, hidden_binary | High, Medium, Medium, Medium | runs from /tmp, a cache, Downloads or a hidden folder |
| ld_preload | High | LD_PRELOAD or LD_AUDIT forces a library into it |
| odd_parent | High (Low for xdg-open) | a browser, mail or document app, or a server, started a shell, an interpreter or a network tool |
| masquerade_name | High / Medium | named like a system program but runs from elsewhere |
| fake_kernel_name | High | calls itself `[kworker...]` but has a program file |
| reverse_shell | High | a network tool wired to a shell |
| credential_access | High / Medium | holds an SSH key, browser passwords or cookies, a wallet, a keyring or cloud credentials it does not own |
| listens_from_odd_place | High | listens for the whole network while running from /tmp, a cache or Downloads |

Each finding keeps where it came from (`source`: the check, `/proc/<pid>`, when), its reasons
with their strength, ATT&CK techniques, and Check and Fix options as commands to copy. Stopping
a process stays copy-only.

How the daemon feeds it (`vigild/src/checks.rs`): every 5th look (10 s), from the look it just
took, plus the dynamic linker's variables from each process's environment (read once per
process; nothing else from the environment is kept) and the paths of its open files (readlink
on `/proc/<pid>/fd`; no file is opened). New findings also become events. The app reads the
current ones with `org.vigil.Findings.Recent(since)`.

Not yet: the package database (Software, milestone 4), so the checks that ask "does a package
own this file?" (the Medium masquerade case, one credential-access risk factor) stay quiet, and
no finding claims a file belongs to no package (D-024).
