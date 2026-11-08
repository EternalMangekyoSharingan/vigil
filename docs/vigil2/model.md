# vigil-model: the shared vocabulary

`vigil2/crates/vigil-model/`. Pure code: no processes, no network, almost no file access (only
reading os-release). Everything else in Vigil 2 speaks in these types.

| module | port of (Vigil 1) | what it does |
| --- | --- | --- |
| `finding.rs` | `core/finding.py` | The finding record, the `Builder` that validates as it builds, `problems()` for imported findings, JSON lines in and out |
| `wording.rs` | `core/wording.py` | Title rules (60 characters, no jargon, no statistics, no raw IPv6), one-sentence check, `fit_title`, human numbers ("every ~7 min"), friendly program and owner names, `printable()` for attacker-controlled text |
| `commands.rs` | `core/commands.py`, `core/runner.py` | Colour roles and tooltips for each word of a command; `plan()`: what Run mode would run (no shell, admin through polkit) or why it refuses |
| `fixes.rs` | `core/fixes.py` | Check / Fix / Undo options and the Fix panel, per distro family |
| `attack.rs` | `core/attack.py` | MITRE ATT&CK techniques per check (generated from the Python tables) |
| `distro.rs` | `core/system.py` | os-release parsing and the distro family |
| `host.rs` | `net/collector.py` (shapes) | Processes, sockets, what is hidden and why, daemon status |
| `netaddr.rs` | `net/collector.py` | Where an address lives (loopback, LAN, internet ...) |
| `api.rs` | (new) | D-Bus names, paths, polkit action ids, API version |
| `sha1.rs`, `pyjson.rs` | (new) | Exactly Vigil 1's finding ids and JSON text (D-004) |

## How the port is kept honest: golden tests

`vigil2/tests/golden/make_golden.py` imports Vigil 1's Python modules, runs them on synthetic
inputs, and writes the answers to `model.json` and `proc.json`. The Rust tests
(`crates/vigil-model/tests/golden.rs`, `crates/vigil-sensor/tests/golden_proc.rs`) must give the
same answer for every input: the same titles accepted and refused with the same reasons, the
same colour role for every word of 74 commands, the same finding JSON byte for byte, the same
error text for broken findings, the same sockets and processes from the /proc fixture.

CI runs the generator again and fails if the file changes, so when a Vigil 1 rule changes, the
Rust side must change with it.

## Things worth knowing

- **No regular expressions.** The Python uses `re`; the `regex` crate is not on the allowlist,
  so each pattern is matched by hand with the original pattern quoted above it (D-003).
- **A finding that breaks the rules cannot be built.** `Builder::make()` returns an error that
  lists every broken rule, in the same words as Vigil 1.
- **Unknown fields survive.** `extra` maps on `Finding`, `FixOption` and `FixPanel` keep fields
  this version does not know, so importing and exporting a newer finding loses nothing.
- **Key order.** Findings are written with sorted keys whatever the build's serde settings
  (`pyjson::sorted`): the UI toolkit turns on serde_json's insertion order, which once made the
  output differ between `cargo test` and `cargo test --workspace`.
