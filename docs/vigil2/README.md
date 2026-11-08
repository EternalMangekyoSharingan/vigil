# Vigil 2: how the code fits together

Vigil 2 is the native rewrite described in `docs/RUST_REWRITE.md`. This folder explains each
part of the code for someone reviewing it, including someone new to Rust. Progress per milestone
is in `docs/PROGRESS2.md`, decisions in `docs/DECISIONS.md`.

## Try it

```bash
cd vigil2
cargo test --workspace --exclude vigil-ui          # everything except the app (no GPU libraries needed)
cargo run -p vigild -- --bus session &             # a development daemon: runs as you, answers only you
cargo run -p vigil-cli -- --bus session status     # what it sees, and how
cargo run -p vigil-cli -- --bus session connections
cargo run --release -p vigil-ui                    # the app (needs the GPU libraries listed in CI)
```

On a real install the daemon is a system service (`vigild.service`) and `vigil-cli` talks to it
on the system bus with no flags.

## The parts

```
 vigil-ui (app)      vigil-cli (terminal)          both talk to the daemon over D-Bus
       │                    │
       └──── D-Bus: org.vigil.Daemon (system bus, polkit) ────┐
                                                               │
 vigild ── sensor thread ── vigil-sensor (/proc now; events and eBPF in milestone 3)
       ├── vigil-store (SQLite: history, first seen, the time machine)
       └── auth (who is calling? polkit says whether they may)

 vigil-model: the shared vocabulary every part uses (findings, wording, commands, ATT&CK)
 vigil-ui-core: the app's logic that does not need a toolkit (keys, palette, motion, theme)
```

| crate | read this | what it is |
| --- | --- | --- |
| `vigil-model` | [model.md](model.md) | The finding format and wording rules, ported from Vigil 1 and held to it by golden tests |
| `vigil-sensor` | [sensor.md](sensor.md) | Where observations come from: /proc today, with the "what Vigil can see" report |
| `vigil-store` | [store.md](store.md) | The SQLite history: migrations, first seen, the time machine, retention |
| `vigild` | [daemon.md](daemon.md) | The system service: polling, D-Bus API, polkit, systemd |
| `vigil-cli` | [cli.md](cli.md) | The terminal client |
| `vigil-ui-core`, `vigil-ui` | [ui.md](ui.md) | The app: shell, keyboard, palette, motion, themes |
| `xtask`, `packaging/` | [packaging.md](packaging.md) | Install tree, distro packages, policy checks |
| `spike/` | `docs/DECISIONS.md` D-002 | The GPUI vs iced measurements |

## Rust in five minutes (for reading this code)

- A **crate** is a library or program; the **workspace** (`vigil2/Cargo.toml`) builds them
  together. Dependencies are listed once there and must be on the allowlist
  (`cargo run -p xtask -- check-deps` fails otherwise).
- `Result<T, E>` is "a T, or an error E". The `?` after a call means "if this failed, return the
  error now". Most functions here return `Result` instead of crashing.
- `Option<T>` is "a T, or nothing" (`Some(x)` / `None`). Where Python would use `None`, Rust
  makes you handle it.
- `#[derive(Serialize, Deserialize)]` on a struct lets `serde_json` turn it into JSON and back.
  That is how findings travel on the bus and into files.
- `Arc<T>` shares one value between threads; `Mutex`/`RwLock` let one thread at a time change
  it. The daemon's sensor thread writes, the bus handlers read.
- `async fn` and `.await` are for code that waits (D-Bus calls). `tokio` runs them.
- `unsafe` is forbidden in every crate (`unsafe_code = "forbid"` in the workspace). Only the
  future eBPF crate will need an exception, and it will be reviewed on its own.
- Tests live next to the code (`#[cfg(test)] mod tests`) or in `tests/*.rs`. `cargo test` runs
  them all.
