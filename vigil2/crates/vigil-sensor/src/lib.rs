//! Where Vigil's observations come from.
//!
//! Each signal (processes, connections, DNS, sensitive file opens ...) can come from
//! several sources, best first: eBPF, then kernel event interfaces (proc connector,
//! sock_diag, fanotify), then polling /proc. The daemon picks the best one that works on
//! this kernel and the visibility panel says which is live and why
//! (docs/RUST_REWRITE.md section 4). Milestone 2 has the /proc polling sources; the
//! others arrive with milestone 3, behind the same functions.

pub mod device;
pub mod procfs;
pub mod visibility;
