//! Vigil's engines: the checks that turn what the sensor sees into findings.
//!
//! - [`tasks`]: Vigil 1's process checks (deleted or memory-only programs, programs run from
//!   temporary, cache, download or hidden folders, forced libraries, shells started by
//!   browsers and servers, borrowed system names, fake kernel threads, reverse shells,
//!   secrets held by programs that do not own them, listeners in odd places).
//! - [`secrets`]: which open files are secrets, and who normally holds them.
//!
//! Engines are pure: they read facts and return findings. They never touch the system.

pub mod net;
pub mod secrets;
pub mod tasks;
