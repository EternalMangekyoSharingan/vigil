//! Vigil's shared vocabulary: the finding format, the wording rules, command tokens,
//! Fix panels, ATT&CK tags and distro facts.
//!
//! Everything here is pure: no I/O except reading os-release, no processes, no
//! network. The daemon, the engine, the app and the CLI all speak in these types, and
//! the D-Bus API sends them as JSON in exactly the format Vigil 1 writes, so a finding
//! exported by either version can be imported by the other.
//!
//! Each module is a port of a Vigil 1 module, named in its header. `tests/golden.rs`
//! checks the port against outputs computed by the Python code
//! (`vigil2/tests/golden/make_golden.py`).

pub mod attack;
pub mod commands;
pub mod distro;
pub mod finding;
pub mod fixes;
pub mod pyjson;
pub mod sha1;
pub mod wording;

pub use finding::{Builder, Finding, FindingError, Severity};
