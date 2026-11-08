//! The daemon's D-Bus API: names, paths, interfaces and the payload version.
//!
//! Methods return JSON text in the shapes of [`crate::host`] and [`crate::finding`], so
//! the finding format is the same on the bus, in exports and in Vigil 1. Every payload
//! carries [`API_VERSION`]; a client that sees a newer major version says so rather than
//! guessing.

pub const BUS_NAME: &str = "org.vigil.Daemon";
pub const OBJECT_PATH: &str = "/org/vigil/Daemon";
pub const API_VERSION: u32 = 1;

pub const IFACE_DAEMON: &str = "org.vigil.Daemon";
pub const IFACE_PROCESSES: &str = "org.vigil.Processes";
pub const IFACE_NETWORK: &str = "org.vigil.Network";
pub const IFACE_FINDINGS: &str = "org.vigil.Findings";
pub const IFACE_EVENTS: &str = "org.vigil.Events";

/// polkit actions (packaging/polkit/org.vigil.policy).
pub const ACTION_READ: &str = "org.vigil.read";
pub const ACTION_MANAGE: &str = "org.vigil.manage";
pub const ACTION_RUN: &str = "org.vigil.run";
pub const ACTION_FIREWALL: &str = "org.vigil.firewall";
