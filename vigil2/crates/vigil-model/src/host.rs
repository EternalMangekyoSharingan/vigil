//! What Vigil sees on the host: processes, sockets, and what it could not see and why.
//!
//! The same shapes Vigil 1's collector (`vigil/net/collector.py`) produces, so its tests'
//! expectations carry over. The daemon fills these from its sensors and sends them on
//! the bus as JSON; the app and the CLI read them.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// One step up a process's parent chain.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Ancestor {
    pub pid: u32,
    pub name: String,
    pub started: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    /// "Which program": the executable, or for an interpreter the script it runs
    /// ("/usr/bin/python3 /home/a/x.py"). Two scripts are two programs.
    pub key: String,
    /// Short display name: "firefox", "x.py (python3)".
    pub name: String,
    pub comm: String,
    pub exe: Option<String>,
    /// The executable was deleted (or replaced) while running.
    pub exe_deleted: bool,
    pub cmdline: Vec<String>,
    pub uid: i64,
    pub user: String,
    pub ppid: u32,
    pub parent: Option<String>,
    pub ancestry: Vec<Ancestor>,
    /// Start time, seconds since the epoch.
    pub started: Option<f64>,
    /// Resident memory, filled in by the daemon (not by Vigil 1's collector).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rss_kb: Option<u64>,
    /// Share of one CPU core used since the daemon's previous look, in percent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_pct: Option<f32>,
}

/// Why a socket has no process attached, in plain words.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hidden {
    /// "closed", "other-user", "protected", "unknown".
    pub reason: String,
    pub label: String,
    pub explanation: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Socket {
    /// tcp, tcp6, udp, udp6.
    pub table: String,
    pub proto: String,
    pub local_ip: String,
    pub local_port: u32,
    pub remote_ip: String,
    pub remote_port: u32,
    pub state: String,
    pub uid: u32,
    pub inode: u64,
    /// "listen" or "connection".
    pub kind: String,
    /// "in" (accepted on a port we listen on) or "out".
    pub direction: String,
    /// Seconds since the program closed it (TIME_WAIT only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub closed_ago: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes_sent: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes_recv: Option<u64>,
    pub pid: Option<u32>,
    pub pids: Vec<u32>,
    pub program: Option<String>,
    pub hidden: Option<Hidden>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Viewer {
    pub uid: u32,
    pub user: String,
    pub root: bool,
}

/// One pass over the socket tables and the processes holding them.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NetSnapshot {
    pub taken_at: f64,
    pub viewer: Viewer,
    pub sockets: Vec<Socket>,
    /// The processes that hold the sockets, by pid.
    pub processes: BTreeMap<u32, ProcessInfo>,
    pub pids_visible: usize,
    /// Processes whose open files the viewer may not read, per uid.
    pub unreadable_by_uid: BTreeMap<u32, usize>,
    pub hidden_counts: BTreeMap<String, usize>,
    /// Socket tables this kernel does not have (tcp6 with IPv6 disabled ...).
    pub missing_tables: Vec<String>,
    /// Whether byte counts were available (sock_diag).
    #[serde(default)]
    pub byte_counts: bool,
    /// /proc's hidepid= mount option, if set.
    #[serde(default)]
    pub hidepid: Option<String>,
}

/// Every visible process, for the Processes area.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProcessList {
    pub taken_at: f64,
    pub viewer: Viewer,
    pub processes: Vec<ProcessInfo>,
    /// Processes the viewer could see exist but not inspect, per uid.
    pub unreadable_by_uid: BTreeMap<u32, usize>,
    pub hidepid: Option<String>,
}

/// Which sensor feeds each signal, and why (the "What Vigil can and cannot see" panel).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceStatus {
    /// "processes", "connections", "dns", "file-opens" ...
    pub signal: String,
    /// "ebpf", "proc-connector", "sock-diag", "proc-poll" ...
    pub source: String,
    pub live: bool,
    /// Plain words: what this source sees, what it misses, and how to get more.
    pub note: String,
    /// Events dropped rather than block the kernel.
    #[serde(default)]
    pub dropped: u64,
}

/// The daemon's own health.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DaemonStatus {
    pub version: String,
    pub api: u32,
    pub started: f64,
    pub uptime_s: f64,
    pub sources: Vec<SourceStatus>,
    pub store: StoreStatus,
    pub rss_kb: u64,
    pub cpu_s: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StoreStatus {
    pub path: String,
    pub schema: u32,
    pub size_bytes: u64,
    pub retention_days: u32,
    pub programs_seen: u64,
    pub destinations_seen: u64,
    pub events: u64,
}
