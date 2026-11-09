//! The process checks, run by the sensor thread every few looks (milestone 3).
//!
//! Facts come from the look the daemon just took, plus two reads the checks need: the
//! dynamic linker's variables from each process's environment (once per process, kept
//! until it exits) and the paths of its open files (readlink only, nothing is opened).
//! Findings go to the store; the first sighting of each also becomes an event.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;

use vigil_engine::{secrets, tasks};
use vigil_model::distro::OsRelease;
use vigil_model::host::{NetSnapshot, ProcessList};
use vigil_sensor::procfs::ProcRoot;
use vigil_store::{Event, Store};

/// Run the checks on every this many looks (10 s at the default 2 s interval).
pub const EVERY: u64 = 5;

pub struct Checker {
    /// LD_* variables per (pid, start time): the environment rarely changes after exec.
    ld: HashMap<(u32, u64), Option<BTreeMap<String, String>>>,
    /// Finding ids already in the store.
    known: HashSet<String>,
    osr: OsRelease,
}

impl Checker {
    pub fn new(store: &Store) -> Checker {
        let known = store.findings().map(|fs| fs.into_iter().map(|f| f.id).collect()).unwrap_or_default();
        Checker { ld: HashMap::new(), known, osr: vigil_model::distro::os_release(Path::new("/etc/os-release")) }
    }

    /// Check every process in `procs`; store the findings. Returns how many are current.
    pub fn run(
        &mut self,
        root: &ProcRoot,
        procs: &ProcessList,
        net: &NetSnapshot,
        viewer: u32,
        store: &Store,
        now: f64,
    ) -> usize {
        let key = |pid: u32, started: Option<f64>| (pid, started.map_or(0, |s| (s * 100.0) as u64));
        let alive: HashSet<(u32, u64)> = procs.processes.iter().map(|p| key(p.pid, p.started)).collect();
        self.ld.retain(|k, _| alive.contains(k));
        let mut facts: HashMap<u32, tasks::ProcFacts> = HashMap::new();
        for p in &procs.processes {
            let exe = p.exe.clone();
            let path =
                exe.as_deref().map(|e| e.strip_suffix(" (deleted)").unwrap_or(e).to_string()).filter(|e| !e.is_empty());
            let kernel = exe.is_none() && (p.ppid == 2 || p.pid == 2) && p.cmdline.is_empty();
            let ld = self.ld.entry(key(p.pid, p.started)).or_insert_with(|| root.ld_vars(p.pid)).clone();
            let sockets = net
                .sockets
                .iter()
                .filter(|s| s.pids.contains(&p.pid))
                .map(|s| tasks::SockFact {
                    kind: s.kind.clone(),
                    local_ip: s.local_ip.clone(),
                    local_port: s.local_port,
                    remote_ip: s.remote_ip.clone(),
                    remote_port: s.remote_port,
                })
                .collect();
            let held = if exe.is_some() {
                root.open_files(p.pid).map(|f| secrets::held(&f)).unwrap_or_default()
            } else {
                vec![]
            };
            let exists_now = path.as_deref().is_some_and(|x| !x.starts_with("/memfd:") && Path::new(x).exists());
            facts.insert(
                p.pid,
                tasks::ProcFacts {
                    pid: p.pid,
                    ppid: p.ppid,
                    comm: p.comm.clone(),
                    exe,
                    exe_deleted: p.exe_deleted,
                    cmdline: p.cmdline.clone(),
                    name: p.name.clone(),
                    kernel,
                    path,
                    exists_now,
                    // The package database arrives with Software (milestone 4).
                    package: None,
                    package_db: None,
                    ld,
                    sockets,
                    secrets: held,
                },
            );
        }
        let mut current = 0;
        for p in &procs.processes {
            let Some(f) = facts.get(&p.pid) else { continue };
            for flag in tasks::flags(f, &facts, "") {
                let cx = tasks::Context {
                    user: &p.user,
                    started: p.started,
                    chain: std::iter::once(p.name.clone()).chain(p.ancestry.iter().map(|a| a.name.clone())).collect(),
                    viewer_uid: viewer,
                    uid: u32::try_from(p.uid).unwrap_or(u32::MAX),
                    osr: &self.osr,
                    now,
                };
                let Ok(finding) = tasks::finding(f, &facts, &flag, &cx) else { continue };
                current += 1;
                if self.known.insert(finding.id.clone()) {
                    let _ = store.event(&Event {
                        ts: now,
                        kind: "finding".into(),
                        summary: finding.title.clone(),
                        source: format!("vigild: process checks ({}), /proc/{}", flag.check, p.pid),
                        detail: serde_json::json!({
                            "id": finding.id, "severity": flag.severity, "check": flag.check, "pid": p.pid,
                        }),
                    });
                }
                let _ = store.put_finding(&finding, now);
            }
        }
        current
    }
}
