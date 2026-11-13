//! The fast path (milestone 3): process events as they happen, between two looks.
//!
//! The kernel's proc connector reports every exec and exit. On an exec the daemon reads the
//! new process from /proc at once (a 50 ms `curl` is still there), records it, runs the process
//! checks on it, and watches it for its first seconds: every 20 ms it lists the process's
//! socket inodes and attributes new ones from the process's own socket tables. A program that
//! connects and exits before the next look is recorded with its connections, and an event says
//! what it did. Programs still running when the next look comes are left to the poll.
//!
//! Without the proc connector (no CAP_NET_ADMIN, or a container's PID namespace) nothing here
//! runs and the daemon polls /proc as before; the visibility panel says which is the case.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use vigil_model::host::{NetSnapshot, ProcessInfo, ProcessList, Socket, Viewer};
use vigil_sensor::events::{Event, ProcEvents};
use vigil_sensor::procfs::ProcRoot;
use vigil_store::Event as StoreEvent;

use crate::{log, Shared};

fn endpoint(ip: &str, port: u32) -> String {
    if ip.contains(':') {
        format!("[{ip}]:{port}")
    } else {
        format!("{ip}:{port}")
    }
}

/// The usual service on a port, for the event's words.
fn service_word(proto: &str, port: u32) -> String {
    match port {
        443 => "HTTPS".into(),
        80 => "HTTP".into(),
        53 => "DNS".into(),
        853 => "DNS over TLS".into(),
        22 => "SSH".into(),
        123 => "NTP".into(),
        _ => format!("{} {port}", proto.to_uppercase()),
    }
}

/// How long a new process is watched for sockets.
const WATCH_FOR: Duration = Duration::from_secs(4);
/// At most this many processes are watched at once (a build starts thousands).
const WATCH_MAX: usize = 256;
const TICK: Duration = Duration::from_millis(20);

/// Counters for the visibility panel.
#[derive(Default)]
pub struct Stats {
    pub execs: AtomicU64,
    /// Processes gone before Vigil could read them.
    pub missed: AtomicU64,
    /// Connections caught on the fast path.
    pub caught: AtomicU64,
}

struct Watched {
    info: ProcessInfo,
    since: Instant,
    seen: HashSet<u64>,
    conns: Vec<Socket>,
}

/// Start the fast path if the proc connector can be opened. Returns why not, otherwise.
pub fn start(shared: Arc<Shared>, root: &ProcRoot, viewer: u32) -> Result<(), String> {
    let events = ProcEvents::open()?;
    let (tx, rx) = mpsc::channel::<Event>();
    std::thread::Builder::new()
        .name("proc-events".into())
        .spawn(move || loop {
            match events.next() {
                Ok(batch) => {
                    for e in batch {
                        if tx.send(e).is_err() {
                            return;
                        }
                    }
                }
                Err(e) => {
                    log!(4, "process events stopped: {e}");
                    return;
                }
            }
        })
        .map_err(|e| e.to_string())?;
    let root = ProcRoot { root: root.root.clone(), blocked: root.blocked.clone(), user_name: root.user_name };
    std::thread::Builder::new()
        .name("fast-path".into())
        .spawn(move || watch(shared, root, viewer, rx))
        .map_err(|e| e.to_string())?;
    Ok(())
}

fn watch(shared: Arc<Shared>, root: ProcRoot, viewer: u32, rx: mpsc::Receiver<Event>) {
    let btime = root.boot_time();
    let own = std::process::id();
    let mut watched: HashMap<u32, Watched> = HashMap::new();
    loop {
        // Events first, as many as are waiting; then one sweep over the watched processes.
        // Nothing watched: sleep until the next event instead of waking every 20 ms.
        let next = if watched.is_empty() {
            rx.recv().map_err(|_| mpsc::RecvTimeoutError::Disconnected)
        } else {
            rx.recv_timeout(TICK)
        };
        match next {
            Ok(first) => {
                let mut batch = vec![first];
                batch.extend(rx.try_iter());
                for e in batch {
                    match e {
                        Event::Exec { pid } if pid != own => {
                            shared.fast.execs.fetch_add(1, Ordering::Relaxed);
                            let Some(info) = root.read_process(pid, btime) else {
                                shared.fast.missed.fetch_add(1, Ordering::Relaxed);
                                continue;
                            };
                            on_exec(&shared, &root, viewer, &info);
                            if watched.len() < WATCH_MAX {
                                watched.insert(
                                    pid,
                                    Watched { info, since: Instant::now(), seen: HashSet::new(), conns: vec![] },
                                );
                            }
                        }
                        Event::Exit { pid, .. } => {
                            if let Some(w) = watched.remove(&pid) {
                                on_exit(&shared, w);
                            }
                        }
                        _ => {}
                    }
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => return,
        }
        let now = vigil_model::finding::now();
        watched.retain(|_, w| w.since.elapsed() < WATCH_FOR);
        for (pid, w) in watched.iter_mut() {
            let Some(inodes) = root.socket_inodes(*pid) else { continue };
            let new: Vec<u64> = inodes.into_iter().filter(|i| w.seen.insert(*i)).collect();
            if new.is_empty() {
                continue;
            }
            let socks: Vec<Socket> = root.sockets_of(*pid, &new, &w.info);
            if socks.is_empty() {
                continue;
            }
            shared.fast.caught.fetch_add(socks.len() as u64, Ordering::Relaxed);
            record(&shared, &w.info, &socks, now, viewer);
            w.conns.extend(socks.into_iter().filter(|s| s.kind == "connection"));
        }
    }
}

/// Record a new process and check it at once.
fn on_exec(shared: &Shared, root: &ProcRoot, viewer: u32, info: &ProcessInfo) {
    let now = vigil_model::finding::now();
    let list = ProcessList {
        taken_at: now,
        viewer: Viewer { uid: viewer, user: String::new(), root: viewer == 0 },
        processes: vec![info.clone()],
        unreadable_by_uid: BTreeMap::new(),
        hidepid: None,
    };
    let store = shared.store.lock().unwrap_or_else(|e| e.into_inner());
    let _ = store_processes(&store, &list);
    let mut checker = shared.checker.lock().unwrap_or_else(|e| e.into_inner());
    let c = checker.get_or_insert_with(|| crate::checks::Checker::new(&store, &shared.state_dir));
    // Its parent, from the last look, for the "a browser started a shell" check.
    let parent = shared
        .procs
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .and_then(|l| l.processes.iter().find(|p| p.pid == info.ppid).cloned());
    let mut processes = vec![info.clone()];
    processes.extend(parent);
    let one = ProcessList { processes, ..list };
    let empty = NetSnapshot {
        taken_at: now,
        viewer: one.viewer.clone(),
        sockets: vec![],
        processes: BTreeMap::new(),
        pids_visible: 0,
        unreadable_by_uid: BTreeMap::new(),
        hidden_counts: BTreeMap::new(),
        missing_tables: vec![],
        byte_counts: false,
        hidepid: None,
    };
    c.run_only(root, &one, &empty, viewer, &store, now, info.pid);
}

fn store_processes(store: &vigil_store::Store, list: &ProcessList) -> Result<(), String> {
    // record_processes takes &mut; the fast path only ever inserts, through its own statement.
    store.insert_processes(list).map_err(|e| e.to_string())
}

/// Store connections caught on the fast path (with their program and first sightings).
fn record(shared: &Shared, info: &ProcessInfo, socks: &[Socket], now: f64, viewer: u32) {
    let snap = NetSnapshot {
        taken_at: now,
        viewer: Viewer { uid: viewer, user: String::new(), root: viewer == 0 },
        sockets: socks.to_vec(),
        processes: [(info.pid, info.clone())].into_iter().collect(),
        pids_visible: 1,
        unreadable_by_uid: BTreeMap::new(),
        hidden_counts: BTreeMap::new(),
        missing_tables: vec![],
        byte_counts: false,
        hidepid: None,
    };
    let mut store = shared.store.lock().unwrap_or_else(|e| e.into_inner());
    if let Ok(rec) = store.record_net(&snap) {
        for key in &rec.new_programs {
            let _ = store.event(&StoreEvent {
                ts: now,
                kind: "first-seen".into(),
                summary: format!("First time Vigil has seen {key} use the network"),
                source: "vigild: proc connector (exec), then /proc/<pid>/fd and /proc/<pid>/net".into(),
                detail: serde_json::json!({"program": key}),
            });
        }
    }
}

/// A watched process ended. If it made connections, say what it did: these are the
/// programs a 2-second look would have missed.
fn on_exit(shared: &Shared, w: Watched) {
    if w.conns.is_empty() {
        return;
    }
    let lived = w.since.elapsed().as_secs_f64();
    let mut targets: Vec<String> = vec![];
    for s in &w.conns {
        let port = if s.direction == "in" { s.local_port } else { s.remote_port };
        let t = format!("{} ({})", endpoint(&s.remote_ip, s.remote_port), service_word(&s.proto, port));
        if !targets.contains(&t) {
            targets.push(t);
        }
    }
    let more = if targets.len() > 3 { format!(" and {} more", targets.len() - 3) } else { String::new() };
    let summary = format!(
        "{} ran for {} and connected to {}{more}",
        w.info.name,
        if lived < 1.0 { format!("{:.0} ms", lived * 1000.0) } else { format!("{lived:.1} s") },
        targets.iter().take(3).cloned().collect::<Vec<_>>().join(", ")
    );
    let store = shared.store.lock().unwrap_or_else(|e| e.into_inner());
    let _ = store.event(&StoreEvent {
        ts: vigil_model::finding::now(),
        kind: "short-lived".into(),
        summary,
        source: "vigild: proc connector (exec, exit), /proc/<pid>/fd and /proc/<pid>/net".into(),
        detail: serde_json::json!({
            "program": w.info.key, "pid": w.info.pid, "seconds": lived,
            "connections": w.conns.iter().map(|s| format!("{} {}", s.proto, endpoint(&s.remote_ip, s.remote_port))).collect::<Vec<_>>(),
        }),
    });
}
