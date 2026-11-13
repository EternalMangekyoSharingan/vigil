//! vigild: Vigil's system service.
//!
//! Small and boring on purpose (docs/RUST_REWRITE.md rule 7). It collects, stores and
//! answers queries:
//!
//! - **sensor thread**: polls /proc (milestone 2's sources) every `--interval-ms`,
//!   records what it saw in the store, notes first sightings in the event log;
//! - **D-Bus**: `org.vigil.Daemon` on the system bus (or the session bus, or a given
//!   address, for development and tests), interfaces `org.vigil.Daemon`, `.Processes`,
//!   `.Network`, `.Events`, `.Findings`; every call checks its caller (src/auth.rs);
//! - **systemd**: READY=1 once the bus name is ours, watchdog pings, STOPPING=1.
//!
//! It never parses untrusted file formats, never runs a shell, never opens a network
//! socket, and has no method that changes the system (privileged actions arrive with
//! Run mode in milestone 5, each behind its own polkit action).
//!
//! Logs go to stderr with sd-daemon priority prefixes, which journald turns into levels.

mod auth;
mod bus;
mod checks;
mod fast;
mod notify;

use clap::Parser;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use vigil_model::finding::now;
use vigil_model::host::{DaemonStatus, NetSnapshot, ProcessList, SourceStatus};
use vigil_sensor::procfs::ProcRoot;
use vigil_sensor::visibility;
use vigil_store::{Event, Store};

macro_rules! log {
    ($lvl:literal, $($arg:tt)*) => { eprintln!("<{}>{}", $lvl, format!($($arg)*)) };
}
pub(crate) use log;

#[derive(Parser, Debug, Clone)]
#[command(name = "vigild", version, about = "Vigil's system service (sensors, store, D-Bus API)")]
struct Args {
    /// Which bus to serve on: "system" (the installed service), "session" (development:
    /// runs as you, answers only you), or "address=<D-Bus address>" (tests).
    #[arg(long, default_value = "system")]
    bus: String,
    /// Where the database lives. Default: /var/lib/vigil (system) or
    /// $XDG_STATE_HOME/vigil (otherwise).
    #[arg(long)]
    state_dir: Option<PathBuf>,
    /// Read processes from another /proc (tests use the synthetic fixture).
    #[arg(long, default_value = "/proc")]
    proc_root: PathBuf,
    /// How often the /proc sources look, in milliseconds.
    #[arg(long, default_value_t = 2000)]
    interval_ms: u64,
    /// Days of history to keep.
    #[arg(long, default_value_t = 30)]
    retention_days: u32,
    /// "polkit" or "same-uid". Default: polkit on the system bus, same-uid otherwise.
    #[arg(long)]
    auth: Option<String>,
    /// Take one look, print the daemon status as JSON and exit (no bus).
    #[arg(long)]
    once: bool,
}

/// CPU ticks per (pid, start time), and when they were read.
pub type TickMap = (std::collections::HashMap<(u32, u64), u64>, Instant);

/// Everything the bus handlers read. The sensor thread is the only writer.
pub struct Shared {
    pub net: RwLock<Option<Arc<NetSnapshot>>>,
    pub procs: RwLock<Option<Arc<ProcessList>>>,
    pub store: Mutex<Store>,
    pub sources: RwLock<Vec<SourceStatus>>,
    pub started: f64,
    pub retention_days: u32,
    pub polls: Mutex<PollStats>,
    /// CPU ticks per (pid, start time) at the previous look, for CPU percentages.
    pub ticks: Mutex<TickMap>,
    /// Processes already in the store, and when every row's last_seen was last refreshed.
    pub recorded: Mutex<(std::collections::HashSet<(u32, u64)>, Instant)>,
    /// The process checks (milestone 3) and how many findings are current.
    pub checker: Mutex<Option<checks::Checker>>,
    /// The daemon's state directory (the database, the user's allowlist).
    pub state_dir: PathBuf,
    /// Seconds between looks.
    pub interval_s: f64,
    /// The fast path's counters (process events).
    pub fast: fast::Stats,
    /// Seconds east of UTC (local time for the words of findings).
    pub utc_offset: i64,
    pub current_findings: Mutex<usize>,
}

#[derive(Debug, Default, Clone)]
pub struct PollStats {
    pub count: u64,
    pub last_ms: f64,
    pub max_ms: f64,
}

fn self_usage() -> (u64, f64) {
    let rss = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("VmRSS:").map(|v| v.trim().trim_end_matches(" kB").trim().to_string()))
        })
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let stat = std::fs::read_to_string("/proc/self/stat").unwrap_or_default();
    let f: Vec<&str> = stat.rsplit_once(')').map_or("", |(_, r)| r).split_whitespace().collect();
    let ticks: f64 = f.get(11).and_then(|v| v.parse::<f64>().ok()).unwrap_or(0.0)
        + f.get(12).and_then(|v| v.parse::<f64>().ok()).unwrap_or(0.0);
    (rss, ticks / 100.0)
}

/// CAP_SYS_PTRACE (bit 19) in the effective set: may read every process's fd table.
fn can_ptrace() -> bool {
    nix::unistd::geteuid().is_root()
        || std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|s| s.lines().find_map(|l| l.strip_prefix("CapEff:").map(|v| v.trim().to_string())))
            .and_then(|hex| u64::from_str_radix(&hex, 16).ok())
            .is_some_and(|caps| caps & (1 << 19) != 0)
}

impl Shared {
    pub fn status(&self) -> DaemonStatus {
        let (rss_kb, cpu_s) = self_usage();
        let store = self.store.lock().unwrap_or_else(|e| e.into_inner()).status(self.retention_days);
        DaemonStatus {
            version: env!("CARGO_PKG_VERSION").into(),
            api: vigil_model::api::API_VERSION,
            started: self.started,
            uptime_s: now() - self.started,
            sources: self.sources.read().unwrap_or_else(|e| e.into_inner()).clone(),
            store,
            rss_kb,
            cpu_s,
        }
    }
}

/// One look at the system: read, keep in memory, record, note first sightings.
///
/// `viewer` is the uid whose view the kernel gives us, or 0 when the daemon may read
/// every process (root, or CAP_SYS_PTRACE): then nothing is "hidden: other user", and
/// an unattributed socket gets the explanation that is actually true.
pub(crate) fn poll(shared: &Shared, root: &ProcRoot, viewer: u32) {
    let t0 = Instant::now();
    let ts = now();
    let mut net = root.net_snapshot(ts, viewer);
    let mut procs = root.process_list(ts, viewer);
    // CPU and memory per process: CPU as the share of one core since the previous look.
    {
        let mut prev = shared.ticks.lock().unwrap_or_else(|e| e.into_inner());
        let dt = prev.1.elapsed().as_secs_f64().max(0.001);
        let mut next = std::collections::HashMap::new();
        for p in procs.processes.iter_mut() {
            if let Some((ticks, rss)) = root.usage(p.pid) {
                let key = (p.pid, p.started.map_or(0, |s| (s * 100.0) as u64));
                p.rss_kb = Some(rss);
                if let Some(before) = prev.0.get(&key) {
                    p.cpu_pct = Some(((ticks.saturating_sub(*before)) as f64 / 100.0 / dt * 100.0) as f32);
                }
                next.insert(key, ticks);
            }
        }
        *prev = (next, Instant::now());
    }
    if viewer == 0 && !nix::unistd::geteuid().is_root() {
        let who = format!(
            "{} (with CAP_SYS_PTRACE)",
            vigil_sensor::procfs::system_user_name(nix::unistd::geteuid().as_raw())
        );
        net.viewer.user.clone_from(&who);
        procs.viewer.user = who;
    }
    {
        let mut store = shared.store.lock().unwrap_or_else(|e| e.into_inner());
        match store.record_net(&net) {
            Ok(rec) => {
                for key in &rec.new_programs {
                    let _ = store.event(&Event {
                        ts,
                        kind: "first-seen".into(),
                        summary: format!("First time Vigil has seen {key} use the network"),
                        source: "vigild: proc-poll, /proc/net and /proc/<pid>/fd".into(),
                        detail: serde_json::json!({"program": key}),
                    });
                }
            }
            Err(e) => log!(3, "could not record connections: {e}"),
        }
        // New processes every look; everyone's last_seen once a minute (fewer disk writes).
        let mut known = shared.recorded.lock().unwrap_or_else(|e| e.into_inner());
        let key = |p: &vigil_model::host::ProcessInfo| (p.pid, p.started.map_or(0, |s| (s * 100.0) as u64));
        let refresh = known.1.elapsed() > Duration::from_secs(60) || known.0.is_empty();
        let res = if refresh {
            store.record_processes(&procs)
        } else {
            store.record_processes_where(&procs, |p| !known.0.contains(&key(p)))
        };
        match res {
            Ok(_) => {
                known.0 = procs.processes.iter().map(key).collect();
                if refresh {
                    known.1 = Instant::now();
                }
            }
            Err(e) => log!(3, "could not record processes: {e}"),
        }
    }
    // The process checks, every few looks (and on the first one).
    let n = shared.polls.lock().unwrap_or_else(|e| e.into_inner()).count;
    if n.is_multiple_of(checks::EVERY) {
        let store = shared.store.lock().unwrap_or_else(|e| e.into_inner());
        let mut checker = shared.checker.lock().unwrap_or_else(|e| e.into_inner());
        let c = checker.get_or_insert_with(|| checks::Checker::new(&store, &shared.state_dir));
        let mut current = c.run(root, &procs, &net, viewer, &store, ts);
        // The network scorer looks at the last 24 hours, so once a minute is plenty.
        if n.is_multiple_of(checks::EVERY * 6) {
            c.score_network(&procs, &store, ts, shared.interval_s, shared.utc_offset);
        }
        current += c.network_alerts;
        *shared.current_findings.lock().unwrap_or_else(|e| e.into_inner()) = current;
    }
    *shared.net.write().unwrap_or_else(|e| e.into_inner()) = Some(Arc::new(net));
    *shared.procs.write().unwrap_or_else(|e| e.into_inner()) = Some(Arc::new(procs));
    let ms = t0.elapsed().as_secs_f64() * 1000.0;
    let mut p = shared.polls.lock().unwrap_or_else(|e| e.into_inner());
    p.count += 1;
    p.last_ms = ms;
    p.max_ms = p.max_ms.max(ms);
}

fn state_dir(args: &Args) -> PathBuf {
    if let Some(d) = &args.state_dir {
        return d.clone();
    }
    if args.bus == "system" {
        // systemd's StateDirectory=vigil.
        return std::env::var_os("STATE_DIRECTORY").map_or_else(|| PathBuf::from("/var/lib/vigil"), PathBuf::from);
    }
    let base = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/state")))
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("vigil")
}

fn main() -> std::process::ExitCode {
    // The local time zone, read before any thread starts (the only time it is safe), for
    // clock times in the words of findings.
    let utc_offset = time::UtcOffset::current_local_offset().map_or(0, |o| i64::from(o.whole_seconds()));
    let args = Args::parse();
    let dir = state_dir(&args);
    if let Err(e) = std::fs::create_dir_all(&dir) {
        log!(3, "cannot create {}: {e}", dir.display());
        return std::process::ExitCode::FAILURE;
    }
    let store = match Store::open(&dir.join("vigil.db")) {
        Ok(s) => s,
        Err(e) => {
            log!(3, "cannot open the store: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };
    let euid = nix::unistd::geteuid().as_raw();
    let ptrace = can_ptrace();
    let facts = visibility::kernel_facts(std::path::Path::new("/"));
    let shared = Arc::new(Shared {
        net: RwLock::new(None),
        procs: RwLock::new(None),
        store: Mutex::new(store),
        sources: RwLock::new(visibility::sources(&facts, ptrace, args.interval_ms)),
        started: now(),
        retention_days: args.retention_days,
        polls: Mutex::new(PollStats::default()),
        ticks: Mutex::new((std::collections::HashMap::new(), Instant::now())),
        recorded: Mutex::new((std::collections::HashSet::new(), Instant::now())),
        checker: Mutex::new(None),
        state_dir: dir.clone(),
        interval_s: args.interval_ms as f64 / 1000.0,
        fast: fast::Stats::default(),
        utc_offset,
        current_findings: Mutex::new(0),
    });
    let root = ProcRoot::at(&args.proc_root);
    let viewer = if ptrace { 0 } else { euid };
    log!(
        6,
        "vigild {} starting: store {}, /proc at {}, every {} ms, sees {}",
        env!("CARGO_PKG_VERSION"),
        dir.join("vigil.db").display(),
        args.proc_root.display(),
        args.interval_ms,
        if ptrace { "every user's processes" } else { "only its own user's processes" }
    );
    if !ptrace && args.bus == "system" {
        log!(4, "no CAP_SYS_PTRACE: other users' sockets will show as hidden (check vigild.service)");
    }
    poll(&shared, &root, viewer);
    if args.once {
        println!("{}", serde_json::to_string_pretty(&shared.status()).unwrap_or_default());
        return std::process::ExitCode::SUCCESS;
    }
    {
        let store = shared.store.lock().unwrap_or_else(|e| e.into_inner());
        let _ = store.event(&Event {
            ts: now(),
            kind: "daemon".into(),
            summary: format!("vigild {} started", env!("CARGO_PKG_VERSION")),
            source: "vigild".into(),
            detail: serde_json::json!({"interval_ms": args.interval_ms, "ptrace": ptrace, "bus": args.bus}),
        });
    }
    let mode = match (args.auth.as_deref(), args.bus.as_str()) {
        (Some("polkit"), _) | (None, "system") => auth::Mode::Polkit,
        (Some("same-uid"), _) | (None, _) => auth::Mode::SameUid(euid),
        (Some(other), _) => {
            log!(3, "unknown --auth {other} (polkit or same-uid)");
            return std::process::ExitCode::FAILURE;
        }
    };
    let rt = match tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            log!(3, "cannot start the async runtime: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };
    let code = rt.block_on(bus::serve(
        args.bus.clone(),
        mode,
        shared.clone(),
        root,
        viewer,
        Duration::from_millis(args.interval_ms),
    ));
    notify::notify("STOPPING=1");
    match code {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            log!(3, "{e}");
            std::process::ExitCode::FAILURE
        }
    }
}
