//! The D-Bus API (docs/RUST_REWRITE.md section 3, "IPC").
//!
//! One object, `/org/vigil/Daemon`, with one interface per area. Methods return JSON
//! text in the shapes of `vigil_model::host` and `vigil_model::finding`. Every method
//! first asks who is calling and whether they may (src/auth.rs); reading is
//! `org.vigil.read`. Nothing here changes the system.
//!
//! Live updates: `org.vigil.Events.Changed(kind, taken_at)` after each look. If a client
//! is slow, signals are skipped, never queued without bound: the client reads the
//! latest state when it catches up.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::signal::unix::{signal, SignalKind};
use zbus::message::Header;
use zbus::object_server::SignalEmitter;
use zbus::{connection, fdo, interface, Connection};

use crate::auth::{Authorizer, Caller, Mode};
use crate::{log, notify, poll, Shared};
use vigil_model::api::{ACTION_READ, API_VERSION, BUS_NAME, OBJECT_PATH};
use vigil_sensor::procfs::ProcRoot;

fn json<T: serde::Serialize>(v: &T) -> fdo::Result<String> {
    serde_json::to_string(v).map_err(|e| fdo::Error::Failed(e.to_string()))
}

async fn guard(auth: &Authorizer, conn: &Connection, hdr: &Header<'_>) -> fdo::Result<Caller> {
    let caller = Authorizer::caller(conn, hdr).await?;
    auth.check(conn, &caller, ACTION_READ, false).await?;
    Ok(caller)
}

fn not_ready() -> fdo::Error {
    fdo::Error::Failed("the first look at the system has not finished yet; try again in a second".into())
}

struct DaemonIface {
    shared: Arc<Shared>,
    auth: Arc<Authorizer>,
}

#[interface(name = "org.vigil.Daemon")]
impl DaemonIface {
    /// The daemon's health: version, sources (what it can and cannot see), store, usage.
    async fn status(
        &self,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &Connection,
    ) -> fdo::Result<String> {
        guard(&self.auth, conn, &hdr).await?;
        json(&self.shared.status())
    }

    /// Who the daemon thinks is calling (uid and pid from the bus). Needs no permission:
    /// it only tells callers about themselves, which helps `vigil-cli doctor`.
    async fn whoami(
        &self,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &Connection,
    ) -> fdo::Result<String> {
        let c = Authorizer::caller(conn, &hdr).await?;
        let mode = match self.auth.mode {
            Mode::Polkit => "polkit".to_string(),
            Mode::SameUid(u) => format!("same-uid {u}"),
        };
        json(&serde_json::json!({"uid": c.uid, "pid": c.pid, "bus_name": c.bus_name, "auth": mode}))
    }

    #[zbus(property)]
    fn api_version(&self) -> u32 {
        API_VERSION
    }
}

struct ProcessesIface {
    shared: Arc<Shared>,
    auth: Arc<Authorizer>,
}

#[interface(name = "org.vigil.Processes")]
impl ProcessesIface {
    /// Every process at the last look.
    async fn list(
        &self,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &Connection,
    ) -> fdo::Result<String> {
        guard(&self.auth, conn, &hdr).await?;
        let procs = self.shared.procs.read().unwrap_or_else(|e| e.into_inner()).clone().ok_or_else(not_ready)?;
        json(&*procs)
    }

    /// One process by pid.
    async fn get(
        &self,
        pid: u32,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &Connection,
    ) -> fdo::Result<String> {
        guard(&self.auth, conn, &hdr).await?;
        let procs = self.shared.procs.read().unwrap_or_else(|e| e.into_inner()).clone().ok_or_else(not_ready)?;
        let p = procs.processes.iter().find(|p| p.pid == pid).ok_or_else(|| {
            fdo::Error::InvalidArgs(format!("no process {pid} at the last look (it may have exited)"))
        })?;
        json(p)
    }
}

struct NetworkIface {
    shared: Arc<Shared>,
    auth: Arc<Authorizer>,
}

#[interface(name = "org.vigil.Network")]
impl NetworkIface {
    /// Sockets and the programs holding them at the last look, with what is hidden and why.
    async fn snapshot(
        &self,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &Connection,
    ) -> fdo::Result<String> {
        guard(&self.auth, conn, &hdr).await?;
        let net = self.shared.net.read().unwrap_or_else(|e| e.into_inner()).clone().ok_or_else(not_ready)?;
        json(&*net)
    }

    /// The time machine: connections open at `t` (seconds since the epoch).
    async fn at(
        &self,
        t: f64,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &Connection,
    ) -> fdo::Result<String> {
        guard(&self.auth, conn, &hdr).await?;
        let store = self.shared.store.lock().unwrap_or_else(|e| e.into_inner());
        json(&store.connections_at(t, 3.0).map_err(|e| fdo::Error::Failed(e.to_string()))?)
    }

    /// Connections open at any moment between `from` and `to`.
    async fn between(
        &self,
        from: f64,
        to: f64,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &Connection,
    ) -> fdo::Result<String> {
        guard(&self.auth, conn, &hdr).await?;
        let store = self.shared.store.lock().unwrap_or_else(|e| e.into_inner());
        json(&store.connections_between(from, to).map_err(|e| fdo::Error::Failed(e.to_string()))?)
    }
}

struct EventsIface {
    shared: Arc<Shared>,
    auth: Arc<Authorizer>,
}

#[interface(name = "org.vigil.Events")]
impl EventsIface {
    /// Vigil's own event log since `ts`, newest first, at most `limit` (capped at 1,000).
    async fn since(
        &self,
        ts: f64,
        limit: u32,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &Connection,
    ) -> fdo::Result<String> {
        guard(&self.auth, conn, &hdr).await?;
        let store = self.shared.store.lock().unwrap_or_else(|e| e.into_inner());
        json(&store.events_since(ts, limit.min(1000) as usize).map_err(|e| fdo::Error::Failed(e.to_string()))?)
    }

    /// Something changed ("poll": a new look at processes and connections).
    #[zbus(signal)]
    async fn changed(emitter: &SignalEmitter<'_>, kind: &str, taken_at: f64) -> zbus::Result<()>;
}

struct FindingsIface {
    shared: Arc<Shared>,
    auth: Arc<Authorizer>,
}

#[interface(name = "org.vigil.Findings")]
impl FindingsIface {
    /// Every stored finding as JSON lines, in Vigil 1's export format.
    async fn list(
        &self,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &Connection,
    ) -> fdo::Result<String> {
        guard(&self.auth, conn, &hdr).await?;
        let store = self.shared.store.lock().unwrap_or_else(|e| e.into_inner());
        let fs = store.findings().map_err(|e| fdo::Error::Failed(e.to_string()))?;
        Ok(vigil_model::finding::to_jsonl(&fs))
    }
}

pub async fn serve(
    bus: String,
    mode: Mode,
    shared: Arc<Shared>,
    root: ProcRoot,
    viewer: u32,
    interval: Duration,
) -> Result<(), String> {
    let auth = Arc::new(Authorizer::new(mode));
    let builder = match bus.as_str() {
        "system" => connection::Builder::system(),
        "session" => connection::Builder::session(),
        a if a.starts_with("address=") => connection::Builder::address(&a["address=".len()..]),
        other => return Err(format!("unknown --bus {other} (system, session or address=...)")),
    }
    .map_err(|e| format!("cannot reach the {bus} bus: {e}"))?;
    let conn = builder
        .name(BUS_NAME)
        .and_then(|b| b.serve_at(OBJECT_PATH, DaemonIface { shared: shared.clone(), auth: auth.clone() }))
        .and_then(|b| b.serve_at(OBJECT_PATH, ProcessesIface { shared: shared.clone(), auth: auth.clone() }))
        .and_then(|b| b.serve_at(OBJECT_PATH, NetworkIface { shared: shared.clone(), auth: auth.clone() }))
        .and_then(|b| b.serve_at(OBJECT_PATH, EventsIface { shared: shared.clone(), auth: auth.clone() }))
        .and_then(|b| b.serve_at(OBJECT_PATH, FindingsIface { shared: shared.clone(), auth: auth.clone() }))
        .map_err(|e| e.to_string())?
        .build()
        .await
        .map_err(|e| format!("cannot take the name {BUS_NAME} on the {bus} bus: {e}"))?;
    log!(
        6,
        "serving {BUS_NAME} on the {bus} bus ({})",
        match mode {
            Mode::Polkit => "callers checked with polkit".to_string(),
            Mode::SameUid(u) => format!("development mode: only uid {u} may call"),
        }
    );
    notify::notify("READY=1");

    // The sensor thread: look, record, tell listeners. Never blocks on a slow client.
    let (tx, mut rx) = tokio::sync::mpsc::channel::<f64>(1);
    let stop = Arc::new(AtomicBool::new(false));
    let thread = {
        let (shared, stop) = (shared.clone(), stop.clone());
        std::thread::Builder::new()
            .name("sensor".into())
            .spawn(move || {
                let mut last_retention = Instant::now();
                while !stop.load(Ordering::Relaxed) {
                    std::thread::sleep(interval);
                    poll(&shared, &root, viewer);
                    let taken =
                        shared.net.read().unwrap_or_else(|e| e.into_inner()).as_ref().map_or(0.0, |n| n.taken_at);
                    let _ = tx.try_send(taken);
                    if last_retention.elapsed() > Duration::from_secs(3600) {
                        last_retention = Instant::now();
                        let mut store = shared.store.lock().unwrap_or_else(|e| e.into_inner());
                        match store.apply_retention(vigil_model::finding::now(), shared.retention_days) {
                            Ok(n) if n > 0 => {
                                log!(6, "retention: removed {n} rows older than {} days", shared.retention_days)
                            }
                            Ok(_) => {}
                            Err(e) => log!(3, "retention failed: {e}"),
                        }
                    }
                }
            })
            .map_err(|e| e.to_string())?
    };
    let emit_conn = conn.clone();
    tokio::spawn(async move {
        while let Some(ts) = rx.recv().await {
            if let Ok(iref) = emit_conn.object_server().interface::<_, EventsIface>(OBJECT_PATH).await {
                let _ = EventsIface::changed(iref.signal_emitter(), "poll", ts).await;
            }
        }
    });
    // Watchdog: ping only while the sensor thread keeps looking.
    if let Some(every) = notify::watchdog_interval() {
        let shared = shared.clone();
        tokio::spawn(async move {
            let mut last = 0;
            loop {
                tokio::time::sleep(every).await;
                let count = shared.polls.lock().unwrap_or_else(|e| e.into_inner()).count;
                if count != last {
                    notify::notify("WATCHDOG=1");
                }
                last = count;
            }
        });
    }
    let mut term = signal(SignalKind::terminate()).map_err(|e| e.to_string())?;
    tokio::select! {
        _ = term.recv() => log!(6, "stopping (SIGTERM)"),
        _ = tokio::signal::ctrl_c() => log!(6, "stopping (Ctrl+C)"),
    }
    stop.store(true, Ordering::Relaxed);
    drop(thread);
    Ok(())
}
